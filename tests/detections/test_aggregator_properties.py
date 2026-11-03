# Feature: loganalyze, Property 15: Aggregation merges duplicates and unions
# their events.
#
# Validates: Requirements 7.3, 7.6
#
# Feature: loganalyze, Property 16: Aggregation ordering is deterministic and
# severity-ranked.
#
# Validates: Requirements 7.4, 7.5
"""Property-based tests for :func:`loganalyze.aggregator.aggregate`.

Property 15 checks the dedupe/union contract: after aggregation no two results
share the same ``(rule_id, dedup_key)``, and each merged ``Finding``'s events
are the union of the events of every input sharing that key.

Property 16 checks determinism and ranking: aggregating any permutation of the
same input yields an identical output order, severities are non-increasing from
``critical`` to ``info``, and ties break deterministically.

Both properties drive ``aggregate`` with Hypothesis-generated ``Finding``s whose
``metadata`` carries one of the identifying fields the aggregator keys on (see
:func:`loganalyze.aggregator._dedup_key`), so generated findings genuinely
collide on ``(rule_id, dedup_key)`` as well as stay distinct.
"""

from __future__ import annotations

from datetime import datetime

from hypothesis import given, settings
from hypothesis import strategies as st

from loganalyze.aggregator import _dedup_key, aggregate
from loganalyze.models import Event, Finding, Severity

# A deliberately small rule_id pool so generated findings frequently share a
# rule_id (a precondition for merging) rather than almost always being unique.
_RULE_IDS = ["auth.bruteforce", "web.sqli.probe", "stat.rate_spike"]

# The metadata fields ``_dedup_key`` keys on, each drawn from a tiny value pool
# so duplicates actually collide. ``client_ip`` is checked before ``path`` and
# ``user`` in the aggregator, so a finding carrying several of these is keyed on
# all present fields; keeping the pools small keeps collisions frequent.
_IDENTIFYING = {
    "client_ip": ["192.0.2.1", "192.0.2.2"],
    "path": ["/login", "/admin"],
    "user": ["alice", "bob"],
    "value": ["404", "500"],
}


def _metadata_strategy() -> st.SearchStrategy[dict]:
    """Build metadata carrying at least one identifying field the key uses.

    Picks one of the known identifying field names and a value from its small
    pool so that findings routinely share — and routinely differ on — the
    resulting dedup key.
    """
    return st.sampled_from(sorted(_IDENTIFYING)).flatmap(
        lambda name: st.sampled_from(_IDENTIFYING[name]).map(
            lambda value: {name: value}
        )
    )


# Severity assigned per identifying metadata value. The aggregator keeps the
# first contributor's severity/detail/metadata for a key and documents that
# inputs sharing a key "describe the same detection, so these agree". Real
# detectors honour that: one logical detection has one severity. We model it by
# making severity a deterministic function of the key-driving value, so any two
# generated findings that collide on (rule_id, dedup_key) also agree on
# severity. Findings that differ on the key still span the whole Severity enum.
_SEVERITY_FOR_VALUE = {
    "192.0.2.1": Severity.CRITICAL,
    "192.0.2.2": Severity.HIGH,
    "/login": Severity.MEDIUM,
    "/admin": Severity.LOW,
    "alice": Severity.INFO,
    "bob": Severity.CRITICAL,
    "404": Severity.HIGH,
    "500": Severity.MEDIUM,
}


def _severity_for(metadata: dict) -> Severity:
    """Return the severity a logical detection with this key carries."""
    (value,) = metadata.values()
    return _SEVERITY_FOR_VALUE[value]


# A small set of distinct timestamps/sources so generated events both collide
# (to exercise de-duplication inside a merge) and differ (to exercise the
# order-preserving union).
_SOURCES = ["access.log", "auth.log"]
_TIMESTAMPS = [
    datetime(2024, 1, 1, 0, 0, 0),
    datetime(2024, 1, 1, 0, 0, 1),
    datetime(2024, 1, 1, 0, 0, 2),
]


@st.composite
def _events(draw) -> Event:
    """Generate a small, value-comparable :class:`Event`.

    Events vary only in ``source`` and ``timestamp`` (the fields the aggregator
    orders on); the remaining fields are fixed so equality — and therefore the
    set-union semantics under test — is driven by that varying pair.
    """
    source = draw(st.sampled_from(_SOURCES))
    ts = draw(st.sampled_from(_TIMESTAMPS))
    return Event(
        timestamp=ts,
        source=source,
        log_type="test",
        message="m",
        raw="raw",
    )


@st.composite
def _findings(draw) -> Finding:
    """Generate a :class:`Finding` that can collide with others on its key.

    ``rule_id`` and ``metadata`` are drawn from small pools so findings share a
    ``(rule_id, dedup_key)`` often enough to exercise merging; ``severity`` spans
    the whole enum so ranking is tested across all levels.
    """
    rule_id = draw(st.sampled_from(_RULE_IDS))
    # Events are unique within a single finding: a real detector attaches
    # distinct contributing events, and the aggregator's union de-duplicates
    # across the findings it merges (not within one finding's own list). Keeping
    # per-finding events distinct keeps the generated input realistic while the
    # cross-finding union remains the behaviour under test.
    events = draw(
        st.lists(_events(), min_size=1, max_size=4, unique_by=_event_identity)
    )
    metadata = draw(_metadata_strategy())
    # severity and detail are deterministic functions of the identifying
    # metadata so inputs that share a (rule_id, dedup_key) also agree on them,
    # matching how real detectors describe one logical detection identically.
    severity = _severity_for(metadata)
    detail = f"{rule_id}:{sorted(metadata.items())}"
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        events=list(events),
        detail=detail,
        metadata=metadata,
    )


def _event_identity(event: Event) -> tuple:
    """A hashable identity for an Event matching frozen-dataclass equality."""
    return (
        event.source,
        str(event.timestamp),
        event.log_type,
        event.message,
        event.raw,
    )


@settings(max_examples=200)
@given(findings=st.lists(_findings(), max_size=25))
def test_aggregation_merges_duplicates_and_unions_events(findings):
    """Property 15: distinct keys out, events are the per-key union (Req 7.3, 7.6)."""
    result = aggregate(findings)

    # No two results share the same (rule_id, dedup_key).
    out_keys = [(f.rule_id, _dedup_key(f)) for f in result]
    assert len(out_keys) == len(set(out_keys))

    # Oracle: group inputs by (rule_id, dedup_key) and union their events,
    # preserving first-seen order exactly as the aggregator documents.
    expected_events: dict[tuple, list[Event]] = {}
    for f in findings:
        key = (f.rule_id, _dedup_key(f))
        bucket = expected_events.setdefault(key, [])
        for ev in f.events:
            if ev not in bucket:
                bucket.append(ev)

    # Every input key appears exactly once in the output and vice versa.
    assert set(out_keys) == set(expected_events)

    # Each merged finding's events equal the union (as a set) of all inputs'
    # events for that key — the merge loses nothing and invents nothing.
    for f in result:
        key = (f.rule_id, _dedup_key(f))
        got = {_event_identity(e) for e in f.events}
        want = {_event_identity(e) for e in expected_events[key]}
        assert got == want
        # The union carries no duplicate events.
        assert len(f.events) == len(got)


@settings(max_examples=200)
@given(data=st.data(), findings=st.lists(_findings(), max_size=25))
def test_aggregation_is_deterministic_and_severity_ranked(data, findings):
    """Property 16: permutation-invariant order, non-increasing severity (Req 7.4, 7.5)."""
    result = aggregate(findings)

    # Severities are non-increasing from critical (4) down to info (0).
    severities = [int(f.severity) for f in result]
    assert severities == sorted(severities, reverse=True)

    # Aggregating any permutation yields identical output order and content.
    permuted = data.draw(st.permutations(findings))
    other = aggregate(permuted)

    assert len(result) == len(other)

    def signature(f: Finding) -> tuple:
        return (
            f.rule_id,
            int(f.severity),
            f.detail,
            tuple(sorted(_event_identity(e) for e in f.events)),
        )

    # Identical order (position by position), not merely the same set.
    assert [signature(f) for f in result] == [signature(f) for f in other]
