"""Property-based tests for the statistical engine's math and explainability.

These tests exercise design Properties 12, 13, and 14 for the Statistical_Engine
and its two detectors (``rate_spike`` and ``rare_event``) using pytest +
Hypothesis. They build :class:`~loganalyze.models.Event` records directly so the
properties can control per-bucket occupancy and categorical frequencies
precisely, and they compare each detector against an independent ground-truth
oracle computed with the standard-library ``statistics``/``collections`` modules
rather than a copy of the detector's own code. A disagreement therefore signals a
real bug, not a shared mistake.

Synthetic data only (Requirement 11): generated IPs fall in the documentation
range ``192.0.2.0/24`` and no real PII or secrets appear.
"""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loganalyze.config import DetectionConfig, StatisticalConfig
from loganalyze.detections.statistical.engine import StatisticalEngine
from loganalyze.detections.statistical.rare_event import RULE_ID as RARE_RULE_ID
from loganalyze.detections.statistical.rate_spike import (
    RATE_SPIKE_RULE_ID,
    RateSpikeDetector,
)
from loganalyze.models import Event

ABS_TOL = 1e-9

# A fixed, naive epoch every synthetic event timestamp is offset from. Buckets
# are anchored at the earliest event, so pinning bucket 0 to be non-empty makes
# the generated count series map one-to-one onto contiguous bucket indices.
_EPOCH = datetime(2024, 1, 1, 0, 0, 0)

# Bucket window used by the rate-spike property. Events are placed near the start
# of each window so they land squarely inside the intended bucket.
_WINDOW_SECONDS = 60


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------


def _web_event(*, timestamp: datetime, status: int = 200) -> Event:
    """Build a minimal nginx web Event at ``timestamp`` with an HTTP status."""
    return Event(
        timestamp=timestamp,
        source="access.log",
        log_type="nginx",
        message="synthetic web request",
        raw="synthetic",
        client_ip="192.0.2.10",
        method="GET",
        path="/",
        status=status,
    )


def _auth_event(*, user: str, timestamp: datetime = _EPOCH) -> Event:
    """Build a minimal authlog Event carrying an authenticating ``user``."""
    return Event(
        timestamp=timestamp,
        source="auth.log",
        log_type="authlog",
        message="Accepted password",
        raw="synthetic",
        client_ip="192.0.2.10",
        user=user,
    )


def _events_from_bucket_counts(counts: list[int]) -> list[Event]:
    """Synthesize web events whose per-bucket occupancy equals ``counts``.

    Bucket ``i`` is the half-open window ``[i * _WINDOW_SECONDS, (i + 1) *
    _WINDOW_SECONDS)`` offset from ``_EPOCH``. For each bucket we place ``counts[i]``
    events a few seconds into the window (never on a boundary), so the detector,
    which anchors buckets at the earliest event, reproduces exactly this count
    series when bucket 0 is non-empty.
    """
    events: list[Event] = []
    for index, count in enumerate(counts):
        base = _EPOCH + timedelta(seconds=index * _WINDOW_SECONDS + 1)
        for offset in range(count):
            # Keep every event within the same bucket: offsets stay well below
            # the window span.
            ts = base + timedelta(milliseconds=offset)
            events.append(_web_event(timestamp=ts, status=200))
    return events


def _stat_config(
    *,
    z_threshold: float = 3.0,
    rare_cutoff: float = 0.01,
    min_observations: int = 20,
) -> DetectionConfig:
    """Build a DetectionConfig with a customized StatisticalConfig."""
    return DetectionConfig(
        statistical=StatisticalConfig(
            baseline_window_seconds=_WINDOW_SECONDS,
            z_threshold=z_threshold,
            rare_cutoff=rare_cutoff,
            min_observations=min_observations,
        )
    )


# ---------------------------------------------------------------------------
# Property 12: Rate-spike detection matches the stdlib statistics computation
# ---------------------------------------------------------------------------
# Feature: loganalyze, Property 12: for any list of bucket counts, the
# Statistical_Engine's z-score for each bucket equals
# (count - statistics.mean(counts)) / statistics.pstdev(counts) within 1e-9, it
# flags exactly the buckets whose z-score is at or above the threshold, and it
# yields no rate-spike Finding when fewer than two buckets exist or the standard
# deviation is zero.
# Validates: Requirements 6.1, 6.3, 6.6


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(
    # The detector anchors buckets at the earliest event and materializes empty
    # buckets only *between* the first and last events; a trailing empty bucket
    # produces no event and is never seen. To make the generated series map
    # one-to-one onto the buckets the detector scores, pin both ends non-empty
    # (first and last counts >= 1) and let interior buckets be zero or more.
    first=st.integers(min_value=1, max_value=8),
    middle=st.lists(st.integers(min_value=0, max_value=8), min_size=0, max_size=8),
    last=st.integers(min_value=1, max_value=8),
    z_threshold=st.floats(min_value=1.0, max_value=10.0),
)
def test_rate_spike_matches_stdlib(first, middle, last, z_threshold):
    counts = [first, *middle, last]
    events = _events_from_bucket_counts(counts)
    config = _stat_config(z_threshold=z_threshold)

    findings = RateSpikeDetector().detect(events, config)

    float_counts = [float(c) for c in counts]

    # Guard behavior (Requirement 6.6): fewer than two buckets, or zero spread.
    if len(counts) < 2 or statistics.pstdev(float_counts) == 0:
        assert findings == []
        return

    series_mean = statistics.mean(float_counts)
    sigma = statistics.pstdev(float_counts)
    expected_z = [(c - series_mean) / sigma for c in float_counts]

    # Oracle: exactly the bucket indices whose z-score reaches the threshold.
    expected_flagged = {
        i for i, z in enumerate(expected_z) if z >= z_threshold
    }
    fired = {f.metadata["bucket_index"] for f in findings}
    assert fired == expected_flagged

    # Each fired finding's reported z-score matches the stdlib formula within
    # tolerance, and its observed/baseline agree with the same series.
    for f in findings:
        idx = f.metadata["bucket_index"]
        assert abs(f.metadata["score"] - expected_z[idx]) <= ABS_TOL
        assert abs(f.metadata["baseline"] - series_mean) <= ABS_TOL
        assert abs(f.metadata["observed"] - float_counts[idx]) <= ABS_TOL
        assert f.metadata["threshold"] == z_threshold


@settings(max_examples=100)
@given(
    value=st.integers(min_value=0, max_value=8),
    n=st.integers(min_value=1, max_value=8),
    z_threshold=st.floats(min_value=1.0, max_value=10.0),
)
def test_rate_spike_silent_when_stdev_zero(value, n, z_threshold):
    """All-equal bucket counts give zero spread, so no finding (Req 6.6)."""
    # Every bucket holds the same count: pstdev is zero, so the detector is
    # silent regardless of how many buckets there are.
    counts = [value] * n
    if value == 0:
        # No events at all -> no buckets; trivially silent. Still a valid case.
        events: list[Event] = []
    else:
        events = _events_from_bucket_counts(counts)
    findings = RateSpikeDetector().detect(events, _stat_config(z_threshold=z_threshold))
    assert findings == []


# ---------------------------------------------------------------------------
# Property 13: Rare-event detection matches relative frequency and the guard
# ---------------------------------------------------------------------------
# Feature: loganalyze, Property 13: for any categorical series with at least
# min_observations samples, the Statistical_Engine flags exactly the values whose
# relative frequency is strictly below rare_cutoff; with fewer than
# min_observations samples it yields no rare-event Finding.
# Validates: Requirements 6.4, 6.7

# Distinct synthetic usernames for the authenticating-user categorical.
_USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(
    # A multiset of user samples drawn from a small label set, so some labels
    # naturally land below the cutoff and others above.
    samples=st.lists(st.sampled_from(_USERS), min_size=0, max_size=60),
    rare_cutoff=st.floats(min_value=0.05, max_value=0.9),
    min_observations=st.integers(min_value=1, max_value=40),
)
def test_rare_event_matches_relative_frequency(samples, rare_cutoff, min_observations):
    events = [_auth_event(user=user) for user in samples]
    config = _stat_config(rare_cutoff=rare_cutoff, min_observations=min_observations)

    findings = StatisticalEngine().run(events, config)
    rare_findings = [f for f in findings if f.rule_id == RARE_RULE_ID]
    fired_values = {f.metadata["observed"]["value"] for f in rare_findings}

    total = len(samples)
    if total < min_observations:
        # Observation guard (Requirement 6.7): below the minimum, yield nothing.
        assert rare_findings == []
        return

    # Oracle: count each distinct label and flag those strictly below the cutoff.
    counts: dict[str, int] = {}
    for user in samples:
        counts[user] = counts.get(user, 0) + 1
    expected_rare = {
        value for value, count in counts.items() if count / total < rare_cutoff
    }
    assert fired_values == expected_rare

    # Each rare finding's score is the value's exact relative frequency, and its
    # threshold is the configured cutoff.
    for f in rare_findings:
        value = f.metadata["observed"]["value"]
        assert abs(f.metadata["score"] - counts[value] / total) <= ABS_TOL
        assert f.metadata["threshold"] == rare_cutoff


# ---------------------------------------------------------------------------
# Property 14: Statistical findings are explainable
# ---------------------------------------------------------------------------
# Feature: loganalyze, Property 14: for any statistical Finding produced, its
# metadata contains the baseline value, the observed value, the score, and the
# threshold.
# Validates: Requirements 6.5

_EXPLAINABLE_KEYS = ("baseline", "observed", "score", "threshold")


@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
@given(
    # Drive both detectors: a bucket-count series feeds rate-spike, and a user
    # multiset feeds rare-event. Low thresholds / cutoffs so findings actually
    # fire across many examples.
    first=st.integers(min_value=1, max_value=10),
    rest=st.lists(st.integers(min_value=0, max_value=10), min_size=1, max_size=9),
    users=st.lists(st.sampled_from(_USERS), min_size=0, max_size=50),
    z_threshold=st.floats(min_value=1.0, max_value=3.0),
    rare_cutoff=st.floats(min_value=0.1, max_value=0.5),
    min_observations=st.integers(min_value=1, max_value=20),
)
def test_statistical_findings_are_explainable(
    first, rest, users, z_threshold, rare_cutoff, min_observations
):
    counts = [first, *rest]
    events = _events_from_bucket_counts(counts)
    # Offset auth events past the web buckets so bucketing anchoring is unaffected
    # for rate-spike (auth events carry no status and are ignored by rate-spike's
    # count of web activity, but they still occupy time buckets; placing them in
    # the same span keeps the example realistic).
    events.extend(_auth_event(user=user, timestamp=_EPOCH) for user in users)
    config = _stat_config(
        z_threshold=z_threshold,
        rare_cutoff=rare_cutoff,
        min_observations=min_observations,
    )

    findings = StatisticalEngine().run(events, config)
    for f in findings:
        for key in _EXPLAINABLE_KEYS:
            assert key in f.metadata, (
                f"statistical finding {f.rule_id!r} missing metadata key {key!r}"
            )
    # Sanity: every finding came from one of the two statistical detectors.
    for f in findings:
        assert f.rule_id in (RATE_SPIKE_RULE_ID, RARE_RULE_ID)
