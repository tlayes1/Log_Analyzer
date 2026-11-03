"""Deduplicate, group, and rank Findings for deterministic output.

The aggregator is the pipeline stage between detection and output. It takes the
raw Findings produced by the Rule_Engine and Statistical_Engine and returns a
single, deterministically ordered list in which duplicate detections have been
merged and their contributing events unioned.

Three transformations are applied, in order:

1. **Dedupe** — Findings sharing the same ``(rule_id, dedup_key)`` are merged
   into one Finding whose ``events`` list is the order-preserving union of the
   contributing Findings' events (Requirements 7.3, 7.6).
2. **Group** — merged Findings that share a ``rule_id`` are kept together so the
   output lists one rule's findings contiguously (Requirement 7.6).
3. **Rank** — the result is ordered by :class:`~loganalyze.models.Severity` from
   ``critical`` down to ``info`` (Requirement 7.4) with a deterministic
   secondary ordering that makes identical input sets always yield identical
   output regardless of input order (Requirement 7.5).

This module is a pure function of its input: it performs no I/O and relies on
nothing but the Python standard library.
"""

from __future__ import annotations

from loganalyze.models import Event, Finding

__all__ = ["aggregate"]


def aggregate(findings: list[Finding]) -> list[Finding]:
    """Merge duplicate Findings, group by rule, and rank by severity.

    Findings sharing ``(rule_id, dedup_key)`` are merged into a single Finding
    whose ``events`` field is the order-preserving, de-duplicated union of the
    contributing Findings' events. The surviving Finding keeps the ``title``,
    ``severity``, ``detail``, and ``metadata`` of the first contributor for that
    key (inputs sharing a key describe the same detection, so these agree). The
    result is ordered ``critical`` → ``info`` with a deterministic secondary
    sort so identical input sets always produce identical output.

    This is a pure function: it does not mutate the input Findings or their
    event lists, performs no I/O, and returns an identical result for an
    identical input regardless of the input's order.

    Args:
        findings: The Findings emitted by all detectors in a single run. May be
            empty.

    Returns:
        A new list of merged Findings ordered by descending severity with a
        deterministic secondary ordering. Each result has a distinct
        ``(rule_id, dedup_key)``.
    """
    merged: dict[tuple, Finding] = {}
    for finding in findings:
        key = (finding.rule_id, _dedup_key(finding))
        existing = merged.get(key)
        if existing is None:
            # First finding for this key: copy it so the input is never mutated
            # and so the event list we extend below is independent of the input.
            merged[key] = Finding(
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                events=list(finding.events),
                detail=finding.detail,
                metadata=finding.metadata,
            )
        else:
            _union_events(existing.events, finding.events)

    return sorted(merged.values(), key=_rank_key)


def _dedup_key(finding: Finding) -> tuple:
    """Derive a deterministic deduplication key from a Finding.

    Two Findings with the same ``rule_id`` and the same ``_dedup_key`` describe
    the same underlying detection and are merged. The key is built from the
    salient identifying metadata each rule family records, so that, for example,
    two brute-force Findings for the same ``client_ip`` collapse into one while
    brute-force Findings for different IPs stay distinct.

    Keying strategy (the first group of present fields wins, giving a stable key
    that is as specific as the available metadata allows):

    - ``client_ip`` — identifies per-source detections such as
      ``auth.bruteforce`` and ``auth.failed_login`` (Requirement 5.4, 5.6).
    - ``path`` — identifies web signature probes keyed on the matched request
      path, e.g. ``web.sqli.probe`` / ``web.xss.probe`` (Requirement 5.1, 5.2).
    - ``user`` — identifies user-scoped detections such as ``auth.privesc``
      (Requirement 5.7).
    - ``value`` / ``observed`` / ``bucket_index`` — identify statistical
      detections, which record the anomalous categorical value or bucket in
      their metadata (Requirement 6.5).

    Any of the above that are present are folded into the key together, so a
    detection that records several of them (e.g. ``client_ip`` *and* ``user``)
    is keyed on all of them. When none of the known identifying fields is
    present, the key falls back to the earliest contributing event's
    ``(source, str(timestamp))`` and finally to the Finding's ``detail`` — a
    deterministic last resort that keeps otherwise-identical Findings merged
    without collapsing genuinely distinct ones.

    Args:
        finding: The Finding to derive a key for.

    Returns:
        A hashable tuple that is stable for a given logical detection. The tuple
        is prefixed with the names of the metadata fields that contributed to it
        so that, for example, a ``path`` key and a ``user`` key with the same
        string value never collide.
    """
    metadata = finding.metadata or {}
    key_parts: list[tuple[str, str]] = []
    for name in ("client_ip", "path", "user", "value", "observed", "bucket_index"):
        if name in metadata and metadata[name] is not None:
            key_parts.append((name, str(metadata[name])))

    if key_parts:
        return tuple(key_parts)

    earliest = _earliest_event(finding.events)
    if earliest is not None:
        return ("event", earliest.source, str(earliest.timestamp))

    return ("detail", finding.detail)


def _union_events(target: list[Event], extra: list[Event]) -> None:
    """Append events from ``extra`` to ``target`` without duplicates.

    Order is preserved: ``extra``'s events are appended in their original order,
    and any event equal to one already present in ``target`` is skipped so the
    merged list is the set-union of the two while remaining a stable list.
    :class:`~loganalyze.models.Event` is a frozen dataclass and therefore
    compares by value, so "identical event" means field-for-field equality.

    Args:
        target: The accumulating event list, mutated in place.
        extra: Events to merge into ``target``.
    """
    for event in extra:
        if event not in target:
            target.append(event)


def _earliest_event(events: list[Event]) -> Event | None:
    """Return the earliest contributing event by ``(source, timestamp)``.

    The earliest event provides the deterministic secondary sort key. Because
    :class:`~loganalyze.models.Event` carries no line number, ordering uses the
    event ``source`` and the string form of its ``timestamp`` as a stable,
    comparable surrogate (mixing aware and naive datetimes cannot be compared
    directly, so their string forms are used).

    Args:
        events: The Finding's contributing events. May be empty.

    Returns:
        The earliest event, or ``None`` when ``events`` is empty.
    """
    if not events:
        return None
    return min(events, key=lambda e: (e.source, str(e.timestamp)))


def _rank_key(finding: Finding) -> tuple:
    """Build the sort key implementing severity ranking and tie-breaking.

    Findings sort by descending severity first (``critical`` → ``info``), which
    is achieved by negating the :class:`~loganalyze.models.Severity` integer
    value since ``critical`` has the highest value. Ties on severity break
    deterministically on ``rule_id``, then the earliest contributing event's
    ``(source, str(timestamp))``, then ``detail`` — so identical input sets
    always yield identical output order (Requirements 7.4, 7.5).

    Args:
        finding: The Finding to compute a sort key for.

    Returns:
        A tuple ordering the Finding: ``(-severity, rule_id,
        earliest_source, earliest_timestamp_str, detail)``.
    """
    earliest = _earliest_event(finding.events)
    if earliest is not None:
        earliest_source = earliest.source
        earliest_ts = str(earliest.timestamp)
    else:
        earliest_source = ""
        earliest_ts = ""
    return (
        -int(finding.severity),
        finding.rule_id,
        earliest_source,
        earliest_ts,
        finding.detail,
    )
