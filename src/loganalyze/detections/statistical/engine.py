"""Statistical_Engine: drive the statistical anomaly detectors over a run.

The :class:`StatisticalEngine` is the deterministic driver for the two
standard-library statistical detectors defined under
``loganalyze.detections.statistical``:

- :class:`~loganalyze.detections.statistical.rate_spike.RateSpikeDetector`
  (``rule_id`` ``"stat.rate_spike"``) — flags fixed-duration time buckets whose
  event count is a statistical rate spike.
- :class:`~loganalyze.detections.statistical.rare_event.RareEventDetector`
  (``rule_id`` ``"stat.rare_event"``) — flags categorical values whose relative
  frequency is rare.

Why these detectors are imported directly (not from the registry)
------------------------------------------------------------------
Unlike the signature detectors driven by the Rule_Engine, the statistical
detectors are *not* registered in the shared plugin registry. Registering them
there would let the Rule_Engine iterate and run them as if they were signature
detectors, coupling the two engines and double-firing statistical findings. They
are therefore plain importable classes that this engine constructs and calls
directly, keeping the Rule_Engine and the Statistical_Engine decoupled (see each
detector's module docstring).

Explainable metadata (Requirement 6.5)
---------------------------------------
Every statistical :class:`~loganalyze.models.Finding` must carry a baseline
value, an observed value, a score, and a threshold in ``metadata`` so a reviewer
can see *why* it fired. Both detectors already populate these keys; this engine
verifies they are present on each produced Finding (:func:`_assert_explainable`)
and raises a :class:`ValueError` if one is missing, so a regression in a
detector surfaces loudly rather than emitting an unexplainable finding.

Evidence enrichment for rate-spike findings
--------------------------------------------
The rate-spike detector reasons over *aggregate* per-bucket counts, so it leaves
each Finding's ``events`` empty — at detection time it knows a bucket is
anomalous but not, as a list of :class:`~loganalyze.models.Event`, which records
fell in it. This engine attaches that evidence: it re-buckets the same events
with the same ``baseline_window_seconds`` logic the detector used, groups the
events by bucket index, and sets ``Finding.events`` to the events of the bucket
named by ``metadata["bucket_index"]``. After enrichment each rate-spike finding
references the concrete events that produced the spike. Enrichment is
deterministic (events are attached in pipeline order) and standard-library only.

Purity
------
:meth:`StatisticalEngine.run` is a pure function of its inputs: it performs no
I/O, raises no alerts for well-formed detector output, and returns an identical
result for identical ``events``/``config``. Detectors run in a fixed order
(rate-spike, then rare-event) so the concatenated output is stable.
"""

from __future__ import annotations

from loganalyze.config import DetectionConfig
from loganalyze.detections.statistical.rare_event import RareEventDetector
from loganalyze.detections.statistical.rate_spike import (
    RATE_SPIKE_RULE_ID,
    RateSpikeDetector,
    _timestamp_key,
)
from loganalyze.models import Event, Finding

#: Metadata keys that make a statistical Finding explainable (Requirement 6.5).
#: Every Finding produced by either statistical detector must carry all four so
#: a reviewer sees the baseline it was measured against, the observed value, the
#: resulting score, and the configured threshold.
_EXPLAINABLE_KEYS = ("baseline", "observed", "score", "threshold")


def _assert_explainable(finding: Finding) -> None:
    """Verify a statistical Finding carries the explainable metadata keys.

    Requirement 6.5 requires every statistical Finding to include a baseline
    value, an observed value, a score, and a threshold in ``metadata``. The
    detectors populate these; this guard confirms the contract held for the
    Finding before the engine returns it, so a detector regression that drops a
    key fails loudly instead of emitting an unexplainable finding.

    Args:
        finding: A Finding produced by a statistical detector.

    Raises:
        ValueError: If any of :data:`_EXPLAINABLE_KEYS` is absent from the
            Finding's ``metadata``.
    """
    missing = [key for key in _EXPLAINABLE_KEYS if key not in finding.metadata]
    if missing:
        raise ValueError(
            f"statistical finding {finding.rule_id!r} is missing explainable "
            f"metadata key(s) {missing}; every statistical finding must include "
            f"baseline, observed, score, and threshold (Requirement 6.5)"
        )


def _events_by_bucket(
    events: list[Event], window_seconds: int
) -> dict[int, list[Event]]:
    """Group events by the rate-spike bucket index they fall in.

    This mirrors the bucketing the rate-spike detector performs: buckets are
    anchored at the earliest event key, span ``window_seconds`` each, and are
    half-open ``[start, start + window)`` so an event exactly on a boundary
    falls into the later bucket. The same :func:`_timestamp_key` mapping is used
    so the indices computed here line up exactly with the detector's
    ``metadata["bucket_index"]`` values (including the mixed-timezone-safe
    fallback). Events are collected in pipeline order within each bucket so the
    enrichment is deterministic.

    Args:
        events: The normalized events to group, in pipeline order.
        window_seconds: Bucket duration in seconds; matches the detector's
            ``baseline_window_seconds``.

    Returns:
        A mapping from bucket index to the events that fell in that bucket, in
        pipeline order. Empty when ``events`` is empty or ``window_seconds`` is
        not positive.
    """
    if not events or window_seconds <= 0:
        return {}

    origin = min(_timestamp_key(event.timestamp) for event in events)
    span = float(window_seconds)

    buckets: dict[int, list[Event]] = {}
    for event in events:
        index = int((_timestamp_key(event.timestamp) - origin) // span)
        buckets.setdefault(index, []).append(event)
    return buckets


class StatisticalEngine:
    """Resolve and run the statistical detectors, enriching their findings.

    The engine holds no mutable state; each :meth:`run` call constructs fresh
    detector instances and drives them in a fixed order (rate-spike, then
    rare-event). It performs two post-processing steps required by the design:

    * **Evidence enrichment.** Rate-spike findings arrive with empty ``events``
      because the detector reasons over aggregate bucket counts. The engine
      attaches the contributing events for each flagged bucket, keyed by the
      finding's ``metadata["bucket_index"]``, so every finding references the
      concrete records that produced it.
    * **Explainability check.** Each returned finding is verified to carry the
      baseline, observed, score, and threshold metadata keys (Requirement 6.5).

    The two statistical detectors are imported and called directly rather than
    resolved from the shared plugin registry, keeping the Statistical_Engine
    decoupled from the Rule_Engine (see the module docstring).
    """

    def __init__(self) -> None:
        """Construct the engine with the two statistical detectors.

        The detectors are plain importable classes (not registry entries); the
        engine owns their instances and calls their ``detect`` directly.
        """
        self._rate_spike = RateSpikeDetector()
        self._rare_event = RareEventDetector()

    def run(
        self, events: list[Event], config: DetectionConfig
    ) -> list[Finding]:
        """Run both statistical detectors over ``events`` and collect findings.

        Pure function of ``events`` and ``config``: no I/O, no alerting, order
        independent for a given input. The rate-spike detector runs first and
        the rare-event detector second, and their findings are concatenated in
        that fixed order so the result is deterministic.

        Rate-spike findings are enriched with the events of their flagged bucket
        (the detector leaves ``events`` empty because it works on aggregate
        counts): the engine re-buckets ``events`` with the same
        ``baseline_window_seconds`` and sets each finding's ``events`` to the
        bucket named by ``metadata["bucket_index"]``. Every returned finding is
        then verified to carry the explainable metadata required by Requirement
        6.5.

        Args:
            events: The normalized events to inspect, in pipeline order.
            config: The injected detection configuration supplying the baseline
                window, z-score threshold, rare cutoff, and minimum
                observations.

        Returns:
            A flat list of every statistical Finding — rate-spike findings
            first, then rare-event findings — each carrying explainable
            metadata, with rate-spike findings referencing their contributing
            events. An empty list when neither detector fired.
        """
        window_seconds = config.statistical.baseline_window_seconds

        rate_spike_findings = self._rate_spike.detect(events, config)
        self._enrich_rate_spike_events(
            rate_spike_findings, events, window_seconds
        )

        rare_event_findings = self._rare_event.detect(events, config)

        findings = [*rate_spike_findings, *rare_event_findings]
        for finding in findings:
            _assert_explainable(finding)
        return findings

    def _enrich_rate_spike_events(
        self,
        findings: list[Finding],
        events: list[Event],
        window_seconds: int,
    ) -> None:
        """Attach each flagged bucket's contributing events to its Finding.

        The rate-spike detector emits findings with empty ``events`` because it
        reasons over aggregate bucket counts. This method re-buckets ``events``
        with the detector's own bucketing logic and the same ``window_seconds``,
        then sets each finding's ``events`` to the events whose timestamp fell in
        the bucket named by its ``metadata["bucket_index"]``. Findings are
        mutated in place (``Finding`` is a mutable dataclass).

        A finding is only enriched when it is a rate-spike finding carrying an
        integer ``bucket_index``; any other finding is left untouched. The
        re-bucketing uses the same :func:`_timestamp_key` mapping as the
        detector, so a finding's ``bucket_index`` always resolves to a known
        bucket here.

        Args:
            findings: The rate-spike findings to enrich, mutated in place.
            events: The full event list, in pipeline order.
            window_seconds: The baseline window in seconds used to bucket.
        """
        if not findings:
            return

        buckets = _events_by_bucket(events, window_seconds)
        for finding in findings:
            if finding.rule_id != RATE_SPIKE_RULE_ID:
                continue
            bucket_index = finding.metadata.get("bucket_index")
            if not isinstance(bucket_index, int):
                continue
            finding.events = buckets.get(bucket_index, [])
