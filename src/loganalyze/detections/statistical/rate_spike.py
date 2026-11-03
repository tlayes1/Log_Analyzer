"""Rate-spike anomaly detector for the Statistical_Engine.

This detector answers a single question over a run's events: *is any
fixed-duration time bucket carrying far more events than the run's typical
bucket?* It baselines the per-bucket event counts with the standard-library
``statistics`` module and flags any bucket whose z-score reaches the configured
threshold (Requirements 6.1, 6.2, 6.3, 6.8, 10.3).

How it works
------------
1. **Bucket.** Events are grouped into fixed-duration buckets of
   ``config.statistical.baseline_window_seconds`` (default 60s) by their
   :attr:`~loganalyze.models.Event.timestamp`. Buckets are anchored at the
   earliest event and are contiguous and half-open ``[start, start + window)``,
   so an event exactly on a boundary falls into the later bucket. Empty gaps
   between events become explicit zero-count buckets, so a lull before a spike
   lowers the baseline just as it should. The one exception is a pathologically
   wide span — e.g. a single run mixing naive ``auth.log`` timestamps (year
   defaults to 1900) with timezone-aware nginx timestamps (2024), whose keys lie
   a century apart. Representing every empty bucket across that gap would need
   tens of millions of entries and exhaust memory, so once the contiguous bucket
   count exceeds :data:`MAX_BUCKETS` the detector falls back to scoring only the
   buckets that actually contain events (the empty gap buckets are dropped). A
   genuine spike among the clustered activity is still detectable; see
   :func:`_bucket_counts`.
2. **Baseline.** The per-bucket counts form the series. :mod:`.zscore` computes
   the population mean and standard deviation and the per-bucket z-scores. With
   fewer than two buckets, or when every bucket holds the same count (zero
   standard deviation), there is no baseline and the detector yields nothing
   (Requirement 6.6).
3. **Flag.** Any bucket whose z-score is at or above
   ``config.statistical.z_threshold`` (default 3.0) produces a
   :class:`~loganalyze.models.Finding` carrying the baseline mean, the observed
   count, the z-score, and the threshold in ``metadata`` (Requirements 6.3,
   6.5).

Why this is a plain importable class, not a registered detector
---------------------------------------------------------------
Statistical detectors are driven by the :class:`Statistical_Engine`
(``engine.py``), *not* by the Rule_Engine. The Rule_Engine resolves its
detectors through :func:`loganalyze.registry.get_detectors`, iterating every
class registered with ``@register_detector``. Registering this detector there
would let the Rule_Engine run it too, coupling the two engines and double-firing
rate-spike findings. To keep the engines independent, :class:`RateSpikeDetector`
is a plain class that the Statistical_Engine imports and calls directly. It still
conforms to the :class:`~loganalyze.detections.base.Detector` protocol
(a ``rule_id`` attribute plus a pure ``detect(events, config)`` method), so the
engine can treat it uniformly alongside the rare-event detector.

Purity
------
:meth:`RateSpikeDetector.detect` is a pure function of its inputs: it performs no
I/O, raises no alerts, and returns an identical result for identical inputs. On a
run that mixes timezone-aware and naive timestamps (the pipeline emits a separate
mixed-timezone warning), subtracting one from another raises :class:`TypeError`;
the detector degrades by bucketing on the POSIX-like ordinal of each timestamp
rather than propagating the error.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from loganalyze.config import DetectionConfig
from loganalyze.detections.statistical import zscore
from loganalyze.models import Event, Finding, Severity

#: Registry-style identifier carried onto every Finding this detector produces.
#: It is namespaced under ``stat.`` to make clear the finding came from the
#: Statistical_Engine rather than a signature rule.
RATE_SPIKE_RULE_ID = "stat.rate_spike"

#: Upper bound on the number of contiguous zero-filled buckets the detector will
#: materialize densely. For any normal run the earliest and latest event are
#: close enough that the contiguous bucket count stays well under this cap and
#: the dense path runs exactly as before (empty gap buckets included, so lulls
#: still pull the baseline down).
#:
#: A single run can, however, mix timestamp *families* whose absolute epochs are
#: wildly apart — e.g. naive ``auth.log`` timestamps (whose year defaults to
#: 1900) alongside timezone-aware nginx timestamps (2024). Their
#: :func:`_timestamp_key` values then differ by a century, so the contiguous
#: bucket count ``last_index + 1`` becomes astronomically large (tens of
#: millions or more) even though almost every bucket is empty. Allocating a
#: dense list that long exhausts memory. When ``last_index + 1`` exceeds this
#: cap we therefore refuse the dense allocation and fall back to scoring only
#: the buckets that actually contain events (see :func:`_bucket_counts`).
MAX_BUCKETS = 1_000_000

#: Multiple of the configured threshold at or above which a spike is escalated
#: from MEDIUM to HIGH severity. A bucket whose z-score reaches twice the
#: threshold is treated as an unusually strong spike. See the severity mapping
#: documented on :func:`_severity_for`.
_HIGH_SEVERITY_FACTOR = 2.0


def _timestamp_key(timestamp: datetime) -> float:
    """Return a numeric sort/offset key for ``timestamp``, mixing-tz safe.

    Bucketing needs to measure elapsed seconds between timestamps. Subtracting a
    naive datetime from an aware one raises :class:`TypeError`, which can happen
    when a single run parsed both offset-bearing and offset-free logs. To stay
    pure and non-raising, we derive a numeric key that is total across both
    kinds: the POSIX timestamp when that is available, falling back to the
    ordinal-plus-seconds of the naive wall-clock value.

    Args:
        timestamp: The event timestamp, aware or naive.

    Returns:
        A float number of seconds suitable for differencing and ordering. Values
        are only compared against other keys from the same series, so the
        absolute epoch does not matter — only that the mapping is monotonic and
        consistent within the run.
    """
    try:
        return timestamp.timestamp()
    except (OverflowError, OSError, ValueError):  # pragma: no cover - defensive
        # Platform-specific failures converting a naive local datetime to epoch;
        # fall back to a stable ordinal-based second count.
        seconds = (
            timestamp.hour * 3600
            + timestamp.minute * 60
            + timestamp.second
            + timestamp.microsecond / 1_000_000
        )
        return timestamp.toordinal() * 86400 + seconds


def _bucket_counts(
    events: list[Event], window_seconds: int
) -> list[tuple[int, int]]:
    """Bucket ``events`` into fixed-duration buckets and count them.

    Buckets are anchored at the earliest event key and span ``window_seconds``
    each, half-open ``[start, start + window)``. Each returned pair is
    ``(bucket_index, count)`` where ``bucket_index`` is exactly
    ``int((key - origin) // span)`` — the same index the Statistical_Engine
    re-derives to attach evidence — and the pairs are ordered by ascending
    bucket index.

    Two regimes, selected by how wide the event span is:

    * **Dense (normal) regime.** When the contiguous bucket count
      ``last_index + 1`` is at most :data:`MAX_BUCKETS`, every bucket between the
      first and last event is represented, *including empty ones with count 0*,
      exactly as the original implementation did. Empty gap buckets still pull
      the baseline down, so the normal-case behavior (and output) is unchanged.
    * **Sparse (fallback) regime.** When ``last_index + 1`` exceeds
      :data:`MAX_BUCKETS`, the span is pathologically large — typically a run
      mixing naive and timezone-aware timestamp families whose epochs lie a
      century apart (see :data:`MAX_BUCKETS`). Materializing the dense
      zero-filled list would exhaust memory, so the detector does **not**
      allocate it. Instead it returns only the buckets that actually contain
      events, ordered by bucket index. The empty gap buckets are dropped from the
      baseline, which means the detector scores just the clustered activity — a
      genuine spike among that activity is still detectable without blowing up
      memory.

    In both regimes counting itself is sparse: a :class:`collections.Counter`
    over ``int((key - origin) // span)`` tallies occupancy without ever touching
    an empty bucket, so the only cost that scales with the span is the dense
    zero-fill, which the cap gates.

    Args:
        events: The events to bucket; order does not matter.
        window_seconds: Bucket duration in seconds; must be positive.

    Returns:
        A list of ``(bucket_index, count)`` pairs ordered by ascending bucket
        index. Empty when ``events`` is empty or ``window_seconds`` is not
        positive.
    """
    if not events or window_seconds <= 0:
        return []

    keys = [_timestamp_key(event.timestamp) for event in events]
    origin = min(keys)
    span = float(window_seconds)

    # Sparse tally first: count only the buckets that actually hold events. This
    # never allocates anything proportional to the (possibly enormous) span.
    occupancy: Counter[int] = Counter(
        int((key - origin) // span) for key in keys
    )

    # Index of the last bucket determines how many contiguous buckets exist.
    last_index = max(occupancy)
    if last_index + 1 <= MAX_BUCKETS:
        # Dense regime: materialize every contiguous bucket, empty ones
        # included, so lulls still lower the baseline (unchanged behavior).
        return [
            (index, occupancy.get(index, 0)) for index in range(last_index + 1)
        ]

    # Sparse fallback: the span is pathologically large, so score only the
    # occupied buckets, ordered by bucket index. Each pair keeps its true
    # ``int((key - origin) // span)`` index so engine enrichment still lines up.
    return sorted(occupancy.items())


def _severity_for(score: float, threshold: float) -> Severity:
    """Map a bucket's z-score to a Finding severity.

    Severity mapping (documented and intentionally simple):

    * **HIGH** when ``score >= threshold * 2`` — an unusually strong spike that
      clears twice the configured bar.
    * **MEDIUM** otherwise — a spike that crosses the threshold but is not
      extreme.

    The caller only invokes this for buckets that already meet the threshold, so
    no severity below MEDIUM is produced.

    Args:
        score: The bucket's z-score (already known to be ``>= threshold``).
        threshold: The configured z-score threshold.

    Returns:
        :data:`~loganalyze.models.Severity.HIGH` or
        :data:`~loganalyze.models.Severity.MEDIUM`.
    """
    if score >= threshold * _HIGH_SEVERITY_FACTOR:
        return Severity.HIGH
    return Severity.MEDIUM


class RateSpikeDetector:
    """Flag time buckets whose event count is a statistical rate spike.

    Conforms structurally to :class:`~loganalyze.detections.base.Detector` (a
    stable ``rule_id`` plus a pure :meth:`detect`) but is *not* registered with
    the Rule_Engine registry; the Statistical_Engine imports and calls it
    directly (see the module docstring).

    Attributes:
        rule_id: The stable identifier ``"stat.rate_spike"`` carried onto every
            Finding this detector produces.
    """

    rule_id = RATE_SPIKE_RULE_ID

    def detect(self, events: list[Event], config: DetectionConfig) -> list[Finding]:
        """Return rate-spike Findings for ``events``.

        Pure function of ``events`` and ``config``: no I/O, no alerting, order
        independent. Events are bucketed by ``baseline_window_seconds``, the
        per-bucket counts are z-scored via :mod:`.zscore`, and every bucket whose
        z-score reaches ``z_threshold`` becomes one Finding.

        Yields nothing (returns ``[]``) when fewer than two buckets are available
        or the baseline standard deviation is zero (Requirement 6.6).

        Args:
            events: The normalized events to inspect, in any order.
            config: Injected detection configuration supplying the baseline
                window and z-score threshold.

        Returns:
            A list of zero or more Findings, one per flagged bucket, in
            chronological bucket order. Each Finding's ``metadata`` carries the
            baseline mean, the observed count, the z-score, and the threshold
            (Requirement 6.5).
        """
        window_seconds = config.statistical.baseline_window_seconds
        threshold = config.statistical.z_threshold

        # Each pair is ``(bucket_index, count)`` where ``bucket_index`` is the
        # true ``int((key - origin) // span)`` — in both the dense and the
        # sparse-fallback regimes — so the engine's evidence enrichment, which
        # re-derives that same index, lines up on ``metadata["bucket_index"]``.
        bucket_counts = _bucket_counts(events, window_seconds)
        counts = [float(count) for _index, count in bucket_counts]
        scores = zscore.z_scores(counts)
        if not scores:
            # Fewer than two buckets or zero standard deviation: no baseline,
            # so no rate-spike finding for this series (Requirement 6.6).
            return []

        baseline = zscore.mean(counts)

        findings: list[Finding] = []
        for (bucket_index, count), score in zip(bucket_counts, scores):
            if score < threshold:
                continue

            severity = _severity_for(score, threshold)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Request-rate spike",
                    severity=severity,
                    # The detector works on aggregate bucket counts rather than a
                    # per-event signature match; the engine attaches contributing
                    # event references when it runs this detector.
                    events=[],
                    detail=(
                        f"Bucket {bucket_index} recorded {count} events versus a "
                        f"baseline of {baseline:.2f} "
                        f"(z-score {score:.2f} >= threshold {threshold})"
                    ),
                    metadata={
                        "bucket_index": bucket_index,
                        "baseline": baseline,
                        "observed": count,
                        "score": score,
                        "threshold": threshold,
                        "window_seconds": window_seconds,
                    },
                )
            )
        return findings
