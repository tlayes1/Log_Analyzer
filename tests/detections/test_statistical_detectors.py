"""Positive and false-positive tests for the statistical detectors.

These example-based tests exercise the rate-spike and rare-event detectors and
the :class:`StatisticalEngine` that drives them, covering both the firing path
(a planted anomaly is surfaced with explainable metadata) and the guardrail path
(ordinary, well-distributed input stays silent).

Positive cases
--------------
- Rate spike (Requirements 6.3, 11.3): the planted ``spike_requests.log``
  fixture carries a steady ~2/minute baseline and a burst of ~30 requests in the
  09:10 bucket. Running it through :class:`StatisticalEngine` yields a
  ``stat.rate_spike`` finding whose metadata carries the baseline, observed
  count, z-score (>= 3.0), threshold (3.0), bucket index, and window, and whose
  events were enriched by the engine (non-empty).
- Rare event (Requirements 6.4, 11.4): a synthetic categorical series of 199
  ``200`` responses and a single ``500`` response — one value strictly below the
  0.01 rare cutoff over >= 20 observations — yields a ``stat.rare_event`` finding
  for ``"500"`` with baseline/observed/score/threshold metadata.

False-positive cases (Requirement 11.5)
----------------------------------------
- Rate spike: a perfectly steady series (equal counts per bucket, zero spread)
  produces no rate-spike finding (the 6.6 zero-sigma guard).
- Rare event: a well-distributed series where no value falls below the cutoff
  produces no rare-event finding; and a series below ``min_observations`` (6.7)
  produces nothing at all.

All sample data is synthetic: documentation-range IPs and ``example.com`` hosts
only (Requirement 11).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from loganalyze.config import DetectionConfig
from loganalyze.detections.statistical.engine import StatisticalEngine
from loganalyze.detections.statistical.rare_event import RareEventDetector
from loganalyze.detections.statistical.rate_spike import RateSpikeDetector
from loganalyze.models import Event
from loganalyze.parsers.nginx import NginxParser


# --- Helpers ---------------------------------------------------------------


def _parse_nginx(lines: list[str]) -> list[Event]:
    """Parse nginx fixture lines into Events, dropping any that don't match."""
    parser = NginxParser()
    events = [parser.parse(line) for line in lines]
    return [event for event in events if event is not None]


def _web_event(status: int, offset_seconds: int = 0) -> Event:
    """Build a minimal synthetic nginx Event carrying an HTTP ``status``."""
    base = datetime(2024, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
    return Event(
        timestamp=base + timedelta(seconds=offset_seconds),
        source="access.log",
        log_type="nginx",
        message=f"synthetic status {status}",
        raw=f"synthetic status {status}",
        client_ip="192.0.2.10",
        method="GET",
        path="/",
        status=status,
    )


# --- Positive: rate spike (Requirements 6.3, 11.3) -------------------------


def test_rate_spike_fires_on_planted_spike_fixture(fixture_lines) -> None:
    """The planted nginx spike bucket is surfaced as a stat.rate_spike finding.

    Validates: Requirements 6.3, 11.3
    """
    events = _parse_nginx(fixture_lines("nginx", "spike_requests.log"))
    assert events, "spike fixture should parse into nginx events"

    findings = StatisticalEngine().run(events, DetectionConfig())

    spikes = [f for f in findings if f.rule_id == "stat.rate_spike"]
    assert spikes, "expected a rate-spike finding on the planted spike fixture"

    spike = spikes[0]
    metadata = spike.metadata
    # Explainable metadata is present (Requirement 6.5).
    for key in ("baseline", "observed", "score", "threshold", "bucket_index",
                "window_seconds"):
        assert key in metadata, f"missing metadata key {key!r}"

    # The spike clears the configured z-threshold.
    assert metadata["threshold"] == 3.0
    assert metadata["score"] >= 3.0
    assert metadata["window_seconds"] == 60
    # Observed burst count is well above the steady ~2/min baseline.
    assert metadata["observed"] > metadata["baseline"]

    # Engine enrichment attached the bucket's contributing events.
    assert spike.events, "engine should attach the flagged bucket's events"
    assert len(spike.events) == metadata["observed"]


# --- Positive: rare event (Requirements 6.4, 11.4) -------------------------


def test_rare_event_flags_lone_status_below_cutoff() -> None:
    """A single 500 among 199 x 200 (freq < 0.01, n >= 20) is flagged rare.

    Validates: Requirements 6.4, 11.4
    """
    events = [_web_event(200, offset_seconds=i) for i in range(199)]
    events.append(_web_event(500, offset_seconds=199))

    findings = RareEventDetector().detect(events, DetectionConfig())

    rare = [f for f in findings if f.rule_id == "stat.rare_event"]
    assert len(rare) == 1, "exactly the lone 500 should be flagged rare"

    finding = rare[0]
    metadata = finding.metadata
    for key in ("baseline", "observed", "score", "threshold"):
        assert key in metadata, f"missing metadata key {key!r}"

    assert metadata["observed"]["value"] == "500"
    assert metadata["observed"]["count"] == 1
    assert metadata["threshold"] == 0.01
    # Relative frequency 1/200 = 0.005 is strictly below the 0.01 cutoff.
    assert metadata["score"] == pytest.approx(1 / 200)
    assert metadata["score"] < metadata["threshold"]
    assert metadata["baseline"]["total_observations"] == 200
    # The finding references the lone rare event.
    assert len(finding.events) == 1
    assert finding.events[0].status == 500


# --- False positive: rate spike steady baseline (Requirement 11.5) ---------


def test_rate_spike_silent_on_steady_baseline() -> None:
    """Equal counts per bucket (zero spread) produce no rate-spike finding.

    Validates: Requirement 11.5
    """
    # Three events in each of five consecutive 60s buckets: identical counts
    # mean zero standard deviation, so the 6.6 guard suppresses any finding.
    events: list[Event] = []
    for bucket in range(5):
        for within in range(3):
            offset = bucket * 60 + within * 2
            events.append(_web_event(200, offset_seconds=offset))

    findings = RateSpikeDetector().detect(events, DetectionConfig())

    assert findings == [], "a perfectly steady series must not spike"


# --- False positive: rare event guardrails (Requirements 11.5, 6.7) --------


def test_rare_event_silent_when_all_values_frequent() -> None:
    """A well-distributed series flags nothing: no value is below the cutoff.

    Validates: Requirement 11.5
    """
    # 100 x 200 and 100 x 404: each relative frequency 0.5, far above 0.01.
    events = [_web_event(200, offset_seconds=i) for i in range(100)]
    events += [_web_event(404, offset_seconds=100 + i) for i in range(100)]

    findings = RareEventDetector().detect(events, DetectionConfig())

    assert findings == [], "no value below the cutoff means no rare finding"


def test_rare_event_silent_below_min_observations() -> None:
    """A series below min_observations (20) yields nothing (Requirement 6.7).

    Validates: Requirement 11.5
    """
    # 10 observations total (< 20), even though one value is a clear minority.
    events = [_web_event(200, offset_seconds=i) for i in range(9)]
    events.append(_web_event(500, offset_seconds=9))

    findings = RareEventDetector().detect(events, DetectionConfig())

    assert findings == [], "below min_observations the series is not evaluated"
