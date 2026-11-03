"""Positive and false-positive unit tests for the windowed rule detectors.

Covers the two sliding-window threshold detectors in
``loganalyze.detections.rules.signatures.windowed``:

* ``auth.bruteforce`` (:class:`BruteForceDetector`) — failed-auth bursts from a
  single client IP within a 60s window (Requirements 5.4, 5.10, 11.3).
* ``web.status_spike`` (:class:`StatusSpikeDetector`) — HTTP error-status spikes
  within a 60s window (Requirements 5.5, 5.10, 11.4).

Positive cases confirm each detector fires exactly one correctly-shaped Finding.
Determinism is checked by shuffling the input and asserting identical metadata
(Requirement 5.10). False-positive guardrails confirm that below-threshold
counts, events spread beyond the window, and non-error traffic produce no
findings (Requirement 11.5).

Brute-force events are parsed from the synthetic
``tests/fixtures/authlog/burst_bruteforce.log`` fixture; status-spike events are
constructed directly as :class:`~loganalyze.models.Event` records with
controlled timestamps, since the planted nginx spike fixture targets the
statistical detector rather than this threshold rule.

Requirements: 5.4, 5.5, 5.10, 11.3, 11.4, 11.5.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

import pytest

from loganalyze.config import DetectionConfig
from loganalyze.detections.rules.signatures.windowed import (
    BruteForceDetector,
    StatusSpikeDetector,
)
from loganalyze.models import Event, Severity
from loganalyze.parsers.authlog import AuthlogParser

#: The single offending client IP in the brute-force fixture.
_BURST_IP = "198.51.100.23"


# --- Helpers ---------------------------------------------------------------


def _parse_authlog(lines: list[str]) -> list[Event]:
    """Parse auth.log lines into Events, dropping unparseable ones."""
    parser = AuthlogParser()
    events = [parser.parse(line) for line in lines]
    return [event for event in events if event is not None]


def _web_error_events(count: int, *, step_seconds: float, status: int = 500) -> list[Event]:
    """Build ``count`` synthetic nginx error-status Events.

    Timestamps start at a fixed base and advance by ``step_seconds`` per event,
    so the caller controls whether they fall inside a single 60s window.
    """
    base = datetime(2024, 1, 15, 9, 15, 0)
    events: list[Event] = []
    for i in range(count):
        ts = base + timedelta(seconds=step_seconds * i)
        events.append(
            Event(
                timestamp=ts,
                source="access.log",
                log_type="nginx",
                message=f"GET /x {status}",
                raw=f"GET /x {status}",
                client_ip="203.0.113.7",
                method="GET",
                path="/x",
                status=status,
            )
        )
    return events


# --- Positive: auth.bruteforce (Requirements 5.4, 5.10, 11.3) --------------


def test_bruteforce_fires_on_fixture_burst(fixture_lines) -> None:
    """Seven failed logins for one IP within 60s yield one HIGH finding."""
    events = _parse_authlog(fixture_lines("authlog", "burst_bruteforce.log"))
    findings = BruteForceDetector().detect(events, DetectionConfig())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "auth.bruteforce"
    assert finding.severity is Severity.HIGH
    assert finding.metadata["client_ip"] == _BURST_IP
    assert finding.metadata["count"] >= 5
    assert finding.metadata["count"] == 7
    assert finding.metadata["threshold"] == 5
    assert finding.metadata["window_seconds"] == 60
    # Every contributing event is a failed login from the offending IP.
    assert all(e.client_ip == _BURST_IP for e in finding.events)
    assert all(e.fields.get("event") == "failed_login" for e in finding.events)


def test_bruteforce_is_order_independent(fixture_lines) -> None:
    """Shuffling the events yields identical finding metadata (determinism)."""
    events = _parse_authlog(fixture_lines("authlog", "burst_bruteforce.log"))
    config = DetectionConfig()

    baseline = BruteForceDetector().detect(events, config)

    shuffled = list(events)
    random.Random(1234).shuffle(shuffled)
    reshuffled = BruteForceDetector().detect(shuffled, config)

    assert len(baseline) == len(reshuffled) == 1
    assert baseline[0].metadata == reshuffled[0].metadata


# --- Positive: web.status_spike (Requirements 5.5, 5.10, 11.4) -------------


def test_status_spike_fires_on_twenty_errors_in_window() -> None:
    """Twenty error-status events within 60s yield one MEDIUM finding."""
    events = _web_error_events(20, step_seconds=2)  # spans 38s < 60s
    findings = StatusSpikeDetector().detect(events, DetectionConfig())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "web.status_spike"
    assert finding.severity is Severity.MEDIUM
    assert finding.metadata["count"] >= 20
    assert finding.metadata["count"] == 20
    assert finding.metadata["threshold"] == 20
    assert finding.metadata["window_seconds"] == 60
    assert all(e.status is not None and e.status >= 400 for e in finding.events)


def test_status_spike_is_order_independent() -> None:
    """Shuffling the events yields identical finding metadata (determinism)."""
    events = _web_error_events(20, step_seconds=2)
    config = DetectionConfig()

    baseline = StatusSpikeDetector().detect(events, config)

    shuffled = list(events)
    random.Random(99).shuffle(shuffled)
    reshuffled = StatusSpikeDetector().detect(shuffled, config)

    assert len(baseline) == len(reshuffled) == 1
    assert baseline[0].metadata == reshuffled[0].metadata


# --- False positives: auth.bruteforce (Requirement 11.5) -------------------


def test_bruteforce_below_threshold_in_window_is_silent() -> None:
    """Four failed logins for one IP within the window produce no finding."""
    base = datetime(2024, 1, 15, 9, 15, 0)
    events = [
        Event(
            timestamp=base + timedelta(seconds=5 * i),
            source="auth.log",
            log_type="authlog",
            message="Failed password",
            raw="Failed password",
            client_ip=_BURST_IP,
            user="admin",
            fields={"event": "failed_login", "auth_result": "failure"},
        )
        for i in range(4)  # below the threshold of 5
    ]
    assert BruteForceDetector().detect(events, DetectionConfig()) == []


def test_bruteforce_enough_events_spread_beyond_window_is_silent() -> None:
    """Five failed logins spaced beyond 60s never co-occur, so no finding."""
    base = datetime(2024, 1, 15, 9, 15, 0)
    events = [
        Event(
            timestamp=base + timedelta(seconds=30 * i),  # 0,30,60,90,120s apart
            source="auth.log",
            log_type="authlog",
            message="Failed password",
            raw="Failed password",
            client_ip=_BURST_IP,
            user="admin",
            fields={"event": "failed_login", "auth_result": "failure"},
        )
        for i in range(5)
    ]
    # No half-open 60s window holds all 5; each window holds at most 2.
    assert BruteForceDetector().detect(events, DetectionConfig()) == []


# --- False positives: web.status_spike (Requirement 11.5) ------------------


def test_status_spike_below_threshold_in_window_is_silent() -> None:
    """Nineteen error events within the window stay below threshold."""
    events = _web_error_events(19, step_seconds=2)  # spans 36s < 60s
    assert StatusSpikeDetector().detect(events, DetectionConfig()) == []


def test_status_spike_enough_events_spread_beyond_window_is_silent() -> None:
    """Twenty error events spaced so no 60s window holds the threshold."""
    # 5s apart over 20 events spans 95s; the densest 60s window holds 13 (<20).
    events = _web_error_events(20, step_seconds=5)
    assert StatusSpikeDetector().detect(events, DetectionConfig()) == []


def test_status_spike_ignores_non_error_traffic() -> None:
    """Twenty 200-status events in the window are not errors, so no finding."""
    events = _web_error_events(20, step_seconds=2, status=200)
    assert StatusSpikeDetector().detect(events, DetectionConfig()) == []
