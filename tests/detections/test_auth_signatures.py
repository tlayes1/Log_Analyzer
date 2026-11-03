"""Positive and false-positive tests for the ``auth.log`` signature detectors.

Covers the two per-event authentication signatures defined in
:mod:`loganalyze.detections.rules.signatures.auth`:

* :class:`FailedLoginDetector` (``auth.failed_login``) — fires on failed
  authentication attempts, ``MEDIUM`` severity (Requirements 5.6, 11.4).
* :class:`PrivilegeEscalationDetector` (``auth.privesc``) — fires on ``sudo``/
  ``su`` escalation, ``HIGH`` severity (Requirements 5.7, 11.4).

Each test parses a synthetic ``authlog`` fixture through the registered
``authlog`` parser to build :class:`~loganalyze.models.Event` records, then runs
the detector under test over those events.

The false-positive guardrail (Requirement 11.5) asserts that *both* detectors
stay silent over the benign fixture (successful logins and ordinary sessions):
a benign line producing a finding is a real defect, not a test to relax.
"""

from __future__ import annotations

import pytest

# Import side effects register the parser and the auth detectors in the registry.
import loganalyze.parsers.authlog  # noqa: F401
import loganalyze.detections.rules.signatures.auth  # noqa: F401
from loganalyze.config import DetectionConfig
from loganalyze.detections.rules.signatures.auth import (
    FailedLoginDetector,
    PrivilegeEscalationDetector,
)
from loganalyze.models import Event, Severity
from loganalyze.registry import get_parser


def _events(lines: list[str]) -> list[Event]:
    """Parse ``authlog`` fixture lines into Events, dropping non-matches.

    Uses the registry-resolved ``authlog`` parser so the test exercises the
    same parse path the pipeline uses. Lines the parser does not recognize
    (``None``) are omitted.
    """
    parser = get_parser("authlog")
    assert parser is not None, "authlog parser must be registered"
    events: list[Event] = []
    for line in lines:
        event = parser.parse(line)
        if event is not None:
            events.append(event)
    return events


# --- Positive: FailedLoginDetector (Requirements 5.6, 11.4) ----------------


@pytest.mark.parametrize("fixture_name", ["signatures.log", "burst_bruteforce.log"])
def test_failed_login_fires_on_failed_login_events(fixture_lines, fixture_name):
    """auth.failed_login yields a MEDIUM finding per failed-login event."""
    events = _events(fixture_lines("authlog", fixture_name))
    expected = [e for e in events if e.fields.get("event") == "failed_login"]
    assert expected, f"fixture {fixture_name} must contain failed-login events"

    findings = FailedLoginDetector().detect(events, DetectionConfig())

    # One finding per failed-login event, nothing else.
    assert len(findings) == len(expected)
    for finding in findings:
        assert finding.rule_id == "auth.failed_login"
        assert finding.severity is Severity.MEDIUM
        # Metadata exposes the explainable context for the match.
        assert "client_ip" in finding.metadata
        assert "user" in finding.metadata
        assert "source" in finding.metadata
        # The finding references exactly the failed-login event it describes.
        assert len(finding.events) == 1
        assert finding.events[0].fields.get("event") == "failed_login"


def test_failed_login_metadata_matches_event(fixture_lines):
    """Finding metadata mirrors the client_ip/user/source of its event."""
    events = _events(fixture_lines("authlog", "burst_bruteforce.log"))
    findings = FailedLoginDetector().detect(events, DetectionConfig())

    assert findings, "burst fixture must produce failed-login findings"
    for finding in findings:
        event = finding.events[0]
        assert finding.metadata["client_ip"] == event.client_ip
        assert finding.metadata["user"] == event.user
        assert finding.metadata["source"] == event.source


# --- Positive: PrivilegeEscalationDetector (Requirements 5.7, 11.4) --------


def test_privesc_fires_on_sudo_and_su(fixture_lines):
    """auth.privesc yields a HIGH finding per sudo/su escalation event."""
    events = _events(fixture_lines("authlog", "signatures.log"))
    expected = [
        e for e in events if e.fields.get("mechanism") in {"sudo", "su"}
    ]
    assert expected, "signatures fixture must contain privilege-escalation events"

    findings = PrivilegeEscalationDetector().detect(events, DetectionConfig())

    assert len(findings) == len(expected)
    mechanisms = {f.metadata.get("mechanism") for f in findings}
    # Both escalation mechanisms present in the fixture are represented.
    assert "sudo" in mechanisms
    assert "su" in mechanisms

    for finding in findings:
        assert finding.rule_id == "auth.privesc"
        assert finding.severity is Severity.HIGH
        assert "user" in finding.metadata
        assert finding.metadata.get("mechanism") in {"sudo", "su"}
        assert "target_user" in finding.metadata
        assert "source" in finding.metadata
        assert len(finding.events) == 1
        assert finding.events[0].fields.get("mechanism") in {"sudo", "su"}


def test_privesc_metadata_matches_event(fixture_lines):
    """Finding metadata mirrors user/mechanism/target_user/source of its event."""
    events = _events(fixture_lines("authlog", "signatures.log"))
    findings = PrivilegeEscalationDetector().detect(events, DetectionConfig())

    assert findings, "signatures fixture must produce privesc findings"
    for finding in findings:
        event = finding.events[0]
        assert finding.metadata["user"] == event.user
        assert finding.metadata["mechanism"] == event.fields.get("mechanism")
        assert finding.metadata["target_user"] == event.fields.get("target_user")
        assert finding.metadata["source"] == event.source


# --- False-positive guardrail: benign fixture stays silent (Req 11.5) ------


def test_failed_login_silent_on_benign(authlog_benign_lines):
    """No auth.failed_login finding on benign auth.log (successful logins)."""
    events = _events(authlog_benign_lines)
    assert events, "benign fixture must parse into at least one event"
    assert not any(e.fields.get("event") == "failed_login" for e in events)

    findings = FailedLoginDetector().detect(events, DetectionConfig())
    assert findings == []


def test_privesc_silent_on_benign(authlog_benign_lines):
    """No auth.privesc finding on benign auth.log (no sudo/su escalation)."""
    events = _events(authlog_benign_lines)
    assert events, "benign fixture must parse into at least one event"
    assert not any(e.fields.get("mechanism") in {"sudo", "su"} for e in events)

    findings = PrivilegeEscalationDetector().detect(events, DetectionConfig())
    assert findings == []
