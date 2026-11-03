"""Positive and false-positive tests for the web signature detectors.

Exercises the three web signature detectors defined in
``loganalyze.detections.rules.signatures.web`` against synthetic nginx and
Apache fixtures:

- :class:`SqliProbe` (``web.sqli.probe``, HIGH) — Requirement 5.1.
- :class:`XssProbe` (``web.xss.probe``, HIGH) — Requirement 5.2.
- :class:`ScannerUserAgent` (``web.scanner.ua``, MEDIUM) — Requirement 5.3.

Positive tests confirm each detector fires on its matching fixture lines with
the right ``rule_id``, severity, explainable ``detail``, and metadata
(Requirements 5.1, 5.2, 5.3, 11.4). False-positive guardrail tests confirm that
none of the three detectors fire on the benign fixtures (Requirement 11.5).

Events are built by parsing the sanitized fixture lines with the registered
``nginx``/``apache`` parsers resolved through the registry, so the detectors are
exercised against the same normalized ``Event`` shape the pipeline produces.
"""
from __future__ import annotations

import pytest

# Importing the signatures package runs the ``@register_detector`` decorators,
# populating the registry for ``get_detectors()`` below. Importing the parser
# modules runs their ``@register_parser`` decorators so ``get_parser`` resolves
# the ``nginx``/``apache`` parsers used to build events from the fixtures.
from loganalyze.detections.rules import signatures  # noqa: F401
from loganalyze.parsers import apache as _apache  # noqa: F401
from loganalyze.parsers import nginx as _nginx  # noqa: F401
from loganalyze.config import DetectionConfig
from loganalyze.models import Event, Severity
from loganalyze.registry import get_detectors, get_parser

SQLI_RULE_ID = "web.sqli.probe"
XSS_RULE_ID = "web.xss.probe"
SCANNER_RULE_ID = "web.scanner.ua"


def _parse(fmt: str, lines: list[str]) -> list[Event]:
    """Parse fixture ``lines`` of format ``fmt`` into normalized events.

    Resolves the parser through the registry (never names the class) and drops
    any line that does not parse, mirroring the pipeline.
    """
    parser = get_parser(fmt)
    assert parser is not None, f"no parser registered for {fmt!r}"
    events: list[Event] = []
    for line in lines:
        event = parser.parse(line)
        assert event is not None, f"fixture line did not parse under {fmt!r}: {line!r}"
        events.append(event)
    return events


def _detector(rule_id: str):
    """Return a fresh detector instance for ``rule_id`` from the registry."""
    detectors = get_detectors()
    assert rule_id in detectors, f"detector {rule_id!r} is not registered"
    return detectors[rule_id]


def _detect(rule_id: str, events: list[Event]):
    """Run the detector ``rule_id`` over ``events`` with default config."""
    return _detector(rule_id).detect(events, DetectionConfig())


# --- Fixtures: parsed events per format ------------------------------------


@pytest.fixture
def nginx_signature_events(nginx_signature_lines) -> list[Event]:
    return _parse("nginx", nginx_signature_lines)


@pytest.fixture
def apache_signature_events(apache_signature_lines) -> list[Event]:
    return _parse("apache", apache_signature_lines)


@pytest.fixture
def nginx_benign_events(nginx_benign_lines) -> list[Event]:
    return _parse("nginx", nginx_benign_lines)


@pytest.fixture
def apache_benign_events(apache_benign_lines) -> list[Event]:
    return _parse("apache", apache_benign_lines)


# --- SqliProbe (web.sqli.probe) --------------------------------------------


@pytest.mark.parametrize("fmt", ["nginx", "apache"])
def test_sqli_probe_fires_on_sqli_fixtures(fmt, request):
    """SqliProbe flags the SQLi fixture lines as HIGH with explainable metadata.

    Validates: Requirements 5.1, 11.4
    """
    events = request.getfixturevalue(f"{fmt}_signature_events")
    findings = _detect(SQLI_RULE_ID, events)

    # The first two signature lines of each fixture are SQLi probes.
    assert len(findings) == 2, f"expected 2 SQLi findings for {fmt}, got {len(findings)}"

    for finding in findings:
        assert finding.rule_id == SQLI_RULE_ID
        assert finding.severity is Severity.HIGH
        # detail names the matched signature substring.
        assert finding.metadata["signature"] in finding.detail
        # metadata records source, matched path, and the matched signature.
        assert "source" in finding.metadata
        assert "path" in finding.metadata
        assert "signature" in finding.metadata
        # The finding references exactly the contributing event.
        assert len(finding.events) == 1
        assert finding.metadata["path"] == finding.events[0].path


@pytest.mark.parametrize("fmt", ["nginx", "apache"])
def test_sqli_probe_ignores_non_sqli_signature_lines(fmt, request):
    """SqliProbe yields nothing beyond the SQLi lines (no XSS/scanner spill-over).

    Validates: Requirements 5.1, 11.4
    """
    events = request.getfixturevalue(f"{fmt}_signature_events")
    findings = _detect(SQLI_RULE_ID, events)
    matched_paths = {f.events[0].path for f in findings}
    # XSS and scanner lines must not be flagged as SQLi.
    for event in events[2:]:
        assert event.path not in matched_paths, (
            f"non-SQLi line unexpectedly flagged as SQLi: {event.path!r}"
        )


# --- XssProbe (web.xss.probe) ----------------------------------------------


@pytest.mark.parametrize("fmt", ["nginx", "apache"])
def test_xss_probe_fires_on_xss_fixtures(fmt, request):
    """XssProbe flags the XSS fixture lines as HIGH with path/source metadata.

    Validates: Requirements 5.2, 11.4
    """
    events = request.getfixturevalue(f"{fmt}_signature_events")
    findings = _detect(XSS_RULE_ID, events)

    # The third and fourth signature lines of each fixture are XSS probes.
    assert len(findings) == 2, f"expected 2 XSS findings for {fmt}, got {len(findings)}"

    for finding in findings:
        assert finding.rule_id == XSS_RULE_ID
        assert finding.severity is Severity.HIGH
        assert finding.metadata["signature"] in finding.detail
        assert "source" in finding.metadata
        assert "path" in finding.metadata
        assert len(finding.events) == 1
        assert finding.metadata["path"] == finding.events[0].path


# --- ScannerUserAgent (web.scanner.ua) -------------------------------------


@pytest.mark.parametrize("fmt", ["nginx", "apache"])
def test_scanner_ua_fires_on_scanner_fixtures(fmt, request):
    """ScannerUserAgent flags scanner UAs as MEDIUM with user_agent/source metadata.

    Validates: Requirements 5.3, 11.4
    """
    events = request.getfixturevalue(f"{fmt}_signature_events")
    findings = _detect(SCANNER_RULE_ID, events)

    # The last four signature lines of each fixture use scanner user-agents
    # (sqlmap, Nikto, Nmap, masscan).
    assert len(findings) == 4, (
        f"expected 4 scanner-UA findings for {fmt}, got {len(findings)}"
    )

    for finding in findings:
        assert finding.rule_id == SCANNER_RULE_ID
        assert finding.severity is Severity.MEDIUM
        assert finding.metadata["signature"] in finding.detail
        assert "source" in finding.metadata
        assert "user_agent" in finding.metadata
        # The matched signature token appears within the reported user agent.
        assert finding.metadata["signature"].lower() in (
            finding.metadata["user_agent"].lower()
        )
        assert len(finding.events) == 1

    # Every well-known scanner token in the fixture is recognized.
    matched = {f.metadata["signature"].lower() for f in findings}
    for token in ("sqlmap", "nikto", "nmap", "masscan"):
        assert token in matched, f"scanner token {token!r} was not recognized"


# --- False-positive guardrails (Requirement 11.5) --------------------------


@pytest.mark.parametrize(
    "rule_id", [SQLI_RULE_ID, XSS_RULE_ID, SCANNER_RULE_ID]
)
@pytest.mark.parametrize("fmt", ["nginx", "apache"])
def test_web_detectors_quiet_on_benign(rule_id, fmt, request):
    """No web detector fires on benign traffic (false-positive guardrail).

    A benign line that triggers any finding is a real false-positive bug.

    Validates: Requirement 11.5
    """
    events = request.getfixturevalue(f"{fmt}_benign_events")
    findings = _detect(rule_id, events)
    assert findings == [], (
        f"{rule_id} produced false positives on benign {fmt} traffic: "
        f"{[f.metadata for f in findings]}"
    )
