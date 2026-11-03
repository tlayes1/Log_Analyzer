"""Property-based tests for the signature and windowed rule detectors.

These tests exercise design Properties 8-11 for the Rule_Engine detectors in
``loganalyze.detections.rules.signatures`` using pytest + Hypothesis. They build
:class:`~loganalyze.models.Event` records directly so the properties can control
paths, user agents, timestamps, and client IPs precisely, and they compare the
windowed detectors against an independent ground-truth oracle rather than against
a reimplementation of the detector's own logic.

Synthetic data only (Requirement 11): generated IPs fall in the documentation
range ``192.0.2.0/24`` and no real PII or secrets appear.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loganalyze.config import DetectionConfig, RuleConfig
from loganalyze.detections.rules.signatures.auth import (
    FailedLoginDetector,
    PrivilegeEscalationDetector,
)
from loganalyze.detections.rules.signatures.web import (
    ScannerUserAgent,
    SqliProbe,
    XssProbe,
)
from loganalyze.detections.rules.signatures.windowed import (
    BruteForceDetector,
    StatusSpikeDetector,
)
from loganalyze.models import Event, Finding, Severity

# A fixed epoch all windowed-property timestamps are offset from. Naive to match
# the "no timezone information" path; the detectors sort on raw datetimes.
_EPOCH = datetime(2024, 1, 1, 0, 0, 0)


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------


def _web_event(
    *,
    path: str | None = None,
    user_agent: str | None = None,
    source: str = "access.log",
    line_number: str | None = None,
    log_type: str = "nginx",
    status: int | None = None,
    timestamp: datetime = _EPOCH,
) -> Event:
    """Build a web (nginx/apache) Event for the signature/spike properties."""
    fields: dict[str, str] = {}
    if user_agent is not None:
        fields["user_agent"] = user_agent
    if line_number is not None:
        fields["line_number"] = line_number
    return Event(
        timestamp=timestamp,
        source=source,
        log_type=log_type,
        message="synthetic web request",
        raw="synthetic",
        fields=fields,
        client_ip="192.0.2.10",
        method="GET",
        path=path,
        status=status,
    )


def _failed_auth_event(
    *, client_ip: str, timestamp: datetime, source: str = "auth.log"
) -> Event:
    """Build an authlog failed-login Event for the brute-force property."""
    return Event(
        timestamp=timestamp,
        source=source,
        log_type="authlog",
        message="Failed password",
        raw="synthetic",
        fields={"event": "failed_login"},
        client_ip=client_ip,
        user="root",
    )


def _error_status_event(*, timestamp: datetime, status: int = 500) -> Event:
    """Build a web Event carrying an HTTP error status for the spike property."""
    return _web_event(path="/", status=status, timestamp=timestamp)


# ---------------------------------------------------------------------------
# Independent oracle for the windowed detectors
# ---------------------------------------------------------------------------


def _window_reaches_threshold(
    timestamps: list[datetime], window_seconds: int, threshold: int
) -> bool:
    """Ground truth: does any half-open window hold at least ``threshold`` events?

    Mirrors the detector's *stated contract* (Requirements 5.4/5.5/5.10): sort the
    timestamps and, treating each event as a window start ``t``, count how many
    events fall in the half-open span ``[t, t + window)``. Returns True when any
    such window contains at least ``threshold`` events. This is written
    independently of the detector implementation so a disagreement signals a real
    bug, not a shared mistake.
    """
    if threshold <= 0:
        return False
    if len(timestamps) < threshold:
        return False
    ordered = sorted(timestamps)
    span = timedelta(seconds=window_seconds)
    n = len(ordered)
    for start in range(n):
        end = ordered[start] + span
        count = sum(1 for ts in ordered[start:] if ts < end)
        if count >= threshold:
            return True
    return False


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Bounded, documentation-range client IPs so brute-force grouping has a few keys.
_client_ips = st.sampled_from(
    ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
)

# Small inter-arrival gaps in seconds; a few land outside a 60s window, most in.
_gaps = st.lists(st.integers(min_value=0, max_value=40), min_size=0, max_size=12)


# ---------------------------------------------------------------------------
# Property 8: Signature matches fire; benign input does not
# ---------------------------------------------------------------------------
# Feature: loganalyze, Property 8: a web Event whose matched field carries a
# probe/scanner signature token yields a Finding whose metadata includes the
# source and the matched value; a benign web Event matching no signature yields
# zero findings.
# Validates: Requirements 5.1, 5.2, 5.3

# (detector, path_token) pairs that MUST fire the path-based web detectors.
_SQLI_TOKENS = ["/x?id=1 UNION SELECT 1", "/x?id=1 OR 1=1", "/x?q=1'OR'1'='1"]
_XSS_TOKENS = ["/x?q=<script>alert(1)</script>", "/x?u=javascript:alert(1)"]
_SCANNER_UAS = ["sqlmap/1.7", "Nikto/2.5", "Mozilla/5.0 nmap scripting engine"]

# Benign paths / UAs that MUST NOT fire any signature detector.
_BENIGN_PATHS = ["/", "/index.html", "/api/users?page=2", "/static/app.css"]
_BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0",
    "curl/8.4.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1",
]


@settings(max_examples=200)
@given(
    token=st.sampled_from(_SQLI_TOKENS),
    log_type=st.sampled_from(["nginx", "apache"]),
    line_number=st.integers(min_value=1, max_value=99999),
)
def test_sqli_signature_fires_with_metadata(token, log_type, line_number):
    event = _web_event(
        path=token, log_type=log_type, line_number=str(line_number)
    )
    findings = SqliProbe().detect([event], DetectionConfig())
    assert len(findings) == 1
    meta = findings[0].metadata
    assert meta["source"] == event.source
    assert meta["path"] == token
    assert meta["signature"] in token or meta["signature"]  # matched value present
    assert meta["line_number"] == str(line_number)


@settings(max_examples=200)
@given(
    token=st.sampled_from(_XSS_TOKENS),
    log_type=st.sampled_from(["nginx", "apache"]),
    line_number=st.integers(min_value=1, max_value=99999),
)
def test_xss_signature_fires_with_metadata(token, log_type, line_number):
    event = _web_event(
        path=token, log_type=log_type, line_number=str(line_number)
    )
    findings = XssProbe().detect([event], DetectionConfig())
    assert len(findings) == 1
    meta = findings[0].metadata
    assert meta["source"] == event.source
    assert meta["path"] == token
    assert meta["signature"]
    assert meta["line_number"] == str(line_number)


@settings(max_examples=200)
@given(
    ua=st.sampled_from(_SCANNER_UAS),
    log_type=st.sampled_from(["nginx", "apache"]),
    line_number=st.integers(min_value=1, max_value=99999),
)
def test_scanner_ua_signature_fires_with_metadata(ua, log_type, line_number):
    event = _web_event(
        path="/", user_agent=ua, log_type=log_type, line_number=str(line_number)
    )
    findings = ScannerUserAgent().detect([event], DetectionConfig())
    assert len(findings) == 1
    meta = findings[0].metadata
    assert meta["source"] == event.source
    assert meta["user_agent"] == ua
    assert meta["signature"]
    assert meta["line_number"] == str(line_number)


@settings(max_examples=200)
@given(
    path=st.sampled_from(_BENIGN_PATHS),
    ua=st.sampled_from(_BENIGN_UAS),
    log_type=st.sampled_from(["nginx", "apache"]),
)
def test_benign_web_event_fires_no_signature(path, ua, log_type):
    event = _web_event(path=path, user_agent=ua, log_type=log_type)
    config = DetectionConfig()
    assert SqliProbe().detect([event], config) == []
    assert XssProbe().detect([event], config) == []
    assert ScannerUserAgent().detect([event], config) == []


# ---------------------------------------------------------------------------
# Property 9: Brute-force detection respects the window and threshold
# ---------------------------------------------------------------------------
# Feature: loganalyze, Property 9: for any sequence of failed-auth events, a
# brute-force Finding for a client_ip is produced exactly when at least
# `threshold` of its failed events fall within a `window_seconds` span; the
# finding's metadata carries client_ip, count, threshold, and window.
# Validates: Requirements 5.4, 5.10


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(
    gaps=_gaps,
    ips=st.lists(_client_ips, min_size=0, max_size=12),
    threshold=st.integers(min_value=2, max_value=6),
    window_seconds=st.integers(min_value=10, max_value=120),
)
def test_bruteforce_matches_oracle(gaps, ips, threshold, window_seconds):
    # Build failed-auth events with cumulative timestamps; pair each gap with an
    # IP so the two lists align in length.
    n = min(len(gaps), len(ips))
    events: list[Event] = []
    t = _EPOCH
    per_ip_ts: dict[str, list[datetime]] = {}
    for i in range(n):
        t = t + timedelta(seconds=gaps[i])
        ip = ips[i]
        events.append(_failed_auth_event(client_ip=ip, timestamp=t))
        per_ip_ts.setdefault(ip, []).append(t)

    config = DetectionConfig(
        rules=RuleConfig(
            brute_force_threshold=threshold,
            brute_force_window_seconds=window_seconds,
        )
    )
    findings = BruteForceDetector().detect(events, config)
    fired_ips = {f.metadata["client_ip"] for f in findings}

    # Oracle: an IP should fire exactly when some window holds >= threshold of its
    # own failed events.
    expected_ips = {
        ip
        for ip, ts in per_ip_ts.items()
        if _window_reaches_threshold(ts, window_seconds, threshold)
    }
    assert fired_ips == expected_ips

    for f in findings:
        meta = f.metadata
        assert meta["client_ip"] in per_ip_ts
        assert meta["count"] >= threshold
        assert meta["threshold"] == threshold
        assert meta["window_seconds"] == window_seconds
        assert f.severity is Severity.HIGH


# ---------------------------------------------------------------------------
# Property 10: Status-code-spike detection respects the window and threshold
# ---------------------------------------------------------------------------
# Feature: loganalyze, Property 10: for any sequence of events, a status-code
# spike Finding is produced exactly when at least `threshold` error-status
# events fall within a `window_seconds` span; metadata carries count, threshold,
# and window.
# Validates: Requirements 5.5, 5.10


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(
    gaps=st.lists(st.integers(min_value=0, max_value=30), min_size=0, max_size=14),
    statuses=st.lists(
        st.sampled_from([200, 302, 404, 500, 503]), min_size=0, max_size=14
    ),
    threshold=st.integers(min_value=2, max_value=6),
    window_seconds=st.integers(min_value=10, max_value=120),
)
def test_status_spike_matches_oracle(gaps, statuses, threshold, window_seconds):
    n = min(len(gaps), len(statuses))
    events: list[Event] = []
    error_ts: list[datetime] = []
    t = _EPOCH
    for i in range(n):
        t = t + timedelta(seconds=gaps[i])
        status = statuses[i]
        events.append(_error_status_event(timestamp=t, status=status))
        if status >= 400:
            error_ts.append(t)

    config = DetectionConfig(
        rules=RuleConfig(
            status_spike_threshold=threshold,
            status_spike_window_seconds=window_seconds,
        )
    )
    findings = StatusSpikeDetector().detect(events, config)
    expected = _window_reaches_threshold(error_ts, window_seconds, threshold)
    assert (len(findings) == 1) == expected

    for f in findings:
        meta = f.metadata
        assert meta["count"] >= threshold
        assert meta["threshold"] == threshold
        assert meta["window_seconds"] == window_seconds
        assert f.severity is Severity.MEDIUM


# ---------------------------------------------------------------------------
# Property 11: Every Finding carries exactly one valid Severity
# ---------------------------------------------------------------------------
# Feature: loganalyze, Property 11: every Finding produced by any rule detector
# has a severity that is a member of the Severity enumeration.
# Validates: Requirements 5.8

_ALL_RULE_DETECTORS = [
    SqliProbe(),
    XssProbe(),
    ScannerUserAgent(),
    FailedLoginDetector(),
    PrivilegeEscalationDetector(),
    BruteForceDetector(),
    StatusSpikeDetector(),
]


def _mixed_event(kind: str, ts: datetime, ip: str) -> Event:
    """Build one of several event shapes to exercise every rule detector."""
    if kind == "sqli":
        return _web_event(path="/x?id=1 UNION SELECT 1", timestamp=ts)
    if kind == "xss":
        return _web_event(path="/x?q=<script>alert(1)</script>", timestamp=ts)
    if kind == "scanner":
        return _web_event(path="/", user_agent="sqlmap/1.7", timestamp=ts)
    if kind == "error":
        return _error_status_event(timestamp=ts, status=500)
    if kind == "failed_login":
        return _failed_auth_event(client_ip=ip, timestamp=ts)
    if kind == "privesc":
        return Event(
            timestamp=ts,
            source="auth.log",
            log_type="authlog",
            message="sudo session opened for root",
            raw="synthetic",
            fields={"mechanism": "sudo", "target_user": "root"},
            user="alice",
        )
    # benign
    return _web_event(path="/index.html", user_agent="curl/8.4.0", timestamp=ts)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(
    kinds=st.lists(
        st.sampled_from(
            ["sqli", "xss", "scanner", "error", "failed_login", "privesc", "benign"]
        ),
        min_size=0,
        max_size=20,
    ),
    ips=st.lists(_client_ips, min_size=1, max_size=3),
)
def test_every_finding_has_valid_severity(kinds, ips):
    events: list[Event] = []
    t = _EPOCH
    for i, kind in enumerate(kinds):
        t = t + timedelta(seconds=1)
        events.append(_mixed_event(kind, t, ips[i % len(ips)]))

    # Use a low threshold so windowed detectors can also fire and contribute.
    config = DetectionConfig(
        rules=RuleConfig(
            brute_force_threshold=2,
            brute_force_window_seconds=120,
            status_spike_threshold=2,
            status_spike_window_seconds=120,
        )
    )
    all_findings: list[Finding] = []
    for detector in _ALL_RULE_DETECTORS:
        all_findings.extend(detector.detect(events, config))

    for f in all_findings:
        assert isinstance(f.severity, Severity)
        assert f.severity in set(Severity)
