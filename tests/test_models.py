"""Unit tests for the shared data contract in :mod:`loganalyze.models`.

Covers the :class:`Severity` enumeration (ordering and string form), the
normalized :class:`Event` (optional-field defaults, required fields, frozen
immutability), the explainable :class:`Finding` shape, and minimal
timezone-awareness checks for :func:`normalize_timestamp`. The exhaustive
property test for timestamp normalization is task 1.5.

Validates: Requirements 3.1, 3.2, 5.8, 7.1
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from loganalyze.models import Event, Finding, Severity, normalize_timestamp


# --- Severity -------------------------------------------------------------


def test_severity_is_int_enum():
    """Severity is an IntEnum so levels compare and sort numerically."""
    assert issubclass(Severity, int)


def test_severity_ordering_descending():
    """CRITICAL > HIGH > MEDIUM > LOW > INFO (Requirement 5.8 enumeration)."""
    assert (
        Severity.CRITICAL
        > Severity.HIGH
        > Severity.MEDIUM
        > Severity.LOW
        > Severity.INFO
    )


def test_severity_sorts_by_rank():
    """Sorting ascending yields INFO..CRITICAL; the rank drives ordering."""
    shuffled = [Severity.HIGH, Severity.INFO, Severity.CRITICAL, Severity.LOW, Severity.MEDIUM]
    assert sorted(shuffled) == [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (Severity.CRITICAL, "critical"),
        (Severity.HIGH, "high"),
        (Severity.MEDIUM, "medium"),
        (Severity.LOW, "low"),
        (Severity.INFO, "info"),
    ],
)
def test_severity_str_is_lowercase_name(level, expected):
    """str(Severity.X) is the lowercase serialized form."""
    assert str(level) == expected


# --- Event: optional-field defaults ---------------------------------------


def _minimal_event(**overrides) -> Event:
    """Build an Event with only the required fields populated."""
    base = dict(
        timestamp=datetime(2024, 1, 1, 0, 0, 0),
        source="/var/log/nginx/access.log",
        log_type="nginx",
        message="GET /",
        raw='203.0.113.5 - - "GET / HTTP/1.1" 200',
    )
    base.update(overrides)
    return Event(**base)


def test_event_optional_fields_default_to_none():
    """host, client_ip, user, method, path, status default to None (Req 3.2)."""
    event = _minimal_event()
    assert event.host is None
    assert event.client_ip is None
    assert event.user is None
    assert event.method is None
    assert event.path is None
    assert event.status is None


def test_event_fields_defaults_to_empty_dict():
    """The ``fields`` mapping defaults to an empty dict."""
    event = _minimal_event()
    assert event.fields == {}


def test_event_fields_default_is_not_shared():
    """Each Event gets its own ``fields`` dict (default_factory, not a shared ref)."""
    first = _minimal_event()
    second = _minimal_event()
    assert first.fields is not second.fields


def test_event_required_fields_set_as_given():
    """Required fields are populated exactly as provided (Req 3.1)."""
    ts = datetime(2024, 6, 1, 12, 30, 0)
    event = _minimal_event(
        timestamp=ts,
        source="/var/log/app.log",
        log_type="apache",
        message="a message",
        raw="the raw line",
        fields={"status": "200"},
    )
    assert event.timestamp == ts
    assert event.source == "/var/log/app.log"
    assert event.log_type == "apache"
    assert event.message == "a message"
    assert event.raw == "the raw line"
    assert event.fields == {"status": "200"}


def test_event_optional_fields_set_as_given():
    """Optional fields hold provided values when present."""
    event = _minimal_event(
        host="web01",
        client_ip="203.0.113.7",
        user="alice",
        method="GET",
        path="/index.html",
        status=200,
    )
    assert event.host == "web01"
    assert event.client_ip == "203.0.113.7"
    assert event.user == "alice"
    assert event.method == "GET"
    assert event.path == "/index.html"
    assert event.status == 200


def test_event_is_frozen():
    """Event is immutable; assigning to a field raises FrozenInstanceError."""
    event = _minimal_event()
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.status = 500  # type: ignore[misc]


# --- Finding --------------------------------------------------------------


def test_finding_holds_given_fields():
    """Finding stores rule_id, title, severity, events, detail, metadata (Req 7.1)."""
    event = _minimal_event()
    metadata = {"source": "/var/log/nginx/access.log", "line_number": 42}
    finding = Finding(
        rule_id="web.sqli_probe",
        title="SQL-injection probe",
        severity=Severity.HIGH,
        events=[event],
        detail="path matched signature sqli_union_select",
        metadata=metadata,
    )
    assert finding.rule_id == "web.sqli_probe"
    assert finding.title == "SQL-injection probe"
    assert finding.severity is Severity.HIGH
    assert finding.events == [event]
    assert finding.detail == "path matched signature sqli_union_select"
    assert finding.metadata == metadata


# --- normalize_timestamp (minimal; exhaustive property test is task 1.5) --


def test_normalize_timestamp_aware_offset_converts_to_utc():
    """A '+0000' offset parses as aware and is reported in UTC."""
    dt, aware = normalize_timestamp("2024-01-01T12:00:00+0000", "%Y-%m-%dT%H:%M:%S%z")
    assert aware is True
    assert dt.tzinfo == timezone.utc


def test_normalize_timestamp_naive_reports_not_aware():
    """A timestamp with no timezone info is reported as naive."""
    dt, aware = normalize_timestamp("2024-01-01T12:00:00", "%Y-%m-%dT%H:%M:%S")
    assert aware is False
    assert dt.tzinfo is None
