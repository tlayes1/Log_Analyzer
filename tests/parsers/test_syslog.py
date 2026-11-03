"""Unit tests for the RFC3164 (BSD) syslog parser.

Covers the normalized :class:`~loganalyze.models.Event` contract for the
``"syslog"`` format: required fields are populated, web-oriented optional fields
stay ``None`` (Requirement 3.2), the ``log_type`` equals the registry key
(Requirement 3.3), malformed lines return ``None`` without raising
(Requirements 3.4, 3.5), and the RFC3164 timestamp is naive because the wire
format carries no timezone (Requirement 3.8).
"""

from __future__ import annotations

import pytest

# Importing the module triggers the ``@register_parser("syslog")`` decorator,
# so the parser is resolvable through the registry.
import loganalyze.parsers.syslog  # noqa: F401
from loganalyze.models import Event
from loganalyze.parsers.syslog import SyslogParser
from loganalyze.registry import get_parser

# A canonical RFC3164 line with a ``process[pid]`` program field.
WELL_FORMED = "Oct 10 08:00:01 host01 CRON[2451]: (root) CMD (/usr/bin/php run.php)"
# A valid line whose program field carries no ``[pid]`` (e.g. kernel messages).
NO_PID = "Oct 10 08:00:12 host01 kernel: eth0: link up, 1000 Mbps, full duplex"


@pytest.fixture
def parser() -> SyslogParser:
    """A fresh syslog parser instance for each test."""
    return SyslogParser()


class TestWellFormedLine:
    """A canonical RFC3164 line parses into a fully populated Event."""

    def test_returns_event(self, parser: SyslogParser) -> None:
        assert isinstance(parser.parse(WELL_FORMED), Event)

    def test_log_type_is_syslog(self, parser: SyslogParser) -> None:
        # Requirement 3.3: log_type equals the registry key.
        event = parser.parse(WELL_FORMED)
        assert event is not None
        assert event.log_type == "syslog"

    def test_host_and_message(self, parser: SyslogParser) -> None:
        event = parser.parse(WELL_FORMED)
        assert event is not None
        assert event.host == "host01"
        assert event.message == "(root) CMD (/usr/bin/php run.php)"
        assert event.raw == WELL_FORMED

    def test_fields_carry_process_and_pid(self, parser: SyslogParser) -> None:
        event = parser.parse(WELL_FORMED)
        assert event is not None
        assert event.fields["process"] == "CRON"
        assert event.fields["pid"] == "2451"
        assert event.fields["host"] == "host01"

    def test_timestamp_is_naive(self, parser: SyslogParser) -> None:
        # Requirement 3.8: RFC3164 has no timezone, so the datetime is naive.
        event = parser.parse(WELL_FORMED)
        assert event is not None
        assert event.timestamp.tzinfo is None
        assert (event.timestamp.month, event.timestamp.day) == (10, 10)
        assert (
            event.timestamp.hour,
            event.timestamp.minute,
            event.timestamp.second,
        ) == (8, 0, 1)

    def test_web_optional_fields_are_none(self, parser: SyslogParser) -> None:
        # Requirement 3.2: web-oriented optional fields are absent for syslog.
        event = parser.parse(WELL_FORMED)
        assert event is not None
        assert event.client_ip is None
        assert event.method is None
        assert event.path is None
        assert event.status is None
        assert event.user is None


class TestLineWithoutPid:
    """A well-formed line without ``[pid]`` still parses; pid is omitted."""

    def test_returns_event(self, parser: SyslogParser) -> None:
        assert isinstance(parser.parse(NO_PID), Event)

    def test_process_present_pid_absent(self, parser: SyslogParser) -> None:
        event = parser.parse(NO_PID)
        assert event is not None
        assert event.fields["process"] == "kernel"
        assert "pid" not in event.fields
        assert event.host == "host01"

    def test_timestamp_is_naive(self, parser: SyslogParser) -> None:
        event = parser.parse(NO_PID)
        assert event is not None
        assert event.timestamp.tzinfo is None


class TestBenignFixtureLines:
    """Every line in the synthetic benign fixture parses as a syslog Event."""

    def test_all_fixture_lines_parse(
        self, parser: SyslogParser, syslog_benign_lines: list[str]
    ) -> None:
        assert syslog_benign_lines  # fixture is non-empty
        for line in syslog_benign_lines:
            event = parser.parse(line)
            assert event is not None, f"expected a match for: {line!r}"
            assert event.log_type == "syslog"
            assert event.timestamp.tzinfo is None  # naive (3.8)
            assert "process" in event.fields


class TestMalformedLines:
    """Non-syslog / malformed input returns None without raising (3.4, 3.5)."""

    @pytest.mark.parametrize(
        "line",
        [
            "",
            "not a syslog line at all",
            "192.0.2.1 - - [10/Oct/2000:13:55:36 -0700] \"GET / HTTP/1.0\" 200 2326",
            "Oct 10 08:00:01",  # no host/process/message
            "Oct 10 25:99:99 host01 proc: bad time",  # impossible time -> None
            "   ",
        ],
    )
    def test_returns_none(self, parser: SyslogParser, line: str) -> None:
        assert parser.parse(line) is None


class TestRegistryResolution:
    """The parser is resolvable via the registry key ``"syslog"`` (3.3)."""

    def test_get_parser_returns_syslog_parser(self) -> None:
        resolved = get_parser("syslog")
        assert isinstance(resolved, SyslogParser)

    def test_resolved_parser_parses(self) -> None:
        resolved = get_parser("syslog")
        assert resolved is not None
        event = resolved.parse(WELL_FORMED)
        assert event is not None
        assert event.log_type == "syslog"
