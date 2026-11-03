"""Unit tests for the nginx combined access-log parser.

These tests exercise :class:`loganalyze.parsers.nginx.NginxParser` directly and
through the registry key ``"nginx"``. Importing ``loganalyze.parsers.nginx``
triggers the ``@register_parser("nginx")`` decorator so the parser is resolvable
via :func:`loganalyze.registry.get_parser` (Requirements 3.1, 3.2, 3.3, 3.4,
3.5).

All fixture data is synthetic (documentation IP ranges and ``example.com``).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

# Import the module so the parser registers under the "nginx" key.
import loganalyze.parsers.nginx  # noqa: F401
from loganalyze.models import Event
from loganalyze.parsers.nginx import NginxParser
from loganalyze.registry import get_parser

# A canonical nginx "combined" access-log line (matches benign.log line 1).
CANONICAL_LINE = (
    '192.0.2.10 - - [10/Oct/2024:13:55:36 +0000] '
    '"GET /index.html HTTP/1.1" 200 1534 "https://example.com/" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/128.0 Safari/537.36"'
)


def test_wellformed_line_from_fixture_produces_event(nginx_benign_lines):
    """A real benign nginx line parses into a fully populated Event.

    Validates: Requirements 3.1, 3.2
    """
    parser = NginxParser()
    line = nginx_benign_lines[0]

    event = parser.parse(line)

    assert isinstance(event, Event)
    assert event.log_type == "nginx"
    assert event.client_ip == "192.0.2.10"
    assert event.method == "GET"
    assert event.path == "/index.html"
    # Status is normalized to an int, not the raw string.
    assert event.status == 200
    assert isinstance(event.status, int)
    # user-agent is preserved in the structured fields mapping.
    assert "Chrome/128.0" in event.fields["user_agent"]
    assert event.fields["referer"] == "https://example.com/"
    assert event.fields["http_version"] == "1.1"
    assert event.fields["size"] == "1534"
    # Raw content is retained for explainability.
    assert event.raw == line


def test_wellformed_line_timestamp_is_aware_utc():
    """An nginx +0000 offset yields an aware datetime converted to UTC.

    Validates: Requirements 3.1, 3.2
    """
    parser = NginxParser()

    event = parser.parse(CANONICAL_LINE)

    assert event is not None
    # The source carried an explicit +0000 offset, so the timestamp must be
    # timezone-aware and expressed in UTC.
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() == timezone.utc.utcoffset(None)
    assert event.timestamp == datetime(2024, 10, 10, 13, 55, 36, tzinfo=timezone.utc)


def test_log_type_matches_registry_key():
    """The emitted Event.log_type equals the registry key "nginx".

    Validates: Requirement 3.3
    """
    parser = get_parser("nginx")
    assert parser is not None

    event = parser.parse(CANONICAL_LINE)

    assert event is not None
    assert event.log_type == "nginx"
    assert parser.log_type == "nginx"


def test_absent_optional_fields_are_none():
    """Fields the nginx format does not supply default to None, not guesses.

    Validates: Requirement 3.2
    """
    parser = NginxParser()

    event = parser.parse(CANONICAL_LINE)

    assert event is not None
    # nginx access logs carry no host or authenticated user identity, so these
    # optional Event fields must remain explicitly absent.
    assert event.host is None
    assert event.user is None


def test_size_dash_is_recorded_as_absent():
    """A "-" body size (304 responses) is omitted rather than stored as "-".

    Validates: Requirement 3.2
    """
    parser = NginxParser()
    line = (
        '203.0.113.43 - - [10/Oct/2024:13:55:41 +0000] '
        '"GET /static/logo.png HTTP/1.1" 304 0 "https://example.com/" '
        '"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"'
    )

    event = parser.parse(line)

    assert event is not None
    assert event.status == 304
    # "0" is a real size here; a literal "-" would be dropped. Confirm the dash
    # case is dropped using a synthesized line.
    dash_line = line.replace('HTTP/1.1" 304 0 ', 'HTTP/1.1" 304 - ')
    dash_event = parser.parse(dash_line)
    assert dash_event is not None
    assert "size" not in dash_event.fields


@pytest.mark.parametrize(
    "garbage",
    [
        "",
        "this is not a log line at all",
        "Oct 10 13:55:36 host sshd[1]: Accepted password for user",  # syslog shape
        '192.0.2.10 - - [10/Oct/2024:13:55:36 +0000] "GET /index.html"',  # truncated
    ],
)
def test_malformed_line_returns_none(garbage):
    """Non-nginx or garbage lines return None without raising.

    Validates: Requirements 3.4, 3.5
    """
    parser = NginxParser()
    # Must not raise on arbitrary, attacker-influenced content.
    assert parser.parse(garbage) is None


def test_unparseable_timestamp_returns_none():
    """A structurally valid line with a bad timestamp parses to None.

    Validates: Requirement 3.5
    """
    parser = NginxParser()
    # Structurally a valid nginx line, but the timestamp is not a real date.
    line = (
        '192.0.2.10 - - [99/Zzz/2024:99:99:99 +0000] '
        '"GET /index.html HTTP/1.1" 200 1534 "https://example.com/" '
        '"Mozilla/5.0"'
    )

    assert parser.parse(line) is None
