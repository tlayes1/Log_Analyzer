"""Unit tests for the Apache combined access-log parser.

Covers Requirements 3.1 (normalized Event emission), 3.2 (absent optionals are
``None``, never guessed), 3.4/3.5 (malformed input returns ``None`` without
raising), and the registry contract that ``log_type`` equals the registry key
``"apache"`` (3.3).

Importing ``loganalyze.parsers.apache`` triggers its ``@register_parser``
decorator so the parser is resolvable via ``registry.get_parser("apache")``.
"""

from __future__ import annotations

from datetime import datetime

import pytest

# Import for side effect: the module-level @register_parser decorator runs on
# import, registering ApacheParser under the "apache" key.
import loganalyze.parsers.apache  # noqa: F401
from loganalyze import registry
from loganalyze.models import Event
from loganalyze.parsers.apache import ApacheParser

#: A canonical Apache combined line carrying an authenticated user ("alice").
_CANONICAL_WITH_USER = (
    '198.51.100.31 - alice [10/Oct/2024:09:12:04 -0700] '
    '"POST /account/settings HTTP/1.1" 200 412 '
    '"https://example.com/account" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36"'
)

#: A canonical line with every optional ("-"): no user, no referer.
_CANONICAL_ALL_DASH = (
    '192.0.2.20 - - [10/Oct/2024:09:12:01 -0700] '
    '"GET / HTTP/1.1" 200 2326 "-" "curl/8.6.0"'
)


@pytest.fixture
def parser() -> ApacheParser:
    """A fresh, stateless Apache parser instance."""
    return ApacheParser()


# --- Registry contract -----------------------------------------------------


def test_registered_under_apache_key():
    """registry.get_parser("apache") resolves to an ApacheParser (3.3)."""
    resolved = registry.get_parser("apache")
    assert isinstance(resolved, ApacheParser)


def test_log_type_equals_registry_key(parser: ApacheParser):
    """The parser's log_type matches its registry key "apache" (3.3)."""
    assert parser.log_type == "apache"


# --- Well-formed parsing (Requirements 3.1, 3.2) ---------------------------


def test_wellformed_line_populates_normalized_event(parser: ApacheParser):
    """A well-formed combined line yields a fully normalized Event (3.1)."""
    event = parser.parse(_CANONICAL_WITH_USER)

    assert isinstance(event, Event)
    assert event.log_type == "apache"
    assert event.client_ip == "198.51.100.31"
    assert event.method == "POST"
    assert event.path == "/account/settings"
    # status is parsed to an int, not left as a string.
    assert event.status == 200
    assert isinstance(event.status, int)
    # timestamp is a real datetime (parsed, normalized to UTC from -0700).
    assert isinstance(event.timestamp, datetime)
    assert event.raw == _CANONICAL_WITH_USER
    # referer and user_agent land in fields.
    assert event.fields["referer"] == "https://example.com/account"
    assert "Chrome/128.0" in event.fields["user_agent"]


def test_present_user_is_captured(parser: ApacheParser):
    """A present remote user (not "-") is captured on the Event (3.1)."""
    event = parser.parse(_CANONICAL_WITH_USER)
    assert event is not None
    assert event.user == "alice"


def test_timestamp_normalized_to_utc(parser: ApacheParser):
    """The -0700 offset is normalized: 09:12:04 -0700 -> 16:12:04 UTC."""
    event = parser.parse(_CANONICAL_WITH_USER)
    assert event is not None
    assert event.timestamp.hour == 16
    assert event.timestamp.minute == 12
    assert event.timestamp.second == 4


def test_dash_placeholders_map_to_none(parser: ApacheParser):
    """Apache "-" placeholders map to None rather than being guessed (3.2)."""
    event = parser.parse(_CANONICAL_ALL_DASH)
    assert event is not None
    # Absent user ("-") -> None.
    assert event.user is None
    # Absent referer ("-") -> not present in fields (recorded as None/absent).
    assert "referer" not in event.fields
    # A present user_agent is still captured.
    assert event.fields["user_agent"] == "curl/8.6.0"


def test_absent_optionals_default_to_none(parser: ApacheParser):
    """Fields the Apache format never carries stay None, not guessed (3.2)."""
    event = parser.parse(_CANONICAL_ALL_DASH)
    assert event is not None
    # host is not part of the combined format; it must be None, never inferred.
    assert event.host is None


def test_benign_fixture_lines_all_parse(parser: ApacheParser, apache_benign_lines):
    """Every benign fixture line parses to an apache Event (3.1)."""
    assert apache_benign_lines, "benign fixture should not be empty"
    for line in apache_benign_lines:
        event = parser.parse(line)
        assert event is not None, f"failed to parse benign line: {line!r}"
        assert event.log_type == "apache"
        assert event.client_ip
        assert event.method
        assert isinstance(event.status, int)


# --- Malformed / unparseable input (Requirements 3.4, 3.5) -----------------


@pytest.mark.parametrize(
    "bad_line",
    [
        "",
        "   ",
        "not an apache line at all",
        "garbage - - without brackets GET / 200",
        # Structurally close but missing the quoted request line.
        "192.0.2.1 - - [10/Oct/2024:09:12:01 -0700] GET / 200 10",
        # Missing status / trailing quoted fields.
        '192.0.2.1 - - [10/Oct/2024:09:12:01 -0700] "GET / HTTP/1.1"',
    ],
)
def test_malformed_line_returns_none_without_raising(
    parser: ApacheParser, bad_line: str
):
    """Malformed lines return None and never raise (3.4, 3.5)."""
    assert parser.parse(bad_line) is None


def test_unparseable_timestamp_returns_none(parser: ApacheParser):
    """A structural line with an unparseable timestamp returns None (3.4)."""
    # Correct combined structure, but the bracketed timestamp is nonsense and
    # cannot be parsed by the %d/%b/%Y:%H:%M:%S %z format.
    line = (
        '192.0.2.1 - - [not-a-timestamp] '
        '"GET / HTTP/1.1" 200 2326 "-" "curl/8.6.0"'
    )
    assert parser.parse(line) is None
