"""Property-based tests for parser totality, purity, and matched-event shape.

These tests exercise the two parser correctness properties from the loganalyze
design document against every registered parser. The parser modules are imported
for their registration side effects; instances are then resolved through the
plugin registry exactly as the pipeline resolves them.

Fixtures are synthetic only (documentation IPs, ``example.com`` emails,
non-authenticating credentials), per testing-standards.md and Requirement 11.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

# Import the parser modules so their @register_parser decorators populate the
# registry. The imports are intentionally unused as names.
import loganalyze.parsers.apache  # noqa: F401
import loganalyze.parsers.authlog  # noqa: F401
import loganalyze.parsers.nginx  # noqa: F401
import loganalyze.parsers.syslog  # noqa: F401
from loganalyze.models import Event
from loganalyze.registry import get_parsers

#: Every registered parser, mapped by its registry key, resolved once at import.
_PARSERS = get_parsers()

#: Root of the synthetic fixture tree.
_FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

# Fixture files, per parser key, known to contain lines that parser matches.
# Property 2 feeds each parser only its own format's matching lines.
_MATCHING_FIXTURES: dict[str, tuple[str, ...]] = {
    "nginx": ("benign.log", "signatures.log", "spike_requests.log"),
    "apache": ("benign.log", "signatures.log"),
    "syslog": ("benign.log",),
    "authlog": ("benign.log", "signatures.log", "burst_bruteforce.log"),
}

# The optional Event fields that a parser sets to None when not applicable.
_OPTIONAL_FIELDS = ("host", "client_ip", "user", "method", "path", "status")


def _fixture_lines(fmt: str, name: str) -> list[str]:
    """Return the non-empty, newline-stripped lines of a fixture file."""
    path = _FIXTURES_DIR / fmt / name
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line]


def _matching_lines(key: str) -> list[str]:
    """Return every fixture line that the parser ``key`` actually matches."""
    parser = _PARSERS[key]
    matched: list[str] = []
    for name in _MATCHING_FIXTURES[key]:
        for line in _fixture_lines(key, name):
            if parser.parse(line) is not None:
                matched.append(line)
    return matched


# ---------------------------------------------------------------------------
# Feature: loganalyze, Property 1: Parsers are total and pure over arbitrary
# input
# Validates: Requirements 3.4, 3.5, 3.6, 4.6
# ---------------------------------------------------------------------------
#
# For ANY string input (empty, binary-ish, truncated, malformed), every
# registered parser's parse() returns either an Event or None, never raises, and
# returns an identical result when called twice on the same input (purity; Event
# is a frozen dataclass, so == is value equality).


# A broad alphabet including control characters and unicode. Lone surrogates
# ("Cs") are excluded so arbitrary strings stay encodable and cannot break the
# test harness itself.
_ARBITRARY_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    min_size=0,
    max_size=512,
)


@settings(max_examples=200)
@given(s=_ARBITRARY_TEXT)
def test_property1_parsers_total_and_pure(s: str) -> None:
    """Every parser maps any string to an Event or None, never raises, is pure.

    Validates: Requirements 3.4, 3.5, 3.6
    """
    for key, parser in _PARSERS.items():
        # Totality / no-raise: simply calling parse() in the test body asserts
        # it does not raise. If any parser raises on an arbitrary input, that is
        # a real bug and the test fails here (Requirements 3.5, 4.6).
        result1 = parser.parse(s)
        result2 = parser.parse(s)

        # Returns an Event or None, nothing else (Requirement 3.4).
        assert result1 is None or isinstance(result1, Event), (
            f"parser {key!r} returned {type(result1).__name__}, "
            "expected Event or None"
        )

        # Purity: identical input yields an identical result (Requirement 3.6).
        assert result1 == result2, (
            f"parser {key!r} is not pure: two calls on the same input "
            "returned different results"
        )


# ---------------------------------------------------------------------------
# Feature: loganalyze, Property 2: Matched events have the required shape
# Validates: Requirements 3.1, 3.2, 3.3
# ---------------------------------------------------------------------------
#
# For ANY raw line a given parser matches (parse returns non-None), the Event has
# timestamp, source, log_type, message, raw, fields populated; every absent
# optional field (host, client_ip, user, method, path, status) is None where not
# applicable; and log_type == that parser's registry key.


def _assert_matched_shape(key: str, event: Event) -> None:
    """Assert a matched Event satisfies the required-shape property."""
    # Required fields are populated with the right types (Requirement 3.1).
    assert isinstance(event.timestamp, datetime), (
        f"{key}: timestamp must be a datetime"
    )
    assert isinstance(event.source, str), f"{key}: source must be a str"
    assert isinstance(event.message, str), f"{key}: message must be a str"
    assert isinstance(event.raw, str), f"{key}: raw must be a str"
    assert isinstance(event.fields, dict), f"{key}: fields must be a dict"

    # log_type equals the registry key the parser is registered under
    # (Requirement 3.3).
    assert event.log_type == key, (
        f"{key}: log_type is {event.log_type!r}, expected the registry key"
    )
    assert isinstance(event.log_type, str) and event.log_type, (
        f"{key}: log_type must be a non-empty str"
    )

    # Every optional field is either populated or explicitly None — never some
    # other sentinel (Requirement 3.2). Fields the parser does not populate for
    # this line must be None, not absent or guessed.
    for name in _OPTIONAL_FIELDS:
        value = getattr(event, name)
        if value is None:
            continue
        if name == "status":
            assert isinstance(value, int), f"{key}: status must be int or None"
        else:
            assert isinstance(value, str), f"{key}: {name} must be str or None"


def test_property2_matched_events_have_required_shape() -> None:
    """Fixture-driven: every matched line yields an Event of the required shape.

    Validates: Requirements 3.1, 3.2, 3.3
    """
    for key in _PARSERS:
        lines = _matching_lines(key)
        # Guard: each parser must have at least one matching fixture line, or
        # this property would vacuously pass and hide a regression.
        assert lines, f"no matching fixture lines found for parser {key!r}"
        for line in lines:
            event = _PARSERS[key].parse(line)
            assert isinstance(event, Event), (
                f"{key}: expected a matched Event for line: {line!r}"
            )
            _assert_matched_shape(key, event)


# A Hypothesis strategy that builds synthetic nginx/apache "combined" access-log
# lines from templated parts, to broaden Property 2 coverage beyond the fixtures.
_METHODS = st.sampled_from(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
_OCTET = st.integers(min_value=0, max_value=255)
_STATUS = st.integers(min_value=100, max_value=599)
# Path and user-agent spans avoid quotes and whitespace so the line stays a
# single well-formed record; bounded to keep generation fast.
_PATH = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters="/._-=?&",
    ),
    min_size=1,
    max_size=40,
)
_UA = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters="/.;:()_- ",
    ),
    min_size=0,
    max_size=40,
)


@st.composite
def _web_log_line(draw: st.DrawFn) -> tuple[str, str]:
    """Draw a (key, line) pair for a synthetic nginx/apache combined log line."""
    key = draw(st.sampled_from(["nginx", "apache"]))
    ip = ".".join(str(draw(_OCTET)) for _ in range(4))
    method = draw(_METHODS)
    path = "/" + draw(_PATH).lstrip("/")
    status = draw(_STATUS)
    size = draw(st.integers(min_value=0, max_value=10_000_000))
    ua = draw(_UA)
    line = (
        f'{ip} - - [10/Oct/2024:13:55:36 +0000] '
        f'"{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    )
    return key, line


@settings(max_examples=150)
@given(pair=_web_log_line())
def test_property2_synthetic_web_lines_have_required_shape(
    pair: tuple[str, str],
) -> None:
    """Synthetic web lines that parse yield Events of the required shape.

    Broadens Property 2 coverage with generated nginx/apache lines. A generated
    line that does not parse (None) is skipped — only matched lines are subject
    to the shape property.

    Validates: Requirements 3.1, 3.2, 3.3
    """
    key, line = pair
    event = _PARSERS[key].parse(line)
    if event is None:
        return
    _assert_matched_shape(key, event)
