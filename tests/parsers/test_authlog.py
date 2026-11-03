"""Unit tests for the auth.log parser (``loganalyze.parsers.authlog``).

Exercises the normalized :class:`~loganalyze.models.Event` contract for the
sshd / PAM / sudo / su payloads the parser recognizes, plus the non-match and
naive-timestamp behavior. Sample lines are drawn from the synthetic
``tests/fixtures/authlog`` fixtures where possible (Requirements 3.1, 3.2, 3.3,
3.4, 3.5, 3.8).
"""

from __future__ import annotations

import pytest

# Importing the module triggers @register_parser("authlog") registration.
import loganalyze.parsers.authlog  # noqa: F401
from loganalyze.models import Event
from loganalyze.parsers.authlog import AuthlogParser
from loganalyze.registry import get_parser


@pytest.fixture
def parser() -> AuthlogParser:
    """A fresh AuthlogParser instance for direct ``parse`` calls."""
    return AuthlogParser()


def _parse_first(parser: AuthlogParser, lines: list[str], predicate) -> Event:
    """Return the first Event from ``lines`` whose parsed Event matches ``predicate``."""
    for line in lines:
        event = parser.parse(line)
        if event is not None and predicate(event):
            return event
    raise AssertionError("no matching line found in fixture")


# --- Registration / log_type (Requirement 3.3) -----------------------------


def test_parser_registered_under_authlog_key():
    """The parser resolves via the registry key ``"authlog"`` (3.3)."""
    resolved = get_parser("authlog")
    assert isinstance(resolved, AuthlogParser)
    assert resolved.log_type == "authlog"


def test_event_log_type_is_registry_key(parser: AuthlogParser):
    """Every emitted Event carries ``log_type == "authlog"`` (3.3)."""
    event = parser.parse(
        "Oct 10 11:20:07 host01 sshd[4121]: "
        "Failed password for root from 203.0.113.120 port 55012 ssh2"
    )
    assert event is not None
    assert event.log_type == "authlog"


# --- Failed password (Requirements 3.1, 3.2) -------------------------------


def test_failed_password_line(parser: AuthlogParser):
    """A failed-password line normalizes to a failed_login failure event (3.1, 3.2)."""
    event = parser.parse(
        "Oct 10 11:20:07 host01 sshd[4121]: "
        "Failed password for root from 203.0.113.120 port 55012 ssh2"
    )
    assert event is not None
    assert event.log_type == "authlog"
    assert event.fields["event"] == "failed_login"
    assert event.fields["auth_result"] == "failure"
    assert event.user == "root"
    assert event.client_ip == "203.0.113.120"
    # A non-invalid-user line must not carry the invalid_user marker.
    assert "invalid_user" not in event.fields


def test_failed_password_invalid_user_variant(parser: AuthlogParser):
    """The ``invalid user`` variant sets ``fields["invalid_user"] == "true"`` (3.1)."""
    event = parser.parse(
        "Oct 10 11:20:05 host01 sshd[4120]: "
        "Failed password for invalid user admin from 203.0.113.120 port 55010 ssh2"
    )
    assert event is not None
    assert event.fields["event"] == "failed_login"
    assert event.fields["auth_result"] == "failure"
    assert event.fields["invalid_user"] == "true"
    assert event.user == "admin"
    assert event.client_ip == "203.0.113.120"


def test_failed_password_from_signature_fixture(
    parser: AuthlogParser, authlog_signature_lines: list[str]
):
    """A failed_login event is recognized in the signature fixture (3.1)."""
    event = _parse_first(
        parser,
        authlog_signature_lines,
        lambda e: e.fields.get("event") == "failed_login",
    )
    assert event.fields["auth_result"] == "failure"
    assert event.user is not None


# --- Accepted login (success) ----------------------------------------------


def test_accepted_line(parser: AuthlogParser):
    """An accepted-password line normalizes to a success event with method set."""
    event = parser.parse(
        "Jan 15 09:14:58 app-host sshd[20410]: "
        "Accepted password for deploy from 192.0.2.10 port 54892 ssh2"
    )
    assert event is not None
    assert event.fields["event"] == "accepted"
    assert event.fields["auth_result"] == "success"
    assert event.fields["method"] == "password"
    assert event.user == "deploy"
    assert event.client_ip == "192.0.2.10"


def test_accepted_publickey_from_benign_fixture(
    parser: AuthlogParser, authlog_benign_lines: list[str]
):
    """An accepted publickey login in the benign fixture parses as success."""
    event = _parse_first(
        parser,
        authlog_benign_lines,
        lambda e: e.fields.get("event") == "accepted",
    )
    assert event.fields["auth_result"] == "success"
    assert event.fields["method"] in {"password", "publickey"}


# --- sudo privilege escalation ---------------------------------------------


def test_sudo_line(parser: AuthlogParser):
    """A sudo line sets mechanism/target_user and carries the invoking user."""
    event = parser.parse(
        "Oct 10 11:25:30 host01 sudo:  carol : "
        "TTY=pts/0 ; PWD=/home/carol ; USER=root ; COMMAND=/bin/bash"
    )
    assert event is not None
    assert event.fields["event"] == "sudo"
    assert event.fields["mechanism"] == "sudo"
    assert event.fields["target_user"] == "root"
    # Invoking user is carried on Event.user, not target_user.
    assert event.user == "carol"


# --- su privilege escalation -----------------------------------------------


def test_su_line(parser: AuthlogParser):
    """A su line sets event/mechanism to ``su`` with the target user."""
    event = parser.parse(
        "Oct 10 11:40:12 host01 su[4890]: Successful su for root by dave"
    )
    assert event is not None
    assert event.fields["event"] == "su"
    assert event.fields["mechanism"] == "su"
    assert event.fields["target_user"] == "root"
    assert event.fields["auth_result"] == "success"
    assert event.user == "dave"


def test_su_failed_line(parser: AuthlogParser):
    """A FAILED su line is an ``su`` event with a failure auth_result."""
    event = parser.parse(
        "Oct 10 11:42:01 host01 su[4905]: FAILED su for root by eve"
    )
    assert event is not None
    assert event.fields["event"] == "su"
    assert event.fields["mechanism"] == "su"
    assert event.fields["auth_result"] == "failure"
    assert event.user == "eve"


# --- Timestamp awareness (Requirement 3.8) ---------------------------------


def test_timestamp_is_naive(parser: AuthlogParser):
    """auth.log timestamps carry no zone, so the Event timestamp is naive (3.8)."""
    event = parser.parse(
        "Oct 10 11:20:07 host01 sshd[4121]: "
        "Failed password for root from 203.0.113.120 port 55012 ssh2"
    )
    assert event is not None
    assert event.timestamp.tzinfo is None


# --- Non-auth / malformed lines return None (Requirement 3.4, 3.5) ---------


def test_session_open_line_returns_none(parser: AuthlogParser):
    """A well-framed session-open line is not an auth event: returns None (3.4)."""
    event = parser.parse(
        "Oct 10 07:15:01 host01 sshd[1820]: "
        "pam_unix(sshd:session): session opened for user alice by (uid=0)"
    )
    assert event is None


def test_systemd_logind_line_returns_none(parser: AuthlogParser):
    """A non-auth systemd-logind line returns None without raising (3.4)."""
    event = parser.parse(
        "Oct 10 07:30:10 host01 systemd-logind[640]: New session 201 of user alice."
    )
    assert event is None


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not a syslog line at all",
        "Oct 10 07:45:22 host01 sshd[2100]: "
        "Received disconnect from 192.0.2.70 port 51022:11: disconnected by user",
    ],
)
def test_unrecognized_lines_return_none(parser: AuthlogParser, line: str):
    """Empty, unframed, and unknown-payload lines return None, never raise (3.4, 3.5)."""
    assert parser.parse(line) is None
