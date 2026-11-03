"""Parser for the Linux ``auth.log`` / sshd authentication log format.

This module owns a small set of precompiled, bounded, ReDoS-safe regexes at
import time. The outer frame is the RFC 3164-like syslog shape::

    MMM dd HH:MM:SS host process[pid]: message

Once the frame is stripped, the auth-specific payload is matched against one of
several bounded alternatives so that the downstream auth detectors (failed
login, brute force, privilege escalation) can key off normalized ``fields``
markers instead of re-parsing ``raw``.

The :class:`AuthlogParser` is registered under the ``"authlog"`` key and
converts one raw line into a normalized :class:`~loganalyze.models.Event`, or
returns ``None`` for any line that does not match a recognized auth payload or
that carries an unparseable timestamp. It performs no I/O and never raises on
malformed input, so the ingest path stays resilient to arbitrary,
attacker-influenced content (Requirements 3.4, 3.5, 3.6, 9.1, 9.2).

Fields-dict markers emitted (contract for detector tasks 9.4 and 9.6)
----------------------------------------------------------------------
Every recognized Event carries ``fields["event"]``; the other keys depend on
the event kind. All values are strings (the ``Event.fields`` contract).

* ``fields["event"]``: one of ``"failed_login"``, ``"accepted"``, ``"sudo"``,
  ``"su"``. This is the primary discriminator for detectors.
* ``fields["auth_result"]``: ``"failure"`` or ``"success"``. Set on every
  recognized event. A brute-force detector (9.6) counts
  ``event == "failed_login"`` (equivalently ``auth_result == "failure"`` for an
  ssh/PAM auth event) per ``client_ip`` within a window.
* ``fields["mechanism"]``: present only for privilege-escalation events; one of
  ``"sudo"`` or ``"su"``. Task 9.4 (``auth.privesc``) keys off this.
* ``fields["service"]``: the originating process name as seen in the syslog
  frame (e.g. ``"sshd"``, ``"sudo"``, ``"su"``), when available.
* ``fields["invalid_user"]``: ``"true"`` when the sshd line reported
  ``invalid user`` (the account does not exist). Absent otherwise.
* ``fields["method"]``: the ssh auth method for ``accepted`` events, e.g.
  ``"password"`` or ``"publickey"``, when available.
* ``fields["target_user"]``: the account escalated *to* for privilege
  escalation (e.g. ``"root"`` for a ``sudo ... USER=root`` or ``su ... for
  root`` line). The invoking user is carried on ``Event.user``.
* ``fields["port"]``: the client source port for ssh auth events, when present.

Top-level ``Event`` fields populated when present: ``host`` (from the syslog
frame), ``user`` (the invoking/authenticating account), and ``client_ip`` (the
remote source address). Absent optional fields are ``None`` (Requirement 3.2).
"""

from __future__ import annotations

import re

from loganalyze.models import Event, normalize_timestamp
from loganalyze.registry import register_parser

# strftime format for the RFC 3164 syslog timestamp, e.g. "Oct 10 11:20:05".
# The year is absent from the wire format, so the parsed datetime is naive and
# recorded with no offset applied (Requirement 3.8).
_TIMESTAMP_FORMAT = "%b %d %H:%M:%S"

# Outer syslog frame. Every quantifier is bounded by an explicit upper bound or
# a negated character class, so there is no nested/ambiguous repetition that
# could trigger catastrophic backtracking (Requirements 9.1, 9.2). The ingest
# layer caps line length before this pattern ever runs.
#
#   "Oct 10 11:20:05 host01 sshd[4120]: Failed password for ..."
#   "Oct 10 11:25:30 host01 sudo:  carol : TTY=..."   (sudo often has no [pid])
_FRAME_RE = re.compile(
    r"^"
    r"(?P<timestamp>[A-Z][a-z]{2}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2})"  # MMM dd HH:MM:SS
    r" (?P<host>[^\s]{1,255})"            # host
    r" (?P<process>[A-Za-z0-9_./-]{1,64})"  # process name
    r"(?:\[(?P<pid>\d{1,10})\])?"        # optional [pid]
    r": {1,2}(?P<message>.{0,8192})"     # ": " (sudo uses two spaces) + message
    r"\s*$"
)

# --- Auth-specific payload patterns (matched against the frame's message) ----

# sshd: "Failed password for [invalid user] <user> from <ip> port <n> ssh2"
_SSH_FAILED_RE = re.compile(
    r"^Failed password for "
    r"(?P<invalid>invalid user )?"
    r"(?P<user>[^\s]{1,255}) "
    r"from (?P<client_ip>[^\s]{1,255}) "
    r"port (?P<port>\d{1,5}) ssh2"
)

# sshd: "Accepted password|publickey for <user> from <ip> port <n> ssh2[: ...]"
_SSH_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>[A-Za-z0-9_-]{1,32}) for "
    r"(?P<user>[^\s]{1,255}) "
    r"from (?P<client_ip>[^\s]{1,255}) "
    r"port (?P<port>\d{1,5}) ssh2"
)

# PAM: "pam_unix(<service>:auth): authentication failure; ... [rhost=<ip>] [user=<user>]"
# Only auth-failure PAM lines are treated as failed logins; session lines are
# not auth attempts. ``rhost`` and ``user`` are optional and order-independent
# enough that we extract them with separate bounded scans.
_PAM_AUTH_FAIL_RE = re.compile(
    r"^pam_unix\((?P<service>[^:)]{1,64}):auth\): authentication failure;"
)
_PAM_RHOST_RE = re.compile(r"\brhost=(?P<client_ip>[^\s]{0,255})")
_PAM_USER_RE = re.compile(r"\buser=(?P<user>[^\s]{1,255})")

# sudo: "  carol : TTY=pts/0 ; PWD=/home/carol ; USER=root ; COMMAND=/bin/bash"
# The invoking user precedes " : ", the escalation target follows "USER=".
_SUDO_RE = re.compile(
    r"^\s*(?P<user>[^\s:]{1,255}) : "
    r".{0,4096}?\bUSER=(?P<target_user>[^\s]{1,255})\b"
)

# su: "Successful su for root by dave" / "FAILED su for root by eve"
_SU_RE = re.compile(
    r"^(?P<result>Successful|FAILED) su for "
    r"(?P<target_user>[^\s]{1,255}) by (?P<user>[^\s]{1,255})"
)


@register_parser("authlog")
class AuthlogParser:
    """Pure parser for Linux ``auth.log`` / sshd, sudo, and su entries.

    Attributes:
        log_type: The registry key ``"authlog"``, copied onto every emitted
            Event's ``log_type`` field (Requirement 3.3).
    """

    log_type = "authlog"

    def parse(self, raw_line: str) -> Event | None:
        """Parse one ``auth.log`` line into an Event, or ``None``.

        The method is a pure function of ``raw_line``: it performs no I/O, reads
        no mutable global state, and never raises on malformed input. A line
        that does not match the syslog frame, carries a payload this parser does
        not recognize, or whose timestamp is unparseable under the syslog
        strftime format, yields ``None`` rather than an exception (Requirements
        3.4, 3.5, 3.6).

        Args:
            raw_line: A single raw log line, already length-capped by the ingest
                layer before any regex runs.

        Returns:
            A normalized :class:`~loganalyze.models.Event` with ``log_type`` set
            to ``"authlog"`` when the line matches a recognized auth payload, or
            ``None`` otherwise.
        """
        frame = _FRAME_RE.match(raw_line)
        if frame is None:
            return None

        payload = self._match_payload(frame.group("message"), frame.group("process"))
        if payload is None:
            # A well-formed syslog frame carrying an uninteresting/unknown
            # payload (e.g. a session-open line) is not an auth event we model;
            # treat it as a non-match (Requirement 3.4).
            return None

        try:
            # auth.log timestamps carry no timezone, so the result is naive and
            # recorded with no offset applied (Requirement 3.8); aware==False.
            timestamp, _aware = normalize_timestamp(
                frame.group("timestamp"), _TIMESTAMP_FORMAT
            )
        except ValueError:
            # Structurally valid frame with an unparseable timestamp is treated
            # as malformed: return None rather than raising (Requirement 3.5).
            return None

        fields, user, client_ip = payload
        return Event(
            timestamp=timestamp,
            # Pure parser: the pipeline sets provenance via LineRecord.source
            # separately, so keep source an empty placeholder (Requirement 3.1).
            source="",
            log_type=self.log_type,
            message=frame.group("message"),
            raw=raw_line,
            fields=fields,
            host=frame.group("host"),
            client_ip=client_ip,
            user=user,
        )

    @staticmethod
    def _match_payload(
        message: str, process: str
    ) -> tuple[dict[str, str], str | None, str | None] | None:
        """Classify an auth payload into (fields, user, client_ip).

        Args:
            message: The syslog frame's message portion (after ``process[pid]:``).
            process: The originating process name from the frame (e.g. ``sshd``).

        Returns:
            A ``(fields, user, client_ip)`` triple for a recognized auth event,
            or ``None`` when the payload is not an auth event this parser models.
        """
        # sshd failed password.
        m = _SSH_FAILED_RE.match(message)
        if m is not None:
            fields: dict[str, str] = {
                "event": "failed_login",
                "auth_result": "failure",
                "service": process,
                "port": m.group("port"),
            }
            if m.group("invalid"):
                fields["invalid_user"] = "true"
            return fields, m.group("user"), m.group("client_ip")

        # sshd accepted (password / publickey / ...).
        m = _SSH_ACCEPTED_RE.match(message)
        if m is not None:
            fields = {
                "event": "accepted",
                "auth_result": "success",
                "service": process,
                "method": m.group("method"),
                "port": m.group("port"),
            }
            return fields, m.group("user"), m.group("client_ip")

        # PAM authentication failure (sshd:auth, su:auth, ...).
        m = _PAM_AUTH_FAIL_RE.match(message)
        if m is not None:
            fields = {
                "event": "failed_login",
                "auth_result": "failure",
                "service": m.group("service"),
            }
            rhost = _PAM_RHOST_RE.search(message)
            client_ip = (
                rhost.group("client_ip")
                if rhost is not None and rhost.group("client_ip")
                else None
            )
            user_m = _PAM_USER_RE.search(message)
            user = user_m.group("user") if user_m is not None else None
            return fields, user, client_ip

        # sudo privilege escalation.
        m = _SUDO_RE.match(message)
        if m is not None:
            fields = {
                "event": "sudo",
                "mechanism": "sudo",
                "auth_result": "success",
                "service": process,
                "target_user": m.group("target_user"),
            }
            return fields, m.group("user"), None

        # su privilege escalation (success or failure).
        m = _SU_RE.match(message)
        if m is not None:
            success = m.group("result") == "Successful"
            fields = {
                "event": "su",
                "mechanism": "su",
                "auth_result": "success" if success else "failure",
                "service": process,
                "target_user": m.group("target_user"),
            }
            return fields, m.group("user"), None

        return None
