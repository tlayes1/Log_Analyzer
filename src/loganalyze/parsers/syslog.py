"""RFC3164 (BSD) syslog line parser.

Converts a single traditional syslog line of the shape
``MMM dd HH:MM:SS hostname process[pid]: message`` into a normalized
:class:`~loganalyze.models.Event`, or ``None`` when the line does not match.
The parser owns one precompiled, bounded, ReDoS-safe regex built at module
import (Requirements 9.1, 9.2) and is registered under the ``"syslog"`` key so
the pipeline resolves it without naming the class (Requirement 3.12).

RFC3164 timestamps carry neither a year nor a timezone, so the parsed value is
naive and recorded with no offset applied (Requirement 3.8). This parser is a
pure function of its input line: it performs no I/O, reads no mutable global
state, and never raises on malformed input, returning ``None`` instead
(Requirements 3.4, 3.5).
"""

from __future__ import annotations

import re

from loganalyze.models import Event, normalize_timestamp
from loganalyze.registry import register_parser

#: ``strptime`` format for an RFC3164 timestamp (``Oct 10 08:00:01``). It omits
#: ``%z``/``%Y`` because the wire format carries no timezone or year, so
#: :func:`~loganalyze.models.normalize_timestamp` yields a naive datetime
#: reported as ``aware=False`` (Requirement 3.8).
_TIMESTAMP_FORMAT = "%b %d %H:%M:%S"

#: One precompiled, bounded, ReDoS-safe regex matching an RFC3164 syslog line
#: (Requirements 9.1, 9.2). Every quantifier is applied to a negated character
#: class with no overlap against its neighbor, so there is no catastrophic
#: backtracking path:
#:   * ``timestamp`` — fixed-shape ``MMM dd HH:MM:SS`` (day may be space-padded).
#:   * ``host``      — one run of non-space characters.
#:   * ``process``   — non-space, non-``[``, non-``:`` run (the ``[pid]`` and the
#:                     trailing ``:`` both delimit it unambiguously).
#:   * ``pid``       — optional ``[digits]`` group.
#:   * ``message``   — the remainder of the line (may be empty).
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\s\[:]+)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":\s?(?P<message>.*)$"
)


@register_parser("syslog")
class SyslogParser:
    """Parser for traditional RFC3164 (BSD) syslog lines.

    Attributes:
        log_type: The registry key ``"syslog"``, copied onto every emitted
            Event's ``log_type`` field (Requirement 3.3).
    """

    log_type = "syslog"

    def parse(self, raw_line: str) -> Event | None:
        """Parse one raw syslog line into an Event, or ``None`` on a non-match.

        The method is a pure function of ``raw_line``: no I/O, no mutable global
        state, and no exceptions on malformed input (Requirements 3.4, 3.5,
        3.6). A line that does not match the RFC3164 shape, or whose timestamp
        cannot be normalized, yields ``None``.

        Args:
            raw_line: A single raw log line, already length-capped by ingest.

        Returns:
            A normalized :class:`~loganalyze.models.Event` with ``log_type``
            equal to ``"syslog"`` when the line matches, otherwise ``None``.
            Required fields (``timestamp``, ``source``, ``log_type``,
            ``message``, ``raw``, ``fields``) are populated; the web-oriented
            optional fields (``client_ip``, ``method``, ``path``, ``status``,
            ``user``) are absent for this format and left as ``None``
            (Requirement 3.2).
        """
        match = _SYSLOG_RE.match(raw_line)
        if match is None:
            return None

        try:
            timestamp, _aware = normalize_timestamp(
                match.group("timestamp"), _TIMESTAMP_FORMAT
            )
        except ValueError:
            # A structurally matching but semantically invalid timestamp
            # (e.g. an impossible date) is treated as a non-match (3.4, 3.5).
            return None

        host = match.group("host")
        process = match.group("process")
        pid = match.group("pid")
        message = match.group("message")

        # ``fields`` carries the syslog-specific attributes. ``pid`` is included
        # only when the line actually supplied one.
        fields: dict[str, str] = {"process": process, "host": host}
        if pid is not None:
            fields["pid"] = pid

        return Event(
            timestamp=timestamp,
            source="",  # Placeholder; the pipeline sets provenance.
            log_type=self.log_type,
            message=message,
            raw=raw_line,
            fields=fields,
            host=host,
        )
