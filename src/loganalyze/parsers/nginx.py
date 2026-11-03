"""Parser for the nginx combined access-log format.

This module owns a single precompiled, bounded regex that matches the nginx
"combined" access-log line shape::

    IP - - [timestamp] "METHOD path HTTP/x" status size "referer" "user-agent"

The :class:`NginxParser` is registered under the ``"nginx"`` key and converts
one raw line into a normalized :class:`~loganalyze.models.Event`, or returns
``None`` for any line that does not match the format or that carries an
unparseable timestamp. It performs no I/O and never raises on malformed input,
so the ingest path stays resilient to arbitrary, attacker-influenced content
(Requirements 3.4, 3.5, 9.1, 9.2).
"""

from __future__ import annotations

import re

from loganalyze.models import Event, normalize_timestamp
from loganalyze.registry import register_parser

# strftime format for the nginx access-log timestamp, e.g.
# "10/Oct/2024:13:55:36 +0000".
_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# One precompiled, bounded, ReDoS-safe regex matching the nginx combined
# access-log format. Every quantifier is bounded by a negated character class
# (``[^...]``) or an explicit upper bound, so there is no nested or ambiguous
# repetition that could trigger catastrophic backtracking (Requirements 9.1,
# 9.2). The ingest layer caps line length before this pattern ever runs.
_LINE_RE = re.compile(
    r"^"
    r"(?P<client_ip>[^\s]{1,255})"           # client IP (or host)
    r" \S{1,255} \S{1,255} "                  # ident and auth user (usually "-")
    r"\[(?P<timestamp>[^\]]{1,64})\]"         # [day/mon/year:hh:mm:ss +zzzz]
    r' "(?P<method>[A-Z]{1,16}) '             # request method
    r"(?P<path>[^\s\"]{1,8192}) "             # request path/target
    r'HTTP/(?P<http_version>[0-9.]{1,8})"'    # protocol version
    r" (?P<status>\d{1,3})"                   # response status code
    r" (?P<size>\d{1,19}|-)"                  # response body size ("-" if none)
    r' "(?P<referer>[^"]{0,8192})"'           # referer header
    r' "(?P<user_agent>[^"]{0,8192})"'        # user-agent header
    r"\s*$"
)


@register_parser("nginx")
class NginxParser:
    """Pure parser for nginx combined access-log lines.

    Attributes:
        log_type: The registry key ``"nginx"``, copied onto every emitted
            Event's ``log_type`` field (Requirement 3.3).
    """

    log_type = "nginx"

    def parse(self, raw_line: str) -> Event | None:
        """Parse one nginx access-log line into an Event, or ``None``.

        The method is a pure function of ``raw_line``: it performs no I/O, reads
        no mutable global state, and never raises on malformed input. A line
        that does not match the nginx combined format, or whose timestamp is not
        parseable under the nginx strftime format, yields ``None`` rather than an
        exception (Requirements 3.4, 3.5).

        Args:
            raw_line: A single raw log line, already length-capped by the ingest
                layer before any regex runs.

        Returns:
            A normalized :class:`~loganalyze.models.Event` with ``log_type`` set
            to ``"nginx"`` when the line matches, or ``None`` otherwise.
        """
        match = _LINE_RE.match(raw_line)
        if match is None:
            return None

        try:
            timestamp, _aware = normalize_timestamp(
                match.group("timestamp"), _TIMESTAMP_FORMAT
            )
        except ValueError:
            # A structurally valid line with an unparseable timestamp is treated
            # as malformed: return None rather than raising (Requirement 3.5).
            return None

        try:
            status = int(match.group("status"))
        except ValueError:  # pragma: no cover - regex guarantees digits
            return None

        size = match.group("size")
        # A size of "-" means no body was sent; record it as an absent value.
        fields: dict[str, str] = {
            "user_agent": match.group("user_agent"),
            "referer": match.group("referer"),
            "http_version": match.group("http_version"),
        }
        if size != "-":
            fields["size"] = size

        # The parser operates on a single line and does not know the file path;
        # the pipeline associates provenance via LineRecord.source separately.
        # Keep the parser pure by using an empty placeholder (Requirement 3.1).
        return Event(
            timestamp=timestamp,
            source="",
            log_type=self.log_type,
            message=raw_line.rstrip("\n"),
            raw=raw_line,
            fields=fields,
            client_ip=match.group("client_ip"),
            method=match.group("method"),
            path=match.group("path"),
            status=status,
        )
