"""Apache combined access-log parser.

This module implements the ``apache`` parser plugin: a pure converter from a
single raw line of the Apache *combined* access-log format into a normalized
:class:`~loganalyze.models.Event`, or ``None`` when the line does not match.

The combined format is Apache's ``LogFormat`` directive::

    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

which expands, for a real line, to::

    127.0.0.1 - alice [10/Oct/2024:09:12:01 -0700] "GET /path HTTP/1.1" 200 2326 "-" "Mozilla/5.0 ..."

The parser owns exactly one precompiled, bounded regex built at module import
(Requirements 9.1, 9.2). The pattern uses only bounded, non-overlapping tokens
(no nested quantifiers over the same input), so it cannot exhibit catastrophic
backtracking (ReDoS) regardless of input. The parser performs no I/O, reads no
mutable global state, and never raises on malformed input — it returns ``None``
instead (Requirements 3.4, 3.5).
"""

from __future__ import annotations

import re

from loganalyze.models import Event, normalize_timestamp
from loganalyze.registry import register_parser

#: ``strftime``/``strptime`` format for the bracketed Apache timestamp, e.g.
#: ``10/Oct/2024:09:12:01 -0700``. Includes ``%z`` so the explicit offset is
#: parsed and normalized to UTC by :func:`normalize_timestamp`.
_APACHE_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

#: One precompiled, bounded, ReDoS-safe regex for the Apache combined format.
#:
#: Every token is bounded: character classes exclude their own delimiter
#: (``[^"]`` inside quotes, ``[^\]]`` inside brackets, ``\S`` for whitespace-free
#: tokens), so no alternative can match the same character two ways and there is
#: no nested quantifier over shared input. This guarantees linear-time matching.
_APACHE_COMBINED_RE = re.compile(
    r"^(?P<client_ip>\S+)"          # %h  remote host / client IP
    r" (?P<ident>\S+)"              # %l  identd (usually "-")
    r" (?P<user>\S+)"               # %u  remote user (usually "-")
    r" \[(?P<time>[^\]]+)\]"        # %t  [day/month/year:hh:mm:ss zone]
    r' "(?P<method>[A-Z]+) '        # request-line verb
    r"(?P<path>[^\s\"]*)"           # request-line path/target
    r' (?P<protocol>HTTP/[0-9.]+)"' # request-line protocol
    r" (?P<status>\d{3})"           # %>s final status code
    r" (?P<size>-|\d+)"             # %b  response size in bytes ("-" when none)
    r' "(?P<referer>[^"]*)"'        # %{Referer}i
    r' "(?P<user_agent>[^"]*)"'     # %{User-Agent}i
    r"\s*$"
)


@register_parser("apache")
class ApacheParser:
    """Pure parser for the Apache combined access-log format.

    The parser is stateless. It exposes :attr:`log_type` (equal to its registry
    key, Requirement 3.3) and a pure :meth:`parse` method that converts one raw
    line into an :class:`~loganalyze.models.Event` or returns ``None``.
    """

    #: Registry key copied onto every emitted Event's ``log_type`` field.
    log_type: str = "apache"

    def parse(self, raw_line: str) -> Event | None:
        """Parse one raw Apache combined-format line into an Event.

        This is a pure function of ``raw_line``: it performs no I/O, reads no
        mutable global state, and never raises on malformed input. A line that
        does not match the combined format, or whose timestamp cannot be parsed,
        yields ``None`` rather than an exception (Requirements 3.4, 3.5).

        Absent optional fields — the request's ``user``, ``referer``,
        ``user_agent``, and ``size``, which Apache writes as ``"-"`` — are
        recorded as ``None`` rather than guessed (Requirement 3.2).

        Args:
            raw_line: A single raw log line, already capped to the configured
                maximum length by the ingest layer before this regex runs.

        Returns:
            A normalized :class:`~loganalyze.models.Event` whose ``log_type``
            equals ``"apache"`` when the line matches, otherwise ``None``.
        """
        match = _APACHE_COMBINED_RE.match(raw_line)
        if match is None:
            return None

        try:
            timestamp, _aware = normalize_timestamp(
                match.group("time"), _APACHE_TIME_FORMAT
            )
        except ValueError:
            # A structurally valid line with an unparseable timestamp is treated
            # as malformed: return None, never raise (Requirement 3.4).
            return None

        user = _none_if_dash(match.group("user"))
        referer = _none_if_dash(match.group("referer"))
        user_agent = _none_if_dash(match.group("user_agent"))
        size = _none_if_dash(match.group("size"))

        method = match.group("method")
        path = match.group("path")
        status = int(match.group("status"))
        protocol = match.group("protocol")

        fields: dict[str, str] = {}
        if user_agent is not None:
            fields["user_agent"] = user_agent
        if referer is not None:
            fields["referer"] = referer
        if size is not None:
            fields["size"] = size

        message = f"{method} {path} {protocol} {status}"

        return Event(
            timestamp=timestamp,
            # Pure parser has no file path; the pipeline associates
            # LineRecord.source separately.
            source="",
            log_type=self.log_type,
            message=message,
            raw=raw_line,
            fields=fields,
            client_ip=match.group("client_ip"),
            user=user,
            method=method,
            path=path,
            status=status,
        )


def _none_if_dash(value: str) -> str | None:
    """Map Apache's ``"-"`` placeholder to ``None``, else return the value.

    Args:
        value: A captured field value.

    Returns:
        ``None`` when ``value`` is the single-dash placeholder Apache writes for
        an absent field, otherwise ``value`` unchanged.
    """
    return None if value == "-" else value
