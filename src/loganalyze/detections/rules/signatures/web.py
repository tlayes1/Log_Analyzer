"""Web signature detectors for SQLi/XSS probes and scanner user agents.

This module defines three pure, registered signature detectors that recognize
*attacks in logs* — they never carry out or assist an attack (see
``detection-rules.md`` "Defensive scope"):

- :class:`SqliProbe` (``web.sqli.probe``, HIGH) — a SQL-injection probe in a web
  request ``path`` (Requirement 5.1).
- :class:`XssProbe` (``web.xss.probe``, HIGH) — a cross-site-scripting probe in a
  web request ``path`` (Requirement 5.2).
- :class:`ScannerUserAgent` (``web.scanner.ua``, MEDIUM) — a known
  vulnerability-scanner user-agent string in ``fields["user_agent"]``
  (Requirement 5.3).

Every detector matches a single precompiled, bounded, ReDoS-safe regex (every
quantifier is explicitly bounded and no nested/ambiguous repetition is used, per
``security.md``). Because web access logs record percent-encoded request targets
(``%20``/``%3C``) and ``+``-encoded spaces, each path detector matches both the
raw path and a length-bounded percent-decoded view of it, so an encoded probe is
recognized without re-parsing the raw line.

Each detector is pure: :meth:`detect` inspects only the events and the injected
configuration, performs no I/O, raises no alerts, and returns an identical result
for identical inputs. Every :class:`~loganalyze.models.Finding` carries exactly
one :class:`~loganalyze.models.Severity` (Requirement 5.8), and the detectors are
resolved purely through their registry keys so the pipeline never names them
directly (Requirement 5.9).
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

from loganalyze.config import DetectionConfig
from loganalyze.models import Event, Finding, Severity
from loganalyze.registry import register_detector

#: Event ``log_type`` values that carry a web request path/user-agent.
_WEB_LOG_TYPES = ("nginx", "apache")

#: Upper bound (characters) on the span percent-decoded before matching. The
#: ingest layer already caps raw line length; this second bound keeps the
#: decoded view small so signature matching stays cheap on hostile input.
_MAX_DECODE_CHARS = 8192


# Bounded, precompiled, ReDoS-safe SQL-injection probe signature. Each
# alternative uses bounded gaps (``.{0,40}`` / ``\s{1,8}``) rather than
# unbounded or nested quantifiers, so there is no catastrophic-backtracking
# shape (Requirements 9.1, 9.2). The signature recognizes common probe tokens:
# a UNION ... SELECT pair, boolean tautologies such as ``OR '1'='1'`` or
# ``AND 1=1``, inline-comment terminators, and time-based ``SLEEP(``/``WAITFOR``
# markers. Recognition only — this is not a payload generator.
_SQLI_RE = re.compile(
    r"(?i)(?:"
    r"\bunion\b.{0,40}\bselect\b"               # UNION ... SELECT
    r"|\bor\b\s{0,8}['\"]?\s{0,8}1\s{0,8}=\s{0,8}1"  # OR 1=1 / OR '1'='1'
    r"|\band\b\s{0,8}['\"]?\s{0,8}1\s{0,8}=\s{0,8}1"  # AND 1=1 / AND '1'='1'
    r"|['\"]\s{0,8}(?:or|and)\b\s{0,8}['\"]?1['\"]?\s{0,8}=\s{0,8}['\"]?1"  # '1'='1'
    r"|;\s{0,8}--"                              # statement terminator + comment
    r"|/\*.{0,40}\*/"                           # inline block comment
    r"|\bsleep\s{0,8}\("                        # time-based SLEEP(
    r"|\bwaitfor\b\s{1,8}\bdelay\b"             # time-based WAITFOR DELAY
    r")"
)

# Bounded, precompiled, ReDoS-safe cross-site-scripting probe signature. Covers
# the canonical recognition tokens: a ``<script>`` tag, inline event handlers
# such as ``onerror=``/``onload=``, ``javascript:`` URIs, and the
# ``<svg/onload=`` and ``<img ... onerror=`` shapes. All gaps are bounded.
_XSS_RE = re.compile(
    r"(?i)(?:"
    r"<\s{0,8}script\b"                         # <script ...>
    r"|</\s{0,8}script\s{0,8}>"                 # </script>
    r"|<\s{0,8}svg\b[^>]{0,80}\bonload\s{0,8}="  # <svg ... onload=
    r"|<\s{0,8}img\b[^>]{0,80}\bonerror\s{0,8}="  # <img ... onerror=
    r"|\bon(?:error|load|mouseover|focus|click)\s{0,8}="  # inline event handler
    r"|javascript\s{0,8}:"                      # javascript: URI
    r")"
)

# Bounded, precompiled, ReDoS-safe scanner user-agent signature. Matches the
# self-identifying tokens emitted by well-known scanning tools; word boundaries
# keep benign agents (e.g. a browser UA) from matching. Recognition only.
_SCANNER_UA_RE = re.compile(
    r"(?i)(?:"
    r"\bsqlmap\b"
    r"|\bnikto\b"
    r"|\bnmap\b"
    r"|\bmasscan\b"
    r"|\bwpscan\b"
    r"|\bdirbuster\b"
    r"|\bgobuster\b"
    r"|\bnessus\b"
    r"|\bacunetix\b"
    r"|\bzgrab\b"
    r"|\bzmap\b"
    r")"
)


def _decoded_view(value: str) -> str:
    """Return a length-bounded percent/plus-decoded view of ``value``.

    Web logs record percent-encoded request targets and ``+``-encoded spaces.
    Decoding a bounded prefix lets the signatures match an encoded probe without
    re-parsing the raw line. The input is truncated to :data:`_MAX_DECODE_CHARS`
    before decoding so decoding cost stays bounded on hostile input.

    Args:
        value: The raw (possibly percent-encoded) string to decode.

    Returns:
        The decoded view of the bounded prefix of ``value``.
    """
    return unquote_plus(value[:_MAX_DECODE_CHARS])


def _line_number(event: Event) -> str | None:
    """Return the ``line_number`` recorded on an event, if any.

    The :class:`~loganalyze.models.Event` model does not carry ``line_number``
    directly; the pipeline records provenance and may surface it through
    ``Event.fields``. This helper reads that field when present so the finding
    metadata can satisfy Requirements 5.1-5.3 once provenance is wired in
    (task 14.1), while remaining correct today when the field is absent.

    Args:
        event: The event to read provenance from.

    Returns:
        The ``line_number`` string from ``event.fields``, or ``None`` when it is
        not present.
    """
    return event.fields.get("line_number")


def _path_match(event: Event, pattern: re.Pattern[str]) -> str | None:
    """Return the matched substring if ``pattern`` hits the event's path.

    The raw path is tested first; when it does not match, a length-bounded
    percent/plus-decoded view is tested so encoded probes are still recognized.

    Args:
        event: The web event whose ``path`` is inspected.
        pattern: The precompiled signature to apply.

    Returns:
        The matched text (from the raw or decoded path), or ``None`` when
        neither matches.
    """
    path = event.path
    if not path:
        return None
    match = pattern.search(path)
    if match is not None:
        return match.group(0)
    decoded = _decoded_view(path)
    if decoded != path:
        match = pattern.search(decoded)
        if match is not None:
            return match.group(0)
    return None


def _path_metadata(event: Event, signature: str) -> dict:
    """Build the metadata mapping for a path-based web finding.

    Includes ``source``, the matched ``path``, and the ``signature`` name, plus
    ``line_number`` when the pipeline has recorded it on the event.

    Args:
        event: The contributing event.
        signature: The matched signature substring named in the finding.

    Returns:
        A metadata mapping satisfying Requirements 5.1/5.2 (``source``,
        ``line_number`` when available, matched ``path``).
    """
    metadata: dict = {
        "source": event.source,
        "path": event.path,
        "signature": signature,
    }
    line_number = _line_number(event)
    if line_number is not None:
        metadata["line_number"] = line_number
    return metadata


@register_detector("web.sqli.probe")
class SqliProbe:
    """Flag SQL-injection probe strings in web request paths (HIGH).

    Recognizes a precompiled SQLi probe signature in the ``path`` of nginx and
    Apache events and yields one :class:`~loganalyze.models.Finding` per matching
    event, naming the matched signature in ``detail`` and recording ``source``,
    ``line_number`` (when available), and the matched ``path`` in ``metadata``
    (Requirement 5.1).

    Attributes:
        rule_id: The stable registry key ``"web.sqli.probe"``.
    """

    rule_id = "web.sqli.probe"

    def detect(self, events: list[Event], config: DetectionConfig) -> list[Finding]:
        """Return SQLi-probe findings for the given web events.

        Pure: inspects only ``events`` and ``config``; performs no I/O.

        Args:
            events: The normalized events to inspect, in pipeline order.
            config: The injected detection configuration (unused by this
                signature detector; present to satisfy the Detector contract).

        Returns:
            One Finding per event whose web request path matches the SQLi
            signature; an empty list when nothing matches.
        """
        findings: list[Finding] = []
        for event in events:
            if event.log_type not in _WEB_LOG_TYPES:
                continue
            matched = _path_match(event, _SQLI_RE)
            if matched is None:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Possible SQL-injection probe",
                    severity=Severity.HIGH,
                    events=[event],
                    detail=(
                        "Request path matched the SQL-injection probe signature "
                        f"{matched!r}."
                    ),
                    metadata=_path_metadata(event, matched),
                )
            )
        return findings


@register_detector("web.xss.probe")
class XssProbe:
    """Flag cross-site-scripting probe strings in web request paths (HIGH).

    Recognizes a precompiled XSS probe signature in the ``path`` of nginx and
    Apache events and yields one :class:`~loganalyze.models.Finding` per matching
    event, naming the matched signature in ``detail`` and recording ``source``,
    ``line_number`` (when available), and the matched ``path`` in ``metadata``
    (Requirement 5.2).

    Attributes:
        rule_id: The stable registry key ``"web.xss.probe"``.
    """

    rule_id = "web.xss.probe"

    def detect(self, events: list[Event], config: DetectionConfig) -> list[Finding]:
        """Return XSS-probe findings for the given web events.

        Pure: inspects only ``events`` and ``config``; performs no I/O.

        Args:
            events: The normalized events to inspect, in pipeline order.
            config: The injected detection configuration (unused by this
                signature detector; present to satisfy the Detector contract).

        Returns:
            One Finding per event whose web request path matches the XSS
            signature; an empty list when nothing matches.
        """
        findings: list[Finding] = []
        for event in events:
            if event.log_type not in _WEB_LOG_TYPES:
                continue
            matched = _path_match(event, _XSS_RE)
            if matched is None:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Possible cross-site-scripting probe",
                    severity=Severity.HIGH,
                    events=[event],
                    detail=(
                        "Request path matched the cross-site-scripting probe "
                        f"signature {matched!r}."
                    ),
                    metadata=_path_metadata(event, matched),
                )
            )
        return findings


@register_detector("web.scanner.ua")
class ScannerUserAgent:
    """Flag known vulnerability-scanner user agents in web events (MEDIUM).

    Recognizes a precompiled scanner user-agent signature in
    ``fields["user_agent"]`` of nginx and Apache events and yields one
    :class:`~loganalyze.models.Finding` per matching event, naming the matched
    signature in ``detail`` and recording ``source``, ``line_number`` (when
    available), and the matched user-agent value in ``metadata``
    (Requirement 5.3).

    Attributes:
        rule_id: The stable registry key ``"web.scanner.ua"``.
    """

    rule_id = "web.scanner.ua"

    def detect(self, events: list[Event], config: DetectionConfig) -> list[Finding]:
        """Return scanner-user-agent findings for the given web events.

        Pure: inspects only ``events`` and ``config``; performs no I/O.

        Args:
            events: The normalized events to inspect, in pipeline order.
            config: The injected detection configuration (unused by this
                signature detector; present to satisfy the Detector contract).

        Returns:
            One Finding per event whose user agent matches the scanner
            signature; an empty list when nothing matches.
        """
        findings: list[Finding] = []
        for event in events:
            if event.log_type not in _WEB_LOG_TYPES:
                continue
            user_agent = event.fields.get("user_agent")
            if not user_agent:
                continue
            match = _SCANNER_UA_RE.search(user_agent)
            if match is None:
                continue
            matched = match.group(0)
            metadata: dict = {
                "source": event.source,
                "user_agent": user_agent,
                "signature": matched,
            }
            line_number = _line_number(event)
            if line_number is not None:
                metadata["line_number"] = line_number
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Vulnerability scanner user agent",
                    severity=Severity.MEDIUM,
                    events=[event],
                    detail=(
                        "User agent matched the scanner signature "
                        f"{matched!r}."
                    ),
                    metadata=metadata,
                )
            )
        return findings
