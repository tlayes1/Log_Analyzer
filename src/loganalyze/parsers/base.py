"""Parser protocol: the shared contract every log-format parser implements.

A parser is a pure converter from a single raw log line of one specific format
into a normalized :class:`~loganalyze.models.Event`, or ``None`` when the line
does not belong to that format. Every registered parser emits the same Event
shape, so detectors share one contract and new formats are added as new modules
without editing the pipeline. Parsers perform no I/O, read no mutable global
state, and never raise on malformed input (they return ``None`` instead), which
keeps the ingest path resilient to arbitrary, attacker-influenced log content.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from loganalyze.models import Event


@runtime_checkable
class Parser(Protocol):
    """Structural contract for a single-format log parser.

    A conforming parser exposes a ``log_type`` attribute and a pure
    :meth:`parse` method. Implementations own one precompiled, bounded regex at
    module import, are registered under a registry key, and are resolved by that
    key without changes to the pipeline module.

    Attributes:
        log_type: The registry key under which the parser is registered. It is
            copied onto the ``log_type`` field of every Event the parser emits,
            so a downstream consumer can tell which format produced a record.
    """

    log_type: str

    def parse(self, raw_line: str) -> Event | None:
        """Parse one raw line into an Event, or return ``None`` on a non-match.

        The method is a pure function of ``raw_line``: it performs no file or
        network I/O, reads no mutable global state, and returns an identical
        result for an identical input line. It never raises on malformed input;
        a line that does not match the parser's format, or that matches only
        partially, yields ``None`` rather than an exception.

        Args:
            raw_line: A single raw log line, already capped to the configured
                maximum length by the ingest layer before any regex runs.

        Returns:
            A normalized :class:`~loganalyze.models.Event` whose ``log_type``
            equals this parser's registry key when the line matches the format,
            or ``None`` when the line does not match or is malformed.
        """
        ...
