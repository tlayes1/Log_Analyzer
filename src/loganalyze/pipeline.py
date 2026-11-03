"""Batch run orchestration for loganalyze.

:func:`run` executes one batch run end to end: it discovers the finite input
set, iterates each file as capped line records, selects a parser (an explicit
format override or per-file auto-detection in deterministic registry order),
normalizes every parseable line into an :class:`~loganalyze.models.Event`, runs
the Rule_Engine and the Statistical_Engine over the combined events, and
aggregates the findings into a deterministic result. Output rendering and
exit-code selection belong to the CLI (task 15.1); this module returns a
:class:`RunResult` and renders nothing.

Plugin registration by import side effect
-----------------------------------------
Parsers register themselves in the shared registry only when their module is
imported, and the ``loganalyze.parsers`` package ``__init__`` does **not** import
them. This module therefore imports the four concrete parser modules
(``nginx``, ``apache``, ``syslog``, ``authlog``) at import time purely for their
``@register_parser`` side effects, so :func:`loganalyze.registry.get_parser` and
:func:`~loganalyze.registry.get_parsers` resolve every format. The signature
detectors are registered by the Rule_Engine's own import of the signatures
package, and the statistical detectors are imported directly by the
Statistical_Engine, so the pipeline keeps the system self-contained without
naming any concrete plugin class.

Provenance stamping (why events are rewritten)
----------------------------------------------
Parsers are pure and emit events with ``source=""`` and no ingest line number,
so the pipeline stamps provenance onto each event before detection: it rebuilds
the frozen :class:`~loganalyze.models.Event` via :func:`dataclasses.replace`
with the record's ``source`` and copies ``fields`` with an added
``"line_number"`` entry. Several detectors (the web and auth signatures) read
``fields["line_number"]`` for their metadata, and aggregation uses ``source``
for its deterministic ordering, so this stamping is required for correct
downstream behavior (Requirements 4.x, 5.9).

Format selection
----------------
When ``config.format_override`` is set it names the single parser applied to
every line of every file; an unknown key is an error surfaced to the caller
(the CLI validates it up front, but the pipeline guards too, Requirement 1.7).
Otherwise the pipeline auto-detects per file: it samples the file's lines to
find the first registered parser (in deterministic registry order) that returns
a non-``None`` event for a non-truncated line, then applies that one parser to
every line of the file (Requirements 1.5, 1.6). Per-file detection keeps a
single file's events consistent and the choice deterministic.

Timezone awareness
-------------------
Each event's timestamp is either timezone-aware (sources with an explicit offset
or ``Z``, normalized to UTC) or naive. When a single run produced both at least
one aware and at least one naive event, the run sets ``mixed_timezones`` True and
emits exactly one warning through this module's :mod:`logging` logger
(Requirement 3.9).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace

from loganalyze.aggregator import aggregate
from loganalyze.config import RunConfig
from loganalyze.detections.rules.engine import RuleEngine
from loganalyze.detections.statistical.engine import StatisticalEngine
from loganalyze.ingest import (
    IngestError,
    LineRecord,
    SkipCounter,
    discover_inputs,
    iter_lines,
)
from loganalyze.models import Event, Finding
from loganalyze.registry import get_parser, get_parsers

# Imported for their ``@register_parser`` side effects so ``get_parser`` and
# ``get_parsers`` resolve every in-scope format. The ``loganalyze.parsers``
# package ``__init__`` deliberately does not import these, so the pipeline must,
# to be self-contained. ``noqa: F401`` marks them as intentionally unused names.
from loganalyze.parsers import apache as _apache  # noqa: F401
from loganalyze.parsers import authlog as _authlog  # noqa: F401
from loganalyze.parsers import nginx as _nginx  # noqa: F401
from loganalyze.parsers import syslog as _syslog  # noqa: F401

__all__ = ["RunResult", "run"]

_LOGGER = logging.getLogger(__name__)


@dataclass
class RunResult:
    """The outcome of a single batch run.

    Attributes:
        findings: The aggregated, deterministically ordered findings produced by
            the Rule_Engine and Statistical_Engine over every parsed event.
        skips: The per-run :class:`~loganalyze.ingest.SkipCounter` tallying lines
            skipped because they were truncated at the byte cap or rejected by
            the applicable parser(s) (Requirements 4.1, 4.2, 4.3).
        mixed_timezones: ``True`` when the run produced both at least one
            timezone-aware and at least one naive event; a single warning is
            emitted in that case (Requirement 3.9).
    """

    findings: list[Finding]
    skips: SkipCounter
    mixed_timezones: bool


def run(config: RunConfig) -> RunResult:
    """Execute one batch run and return its findings and run statistics.

    The run discovers the finite input set from ``config.input_paths``, iterates
    each file as capped line records, selects a parser (explicit override or
    per-file auto-detection), normalizes every parseable line into a
    provenance-stamped :class:`~loganalyze.models.Event`, runs the Rule_Engine
    and Statistical_Engine over the combined events, and aggregates the result.
    Rendering outputs and choosing an exit code are the CLI's responsibility,
    not this function's.

    Truncated lines are counted and never parsed (Requirements 2.5, 4.5, 9.4).
    A line that the applicable parser(s) reject is counted as unparseable and
    skipped; it is never fatal (Requirements 4.1, 4.2, 4.6). A gzip file that
    fails to decompress is logged and the run continues with the next file
    (Requirement 2.8). If the run produced both aware and naive event
    timestamps, ``mixed_timezones`` is set and a single warning is emitted
    (Requirement 3.9).

    Args:
        config: The validated run configuration. ``input_paths`` are discovered,
            ``format_override`` selects the parser strategy, and
            ``ingest``/``detection`` supply the line cap and detector parameters.

    Returns:
        A :class:`RunResult` with the aggregated findings, the skip counter, and
        the mixed-timezone flag.

    Raises:
        FileNotFoundError: If any input path does not exist; propagated from
            :func:`~loganalyze.ingest.discover_inputs` for the CLI to map to an
            error exit (Requirement 1.10).
        LookupError: If ``format_override`` names a parser that is not
            registered (Requirement 1.7). The CLI validates the override up
            front; this is a defensive guard.
    """
    skips = SkipCounter()

    # Resolve the override parser once, up front, so an unknown key fails before
    # any file is read. ``discover_inputs`` may raise FileNotFoundError, which
    # propagates to the caller unchanged.
    override_parser = _resolve_override(config.format_override)
    files = discover_inputs(config.input_paths)

    events: list[Event] = []
    for path in files:
        try:
            records = list(iter_lines(path, config.ingest.max_line_bytes))
        except IngestError as exc:
            # A per-file failure (e.g. bad gzip) is reported and the run
            # continues with the next file (Requirement 2.8).
            _LOGGER.warning("skipping unreadable input %s: %s", path, exc)
            continue
        events.extend(_parse_file(records, override_parser, skips))

    mixed_timezones = _detect_mixed_timezones(events)
    if mixed_timezones:
        _LOGGER.warning(
            "run produced both timezone-aware and naive event timestamps; "
            "cross-source time comparisons may be approximate"
        )

    findings = RuleEngine().run(events, config.detection)
    findings.extend(StatisticalEngine().run(events, config.detection))

    return RunResult(
        findings=aggregate(findings),
        skips=skips,
        mixed_timezones=mixed_timezones,
    )


def _resolve_override(format_override: str | None):
    """Resolve the override parser from its registry key, or return ``None``.

    Args:
        format_override: The parser registry key to force for every line, or
            ``None`` to auto-detect per file.

    Returns:
        The resolved parser instance when ``format_override`` names a registered
        parser, or ``None`` when no override was requested.

    Raises:
        LookupError: If ``format_override`` is set but names no registered
            parser (Requirement 1.7).
    """
    if format_override is None:
        return None
    parser = get_parser(format_override)
    if parser is None:
        raise LookupError(
            f"unknown log format {format_override!r}; no parser is registered "
            f"under that key"
        )
    return parser


def _parse_file(
    records: list[LineRecord],
    override_parser,
    skips: SkipCounter,
) -> list[Event]:
    """Parse one file's line records into provenance-stamped events.

    Truncated records are counted and skipped before any parser sees them. When
    an override parser is supplied it is applied to every non-truncated line;
    otherwise a single parser is auto-detected for the whole file and then
    applied to every line (Requirements 1.5, 1.6). A line the chosen parser
    cannot parse is counted as unparseable and skipped (Requirements 4.1, 4.2).

    Args:
        records: The file's capped line records, in ascending line order.
        override_parser: The forced parser instance, or ``None`` to auto-detect.
        skips: The run's skip counter, mutated as lines are skipped.

    Returns:
        The provenance-stamped events parsed from this file, in line order.
    """
    parser = override_parser or _auto_detect_parser(records)

    events: list[Event] = []
    for record in records:
        if record.truncated:
            # Over-long lines are counted once and never handed to a parser
            # (Requirements 2.5, 4.5, 9.4).
            skips.count_truncated()
            continue
        if parser is None:
            # No parser matched any line in this file, so nothing here can be
            # parsed; every non-truncated line is unparseable.
            skips.count_unparseable()
            continue
        event = parser.parse(record.raw_line)
        if event is None:
            skips.count_unparseable()
            continue
        events.append(_stamp_provenance(event, record))
    return events


def _auto_detect_parser(records: list[LineRecord]):
    """Pick one parser for a file by sampling its non-truncated lines.

    Each registered parser is tried, in deterministic registry order, against
    the file's lines; the first parser that parses any non-truncated line is
    chosen and returned for use on the whole file (Requirements 1.5, 1.6). The
    sample iterates parsers in the outer loop so registry order strictly decides
    ties when more than one format could match a line.

    Args:
        records: The file's capped line records.

    Returns:
        The chosen parser instance, or ``None`` when no registered parser
        matched any non-truncated line in the file.
    """
    parsers = list(get_parsers().values())
    for parser in parsers:
        for record in records:
            if record.truncated:
                continue
            if parser.parse(record.raw_line) is not None:
                return parser
    return None


def _stamp_provenance(event: Event, record: LineRecord) -> Event:
    """Return a copy of ``event`` carrying the record's source and line number.

    Parsers are pure and emit ``source=""`` with no ingest line number, so the
    pipeline stamps provenance here: the frozen event is rebuilt with the
    record's ``source`` and a copy of ``fields`` that adds
    ``"line_number"`` (as a string). Detectors such as the web and auth
    signatures read ``fields["line_number"]`` for their metadata, and the
    aggregator orders on ``source``, so both are set here (Requirement 5.9).

    Args:
        event: The pure event emitted by a parser.
        record: The originating line record supplying provenance.

    Returns:
        A new :class:`~loganalyze.models.Event` with ``source`` set to the
        record's source and ``fields["line_number"]`` set to the record's line
        number; all other fields are unchanged.
    """
    fields = dict(event.fields)
    fields["line_number"] = str(record.line_number)
    return replace(event, source=record.source, fields=fields)


def _detect_mixed_timezones(events: list[Event]) -> bool:
    """Return whether the run produced both aware and naive event timestamps.

    An event timestamp is timezone-aware when its ``tzinfo`` is not ``None``.
    The run is "mixed" only when at least one aware and at least one naive
    timestamp are present together, which the pipeline reports with a single
    warning (Requirement 3.9).

    Args:
        events: Every event produced by the run.

    Returns:
        ``True`` when both an aware and a naive timestamp occur, else ``False``.
    """
    saw_aware = False
    saw_naive = False
    for event in events:
        if event.timestamp.tzinfo is not None:
            saw_aware = True
        else:
            saw_naive = True
        if saw_aware and saw_naive:
            return True
    return False
