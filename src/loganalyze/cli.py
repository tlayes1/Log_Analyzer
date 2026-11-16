"""Command-line interface: argument parsing, config validation, and exit codes.

This module is the console entry point declared in ``pyproject.toml``
(``loganalyze = "loganalyze.cli:main"``). :func:`main` parses arguments with the
standard-library :mod:`argparse` (Requirement 1.1), builds a validated
:class:`~loganalyze.config.RunConfig`, runs the batch pipeline, renders the
selected outputs at the security boundary, reports the per-run skipped-line
count, and maps the outcome to a process exit code.

Exit codes (Requirements 1.13, 1.14)
-------------------------------------
======  ============================================================
 Code    Meaning
======  ============================================================
 0       Clean run: the pipeline produced no findings.
 1       Findings produced: at least one finding was reported.
 2       Error: usage error, unknown ``--format``, a nonexistent /
         unreadable / empty input set, invalid configuration, or an
         output write failure.
======  ============================================================

Configuration is validated *before* any input is ingested (Requirements 2.7,
6.3, 6.4): an out-of-range line cap, z-threshold, or rare-event cutoff is
reported on standard error and the run never begins.

Plugin registration by import side effect
-----------------------------------------
Outputs register themselves in the shared registry only when their module is
imported. This module imports the concrete output modules (``console``,
``file_json``, and the optional ``file_csv``) at import time purely for their
``@register_output`` side effects, so :func:`loganalyze.registry.get_output`
resolves every renderer. Parsers are imported for their side effects by the
pipeline. The optional CSV renderer (Requirement 8.3) may be absent in a
minimal build; its import is therefore guarded and ``--csv`` is rejected with a
clear error when the renderer is not installed.

Output destinations supplied on the command line are operator-chosen, never
derived from log content, so they are passed to the renderers with
``log_derived=False`` (Requirement 8.12 is upheld: no log-derived path is ever
written).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

from loganalyze import pipeline
from loganalyze.config import (
    DetectionConfig,
    IngestConfig,
    RuleConfig,
    RunConfig,
    StatisticalConfig,
    validate_max_line_bytes,
    validate_rare_cutoff,
    validate_z_threshold,
)

# Imported for their ``@register_output`` side effects so the console and JSON
# renderers are resolvable by key. ``noqa: F401`` marks them intentionally
# unused as names.
from loganalyze.outputs import console as _console  # noqa: F401
from loganalyze.outputs import file_html as _file_html  # noqa: F401
from loganalyze.outputs import file_json as _file_json  # noqa: F401
from loganalyze.outputs.base import OutputTarget
from loganalyze.registry import get_parser

# The CSV renderer is optional (Requirement 8.3) and may not exist in a minimal
# build. Import it for its registration side effect when present; record whether
# it is available so ``--csv`` can fail cleanly otherwise.
try:  # pragma: no cover - exercised by presence/absence of the optional module
    from loganalyze.outputs import file_csv as _file_csv  # noqa: F401

    _CSV_AVAILABLE = True
except ImportError:
    _CSV_AVAILABLE = False

__all__ = ["EXIT_CLEAN", "EXIT_ERROR", "EXIT_FINDINGS", "main"]

#: Exit code for a run that completed with no findings (Requirement 1.13).
EXIT_CLEAN = 0

#: Exit code for a run that produced at least one finding (Requirement 1.14).
EXIT_FINDINGS = 1

#: Exit code for any error: usage, unknown format, bad/unreadable/empty input,
#: invalid configuration, or a write failure (Requirements 1.7-1.11, 2.7, 8.13).
EXIT_ERROR = 2

#: Program name shown in usage and error messages.
_PROG = "loganalyze"


class _CliError(Exception):
    """A handled CLI failure carrying a message to print on standard error.

    Raised internally for every condition that maps to :data:`EXIT_ERROR`
    (unknown format, invalid configuration, nonexistent/unreadable/empty input,
    or a write failure). :func:`main` catches it, prints ``message`` to standard
    error, and returns :data:`EXIT_ERROR`, so error handling is uniform and the
    exit-code contract lives in one place.
    """


def _build_parser() -> argparse.ArgumentParser:
    """Construct the :mod:`argparse` parser for the CLI (Requirement 1.1).

    The parser accepts one or more input paths and the optional format, output,
    and detection-override flags. ``nargs="+"`` makes at least one input path
    mandatory, so an invocation with no path triggers argparse's own usage error
    on standard error and a non-zero exit (Requirement 1.10).

    Returns:
        The configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description=(
            "Batch-analyze system and web-server logs for known-attack "
            "signatures and statistical anomalies."
        ),
    )
    parser.add_argument(
        "inputs",
        metavar="PATH",
        nargs="+",
        type=Path,
        help="one or more log files or directories to analyze (read-only)",
    )
    parser.add_argument(
        "--format",
        dest="format_override",
        metavar="KEY",
        default=None,
        help=(
            "force a specific parser (e.g. nginx, apache, syslog, authlog) "
            "instead of auto-detecting per input"
        ),
    )
    parser.add_argument(
        "--report",
        dest="report_json",
        metavar="PATH",
        type=Path,
        default=None,
        help="write a structured JSON report to this path",
    )
    parser.add_argument(
        "--csv",
        dest="report_csv",
        metavar="PATH",
        type=Path,
        default=None,
        help="write a CSV report to this path (optional)",
    )
    parser.add_argument(
        "--html",
        dest="report_html",
        metavar="PATH",
        type=Path,
        default=None,
        help="write a self-contained HTML report to this path",
    )
    parser.add_argument(
        "--max-line-bytes",
        dest="max_line_bytes",
        metavar="N",
        type=int,
        default=None,
        help="line-length cap in bytes before any regex (default 65536, min 1)",
    )
    parser.add_argument(
        "--z-threshold",
        dest="z_threshold",
        metavar="Z",
        type=float,
        default=None,
        help="rate-spike z-score threshold (default 3.0, range 1.0-10.0)",
    )
    parser.add_argument(
        "--rare-cutoff",
        dest="rare_cutoff",
        metavar="F",
        type=float,
        default=None,
        help="rare-event relative-frequency cutoff (default 0.01, 0 < F < 1)",
    )
    return parser


def _build_config(args: argparse.Namespace) -> RunConfig:
    """Validate parsed arguments and assemble a :class:`RunConfig`.

    Every overridable configuration value is validated here, before ingest, via
    the pure validators in :mod:`loganalyze.config`: the line cap must be an
    integer >= 1 (Requirement 2.7), the z-threshold must lie in the inclusive
    range 1.0-10.0 (Requirement 6.3), and the rare-event cutoff must lie in the
    open interval (0.0, 1.0) (Requirement 6.4). An unknown ``--format`` names no
    registered parser and is rejected before the pipeline runs (Requirement
    1.7). A requested CSV report is rejected when the optional renderer is not
    available. Any failure raises :class:`_CliError` so no input is ingested.

    Args:
        args: The namespace produced by the argument parser.

    Returns:
        A fully validated :class:`RunConfig` ready to hand to the pipeline.

    Raises:
        _CliError: If any configuration value is invalid, ``--format`` names no
            registered parser, or ``--csv`` is requested without the renderer.
    """
    # Validate the format override up front so an unknown key fails before any
    # file is read (Requirement 1.7).
    if args.format_override is not None and get_parser(args.format_override) is None:
        raise _CliError(
            f"unrecognized format {args.format_override!r}: no parser is "
            f"registered under that key"
        )

    if args.report_csv is not None and not _CSV_AVAILABLE:
        raise _CliError(
            "CSV output was requested with --csv but the CSV renderer is not "
            "available in this build"
        )

    # Validate numeric overrides; the config validators raise ValueError with a
    # clear message, which we surface as a handled CLI error (Requirements 2.7,
    # 6.3, 6.4).
    try:
        max_line_bytes = (
            validate_max_line_bytes(args.max_line_bytes)
            if args.max_line_bytes is not None
            else IngestConfig().max_line_bytes
        )
        z_threshold = (
            validate_z_threshold(args.z_threshold)
            if args.z_threshold is not None
            else StatisticalConfig().z_threshold
        )
        rare_cutoff = (
            validate_rare_cutoff(args.rare_cutoff)
            if args.rare_cutoff is not None
            else StatisticalConfig().rare_cutoff
        )
    except ValueError as exc:
        raise _CliError(f"invalid configuration: {exc}") from exc

    detection = DetectionConfig(
        rules=RuleConfig(),
        statistical=StatisticalConfig(
            z_threshold=z_threshold,
            rare_cutoff=rare_cutoff,
        ),
    )
    return RunConfig(
        input_paths=list(args.inputs),
        format_override=args.format_override,
        report_json_path=args.report_json,
        report_csv_path=args.report_csv,
        report_html_path=args.report_html,
        ingest=IngestConfig(max_line_bytes=max_line_bytes),
        detection=detection,
    )


def _render_outputs(result: pipeline.RunResult, config: RunConfig) -> None:
    """Render the console table and any requested file reports.

    The console table is always rendered to standard output (Requirement 8.1).
    When a JSON report path was supplied it is written atomically via the
    registered ``json`` renderer (Requirement 8.2); when a CSV path was supplied
    and the optional renderer is available it is written via the ``csv`` renderer
    (Requirement 8.3). File destinations come from the operator, never from log
    content, so they are rendered with an :class:`OutputTarget` carrying the
    chosen path (Requirement 8.12 upheld).

    Args:
        result: The completed run result whose findings are rendered.
        config: The run configuration naming the requested report paths.

    Raises:
        _CliError: If a report file cannot be written (the renderer raised an
            :class:`OSError` or :class:`ValueError`); the exit code is the error
            code (Requirement 8.13).
    """
    console = _require_output("console")
    console.render(result.findings, OutputTarget(path=None))

    if config.report_json_path is not None:
        json_output = _require_output("json")
        try:
            json_output.render(
                result.findings, OutputTarget(path=config.report_json_path)
            )
        except (OSError, ValueError) as exc:
            raise _CliError(
                f"failed to write JSON report to {config.report_json_path}: {exc}"
            ) from exc

    if config.report_csv_path is not None:
        csv_output = _require_output("csv")
        try:
            csv_output.render(
                result.findings, OutputTarget(path=config.report_csv_path)
            )
        except (OSError, ValueError) as exc:
            raise _CliError(
                f"failed to write CSV report to {config.report_csv_path}: {exc}"
            ) from exc

    if config.report_html_path is not None:
        html_output = _require_output("html")
        try:
            html_output.render(
                result.findings,
                OutputTarget(
                    path=config.report_html_path,
                    source=_describe_inputs(config.input_paths),
                    skipped=_skip_summary(result),
                ),
            )
        except (OSError, ValueError) as exc:
            raise _CliError(
                f"failed to write HTML report to {config.report_html_path}: {exc}"
            ) from exc


def _require_output(key: str):
    """Resolve a registered output renderer by key or raise a handled error.

    Args:
        key: The output registry key (e.g. ``"console"``, ``"json"``, ``"csv"``).

    Returns:
        A fresh instance of the registered renderer.

    Raises:
        _CliError: If no renderer is registered under ``key``.
    """
    from loganalyze.registry import get_outputs

    output = get_outputs().get(key)
    if output is None:
        raise _CliError(f"no output renderer registered under {key!r}")
    return output


def _check_inputs(paths: list[Path]) -> None:
    """Resolve the input set and reject nonexistent, unreadable, or empty sets.

    Discovery is performed up front so three distinct input errors are caught
    before the pipeline runs: a path that does not exist (Requirement 1.8), a
    path that exists but cannot be read (Requirement 1.9), and a resolved set
    that contains no readable file (Requirement 1.11). Each maps to the error
    exit code via :class:`_CliError`.

    Args:
        paths: The input files and/or directories supplied on the command line.

    Raises:
        _CliError: If any path does not exist, a path cannot be read, or the
            resolved set is empty.
    """
    from loganalyze.ingest import discover_inputs

    try:
        discovered = discover_inputs(paths)
    except FileNotFoundError as exc:
        raise _CliError(str(exc)) from exc
    except OSError as exc:
        raise _CliError(f"could not read input: {exc}") from exc

    if not discovered:
        joined = ", ".join(str(p) for p in paths)
        raise _CliError(f"no readable input file found in: {joined}")


def _skip_summary(result: pipeline.RunResult) -> str:
    """Return the one-line skipped-line summary text (no trailing newline).

    Names the total and the breakdown by reason (truncated at the byte cap vs.
    unparseable), always including zero (Requirements 4.3, 4.4). Shared by the
    standard-error report and the HTML report header so both read identically.

    Args:
        result: The completed run result carrying the skip counter.

    Returns:
        A summary such as ``"Skipped 12 lines (truncated=0, unparseable=12)."``.
    """
    skips = result.skips
    return (
        f"Skipped {skips.total} lines "
        f"(truncated={skips.truncated}, unparseable={skips.unparseable})."
    )


def _describe_inputs(paths: list[Path]) -> str:
    """Return a short, human description of the analyzed input set.

    Names the single input when exactly one path was given, otherwise reports
    the count. This is operator-supplied run metadata, never derived from log
    content, so it is safe to show in a report header.

    Args:
        paths: The input files and/or directories supplied on the command line.

    Returns:
        A description such as ``"auth.log"`` or ``"3 inputs"``.
    """
    if len(paths) == 1:
        return paths[0].name
    return f"{len(paths)} inputs"


def _report_skips(result: pipeline.RunResult, stream: TextIO) -> None:
    """Report the per-run skipped-line count to ``stream`` (Requirement 4.3).

    The summary names the total and the breakdown by reason so the operator can
    see how much input was skipped because it was truncated at the byte cap or
    could not be parsed. The count is always reported, including zero
    (Requirement 4.4).

    Args:
        result: The completed run result carrying the skip counter.
        stream: The destination stream (standard error) for the summary.
    """
    stream.write(_skip_summary(result) + "\n")


def main(argv: list[str] | None = None) -> int:
    """Parse args, run the pipeline, render outputs, and return the exit code.

    Arguments are parsed with :mod:`argparse` (Requirement 1.1); a missing input
    path triggers argparse's usage error and a non-zero exit (Requirement 1.10).
    Configuration is validated before ingest (Requirements 2.7, 6.3, 6.4) and an
    unknown ``--format`` is rejected up front (Requirement 1.7). The pipeline is
    then run; a nonexistent input path (Requirement 1.8), an unreadable input
    (Requirement 1.9), an empty readable input set (Requirement 1.11), and an
    output write failure (Requirement 8.13) each map to the error exit code. On
    success the console table is always rendered, any requested report files are
    written, the skipped-line count is reported (Requirement 4.3), and the exit
    code reflects whether findings were produced (Requirements 1.13, 1.14).

    Args:
        argv: The argument vector to parse, excluding the program name. Defaults
            to ``sys.argv[1:]`` when ``None``.

    Returns:
        :data:`EXIT_CLEAN` when the run produced no findings,
        :data:`EXIT_FINDINGS` when at least one finding was produced, or
        :data:`EXIT_ERROR` on any usage, configuration, input, or write error.
    """
    parser = _build_parser()
    # parse_args exits with status 2 on a usage error (e.g. no input path),
    # writing its message to standard error (Requirement 1.10). That matches our
    # error exit code, so we let it propagate.
    args = parser.parse_args(argv)

    try:
        config = _build_config(args)
        _check_inputs(config.input_paths)
        try:
            result = pipeline.run(config)
        except FileNotFoundError as exc:
            # A supplied input path does not exist (Requirement 1.8).
            raise _CliError(str(exc)) from exc
        except LookupError as exc:
            # Defensive: the pipeline guards the override key too (Requirement
            # 1.7). _build_config already validated it, so this is belt-and-braces.
            raise _CliError(str(exc)) from exc
        except OSError as exc:
            # An input path exists but cannot be read (Requirement 1.9).
            raise _CliError(f"could not read input: {exc}") from exc

        _render_outputs(result, config)
    except _CliError as exc:
        print(f"{_PROG}: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Always surface how much input was skipped (Requirements 4.3, 4.4).
    _report_skips(result, sys.stderr)

    return EXIT_FINDINGS if result.findings else EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
