"""Input discovery and safe, capped line iteration.

This module turns an input path into an ordered stream of raw line records,
before any parsing happens. It is responsible for the three ingest concerns
that must never be skipped: discovering the finite input set (a file yields
itself, a directory is walked recursively for regular files), transparently
decompressing gzip input detected by its magic bytes rather than its file
extension, and enforcing the ``MAX_LINE_BYTES`` cap on every line *before* any
regex runs (``security.md``; Requirements 2.4, 2.5, 9.4).

Every input is treated as read-only: files are opened for reading only and
nothing in this module writes to an input path (Requirement 1.12). A line that
exceeds the cap is truncated to the cap and flagged ``truncated=True`` so the
pipeline can skip and count it without ever handing an over-long line to a
parser. A gzip file that fails to decompress raises :class:`IngestError`, which
the pipeline logs before continuing with the next file (Requirement 2.8).
"""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from loganalyze.security import cap_line

# gzip streams begin with the two magic bytes 0x1f 0x8b. Gzip is detected by
# these bytes rather than by file extension so a mislabeled ``.log`` that is in
# fact compressed is still decompressed (Requirement 2.2), and a ``.gz`` name on
# plaintext is still read as plaintext (Requirement 2.3).
_GZIP_MAGIC = b"\x1f\x8b"


@dataclass(frozen=True)
class LineRecord:
    """One raw line with provenance, before parsing.

    Attributes:
        source: The originating input file path, as a string, preserved on every
            record emitted for that file (Requirement 2.9).
        line_number: The 1-based line position within the source, ascending and
            incremented by one for each successive line (Requirements 2.1, 2.9).
        raw_line: The line text after the byte cap is enforced; never longer than
            the configured ``max_line_bytes`` (Requirements 2.4, 9.4).
        truncated: ``True`` when the original line exceeded the cap and was cut
            (Requirement 2.5); ``False`` otherwise.
    """

    source: str
    line_number: int
    raw_line: str
    truncated: bool


class IngestError(Exception):
    """A non-fatal-to-run ingest problem, such as bad gzip or an unreadable file.

    Raised for per-file failures that should stop processing of the offending
    file but not the whole run. The pipeline catches it, reports the error, and
    continues with the remaining input files (Requirement 2.8).
    """


def discover_inputs(paths: list[Path]) -> list[Path]:
    """Resolve input paths into the ordered set of regular files to read.

    Each supplied path is expanded independently and the results are
    concatenated in the order the paths were given, so a single run can mix
    files and directories (Requirement 1.4). A path to a file yields that file
    (Requirement 1.2). A path to a directory is walked recursively and every
    regular file beneath it is yielded in sorted order so discovery is
    deterministic across runs and platforms (Requirement 1.3). A path that does
    not exist is an error and aborts discovery.

    Args:
        paths: The input paths supplied on the command line.

    Returns:
        The discovered regular files, in deterministic order.

    Raises:
        FileNotFoundError: If any supplied path does not exist.
    """
    discovered: list[Path] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"input path does not exist: {path}")
        if path.is_dir():
            # rglob("*") walks the tree; keep only regular files and sort so the
            # emitted order is stable regardless of filesystem iteration order.
            for child in sorted(p for p in path.rglob("*") if p.is_file()):
                discovered.append(child)
        else:
            discovered.append(path)
    return discovered


def iter_lines(path: Path, max_line_bytes: int) -> Iterator[LineRecord]:
    """Yield capped :class:`LineRecord`s for one file in ascending line order.

    The file is opened read-only and its first bytes are inspected for the gzip
    magic number; a gzip stream is transparently decompressed and a plaintext
    file is read directly (Requirements 2.2, 2.3). Detection is by magic bytes,
    not file extension. Line numbers start at 1 and increment by one, and the
    source path is preserved on every record (Requirements 2.1, 2.9).

    The ``max_line_bytes`` cap is applied via
    :func:`loganalyze.security.cap_line` to each line *before* it is yielded, so
    no over-long line is ever handed to a parser regex (Requirements 2.4, 2.5,
    9.4). A line that exceeds the cap is truncated and its record carries
    ``truncated=True``; the pipeline skips and counts such a line.

    Args:
        path: The input file to read. Never written to (Requirement 1.12).
        max_line_bytes: The maximum number of bytes to retain per line.

    Yields:
        One :class:`LineRecord` per line, in ascending line-number order.

    Raises:
        IngestError: If the file is detected as gzip but cannot be decompressed
            (Requirement 2.8).
    """
    for line_number, raw_line in enumerate(_read_lines(path), start=1):
        # Strip only the trailing newline so a line's byte length reflects its
        # content, then enforce the cap before anything downstream sees it.
        stripped = raw_line.rstrip("\n")
        capped, truncated = cap_line(stripped, max_line_bytes)
        yield LineRecord(
            source=str(path),
            line_number=line_number,
            raw_line=capped,
            truncated=truncated,
        )


def _is_gzip(path: Path) -> bool:
    """Return whether ``path`` begins with the gzip magic bytes.

    The file is opened read-only and only its first two bytes are read, so the
    check is cheap and never mutates the input (Requirement 1.12). Detection is
    by content, not by the file's extension (Requirement 2.2).

    Args:
        path: The input file to inspect.

    Returns:
        ``True`` when the first two bytes are the gzip magic number.
    """
    with open(path, "rb") as handle:
        return handle.read(2) == _GZIP_MAGIC


def _read_lines(path: Path) -> Iterator[str]:
    """Yield decoded text lines from a plaintext or gzip input file.

    The file is sniffed for the gzip magic number and opened with the matching
    reader, in text mode with lenient UTF-8 decoding so an arbitrary byte in an
    untrusted log cannot abort the whole file. Both readers are opened read-only
    (Requirement 1.12).

    Args:
        path: The input file to read.

    Yields:
        Each line of the decoded content, including its trailing newline.

    Raises:
        IngestError: If ``path`` is a gzip stream that cannot be decompressed
            (Requirement 2.8).
    """
    if _is_gzip(path):
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                # Materialize lazily; a decompression fault surfaces mid-iteration
                # and is converted to IngestError below.
                for line in handle:
                    yield line
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            raise IngestError(f"failed to decompress gzip input: {path}") from exc
    else:
        with open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line


@dataclass
class SkipCounter:
    """Per-run tally of skipped lines, counted at most once each.

    The pipeline owns a single instance for the duration of a run and records
    every line it declines to analyze, so the final totals can be surfaced in
    the run output (Requirements 4.2, 4.3, 4.4). Each skipped line contributes
    to exactly one of the two counters and is counted only once, no matter how
    many parsers were offered the line before it was rejected (Requirement 4.2).

    Two disjoint reasons are tracked. A line whose original byte length exceeded
    the ``MAX_LINE_BYTES`` cap is counted under :attr:`truncated`; such a line is
    skipped before parsing and is never handed to a parser (Requirements 2.5,
    4.5, 9.4). A line that every applicable parser rejected -- each returning
    ``None`` -- is counted under :attr:`unparseable` (Requirements 4.1, 4.2).
    Neither reason is fatal to the run; the pipeline continues with the next line
    (Requirement 4.6).

    This dataclass is intentionally mutable (not ``frozen``) because its counters
    accumulate as the run progresses. Callers record skips through the
    :meth:`count_truncated` and :meth:`count_unparseable` helpers, which make the
    one-skip-one-increment contract explicit at the call site; the underlying
    integer fields may also be read directly when reporting results.

    Attributes:
        truncated: The number of lines skipped because they exceeded the byte
            cap and were truncated (Requirements 2.5, 4.5, 9.4).
        unparseable: The number of lines skipped because no applicable parser
            could parse them (Requirements 4.1, 4.2).
    """

    truncated: int = 0
    unparseable: int = 0

    @property
    def total(self) -> int:
        """Return the total number of skipped lines across both reasons.

        Because the two counters are disjoint and each skipped line increments
        exactly one of them, their sum is the per-run skipped-line total reported
        in the output (Requirements 4.2, 4.3).

        Returns:
            The sum of :attr:`truncated` and :attr:`unparseable`.
        """
        return self.truncated + self.unparseable

    def count_truncated(self) -> None:
        """Record one line skipped because it was truncated at the byte cap.

        Increments :attr:`truncated` by exactly one. The caller invokes this once
        per truncated line, before any parser is offered the line (Requirements
        2.5, 4.5, 9.4).
        """
        self.truncated += 1

    def count_unparseable(self) -> None:
        """Record one line skipped because no applicable parser accepted it.

        Increments :attr:`unparseable` by exactly one. The caller invokes this
        once per line, after every applicable parser has returned ``None``, so
        the line is counted a single time regardless of how many parsers were
        tried (Requirements 4.1, 4.2).
        """
        self.unparseable += 1
