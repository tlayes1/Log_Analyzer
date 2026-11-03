"""Unit tests for ingest edge cases.

Covers input discovery (file, recursive directory, nonexistent path),
magic-byte gzip detection (independent of file extension), bad-gzip handling,
and the per-run SkipCounter tally.

Fixtures are synthetic and built at runtime with ``tmp_path``; no real PII,
secrets, or committed sample data are involved (Requirement 11).

Requirements: 1.2, 1.3, 2.2, 2.3, 2.8, 4.2.
"""
from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from loganalyze.ingest import IngestError, SkipCounter, discover_inputs, iter_lines
from loganalyze.security import MAX_LINE_BYTES_DEFAULT

# --- discover_inputs -------------------------------------------------------


def test_discover_single_file_yields_that_file(tmp_path: Path) -> None:
    """A single file path yields exactly that file (Requirement 1.2)."""
    f = tmp_path / "access.log"
    f.write_text("hello\n", encoding="utf-8")

    assert discover_inputs([f]) == [f]


def test_discover_directory_walks_recursively_sorted(tmp_path: Path) -> None:
    """A directory is walked recursively, yielding regular files in sorted
    order (Requirement 1.3)."""
    # Build a nested tree with files at multiple depths.
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "deep").mkdir()
    (tmp_path / "b").mkdir()

    top = tmp_path / "top.log"
    a1 = tmp_path / "a" / "a1.log"
    deep = tmp_path / "a" / "deep" / "deep.log"
    b1 = tmp_path / "b" / "b1.log"
    for p in (top, a1, deep, b1):
        p.write_text("x\n", encoding="utf-8")

    result = discover_inputs([tmp_path])

    # Only regular files, every one of them, and nothing else.
    assert set(result) == {top, a1, deep, b1}
    # Directories themselves are never yielded.
    assert all(p.is_file() for p in result)
    # Ordering is deterministic: sorted.
    assert result == sorted(result)


def test_discover_nonexistent_path_raises(tmp_path: Path) -> None:
    """A path that does not exist aborts discovery with FileNotFoundError
    (Requirement 1.2/1.3 input resolution)."""
    missing = tmp_path / "nope.log"

    with pytest.raises(FileNotFoundError):
        discover_inputs([missing])


def test_discover_mixes_file_and_directory_in_path_order(tmp_path: Path) -> None:
    """Multiple paths are expanded independently and concatenated in the order
    given, so a run can mix a file and a directory."""
    standalone = tmp_path / "standalone.log"
    standalone.write_text("x\n", encoding="utf-8")

    d = tmp_path / "dir"
    d.mkdir()
    inner = d / "inner.log"
    inner.write_text("x\n", encoding="utf-8")

    result = discover_inputs([standalone, d])

    assert result[0] == standalone
    assert result[1:] == [inner]


# --- iter_lines: gzip detection by magic bytes, not extension --------------


def _lines(path: Path) -> list[str]:
    return [rec.raw_line for rec in iter_lines(path, MAX_LINE_BYTES_DEFAULT)]


def test_gzip_detected_by_magic_bytes_despite_log_extension(tmp_path: Path) -> None:
    """A gzip-compressed file named ``.log`` is still decompressed because
    detection is by magic bytes, not extension (Requirement 2.2)."""
    content = "line one\nline two\nline three\n"
    mislabeled = tmp_path / "compressed.log"  # plain extension on gzip bytes
    with gzip.open(mislabeled, "wt", encoding="utf-8") as handle:
        handle.write(content)

    assert _lines(mislabeled) == ["line one", "line two", "line three"]


def test_plaintext_named_gz_is_read_as_plaintext(tmp_path: Path) -> None:
    """A plaintext file named ``.gz`` is read as plaintext, not decompressed,
    because detection is by magic bytes, not extension (Requirement 2.3)."""
    mislabeled = tmp_path / "plaintext.gz"  # gz extension on plain text
    mislabeled.write_text("alpha\nbeta\n", encoding="utf-8")

    assert _lines(mislabeled) == ["alpha", "beta"]


# --- iter_lines: bad gzip --------------------------------------------------


def test_bad_gzip_raises_ingest_error(tmp_path: Path) -> None:
    """A file beginning with the gzip magic bytes but with a corrupt body
    raises IngestError when iterated (Requirement 2.8)."""
    bad = tmp_path / "corrupt.log"
    # Gzip magic (0x1f 0x8b) followed by garbage that is not a valid stream.
    bad.write_bytes(b"\x1f\x8b" + b"not a real gzip body" * 8)

    with pytest.raises(IngestError):
        # Must consume the generator for decompression to actually run.
        list(iter_lines(bad, MAX_LINE_BYTES_DEFAULT))


# --- SkipCounter -----------------------------------------------------------


def test_skipcounter_starts_at_zero() -> None:
    """A fresh counter reports zero for both reasons and the total
    (Requirement 4.2)."""
    counter = SkipCounter()

    assert counter.truncated == 0
    assert counter.unparseable == 0
    assert counter.total == 0


def test_skipcounter_increments_independently() -> None:
    """Each helper increments only its own disjoint counter by exactly one
    (Requirement 4.2)."""
    counter = SkipCounter()

    counter.count_truncated()
    counter.count_truncated()
    counter.count_unparseable()

    assert counter.truncated == 2
    assert counter.unparseable == 1


def test_skipcounter_total_is_sum_of_reasons() -> None:
    """The total always equals truncated + unparseable (Requirement 4.2)."""
    counter = SkipCounter()

    for _ in range(3):
        counter.count_truncated()
    for _ in range(5):
        counter.count_unparseable()

    assert counter.truncated == 3
    assert counter.unparseable == 5
    assert counter.total == counter.truncated + counter.unparseable == 8
