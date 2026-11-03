"""Unit tests for output-path resolution and atomic writes.

Covers the security-critical I/O helpers in :mod:`loganalyze.security`:

* :func:`resolve_output_path` canonicalizes a destination to an absolute real
  path and refuses any path derived from log content (Requirements 8.11, 8.12).
* :func:`atomic_write` writes content via a temp file + atomic replace, and on
  a failed replace leaves any pre-existing destination intact while removing the
  temp file before the error propagates (Requirement 8.13).

All paths live under pytest's ``tmp_path`` and failure is simulated with
``monkeypatch``; no real filesystem outside the temp dir is touched.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from loganalyze import security


# --- resolve_output_path ---------------------------------------------------


def test_resolve_output_path_returns_canonical_absolute(tmp_path: Path) -> None:
    """A normal path resolves to an absolute canonical form (Req 8.11)."""
    target = tmp_path / "sub" / ".." / "report.json"

    resolved = security.resolve_output_path(target, log_derived=False)

    assert resolved.is_absolute()
    # ``..`` segments are collapsed: canonical form has no parent-dir hops.
    assert ".." not in resolved.parts
    assert resolved == target.resolve(strict=False)
    assert resolved == (tmp_path / "report.json").resolve(strict=False)


def test_resolve_output_path_relative_becomes_absolute(tmp_path: Path) -> None:
    """A relative path is anchored to an absolute path (Req 8.11)."""
    resolved = security.resolve_output_path(Path("findings.json"), log_derived=False)

    assert resolved.is_absolute()
    assert resolved.name == "findings.json"


def test_resolve_output_path_refuses_log_derived(tmp_path: Path) -> None:
    """A log-derived path is refused outright (Req 8.12)."""
    attacker_path = tmp_path / "evil.json"

    with pytest.raises(ValueError):
        security.resolve_output_path(attacker_path, log_derived=True)


# --- atomic_write: happy path ----------------------------------------------


def test_atomic_write_creates_file_with_content(tmp_path: Path) -> None:
    """Writing to a fresh destination creates it with the exact content."""
    dest = tmp_path / "report.json"

    security.atomic_write(dest, "hello world")

    assert dest.is_file()
    assert dest.read_text(encoding="utf-8") == "hello world"


def test_atomic_write_overwrites_existing_file(tmp_path: Path) -> None:
    """A successful write replaces prior destination content atomically."""
    dest = tmp_path / "report.json"
    dest.write_text("old content", encoding="utf-8")

    security.atomic_write(dest, "new content")

    assert dest.read_text(encoding="utf-8") == "new content"


def test_atomic_write_leaves_no_temp_file_on_success(tmp_path: Path) -> None:
    """After a successful write only the destination remains in the dir."""
    dest = tmp_path / "report.json"

    security.atomic_write(dest, "payload")

    entries = list(tmp_path.iterdir())
    assert entries == [dest]


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="POSIX file-mode bits are not enforced on Windows",
)
def test_atomic_write_sets_owner_only_permissions(tmp_path: Path) -> None:
    """The written file is owner read/write only (0o600) on POSIX (Req 8.11)."""
    dest = tmp_path / "report.json"

    security.atomic_write(dest, "secret")

    mode = stat.S_IMODE(dest.stat().st_mode)
    assert mode == 0o600


# --- atomic_write: failure path (Req 8.13) ---------------------------------


def test_atomic_write_failure_preserves_destination_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed replace leaves the old file intact, removes temp, and raises.

    Simulates the atomic-replace step failing: the pre-existing destination must
    keep its original content, no leftover temp file may remain in the
    directory, and the error must propagate (Requirement 8.13).
    """
    dest = tmp_path / "report.json"
    dest.write_text("original", encoding="utf-8")

    def boom(src: object, dst: object) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(security.os, "replace", boom)

    with pytest.raises(OSError, match="simulated replace failure"):
        security.atomic_write(dest, "replacement that should never land")

    # Prior destination is untouched.
    assert dest.read_text(encoding="utf-8") == "original"

    # No leftover temp file: the destination is the only entry in the dir.
    entries = list(tmp_path.iterdir())
    assert entries == [dest]


def test_atomic_write_failure_without_existing_destination_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed replace with no prior destination leaves no files behind."""

    dest = tmp_path / "report.json"
    assert not dest.exists()

    def boom(src: object, dst: object) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(security.os, "replace", boom)

    with pytest.raises(OSError, match="simulated replace failure"):
        security.atomic_write(dest, "content")

    # Destination was never created and the temp file was cleaned up.
    assert not dest.exists()
    assert list(tmp_path.iterdir()) == []
