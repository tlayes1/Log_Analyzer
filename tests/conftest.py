"""Shared pytest fixtures for the loganalyze test suite.

Fixtures and sample data are synthetic only: every IP address falls within a
documentation range, every email is on ``example.com``, and every credential is
non-authenticating (see testing-standards.md and Requirement 11).
"""
from __future__ import annotations

from pathlib import Path

import pytest

#: Absolute path to the ``tests/fixtures`` directory holding synthetic log data.
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _read_lines(path: Path) -> list[str]:
    """Return the non-empty, newline-stripped lines of a fixture file.

    Fixture files are plain UTF-8 log files. Trailing newlines and any blank
    trailing line are discarded so callers receive exactly the log records.
    """
    text = path.read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line]


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Session-scoped path to the synthetic-fixture root (``tests/fixtures``)."""
    return FIXTURES_DIR


@pytest.fixture
def fixture_path(fixtures_dir: Path):
    """Return a loader mapping ``(fmt, name)`` to a fixture file path.

    Example:
        ``fixture_path("nginx", "benign.log")`` ->
        ``tests/fixtures/nginx/benign.log``.
    """

    def _path(fmt: str, name: str) -> Path:
        path = fixtures_dir / fmt / name
        if not path.is_file():
            raise FileNotFoundError(f"fixture not found: {fmt}/{name}")
        return path

    return _path


@pytest.fixture
def fixture_lines(fixture_path):
    """Return a loader mapping ``(fmt, name)`` to the file's log lines."""

    def _lines(fmt: str, name: str) -> list[str]:
        return _read_lines(fixture_path(fmt, name))

    return _lines


# --- Per-format benign (false-positive guardrail) fixtures -----------------


@pytest.fixture
def nginx_benign_lines(fixture_lines) -> list[str]:
    """Benign nginx access-log lines that match no signature (guardrail)."""
    return fixture_lines("nginx", "benign.log")


@pytest.fixture
def apache_benign_lines(fixture_lines) -> list[str]:
    """Benign Apache access-log lines that match no signature (guardrail)."""
    return fixture_lines("apache", "benign.log")


@pytest.fixture
def syslog_benign_lines(fixture_lines) -> list[str]:
    """Benign syslog lines representing ordinary system activity (guardrail)."""
    return fixture_lines("syslog", "benign.log")


@pytest.fixture
def authlog_benign_lines(fixture_lines) -> list[str]:
    """Benign auth.log lines (successful logins/sessions) for the guardrail."""
    return fixture_lines("authlog", "benign.log")


# --- Per-format signature / recognition fixtures ---------------------------


@pytest.fixture
def nginx_signature_lines(fixture_lines) -> list[str]:
    """nginx recognition lines: SQLi/XSS probe paths and scanner user-agents."""
    return fixture_lines("nginx", "signatures.log")


@pytest.fixture
def apache_signature_lines(fixture_lines) -> list[str]:
    """Apache recognition lines: SQLi/XSS probe paths and scanner user-agents."""
    return fixture_lines("apache", "signatures.log")


@pytest.fixture
def authlog_signature_lines(fixture_lines) -> list[str]:
    """auth.log recognition lines: failed logins and sudo/su privilege escalation."""
    return fixture_lines("authlog", "signatures.log")
