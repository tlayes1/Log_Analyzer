"""Unit tests for the console and JSON output renderers.

These tests exercise the output security boundary (Requirements 8.1, 8.2, 8.4,
8.6, 8.10). Every Finding below deliberately embeds attacker-controlled hazards
-- a client IP, an email address, a credential-style token, and forbidden
control characters (ANSI escape ``\x1b``, BEL ``\x07``, NUL ``\x00``) inside
titles, details, and metadata, as well as inside each contributing Event's
``raw``/``message`` fields. The renderers must mask the sensitive values and
strip the control characters so neither reaches the terminal or disk.

All sample data is synthetic: IPs come from documentation ranges, emails are on
``example.com``, and the token is non-authenticating (Requirement 11).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from loganalyze.models import Event, Finding, Severity
from loganalyze.outputs.base import OutputTarget
from loganalyze.outputs.console import ConsoleOutput
from loganalyze.outputs.file_json import JsonOutput

# --- Synthetic sensitive values embedded throughout the fixtures -----------

RAW_IP = "203.0.113.42"  # TEST-NET-3 documentation range.
RAW_EMAIL = "user@example.com"
RAW_SECRET = "SECRETtoken0123456789abcdef"  # non-authenticating fake token.

# Forbidden control characters that must never survive to output.
CTRL_ANSI = "\x1b[31m"
CTRL_BEL = "\x07"
CTRL_NUL = "\x00"
CTRL_BLOB = CTRL_ANSI + CTRL_BEL + CTRL_NUL

# Characters that are forbidden on output: U+0000-U+0008, U+000B-U+001F, U+007F.
FORBIDDEN_CHARS = (
    [chr(c) for c in range(0x00, 0x09)]
    + [chr(c) for c in range(0x0B, 0x20)]
    + ["\x7f"]
)


def _make_event() -> Event:
    """Build an Event whose raw/message carry sensitive values + control chars.

    The ``raw`` and ``message`` fields are deliberately hostile so the tests can
    assert they never leak verbatim to disk (Requirement 8.10).
    """
    return Event(
        timestamp=datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        source="auth.log",
        log_type="authlog",
        message=f"login from {RAW_IP} for {RAW_EMAIL}{CTRL_BLOB}",
        raw=f"raw line token={RAW_SECRET} {RAW_IP} {RAW_EMAIL}{CTRL_BLOB}",
        fields={"token": RAW_SECRET, "note": f"from {RAW_IP}{CTRL_ANSI}"},
        client_ip=RAW_IP,
        user=RAW_EMAIL,
    )


def _make_findings() -> list[Finding]:
    """Build a small list of findings salted with sensitive + control content."""
    event = _make_event()
    return [
        Finding(
            rule_id="auth.bruteforce",
            title=f"Brute force from {RAW_IP}{CTRL_ANSI}",
            severity=Severity.CRITICAL,
            events=[event],
            detail=f"token={RAW_SECRET} user {RAW_EMAIL} src {RAW_IP}{CTRL_BEL}",
            metadata={
                "client_ip": RAW_IP,
                "email": RAW_EMAIL,
                "token": RAW_SECRET,
                f"ctrl{CTRL_NUL}key": f"value{CTRL_ANSI}",
            },
        ),
        Finding(
            rule_id="web.sqli",
            title="SQL injection probe",
            severity=Severity.HIGH,
            events=[event],
            detail=f"payload contains {RAW_EMAIL}",
            metadata={"src_ip": RAW_IP},
        ),
    ]


def _assert_no_forbidden_chars(text: str) -> None:
    """Fail if any forbidden control character appears in ``text``."""
    present = [repr(c) for c in FORBIDDEN_CHARS if c in text]
    assert not present, f"forbidden control chars leaked to output: {present}"


# --- Console output (Requirements 8.1, 8.4, 8.10) --------------------------


def test_console_renders_table_to_stdout(capsys):
    """ConsoleOutput writes a non-empty aligned table to stdout."""
    ConsoleOutput().render(_make_findings(), OutputTarget(path=None))
    out = capsys.readouterr().out
    assert out.strip(), "console produced no output"
    # Header row is always rendered for a non-empty finding list.
    assert "severity" in out and "rule_id" in out


def test_console_strips_all_control_characters(capsys):
    """No forbidden control character reaches the terminal (Requirement 8.4)."""
    ConsoleOutput().render(_make_findings(), OutputTarget(path=None))
    out = capsys.readouterr().out
    _assert_no_forbidden_chars(out)


def test_console_masks_sensitive_values(capsys):
    """Raw IP, email, and secret never appear verbatim; masked forms do.

    Requirements 8.7, 8.8, 8.9, 8.10.
    """
    ConsoleOutput().render(_make_findings(), OutputTarget(path=None))
    out = capsys.readouterr().out

    assert RAW_IP not in out, "raw client IP leaked to console"
    assert RAW_EMAIL not in out, "raw email leaked to console"
    assert RAW_SECRET not in out, "raw secret leaked to console"

    # Masked forms are present instead.
    assert "203.0.x.x" in out, "expected masked IP form missing"
    assert "u\u2026@example.com" in out, "expected masked email form missing"


def test_console_rejects_file_path():
    """A file path on the target raises ValueError (console is stdout-only)."""
    with pytest.raises(ValueError):
        ConsoleOutput().render(_make_findings(), OutputTarget(path=Path("out.txt")))


def test_console_empty_findings_is_safe(capsys):
    """An empty finding list renders a short, control-safe status line."""
    ConsoleOutput().render([], OutputTarget(path=None))
    out = capsys.readouterr().out
    assert out.strip() == "No findings."
    _assert_no_forbidden_chars(out)


# --- JSON output (Requirements 8.2, 8.4, 8.6, 8.10) ------------------------


def test_json_writes_valid_json_file(tmp_path):
    """The renderer writes a file that parses as JSON (Requirement 8.2)."""
    target = tmp_path / "out.json"
    JsonOutput().render(_make_findings(), OutputTarget(path=target))

    assert target.is_file(), "JSON report file was not created"
    with target.open(encoding="utf-8") as handle:
        document = json.load(handle)
    assert document["count"] == 2
    assert len(document["findings"]) == 2


def test_json_does_not_leak_raw_sensitive_values(tmp_path):
    """No raw IP/email/secret and no raw event text reaches disk.

    Requirements 8.8, 8.9, 8.10. The on-disk text is inspected directly so a
    leak anywhere in the document -- metadata, prose, or serialized event --
    is caught.
    """
    target = tmp_path / "out.json"
    JsonOutput().render(_make_findings(), OutputTarget(path=target))
    text = target.read_text(encoding="utf-8")

    assert RAW_IP not in text, "raw client IP leaked to disk"
    assert RAW_EMAIL not in text, "raw email leaked to disk"
    assert RAW_SECRET not in text, "raw secret leaked to disk"
    # The hostile raw/message event strings must not be serialized at all.
    assert "raw line token=" not in text, "raw event line leaked to disk"
    assert "login from" not in text, "raw event message leaked to disk"

    # Masked forms are present instead.
    assert "203.0.x.x" in text, "expected masked IP form missing from JSON"
    assert "u\u2026@example.com" in text, "expected masked email form missing"


def test_json_strips_control_characters(tmp_path):
    """No forbidden control character reaches disk (Requirement 8.4)."""
    target = tmp_path / "out.json"
    JsonOutput().render(_make_findings(), OutputTarget(path=target))
    text = target.read_text(encoding="utf-8")
    _assert_no_forbidden_chars(text)
    # Parsed values must also be clean, not merely the serialized form.
    document = json.loads(text)
    _assert_no_forbidden_chars(json.dumps(document))


def test_json_atomic_write_leaves_no_temp_file(tmp_path):
    """After an atomic write only the report remains -- no temp artifact.

    Requirement 8.6: the write goes through a temp file that is renamed into
    place, so the destination directory holds exactly the final report.
    """
    target = tmp_path / "out.json"
    JsonOutput().render(_make_findings(), OutputTarget(path=target))

    entries = list(tmp_path.iterdir())
    assert entries == [target], f"unexpected leftover files: {entries}"
    # Guard specifically against the temp-file naming scheme used by the writer.
    assert not list(tmp_path.glob(".out.json.*.tmp")), "temp file not cleaned up"


def test_json_rejects_missing_path():
    """A target without a path raises ValueError (a JSON report needs a file)."""
    with pytest.raises(ValueError):
        JsonOutput().render(_make_findings(), OutputTarget(path=None))
