"""End-to-end integration tests for the :mod:`loganalyze.cli` entry point.

These tests exercise :func:`loganalyze.cli.main` the way the console script
does: a list of command-line arguments goes in, a process exit code comes out,
and any human-facing text lands on standard output or standard error. We call
``main([...])`` directly and assert on its integer return value against the
public :data:`~loganalyze.cli.EXIT_CLEAN`, :data:`~loganalyze.cli.EXIT_FINDINGS`,
and :data:`~loganalyze.cli.EXIT_ERROR` constants, capturing streams with pytest's
``capsys`` fixture.

Covered requirements:

* 1.7  - an unrecognized ``--format`` is rejected before any input is read.
* 1.8  - a nonexistent input path is an error.
* 1.10 - a usage error (no input path) exits with the error code.
* 1.12 - input is read-only: analyzed files are never mutated.
* 1.13 - a clean run (no findings) exits 0.
* 1.14 - a run that produces findings exits 1.
* 2.7  - an out-of-range line cap is rejected before ingest.
* 4.3  - the per-run skipped-line count is reported.

Plus exit-code coverage for the z-threshold (6.3) and rare-cutoff (6.4)
validators and the JSON report writer (8.2), all of which route through the same
error/exit contract.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from loganalyze.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main

# Fixture tree root; mirrors the layout used by tests/conftest.py.
FIXTURES_DIR = Path(__file__).parent / "fixtures"

# A planted brute-force burst: one client IP exceeds the failed-auth threshold
# inside the window, so the run must produce at least one finding.
BRUTEFORCE_LOG = FIXTURES_DIR / "authlog" / "burst_bruteforce.log"

# A benign auth.log with only successful logins/sessions: no detection fires.
BENIGN_AUTHLOG = FIXTURES_DIR / "authlog" / "benign.log"

# The raw attacker IP planted in the brute-force fixture. It must never appear
# verbatim in a report; masking collapses it to its first two octets.
BRUTEFORCE_CLIENT_IP = "198.51.100.23"


# --- Exit code: findings produced -> EXIT_FINDINGS (Requirement 1.14) ------


def test_findings_run_returns_exit_findings_and_prints_table(capsys):
    """A run with detections returns EXIT_FINDINGS and prints a results table."""
    code = main([str(BRUTEFORCE_LOG)])

    assert code == EXIT_FINDINGS

    out = capsys.readouterr().out
    # The console renderer prints an aligned table whose header row names the
    # finding columns; its presence proves a table (not the empty-run line).
    assert "rule_id" in out
    assert "severity" in out
    assert "No findings." not in out


# --- Exit code: clean run -> EXIT_CLEAN (Requirement 1.13) -----------------


def test_clean_run_returns_exit_clean_and_prints_no_findings(capsys):
    """A benign input produces no findings: EXIT_CLEAN and the status line."""
    code = main([str(BENIGN_AUTHLOG)])

    assert code == EXIT_CLEAN

    out = capsys.readouterr().out
    assert "No findings." in out


# --- Exit code: error conditions -> EXIT_ERROR (Requirements 1.7-1.10, 2.7) -


def test_nonexistent_path_returns_exit_error(capsys):
    """A path that does not exist is a handled error (Requirement 1.8/1.10)."""
    code = main([str(FIXTURES_DIR / "does_not_exist.log")])

    assert code == EXIT_ERROR
    assert capsys.readouterr().err.strip() != ""


def test_unrecognized_format_returns_exit_error(capsys):
    """An unknown --format names no registered parser (Requirement 1.7)."""
    code = main([str(BENIGN_AUTHLOG), "--format", "bogus"])

    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "bogus" in err


def test_invalid_max_line_bytes_returns_exit_error(capsys):
    """A line cap below 1 is rejected before ingest (Requirement 2.7)."""
    code = main([str(BENIGN_AUTHLOG), "--max-line-bytes", "0"])

    assert code == EXIT_ERROR
    assert capsys.readouterr().err.strip() != ""


def test_invalid_z_threshold_returns_exit_error(capsys):
    """A z-threshold outside 1.0-10.0 is rejected (Requirement 6.3)."""
    code = main([str(BENIGN_AUTHLOG), "--z-threshold", "99"])

    assert code == EXIT_ERROR
    assert capsys.readouterr().err.strip() != ""


def test_invalid_rare_cutoff_returns_exit_error(capsys):
    """A rare-cutoff of 1.0 lies outside the open interval (Requirement 6.4)."""
    code = main([str(BENIGN_AUTHLOG), "--rare-cutoff", "1.0"])

    assert code == EXIT_ERROR
    assert capsys.readouterr().err.strip() != ""


def test_no_input_path_returns_exit_error(capsys):
    """Argparse rejects an empty input set with a usage error (Requirement 1.10).

    ``parse_args`` raises ``SystemExit(2)`` on a usage error, which matches the
    CLI's own error code; we assert both the raised status and the usage text.
    """
    with pytest.raises(SystemExit) as excinfo:
        main([])

    assert excinfo.value.code == EXIT_ERROR
    assert "usage" in capsys.readouterr().err.lower()


# --- Read-only input guarantee (Requirement 1.12) --------------------------


def test_input_file_is_not_modified(tmp_path, capsys):
    """The analyzer never mutates the logs it reads (Requirement 1.12)."""
    target = tmp_path / "brute.log"
    shutil.copy2(BRUTEFORCE_LOG, target)

    before_bytes = target.read_bytes()
    before_mtime = target.stat().st_mtime_ns

    code = main([str(target)])

    assert code == EXIT_FINDINGS  # the copied burst still produces findings
    # Content and modification time are untouched: the run only read the file.
    assert target.read_bytes() == before_bytes
    assert target.stat().st_mtime_ns == before_mtime


# --- Skipped-line count reported (Requirement 4.3) -------------------------


def test_skipped_line_count_reported_on_stderr(tmp_path, capsys):
    """Unparseable lines are counted and the total is reported (Requirement 4.3).

    We build an input mixing two well-formed nginx lines with three lines of
    garbage that no parser recognizes, force the nginx parser, and assert the
    stderr summary reports exactly three skipped lines.
    """
    valid = (
        '192.0.2.10 - - [10/Oct/2024:13:55:36 +0000] "GET /index.html '
        'HTTP/1.1" 200 1534 "https://example.com/" "Mozilla/5.0"'
    )
    garbage = ("this is not a log line at all", "@@@ garbage @@@", "neither-is-this")
    lines = (valid, *garbage, valid)
    log = tmp_path / "mixed.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    code = main([str(log), "--format", "nginx"])

    # Two parseable nginx lines with no signatures: a clean run.
    assert code == EXIT_CLEAN

    err = capsys.readouterr().err
    assert "Skipped" in err
    # Three of the five lines are unparseable garbage.
    assert "Skipped 3 lines" in err
    assert "unparseable=3" in err


def test_skip_summary_always_emitted_with_breakdown(capsys):
    """The skip summary is always emitted with its reason breakdown (Req 4.3/4.4).

    The count is reported on every run, including a clean one, and always names
    the truncated/unparseable breakdown so the operator sees how much input was
    skipped and why.
    """
    code = main([str(BENIGN_AUTHLOG)])

    assert code == EXIT_CLEAN
    err = capsys.readouterr().err
    assert "Skipped" in err
    assert "lines" in err
    assert "truncated=" in err
    assert "unparseable=" in err


# --- JSON report (Requirement 8.2) + masking (Requirement 8.10) ------------


def test_json_report_is_written_and_masks_client_ip(tmp_path, capsys):
    """--report writes valid JSON, exits 1 on findings, and masks the client IP.

    The brute-force fixture produces findings carrying the attacker's client IP
    in event/metadata fields. The JSON renderer masks every value at the output
    boundary, so the raw dotted-quad must not survive to disk (Requirement 8.10)
    while the first two octets remain for triage.
    """
    out_path = tmp_path / "out.json"

    code = main([str(BRUTEFORCE_LOG), "--report", str(out_path)])

    assert code == EXIT_FINDINGS
    assert out_path.is_file()

    raw_text = out_path.read_text(encoding="utf-8")
    # The file is valid JSON with the documented envelope.
    document = json.loads(raw_text)
    assert isinstance(document, dict)
    assert document["count"] >= 1
    assert isinstance(document["findings"], list)
    assert document["findings"]

    # No raw client IP reaches disk; the masked prefix does.
    assert BRUTEFORCE_CLIENT_IP not in raw_text
    assert "198.51." in raw_text
