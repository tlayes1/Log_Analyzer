"""End-to-end integration tests for :mod:`loganalyze.pipeline`.

These tests drive the real pipeline over the synthetic fixtures under
``tests/fixtures/`` by constructing genuine :class:`~loganalyze.config.RunConfig`
objects. They exercise the behaviors the pipeline is responsible for wiring
together: per-file auto-detection and explicit format override (Requirements
1.5, 1.6), surfacing of skip counts for truncated and unparseable lines
(Requirement 4.3), the mixed-timezone warning across log families
(Requirement 3.9), the discovery error path for a missing input, and the
provenance stamped onto each finding's events.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from loganalyze.config import DetectionConfig, IngestConfig, RunConfig
from loganalyze.models import Finding
from loganalyze.pipeline import run

FIXTURES_DIR = Path(__file__).parent / "fixtures"

NGINX_SIGNATURES = FIXTURES_DIR / "nginx" / "signatures.log"
NGINX_BENIGN = FIXTURES_DIR / "nginx" / "benign.log"
AUTHLOG_BURST = FIXTURES_DIR / "authlog" / "burst_bruteforce.log"


def _make_config(
    input_paths: list[Path],
    *,
    format_override: str | None = None,
    max_line_bytes: int = 65536,
) -> RunConfig:
    """Build a RunConfig for a batch run with no report outputs requested."""
    return RunConfig(
        input_paths=input_paths,
        format_override=format_override,
        report_json_path=None,
        report_csv_path=None,
        ingest=IngestConfig(max_line_bytes=max_line_bytes),
        detection=DetectionConfig(),
    )


def _rule_ids(findings: list[Finding]) -> set[str]:
    """Return the distinct rule ids present across findings."""
    return {finding.rule_id for finding in findings}


# --- Auto-detection (Requirement 1.5) --------------------------------------


def test_autodetect_nginx_signatures_produces_web_findings() -> None:
    """A run with no override over the nginx signatures fixture auto-detects
    nginx and yields web.* findings."""
    result = run(_make_config([NGINX_SIGNATURES]))

    rule_ids = _rule_ids(result.findings)
    assert result.findings, "expected findings from the nginx signatures fixture"
    assert any(rule_id.startswith("web.") for rule_id in rule_ids), rule_ids
    # The fixture carries SQLi/XSS probe paths and scanner user agents.
    assert "web.sqli.probe" in rule_ids
    assert "web.xss.probe" in rule_ids
    assert "web.scanner.ua" in rule_ids


def test_autodetect_authlog_burst_produces_auth_findings() -> None:
    """A run with no override over the authlog brute-force fixture auto-detects
    authlog and yields both the brute-force and failed-login findings."""
    result = run(_make_config([AUTHLOG_BURST]))

    rule_ids = _rule_ids(result.findings)
    assert "auth.bruteforce" in rule_ids
    assert "auth.failed_login" in rule_ids


# --- Format override (Requirement 1.6) -------------------------------------


def test_format_override_nginx_matches_autodetect() -> None:
    """Forcing format_override='nginx' over the nginx fixture yields the same
    findings as auto-detection."""
    auto = run(_make_config([NGINX_SIGNATURES]))
    forced = run(_make_config([NGINX_SIGNATURES], format_override="nginx"))

    assert _rule_ids(forced.findings) == _rule_ids(auto.findings)
    assert len(forced.findings) == len(auto.findings)


def test_format_override_authlog_produces_auth_findings() -> None:
    """Forcing format_override='authlog' over the authlog fixture works."""
    result = run(_make_config([AUTHLOG_BURST], format_override="authlog"))

    rule_ids = _rule_ids(result.findings)
    assert "auth.bruteforce" in rule_ids
    assert "auth.failed_login" in rule_ids


# --- Skip counting surfaced in the result (Requirement 4.3) ----------------


def test_unparseable_lines_counted_in_result(tmp_path: Path) -> None:
    """A file mixing valid nginx lines with garbage, parsed as nginx, reports
    the garbage lines as unparseable skips and totals them."""
    valid = NGINX_BENIGN.read_text(encoding="utf-8").splitlines()
    valid_lines = [line for line in valid if line]
    garbage = ["this is not a log line", "@@@ broken @@@", "???"]

    mixed = tmp_path / "mixed.log"
    mixed.write_text("\n".join(valid_lines + garbage) + "\n", encoding="utf-8")

    result = run(_make_config([mixed], format_override="nginx"))

    assert result.skips.unparseable == len(garbage)
    assert result.skips.truncated == 0
    assert result.skips.total == result.skips.unparseable + result.skips.truncated


def test_truncated_lines_counted_in_result(tmp_path: Path) -> None:
    """Shrinking max_line_bytes so an over-long line is truncated reports the
    truncated line as a truncated skip."""
    valid = NGINX_BENIGN.read_text(encoding="utf-8").splitlines()
    valid_lines = [line for line in valid if line]
    # Any real nginx line here is well over 80 bytes, so the cap truncates it.
    cap = 80
    assert any(len(line) > cap for line in valid_lines)

    over_long = tmp_path / "overlong.log"
    over_long.write_text("\n".join(valid_lines) + "\n", encoding="utf-8")

    result = run(_make_config([over_long], format_override="nginx", max_line_bytes=cap))

    assert result.skips.truncated > 0
    assert result.skips.total >= result.skips.truncated


# --- Mixed-timezone warning (Requirement 3.9) ------------------------------


def test_mixed_timezones_true_across_families(caplog: pytest.LogCaptureFixture) -> None:
    """A run spanning naive authlog timestamps and aware nginx timestamps sets
    mixed_timezones and emits a warning."""
    with caplog.at_level(logging.WARNING, logger="loganalyze.pipeline"):
        result = run(_make_config([AUTHLOG_BURST, NGINX_SIGNATURES]))

    assert result.mixed_timezones is True
    warnings = [
        rec
        for rec in caplog.records
        if rec.levelno == logging.WARNING and "timezone" in rec.getMessage().lower()
    ]
    assert warnings, "expected a mixed-timezone warning to be emitted"


def test_mixed_timezones_false_single_family(caplog: pytest.LogCaptureFixture) -> None:
    """A single-family nginx-only run does not flag mixed timezones."""
    with caplog.at_level(logging.WARNING, logger="loganalyze.pipeline"):
        result = run(_make_config([NGINX_SIGNATURES]))

    assert result.mixed_timezones is False


# --- Discovery error path --------------------------------------------------


def test_nonexistent_input_raises_file_not_found(tmp_path: Path) -> None:
    """A nonexistent input path makes pipeline.run raise FileNotFoundError,
    confirming the CLI's error path."""
    missing = tmp_path / "does-not-exist.log"
    with pytest.raises(FileNotFoundError):
        run(_make_config([missing]))


# --- Provenance ------------------------------------------------------------


def test_findings_carry_source_and_line_number_provenance() -> None:
    """Every finding's events carry a non-empty source (the file path) and a
    fields['line_number'] stamped by the pipeline."""
    result = run(_make_config([NGINX_SIGNATURES]))

    assert result.findings
    expected_source = str(NGINX_SIGNATURES)
    for finding in result.findings:
        assert finding.events, f"{finding.rule_id} had no contributing events"
        for event in finding.events:
            assert event.source == expected_source
            assert event.fields.get("line_number")
            assert int(event.fields["line_number"]) >= 1
