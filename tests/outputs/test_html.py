"""Unit tests for the self-contained HTML report renderer.

These tests exercise the HTML output security boundary and its structure:

* The pure view-model (:func:`build_report_model`) computes correct severity
  counts and a breakdown sorted by severity band (high->low), then count
  descending, then friendly-label name.
* The rendered document is self-contained (inline CSS + a single inline script,
  no external asset references) and contains the summary, the "What was found"
  dropdown, the type chips, and the typeahead ``<datalist>``.
* No raw log-derived content ever becomes executable: hostile payloads embedded
  in a finding's title, detail, and metadata render inert (HTML-escaped), never
  as live ``<script>`` or an event-handler attribute, in both card text and
  ``data-*`` attributes.
* The inline script is the fixed static asset with no interpolated/log-derived
  content.

All sample data is synthetic: IPs come from documentation ranges and the tokens
are non-authenticating (Requirement 11).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from loganalyze.models import Event, Finding, Severity
from loganalyze.outputs.base import OutputTarget
from loganalyze.outputs.file_html import (
    FRIENDLY_LABELS,
    HtmlOutput,
    build_report_model,
    render_report,
)

# --- Synthetic hostile payloads --------------------------------------------

# A TEST-NET-3 documentation IP planted in a finding; masking must collapse it.
RAW_IP = "203.0.113.42"
# Script-injection payloads that must render inert everywhere they appear.
PAYLOAD_SCRIPT = "<script>alert(1)</script>"
PAYLOAD_HANDLER = '" onmouseover=alert(1) "'
PAYLOAD_JS_URL = "javascript:alert(1)"
PAYLOAD_TITLE_BREAK = "</title><script>alert(1)</script>"


def _brute_force_findings() -> list[Finding]:
    """Return findings mirroring the real brute-force run (2 high, 6 medium).

    One brute-force (HIGH), one privilege escalation (HIGH), five failed-login
    (MEDIUM), and one rate-spike (MEDIUM): eight findings total, matching the
    locked counts used throughout the design discussion.
    """
    out: list[Finding] = [
        Finding(
            "auth.bruteforce",
            "Brute-force authentication burst",
            Severity.HIGH,
            [],
            "9 failed authentication attempts from 198.51.100.23 within 60s",
            {"client_ip": "198.51.100.23", "count": "9", "threshold": "5"},
        ),
        Finding(
            "auth.privesc",
            "Privilege escalation",
            Severity.HIGH,
            [],
            "backup escalated privileges to root via sudo.",
            {"user": "backup", "mechanism": "sudo", "target_user": "root"},
        ),
    ]
    for user in ("root", "admin", "postgres", "root", "admin"):
        out.append(
            Finding(
                "auth.failed_login",
                "Failed authentication attempt",
                Severity.MEDIUM,
                [],
                f"auth.log reported a failed login for {user}.",
                {"user": user, "client_ip": "198.51.100.23"},
            )
        )
    out.append(
        Finding(
            "stat.rate_spike",
            "Request-rate spike",
            Severity.MEDIUM,
            [],
            "Bucket 0 recorded 9 events versus a baseline of 1.06",
            {"observed": "9", "baseline": "1.06", "score": "3.49"},
        )
    )
    return out


def _hostile_findings() -> list[Finding]:
    """Return a finding whose fields are packed with injection payloads."""
    event = Event(
        timestamp=datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        source="auth.log",
        log_type="authlog",
        message=f"login {PAYLOAD_SCRIPT}",
        raw=f"raw {PAYLOAD_SCRIPT} {RAW_IP}",
    )
    return [
        Finding(
            rule_id="auth.failed_login",
            title=f"Failed auth {PAYLOAD_SCRIPT}{PAYLOAD_TITLE_BREAK}",
            severity=Severity.MEDIUM,
            events=[event],
            detail=f"login for {PAYLOAD_SCRIPT} via {PAYLOAD_JS_URL}",
            metadata={
                "user": PAYLOAD_SCRIPT,
                "note": PAYLOAD_HANDLER,
                "url": PAYLOAD_JS_URL,
            },
        )
    ]


# --- View-model: counts and breakdown ordering -----------------------------


def test_model_counts_match_locked_brute_force_totals():
    """The brute-force finding set yields 2 high, 6 medium, 0 low, 8 total."""
    model = build_report_model(_brute_force_findings())
    assert model.counts == {"high": 2, "med": 6, "low": 0}
    assert model.total == 8


def test_model_breakdown_sorted_by_severity_then_count_then_name():
    """Breakdown is severity-first, then count desc, then friendly-label name."""
    model = build_report_model(_brute_force_findings())
    rows = [(r.label, r.count, r.band) for r in model.breakdown]
    # High band first (both high types, count 1 each -> tie broken by name:
    # "Brute force" < "Privilege escalation"), then medium band (Failed auth 5
    # before Rate spike 1 by count).
    assert rows == [
        ("Brute force", 1, "high"),
        ("Privilege escalation", 1, "high"),
        ("Failed auth", 5, "med"),
        ("Rate spike", 1, "med"),
    ]


def test_breakdown_uses_only_friendly_labels():
    """Every breakdown label comes from the fixed friendly-label map."""
    model = build_report_model(_brute_force_findings())
    for row in model.breakdown:
        assert row.label == FRIENDLY_LABELS[row.rule_id]


# --- Document structure -----------------------------------------------------


def _render(findings: list[Finding]) -> str:
    return render_report(
        findings,
        source="authlog_brute_force.log",
        skipped="Skipped 10 lines (truncated=0, unparseable=10).",
        generated="2026-11-10 14:02 UTC",
    )


def test_document_is_self_contained():
    """No external asset references: no http(s) src/href, no link/img tags."""
    html = _render(_brute_force_findings())
    assert "<!DOCTYPE html>" in html
    assert "<style>" in html and "<script>" in html
    assert "src=" not in html
    assert 'href="http' not in html
    assert "http://" not in html and "https://" not in html


def test_document_has_summary_dropdown_controls_and_cards():
    """Summary cards, the dropdown, chips, datalist, and cards are all present."""
    html = _render(_brute_force_findings())
    assert "Total findings" in html
    assert "What was found (8)" in html
    assert 'id="type-suggestions"' in html
    assert 'data-type="auth.bruteforce"' in html
    # Every finding is listed individually: 5 failed-login cards must appear.
    # (A sixth data-type="auth.failed_login" belongs to the filter chip, not a
    # card, so count only the card occurrences.)
    assert html.count('<div class="card med" data-type="auth.failed_login"') == 5


def test_header_shows_source_and_skipped_summary():
    """The header carries the source name and the skipped-line summary."""
    html = _render(_brute_force_findings())
    assert "authlog_brute_force.log" in html
    assert "Skipped 10 lines (truncated=0, unparseable=10)." in html


def test_datalist_options_are_only_present_friendly_labels():
    """Typeahead options are exactly the friendly labels of present types."""
    html = _render(_brute_force_findings())
    options = re.findall(r'<option value="([^"]*)"></option>', html)
    assert set(options) == {
        "Brute force",
        "Privilege escalation",
        "Failed auth",
        "Rate spike",
    }


# --- Security: no executable log-derived content ----------------------------


def test_hostile_payloads_render_inert():
    """Script/handler/js-url payloads are escaped; none remain executable."""
    html = _render(_hostile_findings())

    # The only <script> in the document is the fixed inline behavior script.
    assert html.count("<script>") == 1
    # The injected payload never appears as a live script tag.
    assert PAYLOAD_SCRIPT not in html
    # It appears only in escaped form.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    # The handler payload's raw double-quote is escaped everywhere, so it can
    # never close an attribute and open a live event handler. The inert escaped
    # text "&quot; onmouseover=alert(1) &quot;" is harmless.
    assert PAYLOAD_HANDLER not in html
    assert "&quot; onmouseover=alert(1) &quot;" in html
    # A javascript: URL is never placed in an href/src; it only appears as text.
    assert 'href="javascript:' not in html
    assert 'src="javascript:' not in html


def test_hostile_payloads_escaped_inside_data_attributes():
    """data-text attribute values are escaped so they cannot break the quote."""
    html = _render(_hostile_findings())
    # The regex stops at the first literal double-quote, so if any raw quote had
    # survived inside a value it would truncate the capture. Capturing the full
    # intended content proves no raw quote broke out of the attribute.
    data_texts = re.findall(r'data-text="([^"]*)"', html)
    assert data_texts, "expected at least one data-text attribute"
    for value in data_texts:
        # No live markup and no raw quote survived inside the attribute value.
        assert "<script>" not in value
        assert '"' not in value
        # The handler payload only appears with its quotes escaped (inert).
        assert PAYLOAD_HANDLER not in value


def test_inline_script_has_no_interpolated_content():
    """The inline script is static: no log-derived or finding text leaks in."""
    html = _render(_hostile_findings())
    script = html.split("<script>", 1)[1].rsplit("</script>", 1)[0]
    # Static markers that must be present verbatim.
    assert "function apply()" in script
    assert "classList.toggle" in script
    # innerHTML is never used (prevents re-interpretation as markup).
    assert "innerHTML" not in script
    # No finding/log payload text is concatenated into the script.
    assert "alert(1)" not in script
    assert "198.51" not in script


# --- Renderer: file writing + protocol --------------------------------------


def test_render_writes_self_contained_file(tmp_path: Path):
    """HtmlOutput.render writes a readable HTML file to the target path."""
    out = tmp_path / "report.html"
    HtmlOutput().render(
        _brute_force_findings(),
        OutputTarget(
            path=out,
            source="authlog_brute_force.log",
            skipped="Skipped 10 lines (truncated=0, unparseable=10).",
        ),
    )
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "What was found (8)" in text
    assert "authlog_brute_force.log" in text


def test_render_requires_a_path():
    """Rendering to a None path is a ValueError (an HTML report needs a file)."""
    with pytest.raises(ValueError):
        HtmlOutput().render(_brute_force_findings(), OutputTarget(path=None))


def test_render_empty_findings_states_clean_run(tmp_path: Path):
    """With no findings the report says so and still renders a valid document."""
    out = tmp_path / "empty.html"
    HtmlOutput().render([], OutputTarget(path=out))
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "No findings" in text
    assert "Total findings" in text
