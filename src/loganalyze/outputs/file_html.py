"""Self-contained HTML report renderer (``@register_output("html")``).

Serializes aggregated :class:`~loganalyze.models.Finding` results to a single
self-contained HTML document (inline CSS and a small, fixed inline script, with
no external assets and no network calls) and writes it to the resolved
destination with :func:`loganalyze.security.atomic_write`, so an interrupted run
leaves either the prior report or the fully written one, never a partial file
(Requirements 8.6, 8.13). The destination is resolved to its canonical absolute
form and created with the most restrictive permissions the platform supports
(Requirement 8.11).

Security boundary — no log-derived content ever becomes executable
------------------------------------------------------------------
The report embeds attacker-controlled strings (request paths, user agents,
usernames). The following rules are binding and enforced by this module:

1. Every log-derived value passes through the shared masking boundary
   (:func:`loganalyze.security.mask_prose` / ``mask_field_value``) then
   :func:`loganalyze.security.strip_control` and finally
   :func:`html.escape` with ``quote=True``, before it is placed anywhere in the
   document (Requirements 8.4, 8.7, 8.8, 8.9, 8.10). See :func:`_sanitize` and
   :func:`_sanitize_keyed`.
2. Log-derived values appear only in text positions or inside quoted, escaped
   ``data-*`` attributes. They never appear in a ``<script>`` block, an inline
   event handler, a ``style`` attribute, or an ``href``/``src`` URL.
3. The inline :data:`_SCRIPT` is a fixed, static string with zero interpolated
   values. It reads only ``data-*`` attributes and uses ``textContent`` /
   ``classList`` — never ``innerHTML`` — so nothing it touches is reinterpreted
   as markup. No log text is ever concatenated into it.
4. The ``<datalist>`` typeahead suggestions and the "What was found" breakdown
   use only the fixed :data:`FRIENDLY_LABELS` map and integer counts — never raw
   rule text or log content.

Raw event text (the unmasked ``raw`` and ``message`` fields) is deliberately
never emitted. The renderer is resolved by its registry key only, so the
pipeline never names this class (Requirement 8.14).
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from loganalyze.models import Finding, Severity
from loganalyze.outputs.base import OutputTarget
from loganalyze.registry import register_output
from loganalyze.security import (
    atomic_write,
    mask_field_value,
    mask_prose,
    resolve_output_path,
    strip_control,
)

__all__ = ["FRIENDLY_LABELS", "HtmlOutput", "build_report_model"]

#: Fixed map from a detector ``rule_id`` to a human-friendly label. This is the
#: *only* source of the type-chip labels, the typeahead ``<datalist>`` options,
#: and the "What was found" breakdown rows, so none of those surfaces can ever
#: carry raw rule text or log-derived content (security rule 4).
FRIENDLY_LABELS: dict[str, str] = {
    "auth.bruteforce": "Brute force",
    "auth.privesc": "Privilege escalation",
    "auth.failed_login": "Failed auth",
    "web.sqli.probe": "SQL injection probe",
    "web.xss.probe": "XSS probe",
    "web.scanner.ua": "Scanner user-agent",
    "web.status_spike": "HTTP error spike",
    "stat.rate_spike": "Rate spike",
    "stat.rare_event": "Rare event",
}

#: The severity groups rendered, highest first. ``Severity`` also includes INFO
#: and CRITICAL; CRITICAL is folded into the "High" band for display and INFO
#: into the "Low" band so the report always has three named severity sections.
_SEVERITY_BANDS: tuple[tuple[str, str, str], ...] = (
    ("high", "High severity", "var(--high)"),
    ("med", "Medium severity", "var(--med)"),
    ("low", "Low severity", "var(--low)"),
)


def _band_of(severity: Severity) -> str:
    """Map a :class:`Severity` to one of the three display bands.

    CRITICAL and HIGH both render in the ``high`` band; MEDIUM in ``med``; LOW
    and INFO in ``low``. Collapsing the five severities into three named bands
    keeps the report's layout and the summary cards stable regardless of which
    detectors fired.

    Args:
        severity: The finding severity.

    Returns:
        The band key ``"high"``, ``"med"``, or ``"low"``.
    """
    if severity >= Severity.HIGH:
        return "high"
    if severity == Severity.MEDIUM:
        return "med"
    return "low"


def _friendly(rule_id: str) -> str:
    """Return the friendly label for a ``rule_id`` from the fixed map.

    Falls back to the raw ``rule_id`` only when it is not in
    :data:`FRIENDLY_LABELS`. Because an unknown ``rule_id`` is an internal
    detector key (never log-derived), using it as a label introduces no
    log-derived content; it is still HTML-escaped by every caller before it
    reaches the document.

    Args:
        rule_id: The detector's registry key.

    Returns:
        The friendly label, or the ``rule_id`` itself when unmapped.
    """
    return FRIENDLY_LABELS.get(rule_id, rule_id)


def _sanitize(value: str) -> str:
    """Mask prose, strip control chars, then HTML-escape (quotes included).

    Used for free-form, human-readable strings (finding titles and details) that
    may embed a sensitive value in a larger sentence. The order is binding:
    :func:`loganalyze.security.mask_prose` first so embedded secrets/emails/IPs
    are masked in place, then :func:`loganalyze.security.strip_control`, then
    :func:`html.escape` with ``quote=True`` so the result can be placed safely in
    either a text node or a quoted attribute without ever becoming executable
    markup (security rules 1-2).

    Args:
        value: The raw string to sanitize.

    Returns:
        The masked, control-stripped, HTML-escaped string.
    """
    return html.escape(strip_control(mask_prose(value)), quote=True)


def _sanitize_keyed(key: str, value: str) -> str:
    """Mask a keyed value by key/shape/prose, strip control, then HTML-escape.

    Delegates masking to :func:`loganalyze.security.mask_field_value` — the same
    key-based, then shape-based, then in-prose contract the console/JSON/CSV
    renderers use — then control-strips and HTML-escapes with quotes, so the
    result is safe in text and in quoted attributes alike (security rules 1-2).

    Args:
        key: The field or metadata key naming ``value``.
        value: The raw string value to sanitize.

    Returns:
        The masked, control-stripped, HTML-escaped value.
    """
    return html.escape(strip_control(mask_field_value(key, value)), quote=True)


def _escape_plain(value: str) -> str:
    """Control-strip and HTML-escape a non-log-derived internal string.

    Used for internal strings that are not log-derived (friendly labels, the
    source path, the generation timestamp). They carry no sensitive tokens, so
    masking is unnecessary, but they are still control-stripped and HTML-escaped
    so the document stays well-formed and no stray control byte survives.

    Args:
        value: The internal string to escape.

    Returns:
        The control-stripped, HTML-escaped string.
    """
    return html.escape(strip_control(value), quote=True)


@dataclass(frozen=True)
class _BreakdownRow:
    """One row of the "What was found" breakdown.

    Attributes:
        rule_id: The detector key (internal, never log-derived).
        label: The friendly label for ``rule_id``.
        band: The display band (``"high"``/``"med"``/``"low"``) of this type.
        count: How many findings of this type the run produced.
    """

    rule_id: str
    label: str
    band: str
    count: int


@dataclass(frozen=True)
class ReportModel:
    """Pure view-model computed from a run's findings.

    Attributes:
        findings: The findings in aggregator order (unchanged).
        counts: Mapping of band key (``"high"``/``"med"``/``"low"``) to count.
        total: Total number of findings.
        breakdown: Per-type rows sorted by severity band (high->low), then count
            descending, then friendly-label name.
        present_types: Ordered ``(rule_id, label)`` pairs for the type chips,
            one per detector type present, in breakdown order.
    """

    findings: list[Finding]
    counts: dict[str, int]
    total: int
    breakdown: list[_BreakdownRow]
    present_types: list[tuple[str, str]]


# Sort rank for a band so "high" sorts before "med" before "low".
_BAND_RANK = {"high": 0, "med": 1, "low": 2}


def build_report_model(findings: list[Finding]) -> ReportModel:
    """Compute the pure view-model for the HTML report.

    Counts findings per display band, builds the per-type breakdown sorted by
    severity band (high->low), then count descending, then friendly-label name
    (a deterministic, diff-stable order), and derives the ordered list of
    detector types present for the filter chips. This function is pure: it reads
    only ``findings`` and performs no I/O.

    Args:
        findings: The aggregated findings, in aggregator order.

    Returns:
        The :class:`ReportModel` describing the report.
    """
    counts = {"high": 0, "med": 0, "low": 0}
    per_type_count: dict[str, int] = {}
    per_type_band: dict[str, str] = {}
    for finding in findings:
        band = _band_of(finding.severity)
        counts[band] += 1
        per_type_count[finding.rule_id] = per_type_count.get(finding.rule_id, 0) + 1
        # The strongest (lowest rank) band seen for this type drives its sort
        # position, so a type that ever fired HIGH sorts in the high band.
        existing = per_type_band.get(finding.rule_id)
        if existing is None or _BAND_RANK[band] < _BAND_RANK[existing]:
            per_type_band[finding.rule_id] = band

    breakdown = [
        _BreakdownRow(
            rule_id=rule_id,
            label=_friendly(rule_id),
            band=per_type_band[rule_id],
            count=count,
        )
        for rule_id, count in per_type_count.items()
    ]
    breakdown.sort(
        key=lambda row: (_BAND_RANK[row.band], -row.count, row.label.lower())
    )

    present_types = [(row.rule_id, row.label) for row in breakdown]

    return ReportModel(
        findings=list(findings),
        counts=counts,
        total=len(findings),
        breakdown=breakdown,
        present_types=present_types,
    )


# --- Static assets (no interpolation) --------------------------------------

#: Inline stylesheet. A fixed constant; carries no log-derived content.
_STYLE = """
  :root{--high:#d64545;--high-bg:#fdecec;--med:#d9880a;--med-bg:#fdf3e3;
    --low:#3a7bd5;--low-bg:#eaf1fb;--ink:#1f2430;--muted:#6b7280;
    --line:#e5e7eb;--card:#fff;--bg:#f6f7f9;}
  *{box-sizing:border-box;}
  body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
    margin:0;background:var(--bg);color:var(--ink);line-height:1.5;}
  .wrap{max-width:1040px;margin:0 auto;padding:32px 24px 64px;}
  header h1{font-size:22px;margin:0 0 4px;}
  header .meta{color:var(--muted);font-size:13px;}
  .summary{display:flex;gap:12px;margin:24px 0 8px;flex-wrap:wrap;}
  .stat{background:var(--card);border:1px solid var(--line);border-radius:10px;
    padding:14px 18px;min-width:120px;}
  .stat .n{font-size:26px;font-weight:700;}
  .stat.high .n{color:var(--high);} .stat.med .n{color:var(--med);}
  .stat.low .n{color:var(--low);}
  .stat .l{font-size:12px;color:var(--muted);text-transform:uppercase;
    letter-spacing:.04em;}
  details.found{background:var(--card);border:1px solid var(--line);
    border-radius:10px;padding:12px 16px;margin:16px 0 4px;}
  details.found summary{cursor:pointer;font-weight:600;}
  details.found table{margin:10px 0 2px;border-collapse:collapse;width:100%;
    max-width:380px;}
  details.found td{padding:3px 0;font-size:14px;}
  details.found td.c{text-align:right;color:var(--muted);}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;
    margin-right:8px;}
  .dot.high{background:var(--high);} .dot.med{background:var(--med);}
  .dot.low{background:var(--low);}
  .controls{display:flex;gap:8px;align-items:center;margin:20px 0 10px;
    flex-wrap:wrap;}
  .controls input{flex:1;min-width:220px;padding:9px 12px;
    border:1px solid var(--line);border-radius:8px;font-size:14px;}
  .chip{border:1px solid var(--line);background:var(--card);border-radius:999px;
    padding:6px 14px;font-size:13px;cursor:pointer;user-select:none;}
  .chip.active{background:var(--ink);color:#fff;border-color:var(--ink);}
  .sev-group{margin-top:26px;}
  .sev-group h2{font-size:14px;text-transform:uppercase;letter-spacing:.05em;
    margin:0 0 10px;}
  .empty{color:var(--muted);font-style:italic;padding:8px 0;}
  .card{background:var(--card);border:1px solid var(--line);
    border-left-width:5px;border-radius:10px;padding:14px 16px;
    margin-bottom:10px;}
  .card.high{border-left-color:var(--high);}
  .card.med{border-left-color:var(--med);} .card.low{border-left-color:var(--low);}
  .card .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
  .badge{font-size:11px;font-weight:700;text-transform:uppercase;
    letter-spacing:.04em;padding:3px 9px;border-radius:6px;}
  .badge.high{background:var(--high-bg);color:var(--high);}
  .badge.med{background:var(--med-bg);color:var(--med);}
  .badge.low{background:var(--low-bg);color:var(--low);}
  .rule{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;
    color:var(--muted);}
  .title{font-weight:600;} .detail{margin:7px 0 10px;}
  .meta-grid{display:flex;flex-wrap:wrap;gap:6px;}
  .kv{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;
    background:var(--bg);border:1px solid var(--line);border-radius:6px;
    padding:2px 8px;}
  .kv b{color:var(--ink);font-weight:600;} .kv span{color:var(--muted);}
  .hidden{display:none;}
  .noresults{color:var(--muted);font-style:italic;margin-top:18px;}
  footer{margin-top:36px;color:var(--muted);font-size:12px;text-align:center;}
"""

#: Inline behavior script. A fixed constant: it contains NO interpolated or
#: log-derived values, reads only ``data-*`` attributes, and uses ``textContent``
#: / ``classList`` (never ``innerHTML``). The datalist typeahead maps a chosen
#: friendly label back to its type chip by matching ``textContent``. Security
#: rules 2 and 3 depend on this string never being templated.
_SCRIPT = """
(function () {
  var active = new Set();
  var chips = Array.prototype.slice.call(document.querySelectorAll(".chip"));
  var q = document.getElementById("q");
  var noresults = document.getElementById("noresults");

  function labelToChip(text) {
    var needle = (text || "").trim().toLowerCase();
    if (!needle) return null;
    for (var i = 0; i < chips.length; i++) {
      if (chips[i].getAttribute("data-type") === "all") continue;
      if (chips[i].textContent.trim().toLowerCase() === needle) return chips[i];
    }
    return null;
  }

  function apply() {
    var text = (q.value || "").toLowerCase();
    var anyType = active.size > 0;
    var shown = 0;
    var cards = document.querySelectorAll(".card");
    for (var i = 0; i < cards.length; i++) {
      var card = cards[i];
      var type = card.getAttribute("data-type");
      var hay = (card.getAttribute("data-text") || "").toLowerCase();
      var typeOk = !anyType || active.has(type);
      var textOk = text === "" || hay.indexOf(text) !== -1;
      var show = typeOk && textOk;
      card.classList.toggle("hidden", !show);
      if (show) shown++;
    }
    if (noresults) noresults.classList.toggle("hidden", shown !== 0);
    syncChips();
  }

  function syncChips() {
    for (var i = 0; i < chips.length; i++) {
      var t = chips[i].getAttribute("data-type");
      if (t === "all") chips[i].classList.toggle("active", active.size === 0);
      else chips[i].classList.toggle("active", active.has(t));
    }
  }

  function toggleType(t) {
    if (t === "all") { active.clear(); }
    else if (active.has(t)) { active.delete(t); }
    else { active.add(t); }
    apply();
  }

  for (var i = 0; i < chips.length; i++) {
    (function (chip) {
      chip.addEventListener("click", function () {
        toggleType(chip.getAttribute("data-type"));
      });
    })(chips[i]);
  }

  q.addEventListener("input", function () {
    var chip = labelToChip(q.value);
    if (chip) {
      toggleType(chip.getAttribute("data-type"));
      q.value = "";
      apply();
      return;
    }
    apply();
  });

  apply();
})();
"""


def _render_summary(model: ReportModel) -> str:
    """Render the four severity/total summary cards (no log-derived content)."""
    c = model.counts
    return (
        '<section class="summary">'
        f'<div class="stat high"><div class="n">{c["high"]}</div>'
        '<div class="l">High</div></div>'
        f'<div class="stat med"><div class="n">{c["med"]}</div>'
        '<div class="l">Medium</div></div>'
        f'<div class="stat low"><div class="n">{c["low"]}</div>'
        '<div class="l">Low</div></div>'
        f'<div class="stat"><div class="n">{model.total}</div>'
        '<div class="l">Total findings</div></div>'
        "</section>"
    )


def _render_breakdown(model: ReportModel) -> str:
    """Render the "What was found" ``<details>`` dropdown.

    Each row uses only the friendly label and an integer count (security rule 4),
    plus a colored severity dot for its band. Rows are already severity-sorted by
    :func:`build_report_model`.
    """
    rows = []
    for row in model.breakdown:
        rows.append(
            f'<tr><td><span class="dot {row.band}"></span>'
            f"{_escape_plain(row.label)}</td>"
            f'<td class="c">{row.count}</td></tr>'
        )
    body = "".join(rows) if rows else '<tr><td class="empty">Nothing</td></tr>'
    return (
        '<details class="found" open>'
        f"<summary>What was found ({model.total})</summary>"
        f"<table>{body}</table>"
        "</details>"
    )


def _render_controls(model: ReportModel) -> str:
    """Render the filter text box, typeahead datalist, and type chips.

    The ``<datalist>`` options and the chip labels come only from the fixed
    friendly-label map via :data:`present_types` (security rule 4). Each option
    and label is HTML-escaped defensively even though it is not log-derived.
    """
    options = "".join(
        f'<option value="{_escape_plain(label)}"></option>'
        for _rule_id, label in model.present_types
    )
    chips = ['<span class="chip active" data-type="all">All types</span>']
    for rule_id, label in model.present_types:
        chips.append(
            f'<span class="chip" data-type="{_escape_plain(rule_id)}">'
            f"{_escape_plain(label)}</span>"
        )
    return (
        '<div class="controls">'
        '<input id="q" type="text" list="type-suggestions" '
        'placeholder="Filter by text, or type a category (e.g. Pri\u2026)">'
        f'<datalist id="type-suggestions">{options}</datalist>'
        + "".join(chips)
        + "</div>"
    )


def _finding_filter_text(finding: Finding) -> str:
    """Build the lowercase, sanitized ``data-text`` haystack for a finding.

    Concatenates the friendly label, the sanitized title and detail, and the
    sanitized metadata values so the live text filter can match any of them. The
    result is already HTML-escaped (every part goes through the sanitize path),
    so it is safe inside a quoted attribute.
    """
    parts = [
        _escape_plain(_friendly(finding.rule_id)),
        _sanitize(finding.title),
        _sanitize(finding.detail),
    ]
    for key, value in finding.metadata.items():
        parts.append(_sanitize_keyed(str(key), str(value)))
    return " ".join(parts)


def _render_card(finding: Finding) -> str:
    """Render one finding card.

    The card's ``data-type`` is the internal ``rule_id`` (not log-derived) and
    its ``data-text`` is the sanitized filter haystack. The badge/title/detail
    and each metadata key/value chip are all sanitized (masked, control-stripped,
    HTML-escaped). No value lands in an executable position.
    """
    band = _band_of(finding.severity)
    band_label = {"high": "High", "med": "Medium", "low": "Low"}[band]
    chips = []
    for key, value in finding.metadata.items():
        safe_key = _escape_plain(str(key))
        safe_val = _sanitize_keyed(str(key), str(value))
        chips.append(
            f'<span class="kv"><b>{safe_key}</b> <span>=</span> {safe_val}</span>'
        )
    meta = f'<div class="meta-grid">{"".join(chips)}</div>' if chips else ""
    return (
        f'<div class="card {band}" data-type="{_escape_plain(finding.rule_id)}" '
        f'data-text="{_finding_filter_text(finding)}">'
        f'<div class="top"><span class="badge {band}">{band_label}</span>'
        f'<span class="title">{_sanitize(finding.title)}</span>'
        f'<span class="rule">{_escape_plain(finding.rule_id)}</span></div>'
        f'<div class="detail">{_sanitize(finding.detail)}</div>'
        f"{meta}</div>"
    )


def _render_groups(model: ReportModel) -> str:
    """Render the severity-grouped finding cards (High -> Medium -> Low).

    Every finding is listed individually (no collapsing of repeats). A band with
    no findings is omitted. Within a band, aggregator order is preserved.
    """
    sections = []
    for band, heading, color in _SEVERITY_BANDS:
        cards = [
            _render_card(f) for f in model.findings if _band_of(f.severity) == band
        ]
        if not cards:
            continue
        sections.append(
            f'<div class="sev-group"><h2 style="color:{color}">'
            f"{_escape_plain(heading)}</h2>" + "".join(cards) + "</div>"
        )
    return "".join(sections)


def render_report(
    findings: list[Finding], *, source: str, skipped: str, generated: str
) -> str:
    """Build the complete self-contained HTML document as a string.

    Args:
        findings: The aggregated findings, in aggregator order.
        source: A human description of the analyzed input (not log-derived;
            escaped defensively).
        skipped: A short skipped-line summary line (not log-derived).
        generated: The generation timestamp text (not log-derived).

    Returns:
        The full HTML document.
    """
    model = build_report_model(findings)
    if findings:
        body = (
            _render_summary(model)
            + _render_breakdown(model)
            + _render_controls(model)
            + _render_groups(model)
            + '<div id="noresults" class="noresults hidden">'
            "No findings match the current filter.</div>"
        )
    else:
        body = (
            _render_summary(model)
            + '<p class="empty">No findings. The scan completed and nothing '
            "matched a detector.</p>"
        )

    head = (
        "<!DOCTYPE html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>loganalyze report</title>"
        f"<style>{_STYLE}</style></head><body>"
    )
    skipped_segment = f" &bull; {_escape_plain(skipped)}" if skipped else ""
    header = (
        '<div class="wrap"><header><h1>loganalyze report</h1>'
        f'<div class="meta">Source: <b>{_escape_plain(source)}</b> &bull; '
        f"Generated {_escape_plain(generated)}{skipped_segment}"
        "</div></header>"
    )
    footer = (
        "<footer>Generated by loganalyze &bull; standard-library only &bull; "
        "self-contained HTML (no external assets)</footer></div>"
    )
    tail = f"<script>{_SCRIPT}</script></body></html>"
    return head + header + body + footer + tail


@register_output("html")
class HtmlOutput:
    """Render findings as a self-contained HTML report file.

    Conforms structurally to the :class:`~loganalyze.outputs.base.Output`
    protocol. Builds the full HTML text in memory, resolves the destination to
    its canonical absolute form (refusing to treat it as log-derived), and writes
    it atomically with restrictive permissions. Every log-derived string is
    masked, control-stripped, and HTML-escaped at this boundary, and the inline
    script is a fixed static asset, so no raw unmasked secret or PII, no control
    character, and no executable log-derived content ever reaches disk
    (Requirements 8.4, 8.6, 8.7, 8.8, 8.9, 8.10, 8.11, 8.13, 8.14).
    """

    def render(self, findings: list[Finding], target: OutputTarget) -> None:
        """Serialize ``findings`` to a self-contained HTML file at ``target.path``.

        Builds a sanitized HTML document in memory, resolves ``target.path`` to
        its canonical absolute form (``log_derived=False``), and writes it
        atomically. On any write failure the atomic writer leaves a pre-existing
        destination unchanged, removes the temporary file, and re-raises so the
        caller can report a write error (Requirement 8.13).

        Args:
            findings: The aggregated findings to render, in aggregator order.
            target: The destination; its ``path`` names the HTML file to write.

        Raises:
            ValueError: If ``target.path`` is ``None``; an HTML report needs a
                destination file.
            OSError: If the report cannot be written or atomically replaced. Any
                pre-existing destination is left unchanged.
        """
        if target.path is None:
            raise ValueError("HTML output requires a destination file path")

        resolved: Path = resolve_output_path(target.path, log_derived=False)
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        source = target.source if target.source is not None else str(resolved.name)
        skipped = target.skipped if target.skipped is not None else ""
        text = render_report(
            findings,
            source=source,
            skipped=skipped,
            generated=generated,
        )
        atomic_write(resolved, text + "\n")
