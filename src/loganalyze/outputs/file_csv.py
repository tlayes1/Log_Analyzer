"""Optional CSV file output renderer (``@register_output("csv")``).

Serializes aggregated :class:`~loganalyze.models.Finding` results to a CSV
document and writes it to the resolved destination with
:func:`loganalyze.security.atomic_write`, so an interrupted run leaves either
the prior report or the fully written one, never a partial file (Requirements
8.3, 8.6, 8.13). The destination is resolved to its canonical absolute form and
created with the most restrictive permissions the platform supports
(Requirement 8.11).

This renderer is the output security boundary. For every field it emits the
three required transforms are applied in a fixed, non-negotiable order:

1. **Mask** sensitive values -- the free-form ``title``/``detail`` via
   :func:`loganalyze.security.mask_prose` and metadata values via
   :func:`loganalyze.security.mask_field_value` -- using the same shared
   key-based plus shape-based plus in-prose approach as the console and JSON
   renderers (Requirements 8.7, 8.8, 8.9, 8.10).
2. **Strip control characters** from every field with
   :func:`loganalyze.security.strip_control`, so attacker-controlled log text
   cannot inject control bytes into the file (Requirement 8.4).
3. **Neutralize formulas** last with :func:`loganalyze.security.csv_safe`, so a
   field beginning with ``=``, ``+``, ``-``, or ``@`` is disarmed and a
   spreadsheet never evaluates it (Requirement 8.5).

Applying ``csv_safe`` last is deliberate: a leading apostrophe added by the
formula guard must survive to disk, and masking/stripping could otherwise
re-expose a formula prefix. Together these guarantee no raw unmasked secret,
email, or client IP and no forbidden control character ever reaches disk
(Requirement 8.10). The renderer is resolved by its registry key only, so the
pipeline need not name this class (Requirement 8.14).
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from loganalyze.models import Finding
from loganalyze.outputs.base import OutputTarget
from loganalyze.registry import register_output
from loganalyze.security import (
    atomic_write,
    csv_safe,
    mask_field_value,
    mask_prose,
    resolve_output_path,
    strip_control,
)

# Column headers in render order. The metadata summary is a single compact
# trailing column, mirroring the console renderer's layout.
_HEADERS: tuple[str, ...] = ("severity", "rule_id", "title", "detail", "metadata")


def _mask_metadata_value(key: str, value: object) -> str:
    """Mask a single metadata value according to its key and shape.

    Delegates to the shared :func:`loganalyze.security.mask_field_value` so the
    console, JSON, and CSV renderers mask identically from one implementation:
    key-based (secret/email/IP) first, then value shape, then in-place prose
    masking of any embedded assignment/email/IP (Requirements 8.7, 8.8, 8.9,
    8.10). Control-stripping and formula neutralization are applied later by the
    caller, uniformly across every field.

    Args:
        key: The metadata key name (used case-insensitively).
        value: The raw metadata value; coerced to ``str`` before masking.

    Returns:
        The masked string form of the value.
    """
    return mask_field_value(key, str(value))


def _summarize_metadata(metadata: dict) -> str:
    """Build a compact, masked ``key=value`` summary of a finding's metadata.

    Each value is masked by :func:`_mask_metadata_value` before it is joined, so
    the summary never carries a raw secret, email, or client IP. Keys are
    emitted in their stored order for deterministic output; the key names
    themselves are not sensitive and are rendered as-is (the whole field is
    control-stripped and formula-neutralized by the caller).

    Args:
        metadata: The finding's metadata mapping (may be empty).

    Returns:
        A single ``k=v`` summary joined by ``", "``, or the empty string when
        there is no metadata.
    """
    if not metadata:
        return ""
    parts = [
        f"{key}={_mask_metadata_value(key, value)}" for key, value in metadata.items()
    ]
    return ", ".join(parts)


def _secure_field(value: str) -> str:
    """Apply the fixed output-safety tail to a single, already-masked CSV field.

    The order is binding (Requirements 8.5, 8.10): strip control characters
    first, then neutralize spreadsheet formulas last. Masking is performed by the
    caller before this point -- metadata via :func:`_summarize_metadata` and the
    free-form ``title``/``detail`` via :func:`loganalyze.security.mask_prose` --
    so this function only completes sanitization. Doing ``csv_safe`` last
    guarantees the apostrophe guard survives to disk and is not re-exposed by any
    later transform.

    Args:
        value: The already string-reduced and masked field.

    Returns:
        The control-stripped, formula-neutralized field safe to write to disk.
    """
    return csv_safe(strip_control(value))


def _finding_to_row(finding: Finding) -> list[str]:
    """Convert a finding into a fully sanitized CSV row.

    The free-form ``title`` and ``detail`` have embedded sensitive tokens masked
    via :func:`loganalyze.security.mask_prose`, metadata values are masked by
    :func:`_summarize_metadata`, and every cell then passes through
    :func:`_secure_field`, so no raw control character, no unmasked sensitive
    value, and no live spreadsheet formula reaches disk (Requirements 8.5, 8.7,
    8.8, 8.9, 8.10). The order is always mask -> strip_control -> csv_safe.

    Args:
        finding: The finding to render.

    Returns:
        A list of sanitized cell strings aligned with :data:`_HEADERS`.
    """
    cells = (
        str(finding.severity),
        finding.rule_id,
        mask_prose(finding.title),
        mask_prose(finding.detail),
        _summarize_metadata(finding.metadata),
    )
    return [_secure_field(cell) for cell in cells]


def _render_csv_text(findings: list[Finding]) -> str:
    """Render findings to a complete CSV document in memory.

    Uses the standard-library :mod:`csv` writer over an :class:`io.StringIO`
    buffer so quoting and escaping follow the CSV standard. A header row is
    always written, followed by one sanitized row per finding in aggregator
    order. A single ``\\n`` line terminator is used so the text written by
    :func:`loganalyze.security.atomic_write` is not double-terminated by
    platform newline translation.

    Args:
        findings: The aggregated findings to render, in aggregator order.

    Returns:
        The complete CSV document as a single string.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(list(_HEADERS))
    for finding in findings:
        writer.writerow(_finding_to_row(finding))
    return buffer.getvalue()


@register_output("csv")
class CsvOutput:
    """Render findings as a CSV report file (optional ``csv`` renderer).

    Conforms structurally to the :class:`~loganalyze.outputs.base.Output`
    protocol. Builds the full CSV text in memory with the standard-library
    :mod:`csv` writer, resolves the destination to its canonical absolute form
    (refusing to treat it as log-derived), and writes it atomically with
    restrictive permissions. Every field is masked, control-stripped, and
    formula-neutralized at this boundary, so no raw unmasked secret or PII and no
    forbidden control character reaches disk (Requirements 8.3, 8.4, 8.5, 8.6,
    8.7, 8.8, 8.9, 8.10, 8.11, 8.13, 8.14).
    """

    def render(self, findings: list[Finding], target: OutputTarget) -> None:
        """Serialize ``findings`` to a CSV file at ``target.path``.

        Builds a sanitized CSV document in memory, resolves ``target.path`` to
        its canonical absolute form (``log_derived=False``), and writes it
        atomically. On any write failure the atomic writer leaves a pre-existing
        destination unchanged, removes the temporary file, and re-raises so the
        caller can report a write error (Requirement 8.13).

        Args:
            findings: The aggregated findings to render, in aggregator order.
            target: The destination; its ``path`` names the CSV file to write.

        Raises:
            ValueError: If ``target.path`` is ``None``; a CSV report needs a
                destination file.
            OSError: If the report cannot be written or atomically replaced. Any
                pre-existing destination is left unchanged.
        """
        if target.path is None:
            raise ValueError("CSV output requires a destination file path")

        text = _render_csv_text(findings)
        resolved: Path = resolve_output_path(target.path, log_derived=False)
        atomic_write(resolved, text)
