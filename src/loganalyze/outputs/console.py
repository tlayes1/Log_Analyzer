"""Console table output: render findings as an aligned terminal table.

This is one of the system's output-boundary renderers (Requirement 8.1). It
takes the aggregated, already-ranked :class:`~loganalyze.models.Finding` list
and writes a plain, column-aligned table to standard output using only the
standard library — no third-party table or color libraries.

Every string that originates in a finding (``severity``, ``rule_id``,
``title``, ``detail``, and each ``metadata`` value) is pushed through the
``Security_Helpers`` boundary before it is written: sensitive metadata values
are masked with the appropriate ``mask_*`` helper, and then *every* rendered
cell — without exception — is passed through :func:`strip_control`. That order
(mask, then strip) guarantees no raw unmasked secret, email, or client IP and
no forbidden control character can reach the terminal, so attacker-controlled
log text cannot inject ANSI escapes or leak credentials (Requirements 8.4, 8.7,
8.8, 8.9, 8.10). The renderer is selected purely by its registry key, so the
pipeline need not name this class (Requirement 8.14).
"""

from __future__ import annotations

import sys
from typing import TextIO

from loganalyze.models import Finding
from loganalyze.outputs.base import OutputTarget
from loganalyze.registry import register_output
from loganalyze.security import (
    mask_field_value,
    mask_prose,
    strip_control,
)

# Column headers in render order. The metadata summary is a single compact
# trailing column so wide, variable metadata never disrupts the fixed columns.
_HEADERS: tuple[str, ...] = ("severity", "rule_id", "title", "detail", "metadata")


def _mask_metadata_value(key: str, value: object) -> str:
    """Mask a single metadata value according to its key and shape.

    Delegates to the shared :func:`loganalyze.security.mask_field_value` so the
    console, JSON, and CSV renderers mask identically from one implementation:
    a key that names a secret/email/IP routes to the matching masker, an
    IP/email-shaped value is masked even on an unremarkable key, and anything
    else has embedded assignments/emails/IPs masked in place (Requirements 8.7,
    8.8, 8.9, 8.10). Control-stripping is applied later by the caller, uniformly
    across every cell.

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
    themselves are not sensitive and are rendered as-is (the whole cell is
    control-stripped by the caller).

    Args:
        metadata: The finding's metadata mapping (may be empty).

    Returns:
        A single-line ``k=v`` summary joined by ``", "``, or the empty string
        when there is no metadata.
    """
    if not metadata:
        return ""
    parts = [
        f"{key}={_mask_metadata_value(key, value)}"
        for key, value in metadata.items()
    ]
    return ", ".join(parts)


def _finding_to_row(finding: Finding) -> tuple[str, ...]:
    """Convert a finding into a fully sanitized table row.

    Every field is first reduced to its safe string form -- the free-form
    ``title`` and ``detail`` have embedded sensitive tokens masked via
    :func:`loganalyze.security.mask_prose`, and metadata values are masked where
    sensitive -- and
    then control-stripped, so no raw control character and no unmasked sensitive
    value reaches the terminal (Requirements 8.4, 8.7, 8.8, 8.9, 8.10).

    Args:
        finding: The finding to render.

    Returns:
        A tuple of sanitized cell strings aligned with :data:`_HEADERS`.
    """
    cells = (
        str(finding.severity),
        finding.rule_id,
        mask_prose(finding.title),
        mask_prose(finding.detail),
        _summarize_metadata(finding.metadata),
    )
    # Binding rule: strip control characters from EVERY cell, unconditionally.
    return tuple(strip_control(cell) for cell in cells)


def _format_table(rows: list[tuple[str, ...]]) -> str:
    """Render header and data rows as a space-padded, aligned text table.

    Column widths are the maximum rendered width across the header and all data
    cells, so columns line up without any third-party dependency. A separator
    rule of dashes sits under the header. Trailing whitespace on each line is
    stripped so the final metadata column does not leave ragged padding.

    Args:
        rows: The already-sanitized data rows, each aligned with
            :data:`_HEADERS`.

    Returns:
        The complete table as a single newline-joined string (no trailing
        newline).
    """
    all_rows: list[tuple[str, ...]] = [_HEADERS, *rows]
    widths = [
        max(len(row[col]) for row in all_rows) for col in range(len(_HEADERS))
    ]

    def render_row(row: tuple[str, ...]) -> str:
        return "  ".join(
            cell.ljust(widths[col]) for col, cell in enumerate(row)
        ).rstrip()

    lines = [render_row(_HEADERS)]
    lines.append("  ".join("-" * width for width in widths).rstrip())
    lines.extend(render_row(row) for row in rows)
    return "\n".join(lines)


@register_output("console")
class ConsoleOutput:
    """Terminal-table renderer registered under the ``console`` key.

    Conforms structurally to the :class:`~loganalyze.outputs.base.Output`
    protocol. Renders to standard output when the target carries no path (the
    only mode this renderer supports). All sanitization happens at this
    boundary via :func:`_finding_to_row`.
    """

    def render(self, findings: list[Finding], target: OutputTarget) -> None:
        """Render findings as an aligned table to standard output.

        Findings are rendered in the order given (the aggregator has already
        deduplicated and severity-ranked them). When there are no findings, a
        short, control-safe status line is written instead of an empty table.

        Args:
            findings: The aggregated findings to render, in aggregator order.
            target: The destination. Its ``path`` must be ``None`` (console);
                a non-``None`` path selects a file destination handled by a
                different renderer.

        Returns:
            None.

        Raises:
            ValueError: If ``target.path`` is set, since this renderer only
                writes to standard output.
        """
        if target.path is not None:
            raise ValueError(
                "ConsoleOutput renders only to stdout; a file path was given"
            )

        stream: TextIO = sys.stdout
        if not findings:
            stream.write(strip_control("No findings.") + "\n")
            return

        rows = [_finding_to_row(finding) for finding in findings]
        stream.write(_format_table(rows) + "\n")
