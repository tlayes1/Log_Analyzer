"""Structured JSON file output renderer (``@register_output("json")``).

Serializes aggregated :class:`~loganalyze.models.Finding` results to a
structured JSON document and writes it to the resolved destination with
:func:`loganalyze.security.atomic_write`, so an interrupted run leaves either
the prior report or the fully written one, never a partial file (Requirements
8.2, 8.6, 8.13), and so the file is created with the most restrictive
permissions the platform supports at a canonical, resolved path (Requirement
8.11).

This renderer is the output security boundary. Every string value it emits —
titles, details, metadata keys and values, and the safe subset of each event's
fields — is first masked with the ``Security_Helpers`` ``mask_*`` functions and
then control-stripped with :func:`loganalyze.security.strip_control`, so no raw
unmasked secret, email, or client IP and no forbidden control character ever
reaches disk (Requirements 8.4, 8.7, 8.8, 8.9, 8.10). Raw event text (the
unmasked ``raw`` and ``message`` fields) is deliberately never serialized.
"""

from __future__ import annotations

import json
from pathlib import Path

from loganalyze.models import Event, Finding
from loganalyze.outputs.base import OutputTarget
from loganalyze.registry import register_output
from loganalyze.security import (
    atomic_write,
    mask_field_value,
    mask_ip,
    mask_prose,
    resolve_output_path,
    strip_control,
)

# Event fields serialized verbatim (after masking) from the normalized Event.
# The unmasked ``raw`` and ``message`` fields are intentionally excluded so no
# raw attacker-controlled line reaches disk.


def _sanitize(value: str) -> str:
    """Mask sensitive tokens inside a free-form string, then strip control chars.

    Used for human-readable prose (finding titles, details, and free-form field
    values with no credential-naming key) that may embed a sensitive value
    within a larger sentence. Embedded credential assignments, emails, and
    dotted-quad IPs are masked in place via the shared
    :func:`loganalyze.security.mask_prose`, so the surrounding prose is preserved
    while no raw secret, email, or client IP survives (Requirements 8.7, 8.8,
    8.9, 8.10). The result is always control-stripped.

    Args:
        value: The raw string to sanitize before serialization.

    Returns:
        The masked, control-stripped string safe to write to disk.
    """
    return strip_control(mask_prose(value))


def _sanitize_keyed(key: str, value: str) -> str:
    """Mask a keyed value by key, then shape, then in-prose, and strip control.

    Delegates to the shared :func:`loganalyze.security.mask_field_value` so a
    credential-named key masks as a secret, an IP/email-named or IP/email-shaped
    value masks accordingly, and any other value still has embedded
    assignments/emails/IPs masked in place -- the same contract the console and
    CSV renderers use (Requirements 8.7, 8.8, 8.9, 8.10). The result is always
    control-stripped.

    Args:
        key: The field or metadata key naming ``value``.
        value: The raw string value to sanitize.

    Returns:
        The masked, control-stripped value safe to write to disk.
    """
    return strip_control(mask_field_value(key, value))


def _sanitize_metadata(metadata: dict) -> dict[str, object]:
    """Sanitize a finding's metadata mapping for serialization.

    Every key is control-stripped and every value is masked and control-stripped.
    String values are routed through :func:`_sanitize_keyed` so credential-named
    entries are secret-masked; non-string values are stringified first so nothing
    bypasses the masking boundary. Nested mappings are sanitized recursively and
    sequences element-by-element.

    Args:
        metadata: The finding's machine-readable metadata.

    Returns:
        A new mapping with sanitized keys and values, safe to write to disk.
    """
    result: dict[str, object] = {}
    for raw_key, raw_value in metadata.items():
        key = strip_control(str(raw_key))
        result[key] = _sanitize_value(str(raw_key), raw_value)
    return result


def _sanitize_value(key: str, value: object) -> object:
    """Sanitize an arbitrary metadata value under its key.

    Mappings and sequences are sanitized structurally so every leaf string is
    masked; every scalar is stringified and routed through
    :func:`_sanitize_keyed`, so no value — numeric, boolean, or otherwise —
    reaches disk without passing the masking boundary.

    Args:
        key: The key naming ``value`` (drives credential detection).
        value: The arbitrary value to sanitize.

    Returns:
        A sanitized, JSON-serializable value safe to write to disk.
    """
    if isinstance(value, dict):
        return {
            strip_control(str(k)): _sanitize_value(str(k), v) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(key, item) for item in value]
    return _sanitize_keyed(key, str(value))


def _serialize_event(event: Event) -> dict[str, object]:
    """Serialize a safe, masked subset of an event.

    Emits the event timestamp in ISO 8601 form plus the masked, control-stripped
    ``log_type``, ``source``, and the optional identity/request fields (host,
    client IP, user, method, path, status) and the free-form ``fields`` mapping.
    The unmasked ``raw`` and ``message`` fields are deliberately omitted so no
    raw attacker-controlled line reaches disk (Requirement 8.10).

    Args:
        event: The normalized event to serialize.

    Returns:
        A JSON-serializable mapping of the event's safe, masked subset.
    """
    record: dict[str, object] = {
        "timestamp": event.timestamp.isoformat(),
        "log_type": strip_control(event.log_type),
        "source": _sanitize(event.source),
    }
    if event.host is not None:
        record["host"] = _sanitize(event.host)
    if event.client_ip is not None:
        record["client_ip"] = strip_control(mask_ip(event.client_ip))
    if event.user is not None:
        record["user"] = _sanitize(event.user)
    if event.method is not None:
        record["method"] = strip_control(event.method)
    if event.path is not None:
        record["path"] = _sanitize(event.path)
    if event.status is not None:
        record["status"] = event.status
    if event.fields:
        record["fields"] = {
            strip_control(str(k)): _sanitize_keyed(str(k), str(v))
            for k, v in event.fields.items()
        }
    return record


def _serialize_finding(finding: Finding) -> dict[str, object]:
    """Serialize a single finding to a sanitized, JSON-ready mapping.

    The ``rule_id`` and the lowercase ``severity`` string are control-stripped;
    the ``title`` and ``detail`` are masked and control-stripped; the metadata is
    sanitized structurally; and each contributing event is reduced to its safe,
    masked subset. No value bypasses the masking boundary.

    Args:
        finding: The finding to serialize.

    Returns:
        A JSON-serializable mapping describing the finding.
    """
    return {
        "rule_id": strip_control(finding.rule_id),
        "title": _sanitize(finding.title),
        "severity": strip_control(str(finding.severity)),
        "detail": _sanitize(finding.detail),
        "metadata": _sanitize_metadata(finding.metadata),
        "events": [_serialize_event(event) for event in finding.events],
    }


@register_output("json")
class JsonOutput:
    """Render findings as a structured JSON report file.

    Resolves the destination to its canonical absolute form (refusing to treat
    it as log-derived) and writes the serialized document atomically with
    restrictive permissions. Every string emitted is masked then control-stripped
    at this boundary, so no raw unmasked secret or PII and no forbidden control
    character reaches disk (Requirements 8.2, 8.4, 8.6, 8.7, 8.8, 8.9, 8.10,
    8.11, 8.13, 8.14).
    """

    def render(self, findings: list[Finding], target: OutputTarget) -> None:
        """Serialize ``findings`` to a JSON file at ``target.path``.

        Builds a sanitized JSON document in memory, resolves ``target.path`` to
        its canonical absolute form (``log_derived=False``), and writes it
        atomically. On any write failure the atomic writer leaves a pre-existing
        destination unchanged, removes the temporary file, and re-raises so the
        caller can report a write error (Requirement 8.13).

        Args:
            findings: The aggregated findings to render, in aggregator order.
            target: The destination; its ``path`` names the JSON file to write.

        Raises:
            ValueError: If ``target.path`` is ``None``; a JSON report needs a
                destination file.
            OSError: If the report cannot be written or atomically replaced. Any
                pre-existing destination is left unchanged.
        """
        if target.path is None:
            raise ValueError("JSON output requires a destination file path")

        document = {
            "findings": [_serialize_finding(finding) for finding in findings],
            "count": len(findings),
        }
        # sort_keys keeps the output deterministic and diff-friendly; the
        # trailing newline is conventional for text files.
        data = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
        resolved: Path = resolve_output_path(target.path, log_derived=False)
        atomic_write(resolved, data + "\n")
