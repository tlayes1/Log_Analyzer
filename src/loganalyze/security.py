"""Shared sanitization and masking helpers (``Security_Helpers``).

This module is the single home for the binding, non-negotiable security rules
from ``security.md`` that are shared by ingest, detections, and outputs
(Requirement 9.5). It provides the line-length cap enforced before any regex
runs, control-character stripping, CSV formula-injection neutralization, and
PII/secret masking applied at the output boundary.

Every function here is pure: it maps its arguments to a return value with no
I/O, no mutable global state, and no side effects. No function passes
log-derived data to ``eval``, ``exec``, ``compile``, ``pickle``, a shell, or a
dynamic import (Requirement 9.3). The control-character pattern is precompiled
once at import time to keep the hot path allocation-free and ReDoS-safe.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

MAX_LINE_BYTES_DEFAULT = 65536  # 64 KiB default line-length cap.

# Precompiled at import: matches every control character except the tab (\t),
# i.e. U+0000–U+0008, U+000B–U+001F, and U+007F. Bounded single-character class,
# so it is not susceptible to catastrophic backtracking.
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# Characters that make a spreadsheet treat a cell as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@")

# --- Shared masking patterns (precompiled, bounded, ReDoS-safe) -------------
# These back :func:`mask_prose` and :func:`mask_field_value`, the two shared
# helpers every output renderer uses so masking is implemented once here rather
# than copy-pasted into console/json/csv.

# Whole-value shapes: a value that *is* exactly a dotted-quad IP or an email.
# Each octet/segment class is bounded, so neither pattern can backtrack
# catastrophically on attacker-controlled input.
_IP_SHAPE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_EMAIL_SHAPE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Embedded-token shapes: a sensitive substring sitting inside free-form prose.
# Bounded and anchored to token boundaries, so masking in place leaves the
# surrounding words intact without risking catastrophic backtracking.
_EMAIL_TOKEN = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IP_TOKEN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# Credential-style assignment embedded in prose, e.g. ``token=abc123`` or
# ``authorization: Bearer xyz``. Group 1 is the key, group 2 the separator plus
# any ``Bearer`` prefix, group 3 the secret value to mask. The value class is a
# bounded run of non-whitespace, so the pattern cannot backtrack catastrophically.
_SECRET_ASSIGNMENT = re.compile(
    r"\b(password|passwd|secret|token|api[_-]?key|session|authorization|"
    r"auth|credential|bearer|cookie)(\s*[:=]\s*(?:Bearer\s+)?)(\S+)",
    re.IGNORECASE,
)

# Metadata/field key fragments whose values are credentials and masked with
# :func:`mask_secret` regardless of their shape (Requirement 8.7).
_SECRET_KEY_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "session",
    "authorization",
    "auth",
    "credential",
    "key",
    "bearer",
    "cookie",
)

# Keys whose values are client IP addresses, matched case-insensitively.
_IP_KEYS = frozenset({"client_ip", "ip", "remote_addr", "src_ip", "source_ip"})

# Keys whose values are email addresses.
_EMAIL_KEYS = frozenset({"email", "mail", "email_address"})


def cap_line(raw: str, max_line_bytes: int) -> tuple[str, bool]:
    """Enforce the byte cap on a raw line before any regex runs.

    The cap is measured in UTF-8 bytes so a single pathological line cannot
    exhaust memory or stall a regex (``security.md`` line-length caps). When the
    line must be truncated, the cut is made on a UTF-8 character boundary so the
    returned string never contains a partial multibyte sequence.

    Args:
        raw: The raw log line, already decoded to ``str``.
        max_line_bytes: The maximum number of UTF-8 bytes to retain. Values
            below 1 are treated as 1 so at least one byte of budget remains.

    Returns:
        A tuple ``(line, truncated)`` where ``line`` is the original string when
        it fits within the cap or a byte-bounded prefix otherwise, and
        ``truncated`` is ``True`` only when bytes were dropped.
    """
    cap = max_line_bytes if max_line_bytes >= 1 else 1
    encoded = raw.encode("utf-8")
    if len(encoded) <= cap:
        return raw, False
    # Slice on a byte boundary then drop any trailing partial character.
    truncated = encoded[:cap].decode("utf-8", errors="ignore")
    return truncated, True


def strip_control(text: str) -> str:
    """Replace control characters (except tab) with U+FFFD.

    Neutralizes attacker-controlled control bytes so rendered findings cannot
    inject ANSI escapes, clear the screen, or forge output (Requirement 8.4).
    The tab character (``\\t``) is preserved. The function is idempotent:
    applying it to already-stripped text returns that text unchanged, because
    U+FFFD is not itself a control character.

    Args:
        text: Arbitrary, possibly attacker-controlled, text.

    Returns:
        The text with every forbidden control character replaced by U+FFFD.
    """
    return _CTRL.sub("\ufffd", text)


def csv_safe(value: str) -> str:
    """Neutralize a CSV field against spreadsheet formula injection.

    When a field's first character is ``=``, ``+``, ``-``, or ``@`` a spreadsheet
    evaluates the cell as a formula. Prefixing a single apostrophe disarms it
    (Requirement 8.5). The function is idempotent on already-safe fields: an
    apostrophe is not a formula prefix, so a value that has already been
    neutralized is returned unchanged.

    Args:
        value: The field value destined for a CSV cell.

    Returns:
        The value, apostrophe-prefixed when it begins with a formula character.
    """
    if value and value[0] in _FORMULA_PREFIXES:
        return "'" + value
    return value


def mask_secret(value: str) -> str:
    """Mask a credential-like value, revealing at most first 2 + last 2 chars.

    Masks passwords, API keys, tokens, session identifiers, and
    authorization-header values at the output boundary (Requirement 8.7). A
    value of 4 or fewer characters reveals no original characters; a longer value
    reveals at most its first two and last two characters, with the middle
    collapsed to a single ellipsis. The function is idempotent: a value already
    reduced to the masked form maps to that same form.

    Args:
        value: The sensitive string to mask.

    Returns:
        The masked representation of the value.
    """
    if len(value) <= 4:
        return "****"
    return value[:2] + "\u2026" + value[-2:]


def mask_email(value: str) -> str:
    """Mask an email address, revealing at most the first local char + domain.

    Reveals at most the first character of the local part and the full domain,
    masking the remainder of the local part (Requirement 8.8). Values that do not
    look like an ``local@domain`` address are routed through :func:`mask_secret`
    so no sensitive remainder leaks. The function is idempotent on values already
    in this masked shape.

    Args:
        value: The email address to mask.

    Returns:
        The masked email, or a secret-masked value when the input is not a
        recognizable single-``@`` address.
    """
    local, sep, domain = value.partition("@")
    if not sep or not local or not domain or "@" in domain:
        return mask_secret(value)
    if len(local) <= 1:
        masked_local = local
    else:
        masked_local = local[0] + "\u2026"
    return masked_local + "@" + domain


def mask_ip(value: str) -> str:
    """Mask a dotted-quad IP, revealing at most the first two octets.

    Reveals at most the first two octets of a dotted-quad client IP and masks the
    rest (Requirement 8.9). Values that are not a four-octet dotted quad collapse
    to a fully masked ``x.x.x.x`` so no address detail leaks. The function is
    idempotent: an already-masked ``a.b.x.x`` value maps back to itself.

    Args:
        value: The IP address to mask.

    Returns:
        The masked IP with its final two octets replaced by ``x``.
    """
    parts = value.split(".")
    if len(parts) != 4:
        return "x.x.x.x"
    return ".".join([parts[0], parts[1], "x", "x"])


def mask_prose(text: str) -> str:
    """Mask sensitive substrings embedded in free-form text, in place.

    Finding titles, details, and other human-readable prose may embed a
    credential, email, or client IP inside a larger sentence. This masks each
    such substring where it sits -- credential ``key=value``/``Bearer``
    assignments first, then embedded emails, then dotted-quad IPs -- so the
    surrounding words survive while no raw secret, email, or client IP reaches a
    report (Requirements 8.7, 8.8, 8.9, 8.10).

    Only *shape-detectable* or *marker-prefixed* values are masked: a bare
    high-entropy token with no ``key=`` marker and no IP/email shape cannot be
    distinguished from ordinary prose and is left untouched. Callers that know a
    value is sensitive by its key should route it through
    :func:`mask_field_value` instead. This function is pure and does not
    control-strip; the caller applies :func:`strip_control` uniformly.

    Args:
        text: The raw prose to mask.

    Returns:
        The prose with every detectable embedded sensitive token masked.
    """
    masked = _SECRET_ASSIGNMENT.sub(
        lambda m: m.group(1) + m.group(2) + mask_secret(m.group(3)), text
    )
    masked = _EMAIL_TOKEN.sub(lambda m: mask_email(m.group(0)), masked)
    masked = _IP_TOKEN.sub(lambda m: mask_ip(m.group(0)), masked)
    return masked


def mask_field_value(key: str, value: str) -> str:
    """Mask a keyed value by its key first, then by its shape, then as prose.

    The key name is the strongest signal: a key that names a credential, email,
    or client IP routes its value to the matching ``mask_*`` helper regardless
    of the value's shape (Requirement 8.7). When the key is unremarkable, a
    value that merely *looks* like a dotted-quad IP or an email is still masked
    so a sensitive value cannot slip through on an unexpected key name
    (Requirements 8.8, 8.9). Any remaining value falls through to
    :func:`mask_prose`, so an embedded assignment/email/IP inside an otherwise
    free-form value (for example ``user_agent: "... Bearer xyz"``) is still
    masked (Requirement 8.10).

    This function is pure and does not control-strip; the caller applies
    :func:`strip_control` uniformly across every emitted field.

    Args:
        key: The field or metadata key naming ``value`` (used case-insensitively).
        value: The raw string value to mask.

    Returns:
        The masked string form of the value.
    """
    lowered = key.lower()
    if lowered in _IP_KEYS:
        return mask_ip(value)
    if lowered in _EMAIL_KEYS:
        return mask_email(value)
    if any(hint in lowered for hint in _SECRET_KEY_HINTS):
        return mask_secret(value)
    # Key is unremarkable: fall back to value shape, then in-place prose masking.
    if _IP_SHAPE.match(value):
        return mask_ip(value)
    if _EMAIL_SHAPE.match(value):
        return mask_email(value)
    return mask_prose(value)


def resolve_output_path(path: Path, *, log_derived: bool) -> Path:
    """Resolve an output path to its canonical absolute form, refusing log data.

    Output destinations are resolved to a single canonical, absolute real path
    so that later writes cannot be redirected through ``..`` segments, symlinks,
    or relative-path tricks (Requirement 8.11). A path whose value originates in
    log content is never resolved or written: following an attacker-controlled
    path would let malicious log text choose where the tool writes, so such a
    request is refused outright (Requirement 8.12).

    Args:
        path: The candidate output path to canonicalize.
        log_derived: ``True`` when ``path`` was derived from log content. The
            function refuses to resolve such a path and raises instead.

    Returns:
        The canonical absolute :class:`~pathlib.Path`, equivalent to
        ``path.resolve()``, when the path is not log-derived.

    Raises:
        ValueError: If ``log_derived`` is ``True``; a log-derived path is never
            followed or written.
    """
    if log_derived:
        raise ValueError(
            "refusing to resolve an output path derived from log content"
        )
    # strict=False: the destination need not exist yet, but every parent that
    # does exist is canonicalized (symlinks and ``..`` resolved) so the returned
    # path is unambiguous.
    return path.resolve(strict=False)


def atomic_write(path: Path, data: str) -> None:
    """Write ``data`` to ``path`` atomically with restrictive permissions.

    The content is first written in full to a temporary file created in the
    destination's own directory (so the final :func:`os.replace` is a same
    filesystem rename and therefore atomic), then that temporary file replaces
    the destination in one step. An interrupted run therefore leaves either the
    prior file or the fully written new file, never a partial report
    (Requirement 8.6). The temporary file is created with owner-only ``0o600``
    permissions — the most restrictive mode the platform supports — so no
    secret-bearing report is briefly world-readable (Requirement 8.11).

    On any failure the temporary file is removed and any pre-existing
    destination is left untouched before the error is re-raised, so a failed
    write never destroys an existing report (Requirement 8.13).

    Args:
        path: The destination path. Expected to already be canonicalized via
            :func:`resolve_output_path`.
        data: The complete file content to write.

    Raises:
        OSError: If the temporary file cannot be written or the atomic replace
            fails. The pre-existing destination is left unchanged and the
            temporary file is removed before the error propagates.
    """
    directory = path.parent
    # mkstemp creates the file with 0o600 by default and returns an open fd.
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=directory
    )
    tmp_path = Path(tmp_name)
    try:
        # Restate the restrictive mode explicitly in case the platform umask or
        # mkstemp default ever differs; owner read/write only.
        os.chmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # Atomic within a single filesystem: either the old or the new file is
        # seen by any concurrent reader, never a mix.
        os.replace(tmp_path, path)
    except BaseException:
        # Leave any pre-existing destination untouched; clean up the temp file.
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise
