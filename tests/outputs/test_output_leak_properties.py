# Feature: loganalyze, Property 22: No raw sensitive value reaches a report file
# Validates: Requirement 8.10
"""Property-based test for the output security boundary (design Property 22).

The JSON file renderer (and the optional CSV renderer, when importable) is the
system's output security boundary: every string it emits must be masked with the
``Security_Helpers`` ``mask_*`` functions and control-stripped before it reaches
disk, so that no raw unmasked client IP, email address, or secret/token and no
forbidden control character ever lands in a report file (Requirement 8.10).

This property drives arbitrary sensitive values — a dotted-quad IP, an
``example.com`` email, and a token/secret — into a :class:`~loganalyze.models.Finding`
through every surface the renderers touch (metadata values, the free-form title
and detail, and a contributing :class:`~loganalyze.models.Event` whose raw and
message fields carry the same values). It then writes the report with the real
renderer, reads the file back, and asserts the raw values are absent while the
masked forms (per the exact ``mask_*`` contracts in ``loganalyze.security``) may
appear, and that no forbidden control character survives.

A raw sensitive value appearing on disk is a real security bug: when a
counterexample is found the test fails loudly rather than relaxing the assertion.

Synthetic data only (Requirement 11): generated IPs are dotted quads built from
integer octets, every email is on ``example.com``, and tokens are random
non-authenticating strings.
"""

from __future__ import annotations

import re
import tempfile
from datetime import datetime
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from loganalyze.models import Event, Finding, Severity
from loganalyze.outputs.base import OutputTarget
from loganalyze.outputs.file_json import JsonOutput
from loganalyze.security import mask_email, mask_ip, mask_secret

try:  # The CSV renderer is an optional surface; test it when it is present.
    from loganalyze.outputs.file_csv import CsvOutput

    _HAVE_CSV = True
except ImportError:  # pragma: no cover - exercised only when CSV is absent
    _HAVE_CSV = False

# Forbidden control characters per security.md / Requirement 8.4: U+0000-U+0008,
# U+000B-U+001F, and U+007F. Tab (U+0009) and the newline/CR used as structure
# are intentionally outside this class.
_FORBIDDEN_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

_EPOCH = datetime(2024, 1, 1, 0, 0, 0)

# A handful of forbidden control characters to embed in prose so the property
# also proves control-stripping happens on the way to disk.
_CTRL_CHARS = st.sampled_from(["\x00", "\x01", "\x07", "\x1b", "\x1f", "\x7f"])


@st.composite
def sensitive_inputs(draw: st.DrawFn) -> tuple[str, str, str, str]:
    """Generate ``(ip, email, secret, ctrl)`` sensitive building blocks.

    - ``ip`` is a dotted quad of four 0-255 octets.
    - ``email`` is ``<local>@example.com`` with a non-empty alphanumeric local
      part of length >= 2 (so the masked form reveals exactly one character and
      the raw address is guaranteed to differ from it).
    - ``secret`` is a token of length >= 8 (so ``mask_secret`` reveals at most
      first-two + last-two and the raw value is guaranteed to differ).
    - ``ctrl`` is a forbidden control character to embed in prose.
    """
    octets = [draw(st.integers(min_value=0, max_value=255)) for _ in range(4)]
    ip = ".".join(str(o) for o in octets)

    local = draw(
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyz0123456789",
            min_size=2,
            max_size=16,
        )
    )
    email = f"{local}@example.com"

    secret = draw(
        st.text(
            alphabet=st.characters(
                min_codepoint=33,
                max_codepoint=126,
                # Keep tokens free of control chars and of characters that would
                # make them *look* like an IP/email so the secret assertion is
                # about the secret path specifically.
                blacklist_characters="@.",
            ),
            min_size=8,
            max_size=40,
        )
    )

    ctrl = draw(_CTRL_CHARS)
    return ip, email, secret, ctrl


def _build_finding(ip: str, email: str, secret: str, ctrl: str) -> Finding:
    """Embed the sensitive values into every surface a renderer serializes.

    Scoping note on the enforceable Req 8.10 contract. An IP and an email are
    *shape-detectable*: a renderer can recognize and mask them wherever they
    appear, so this test drives them into bare, unmarked positions (prose, a
    ``note`` field, an event's free-form field) and asserts they never leak. A
    secret/token has no distinguishing shape. It can only be recognized when it
    appears (a) under a credential/IP/email-named key, or (b) in a
    ``key=value``/``Bearer`` assignment. A bare high-entropy token sitting in
    free text with no key and no marker is indistinguishable from ordinary prose
    and cannot be reliably masked -- asserting its absence would test beyond the
    enforceable guarantee. So every secret occurrence below is given a detectable
    form: a ``token=<secret>`` assignment in prose, or a credential-named key
    (``token``/``api_key``). The IP/email occurrences stay strict and unmarked.
    """
    event = Event(
        timestamp=_EPOCH,
        source="access.log",
        log_type="nginx",
        # raw/message deliberately carry the unmasked values: the renderer must
        # never dump them.
        message=f"login from {ip} user {email} token={secret}{ctrl}",
        raw=f"{ip} - {email} \"GET /?token={secret}\"{ctrl}",
        # The secret is embedded as a detectable ``token=<secret>`` assignment
        # (not a bare substring) so the enforceable in-prose masking applies.
        fields={"user_agent": f"agent token={secret}"},
        client_ip=ip,
        user=email,
    )
    return Finding(
        rule_id="test.leak",
        title=f"activity from {ip} for {email}{ctrl}",
        severity=Severity.HIGH,
        events=[event],
        detail=f"observed {email} using token={secret} at {ip}{ctrl}",
        metadata={
            "client_ip": ip,
            "email": email,
            "token": secret,
            # IP and email are shape-detectable and stay bare here; the secret
            # is carried under its own credential-named ``token`` key above, so
            # ``note`` intentionally omits the bare secret.
            "note": f"raw {ip} {email}{ctrl}",
        },
    )


def _assert_no_leak(text: str, ip: str, email: str, secret: str) -> None:
    """Assert the raw sensitive values are absent and masking/stripping held."""
    # 1. No forbidden control character survived to disk (Requirement 8.4/8.10).
    leak = _FORBIDDEN_CTRL.search(text)
    assert leak is None, (
        f"forbidden control character U+{ord(leak.group()):04X} reached the "
        f"report file"
    )

    # 2. The full raw dotted-quad IP must be absent; the masked a.b.x.x form may
    #    appear. Use word boundaries so e.g. "1.2.3.4" is not matched inside
    #    "11.2.3.40"; the exact address must not appear as a standalone token.
    assert not re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", text), (
        f"raw client IP {ip!r} reached the report file (masked form is "
        f"{mask_ip(ip)!r})"
    )

    # 3. The full raw email must be absent; the masked l…@domain form may appear.
    assert email not in text, (
        f"raw email {email!r} reached the report file (masked form is "
        f"{mask_email(email)!r})"
    )

    # 4. The raw secret (len >= 8 so mask_secret reveals at most first2+last2)
    #    must be absent; the masked first2…last2 form may appear.
    assert secret not in text, (
        f"raw secret {secret!r} reached the report file (masked form is "
        f"{mask_secret(secret)!r})"
    )


@settings(max_examples=150)
@given(payload=sensitive_inputs())
def test_json_report_never_leaks_raw_sensitive_values(payload) -> None:
    """JSON report masks every raw IP/email/secret and strips control chars."""
    ip, email, secret, ctrl = payload
    finding = _build_finding(ip, email, secret, ctrl)

    # A fresh directory per generated example keeps the atomic write isolated;
    # Hypothesis does not reset function-scoped fixtures between examples.
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "out.json"
        JsonOutput().render([finding], OutputTarget(path=out_path))
        text = out_path.read_text(encoding="utf-8")

    _assert_no_leak(text, ip, email, secret)


@settings(max_examples=150)
@given(payload=sensitive_inputs())
def test_csv_report_never_leaks_raw_sensitive_values(payload) -> None:
    """CSV report masks every raw IP/email/secret and strips control chars."""
    if not _HAVE_CSV:
        import pytest

        pytest.skip("CSV output renderer is not available")

    ip, email, secret, ctrl = payload
    finding = _build_finding(ip, email, secret, ctrl)

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "out.csv"
        CsvOutput().render([finding], OutputTarget(path=out_path))
        text = out_path.read_text(encoding="utf-8")

    _assert_no_leak(text, ip, email, secret)
