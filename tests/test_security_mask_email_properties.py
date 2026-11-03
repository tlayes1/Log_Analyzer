# Feature: loganalyze, Property 20: Email masking reveals at most the first local character and the domain
# Validates: Requirements 8.8
"""Property-based tests for :func:`loganalyze.security.mask_email`.

Property 20 states that for any recognizable ``local@domain`` address (a single
``@``, non-empty local and domain, and no ``@`` inside the domain), masking
reveals at most the first character of the local part plus the full domain and
masks the remainder of the local part. Non-email-shaped values are routed
through :func:`loganalyze.security.mask_secret`, so no sensitive remainder
leaks through that path either.

The real contract in ``security.py`` shows the first local character verbatim
followed by an ellipsis (``local[0] + "\u2026"``) when the local part has more
than one character, and leaves a single-character local part as-is. These tests
match that implementation exactly rather than assuming a stricter shape.
"""
from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from loganalyze.security import mask_email, mask_secret

# Local part: the characters an email local part may plausibly contain, bounded
# to keep examples small and the input space realistic.
_local = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-",
    min_size=1,
    max_size=20,
)

# A DNS label: letters/digits/hyphen, bounded. Domains are one or more labels
# joined by dots (e.g. ``sub.example.com``). No ``@`` can appear here.
_label = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
    min_size=1,
    max_size=10,
)
_domain = st.builds(".".join, st.lists(_label, min_size=2, max_size=4))

# Non-email values: arbitrary text that contains no ``@`` at all, so partition
# yields an empty separator and the value is routed through mask_secret.
_non_email = st.text().filter(lambda s: "@" not in s)


@settings(max_examples=200)
@given(_local, _domain)
def test_mask_email_preserves_full_domain(local: str, domain: str) -> None:
    """The masked result ends with ``@`` + the full, unmodified domain."""
    result = mask_email(f"{local}@{domain}")
    assert result.endswith("@" + domain)


@settings(max_examples=200)
@given(_local, _domain)
def test_mask_email_reveals_at_most_first_local_char(
    local: str, domain: str
) -> None:
    """At most the first local character is shown; the tail is not leaked."""
    result = mask_email(f"{local}@{domain}")
    # Everything before the final ``@domain`` suffix is the masked local part.
    masked_local = result[: -(len(domain) + 1)]

    # The first original character is always revealed.
    assert masked_local.startswith(local[0])

    if len(local) == 1:
        # A single-character local part may be shown as-is per the code.
        assert masked_local == local
    else:
        # For longer local parts the remainder is masked: the verbatim tail
        # local[1:] must not appear anywhere in the masked local portion.
        assert local[1:] not in masked_local


@settings(max_examples=200)
@given(_non_email)
def test_mask_email_routes_non_email_through_mask_secret(s: str) -> None:
    """A value with no ``@`` is handled exactly as mask_secret would handle it."""
    assert mask_email(s) == mask_secret(s)
