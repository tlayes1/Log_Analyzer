# Feature: loganalyze, Property 21: IP masking reveals at most the first two octets
# Validates: Requirements 8.9
"""Property-based tests for :func:`loganalyze.security.mask_ip`.

Property 21 states that masking a dotted-quad client IP reveals at most its
first two octets and masks the rest. The real contract in
``loganalyze.security.mask_ip`` is: for a four-part dotted quad ``a.b.c.d`` the
result is ``f"{a}.{b}.x.x"`` (first two octets revealed, last two replaced by
``x``); for any value that is not a four-part dotted quad the result collapses
to a fully masked ``x.x.x.x`` so no address detail leaks.

The tests below exercise both branches: generated dotted-quad addresses (built
from integer octets, including leading-zero string forms) and strings that do
not split into exactly four dot-separated parts.
"""
from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from loganalyze.security import mask_ip

# A single octet as an integer in the valid 0..255 range.
_octet = st.integers(min_value=0, max_value=255)

# Octet rendered as a string: either its plain decimal form or a leading-zero
# padded form (e.g. "007"). mask_ip splits on ".", so leading zeros must not
# break the first-two-octets-revealed contract.
_octet_str = st.one_of(
    _octet.map(str),
    _octet.map(lambda n: f"{n:03d}"),
)


@settings(max_examples=200)
@given(_octet_str, _octet_str, _octet_str, _octet_str)
def test_mask_ip_reveals_at_most_first_two_octets(
    a: str, b: str, c: str, d: str
) -> None:
    """A dotted quad reveals exactly its first two octets; the rest is masked."""
    ip = f"{a}.{b}.{c}.{d}"
    result = mask_ip(ip)

    # First two octets revealed verbatim, last two masked to literal "x".
    assert result == f"{a}.{b}.x.x"

    # At most two octets revealed: the masked tail is always ".x.x".
    assert result.endswith(".x.x")

    # The result is itself a four-part dotted quad.
    revealed = result.split(".")
    assert len(revealed) == 4
    assert revealed[:2] == [a, b]
    assert revealed[2:] == ["x", "x"]

    # The third and fourth octets never leak into the masked positions.
    assert revealed[2] == "x"
    assert revealed[3] == "x"


@settings(max_examples=200)
@given(
    st.text().filter(lambda s: len(s.split(".")) != 4),
)
def test_mask_ip_non_dotted_quad_is_fully_masked(s: str) -> None:
    """Anything that is not a four-part dotted quad collapses to x.x.x.x."""
    assert mask_ip(s) == "x.x.x.x"


@settings(max_examples=200)
@given(_octet_str, _octet_str, _octet_str, _octet_str)
def test_mask_ip_is_idempotent_on_its_output(
    a: str, b: str, c: str, d: str
) -> None:
    """Re-masking an already-masked a.b.x.x value maps back to itself."""
    once = mask_ip(f"{a}.{b}.{c}.{d}")
    assert mask_ip(once) == once
