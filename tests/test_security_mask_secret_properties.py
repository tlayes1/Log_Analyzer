# Feature: loganalyze, Property 19: Secret masking never reveals more than allowed and is idempotent
#
# Validates: Requirements 8.7
#
# Requirement 8.7: when rendering a Finding, credential-like string values are
# masked at the output boundary such that a masked value of 4 or fewer
# characters reveals no original characters, and a masked value longer than 4
# characters reveals at most its first 2 and last 2 characters.
#
# The real contract of ``loganalyze.security.mask_secret`` (read from the
# implementation) is:
#   - len(value) <= 4  -> "****"           (no original characters revealed)
#   - len(value) >  4  -> value[:2] + "\u2026" + value[-2:]
"""Property-based tests for :func:`loganalyze.security.mask_secret`."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from loganalyze.security import mask_secret

_ELLIPSIS = "\u2026"


@settings(max_examples=200)
@given(s=st.text())
def test_short_values_reveal_nothing(s):
    """A value of 4 or fewer chars masks to "****", revealing no originals (Req 8.7)."""
    if len(s) <= 4:
        result = mask_secret(s)
        # The sentinel is a fixed literal independent of the input content: even
        # if the input happens to equal "****", the output carries no original
        # characters because it is the same constant for every short value.
        assert result == "****"


@settings(max_examples=200)
@given(s=st.text(min_size=5))
def test_long_values_reveal_at_most_first_two_and_last_two(s):
    """A value longer than 4 chars reveals at most first 2 + last 2 (Req 8.7)."""
    result = mask_secret(s)

    # Exactly the contract: first two, an ellipsis, last two.
    assert result == s[:2] + _ELLIPSIS + s[-2:]
    assert result.startswith(s[:2])
    assert result.endswith(s[-2:])
    assert _ELLIPSIS in result

    # The middle is collapsed: at most the first two and last two characters of
    # the original survive. Everything the original contributes to the result
    # lives in those two 2-char windows, so no more than four original chars are
    # present.
    assert len(result) == len(s[:2]) + 1 + len(s[-2:])
    assert len(result) <= 5

    # For values strictly longer than 5 characters the full original can never
    # be a substring of the shorter masked form, so the middle is provably
    # collapsed and not leaked verbatim.
    if len(s) > 5:
        assert s not in result


@settings(max_examples=200)
@given(s=st.text())
def test_output_is_never_longer_than_input_or_five(s):
    """Masking never grows a value beyond 5 chars and never beyond its length+? guard (Req 8.7)."""
    result = mask_secret(s)
    # Masked output is bounded: "****" (4) for short values, or a 5-char
    # first2+ellipsis+last2 form for longer ones. It never exceeds 5 characters.
    assert len(result) <= 5


@settings(max_examples=200)
@given(s=st.text())
def test_masking_is_stable_on_its_own_output(s):
    """Idempotence as implemented: re-masking an already-masked value is stable (Req 8.7).

    The docstring of ``mask_secret`` guarantees a value already reduced to the
    masked form maps to that same form. Both masked shapes are fixed points:
      - "****" has length 4, so it re-masks to "****".
      - the 5-char first2+ellipsis+last2 form re-masks to its own first2 +
        ellipsis + last2, which for a stable masked value equals itself.
    We assert the universal fixed-point property: applying mask_secret twice
    equals applying it once whenever the once-masked value is already a fixed
    point of the contract.
    """
    once = mask_secret(s)
    twice = mask_secret(once)

    if len(once) <= 4:
        # Short masked values ("****") are fixed points.
        assert twice == once
    else:
        # The 5-char masked form re-masks to first2 + ellipsis + last2 of
        # itself. For the canonical "ab…yz" shape this is the same string.
        assert twice == once[:2] + _ELLIPSIS + once[-2:]
        assert twice == once
