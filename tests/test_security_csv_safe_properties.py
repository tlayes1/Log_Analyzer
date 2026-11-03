# Feature: loganalyze, Property 18: CSV fields never begin with a bare formula character
# Validates: Requirements 8.5
"""Property-based tests for :func:`loganalyze.security.csv_safe`.

Property 18 states that for any field value the CSV-neutralized output never
begins with a bare formula character (``=``, ``+``, ``-``, ``@``) — such values
are apostrophe-prefixed — and that re-applying the neutralizer does not change
an already-safe field. An apostrophe is not a formula character, so a value that
has already been neutralized is returned unchanged, making ``csv_safe``
idempotent on its own output.
"""
from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from loganalyze.security import csv_safe

# The four characters a spreadsheet treats as the start of a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@")

# Draw arbitrary text, but bias toward strings that begin with a formula
# character so the neutralizing branch is exercised frequently rather than by
# chance alone.
_text = st.text()
_formula_leading = st.builds(
    lambda c, rest: c + rest,
    st.sampled_from(_FORMULA_PREFIXES),
    st.text(),
)
_values = st.one_of(_text, _formula_leading)


@settings(max_examples=200)
@given(_values)
def test_csv_safe_matches_specified_behavior(s: str) -> None:
    """csv_safe apostrophe-prefixes formula-leading values and leaves the rest."""
    result = csv_safe(s)
    if s and s[0] in _FORMULA_PREFIXES:
        assert result == "'" + s
        assert result[0] == "'"
    else:
        assert result == s


@settings(max_examples=200)
@given(_values)
def test_csv_safe_output_never_begins_with_bare_formula_char(s: str) -> None:
    """The neutralized output never starts with a bare formula character."""
    result = csv_safe(s)
    if result:
        assert result[0] not in _FORMULA_PREFIXES


@settings(max_examples=200)
@given(_values)
def test_csv_safe_is_idempotent_on_its_output(s: str) -> None:
    """Re-applying csv_safe to an already-safe field changes nothing."""
    once = csv_safe(s)
    assert csv_safe(once) == once
