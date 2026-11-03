# Feature: loganalyze, Property 17: Output contains no forbidden control characters
#
# Validates: Requirements 8.4
#
# For any string, ``loganalyze.security.strip_control`` preserves the tab
# character (``\t``), emits no code point in U+0000–U+0008, U+000B–U+001F, or
# U+007F, and is idempotent (``strip(strip(x)) == strip(x)``).
"""Property-based tests for :func:`loganalyze.security.strip_control`."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from loganalyze.security import strip_control

# The forbidden control code points: U+0000–U+0008, U+000B–U+001F, and U+007F.
# The tab (U+0009), newline (U+000A), and everything at or above U+0020 except
# U+007F are permitted to pass through unchanged.
_FORBIDDEN = (
    set(range(0x00, 0x09)) | set(range(0x0B, 0x20)) | {0x7F}
)

# Draw text over the full Unicode range so control characters are generated
# frequently; mix in a dedicated control-character alphabet to guarantee the
# forbidden set and the tab are exercised rather than left to chance.
_text = st.text(
    alphabet=st.one_of(
        st.characters(min_codepoint=0x00, max_codepoint=0x10FFFF),
        st.sampled_from([chr(cp) for cp in sorted(_FORBIDDEN)] + ["\t"]),
    ),
    max_size=200,
)


@settings(max_examples=200)
@given(_text)
def test_strip_control_removes_all_forbidden_controls(text: str) -> None:
    """No forbidden control code point survives stripping."""
    result = strip_control(text)
    assert not any(ord(ch) in _FORBIDDEN for ch in result)


@settings(max_examples=200)
@given(_text)
def test_strip_control_preserves_every_tab(text: str) -> None:
    """Every tab in the input is preserved in the output."""
    result = strip_control(text)
    assert result.count("\t") == text.count("\t")


@settings(max_examples=200)
@given(_text)
def test_strip_control_is_idempotent(text: str) -> None:
    """Applying the stripper twice equals applying it once."""
    once = strip_control(text)
    assert strip_control(once) == once
