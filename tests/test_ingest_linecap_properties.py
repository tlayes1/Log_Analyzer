# Feature: loganalyze, Property 6: No line longer than the cap is ever handed to a parser
# Validates: Requirements 2.4, 2.5, 9.4
"""Property-based test for Ingest's byte-cap enforcement.

Property 6 (design.md): for any raw line and any cap >= 1, the line
``iter_lines`` emits is at most ``cap`` UTF-8 bytes, its ``truncated`` flag is
true exactly when the original line exceeded the cap, and a truncated line's
emitted text is the byte-bounded, character-aligned prefix that
``security.cap_line`` produces. A line longer than the cap reaching a parser is
a real security bug (ReDoS / memory exhaustion); this test guards that boundary.
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loganalyze.ingest import iter_lines
from loganalyze.security import cap_line

# Exclude newline characters: iter_lines strips a trailing "\n" and the file is
# read in universal-newline text mode, so "\n"/"\r" would be normalized on read
# and would not represent the single raw line under test. The byte cap (the
# property's subject) is unaffected by this exclusion.
# Exclude the surrogate category too: lone surrogates (U+D800-U+DFFF) are not
# UTF-8 encodable and so can never appear in a real on-disk log line that
# iter_lines reads back; including them would only fail the file write, not the
# code under test.
_LINE_TEXT = st.text(
    alphabet=st.characters(blacklist_characters="\n\r", blacklist_categories=("Cs",)),
    min_size=0,
    max_size=400,
)


# tmp_path is function-scoped and so is reused across Hypothesis examples; that
# is safe here because each example writes its own file and reads it back
# immediately, with no state carried between examples.
@settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(original_line=_LINE_TEXT, cap=st.integers(min_value=1, max_value=200))
def test_no_line_longer_than_cap_reaches_parser(
    original_line: str, cap: int, tmp_path: Path
) -> None:
    log_path = tmp_path / "input.log"
    log_path.write_text(original_line + "\n", encoding="utf-8")

    records = list(iter_lines(log_path, cap))

    # Exactly one line was written, so exactly one record is emitted.
    assert len(records) == 1
    record = records[0]

    original_bytes = len(original_line.encode("utf-8"))

    # 1. The emitted line never exceeds the cap in UTF-8 bytes. This is the core
    #    security guarantee: an over-long line must never be handed onward.
    assert len(record.raw_line.encode("utf-8")) <= cap

    # 2. The truncated flag is true exactly when the original exceeded the cap.
    assert record.truncated == (original_bytes > cap)

    # 3. The emitted text matches cap_line's byte-boundary truncation exactly,
    #    and when truncated it is a genuine character-prefix of the original.
    expected_line, expected_truncated = cap_line(original_line, cap)
    assert record.raw_line == expected_line
    assert record.truncated == expected_truncated
    if record.truncated:
        assert original_line.startswith(record.raw_line)
        assert len(record.raw_line.encode("utf-8")) <= cap
    else:
        assert record.raw_line == original_line
