# Feature: loganalyze, Property 4: Ingest emits contiguous ascending line numbers
#
# Validates: Requirements 2.1, 2.9
#
# Property 4: For any input file content of N lines, ``iter_lines`` emits exactly
# the line numbers 1, 2, ..., N in strictly ascending order, each incremented by
# one, and preserves the originating source path on every emitted record.
from __future__ import annotations

from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loganalyze.ingest import iter_lines

MAX_LINE_BYTES = 65536

# Printable-ish line content with newlines excluded: a line generator must never
# embed the record separator, otherwise one "line" would become several records.
_line_text = st.text(
    alphabet=st.characters(
        min_codepoint=0x20,
        max_codepoint=0x7E,
    ),
    min_size=0,
    max_size=80,
)


@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(lines=st.lists(_line_text, min_size=0, max_size=50))
def test_line_numbers_are_contiguous_ascending_and_preserve_source(
    lines: list[str], tmp_path: Path
) -> None:
    """Emitted line numbers are 1..n, step 1, with the source path on each record."""
    path = tmp_path / "input.log"
    path.write_text("\n".join(lines), encoding="utf-8")

    records = list(iter_lines(path, max_line_bytes=MAX_LINE_BYTES))

    # Contiguous ascending from 1 by exactly 1: the sequence equals [1, 2, ..., n].
    numbers = [record.line_number for record in records]
    assert numbers == list(range(1, len(records) + 1))

    # Strictly increasing by exactly one between successive records.
    for previous, current in zip(records, records[1:]):
        assert current.line_number == previous.line_number + 1

    # The source path is preserved verbatim on every emitted record.
    assert all(record.source == str(path) for record in records)
