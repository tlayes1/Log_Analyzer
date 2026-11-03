# Feature: loganalyze, Property 5: Gzip and plaintext ingest agree
# Validates: Requirements 2.2, 2.3
"""Property-based test that gzip and plaintext ingest agree.

For any text content, the line records produced from the gzip-compressed form of
that content equal -- modulo the source path -- the line records produced from the
plaintext form. This exercises the ingest requirement that gzip input is detected
by its magic bytes and decompressed (Requirement 2.2) while plaintext input is read
directly (Requirement 2.3), and that both paths yield the same ascending,
byte-capped line records.
"""
from __future__ import annotations

import gzip
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from loganalyze.ingest import LineRecord, iter_lines

# A generous but finite per-line cap; the generated content stays well under it so
# neither path truncates, and the two streams are compared purely on content.
MAX_LINE_BYTES = 65536

# The gzip magic bytes that ingest sniffs for (0x1f 0x8b). Asserting on them keeps
# the test honest that the compressed fixture really is detected as gzip rather than
# read as plaintext.
_GZIP_MAGIC = b"\x1f\x8b"

# Lines contain no embedded newline so that joining with "\n" yields exactly the
# intended number of records; control chars and unicode are otherwise fair game as
# untrusted log content. Lone surrogates are excluded because they cannot be UTF-8
# encoded to bytes on disk at all, which is outside the space of real log files
# (whose bytes decode to valid text) that this property is about.
line_strategy = st.text(
    alphabet=st.characters(blacklist_characters="\n", blacklist_categories=("Cs",)),
    max_size=200,
)


def _non_source_fields(record: LineRecord) -> tuple[int, str, bool]:
    """Return the record's content fields, excluding the differing source path."""
    return (record.line_number, record.raw_line, record.truncated)


@settings(max_examples=100)
@given(lines=st.lists(line_strategy, max_size=50))
def test_gzip_and_plaintext_ingest_agree(lines: list[str]) -> None:
    """Gzip and plaintext ingest of identical content agree modulo source path.

    A fresh temporary directory is created per example (rather than relying on the
    function-scoped ``tmp_path`` fixture, which Hypothesis does not reset between
    generated inputs) so each example reads clean files.
    """
    content = "\n".join(lines)
    encoded = content.encode("utf-8")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        plain = tmp_path / "plain.log"
        plain.write_bytes(encoded)

        zipped = tmp_path / "zipped.log"
        zipped.write_bytes(gzip.compress(encoded))

        # Guard the premise of the property: the compressed file must actually
        # begin with the gzip magic bytes, or ingest would read it as plaintext.
        assert zipped.read_bytes()[:2] == _GZIP_MAGIC

        plain_records = list(iter_lines(plain, MAX_LINE_BYTES))
        zipped_records = list(iter_lines(zipped, MAX_LINE_BYTES))

        # Same number of records from both forms.
        assert len(plain_records) == len(zipped_records)

        # Each record agrees on every field except the source path.
        plain_content = [_non_source_fields(r) for r in plain_records]
        zipped_content = [_non_source_fields(r) for r in zipped_records]
        assert plain_content == zipped_content

        # The source paths are the only thing that legitimately differs.
        assert all(r.source == str(plain) for r in plain_records)
        assert all(r.source == str(zipped) for r in zipped_records)
