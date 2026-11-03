# Feature: loganalyze, Property 3: Timestamp normalization is offset-correct
#
# Validates: Requirements 3.7, 3.8
#
# Requirement 3.7 (aware): when a timestamp carries an explicit UTC offset or a
# ``Z`` designator, ``normalize_timestamp`` converts it to UTC and reports it as
# aware. Requirement 3.8 (naive): when a timestamp carries no timezone
# information, it is recorded as a naive local datetime with no offset applied.
"""Property-based tests for :func:`loganalyze.models.normalize_timestamp`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from loganalyze.models import normalize_timestamp

# Format strings used by the tests. ``%z`` makes strptime parse an explicit
# offset (including ``Z``); omitting ``%z`` yields a naive datetime.
_FMT_AWARE = "%Y-%m-%d %H:%M:%S %z"
_FMT_NAIVE = "%Y-%m-%d %H:%M:%S"

# Explicit offsets exercised by the aware case: UTC, a positive half-hour
# offset, and a negative whole-hour offset. ``offset_str`` is what gets written
# into the raw timestamp with the ``%z`` format.
_OFFSETS = [
    ("+0000", timezone.utc),
    ("+0530", timezone(timedelta(hours=5, minutes=30))),
    ("-0800", timezone(timedelta(hours=-8))),
]

# Bound the generated datetimes so every offset shift stays representable and
# strftime/strptime round-trip without platform-specific edge cases. The format
# strings under test have second precision (no ``%f``), so sub-second detail is
# not representable in the raw string; drop microseconds in the generator so the
# round-trip compares like for like.
_datetimes = st.datetimes(
    min_value=datetime(1, 1, 2, 0, 0, 0),
    max_value=datetime(9999, 12, 30, 23, 59, 59),
).map(lambda d: d.replace(microsecond=0))


@settings(max_examples=200)
@given(naive_dt=_datetimes, offset=st.sampled_from(_OFFSETS))
def test_offset_sources_normalize_to_utc(naive_dt, offset):
    """An explicit UTC offset is converted to UTC and reported aware (Req 3.7)."""
    offset_str, tz = offset
    aware_dt = naive_dt.replace(tzinfo=tz)
    raw = f"{naive_dt:%Y-%m-%d %H:%M:%S} {offset_str}"

    dt, aware = normalize_timestamp(raw, _FMT_AWARE)

    assert aware is True
    assert dt.tzinfo == timezone.utc
    # The instant is preserved: the returned UTC datetime equals the input
    # instant converted to UTC.
    assert dt == aware_dt.astimezone(timezone.utc)


@settings(max_examples=200)
@given(naive_dt=_datetimes)
def test_zulu_sources_normalize_to_utc(naive_dt):
    """A ``Z`` designator is treated as UTC and reported aware (Req 3.7)."""
    raw = f"{naive_dt:%Y-%m-%d %H:%M:%S} Z"

    dt, aware = normalize_timestamp(raw, _FMT_AWARE)

    assert aware is True
    assert dt.tzinfo == timezone.utc
    # ``Z`` means a zero offset, so the UTC instant equals the wall-clock value.
    assert dt == naive_dt.replace(tzinfo=timezone.utc)


@settings(max_examples=200)
@given(naive_dt=_datetimes)
def test_naive_sources_stay_naive(naive_dt):
    """A timestamp without timezone info stays naive, no offset (Req 3.8)."""
    raw = f"{naive_dt:%Y-%m-%d %H:%M:%S}"

    dt, aware = normalize_timestamp(raw, _FMT_NAIVE)

    assert aware is False
    assert dt.tzinfo is None
    # No offset is applied: the wall-clock fields are preserved exactly.
    assert dt == naive_dt
