"""Shared data contract for the loganalyze pipeline.

This module defines the only types that cross component boundaries: the
:class:`Severity` enumeration, the normalized :class:`Event` emitted by every
parser, and the explainable :class:`Finding` produced by every detector. Their
shapes mirror the schemas in ``detection-rules.md`` exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum


class Severity(IntEnum):
    """Finding severity; ordering value drives ranking (critical highest).

    The integer values give a natural rank so the aggregator can sort
    descending with ``critical`` leading. The serialized string forms are
    ``info``, ``low``, ``medium``, ``high``, and ``critical``.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        """Return the lowercase serialized form (e.g. ``"critical"``)."""
        return self.name.lower()


@dataclass(frozen=True)
class Event:
    """Normalized record emitted by a Parser.

    The required fields (``timestamp``, ``source``, ``log_type``, ``message``,
    ``raw``) are always populated; ``fields`` defaults to an empty mapping. Every
    optional field defaults to ``None`` so an absent value is explicit rather
    than guessed.
    """

    timestamp: datetime
    source: str
    log_type: str
    message: str
    raw: str
    fields: dict[str, str] = field(default_factory=dict)
    host: str | None = None
    client_ip: str | None = None
    user: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None


@dataclass
class Finding:
    """Explainable detection result.

    ``detail`` and ``metadata`` carry the human- and machine-readable
    explanation of what matched and why. Each finding carries exactly one
    :class:`Severity`.
    """

    rule_id: str
    title: str
    severity: Severity
    events: list[Event]
    detail: str
    metadata: dict


def normalize_timestamp(raw: str, fmt: str) -> tuple[datetime, bool]:
    """Parse a timestamp string into a datetime and report its awareness.

    The source is parsed with :meth:`datetime.datetime.strptime` using ``fmt``.
    When the parsed value carries an explicit UTC offset or ``Z`` designator
    (``fmt`` includes ``%z``), the datetime is converted to UTC and reported as
    aware. When the source carries no timezone information, it is recorded as a
    naive local datetime with no offset applied.

    This is a pure function: it performs no I/O, reads no mutable global state,
    and never raises for input that is parseable under ``fmt``.

    Args:
        raw: The raw timestamp string to parse.
        fmt: A :func:`time.strftime`/``strptime`` format string describing
            ``raw``. Include ``%z`` to parse an explicit offset or ``Z``.

    Returns:
        A ``(dt, aware)`` tuple. ``aware`` is ``True`` when the source carried an
        explicit offset or ``Z`` (``dt`` is then in UTC); ``False`` when the
        source was naive (``dt`` is a naive local datetime, no offset applied).
    """
    parsed = datetime.strptime(raw, fmt)
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc), True
    return parsed, False
