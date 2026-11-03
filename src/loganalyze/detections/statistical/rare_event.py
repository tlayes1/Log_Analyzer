"""Rare-event statistical detector (standard-library only).

This module implements rare-event anomaly detection for the Statistical_Engine.
Over a *categorical series* extracted from the normalized
:class:`~loganalyze.models.Event` records, it computes each distinct value's
**relative frequency** ``count(value) / total`` and flags every value whose
relative frequency is *strictly below* ``config.statistical.rare_cutoff``
(default ``0.01``) (Requirement 6.4). When fewer than
``config.statistical.min_observations`` samples are available for the series, the
detector yields nothing (Requirement 6.7).

Categoricals
------------
Two categoricals are documented and extracted, each from the log family that
naturally carries it, so the detector is useful across both web and auth input
without guessing a meaningless series:

- **HTTP status code** — ``Event.status`` for web events (``log_type`` in
  ``{"nginx", "apache"}``). A status that almost never appears (e.g. a lone
  ``500`` amid a sea of ``200`` responses) is surfaced as rare.
- **Authentication user** — ``Event.user`` for auth events
  (``log_type == "authlog"``). A user that authenticates far less often than the
  population is surfaced as rare.

Each categorical is treated as its own independent series: counts, totals, the
``min_observations`` guard, and the rare-value decision are all computed
*within* a single series and never mixed across categoricals.

Engine coupling
---------------
Like the rate-spike detector (task 10.1), this detector is **not** registered in
the shared detector registry that the :class:`Rule_Engine` iterates. The
Rule_Engine and the Statistical_Engine are distinct engines with distinct inputs
and lifecycles; registering a statistical detector in the shared registry would
make the Rule_Engine iterate and run it as if it were a signature detector,
coupling the two engines. Instead the detector is exposed as a plain importable
class, :class:`RareEventDetector`, that the Statistical_Engine constructs and
calls directly (see :meth:`RareEventDetector.detect`). This keeps the two
engines decoupled and mirrors how ``rate_spike`` is exposed.

Standard library only
----------------------
All counting uses :class:`collections.Counter`; no ``numpy``/``pandas`` is
imported or required (Requirements 6.1, 6.8, 10.3).
"""

from __future__ import annotations

from collections import Counter

from loganalyze.config import DetectionConfig
from loganalyze.models import Event, Finding, Severity

#: Stable rule identifier carried onto every rare-event Finding.
RULE_ID = "stat.rare_event"

#: ``log_type`` values whose events carry an HTTP status code categorical.
_WEB_LOG_TYPES = ("nginx", "apache")

#: ``log_type`` value whose events carry an authenticating-user categorical.
_AUTH_LOG_TYPE = "authlog"


def _status_series(events: list[Event]) -> list[str]:
    """Extract the HTTP-status categorical series from web events.

    Each web event (``log_type`` in :data:`_WEB_LOG_TYPES`) with a non-``None``
    ``status`` contributes one sample, rendered as its decimal string (e.g.
    ``"200"``, ``"500"``). Non-web events and web events without a status are
    excluded, so the series reflects only observations where the categorical is
    actually present.

    Args:
        events: The normalized events to inspect, in pipeline order.

    Returns:
        The list of status-code samples, in event order.
    """
    return [
        str(event.status)
        for event in events
        if event.log_type in _WEB_LOG_TYPES and event.status is not None
    ]


def _user_series(events: list[Event]) -> list[str]:
    """Extract the authenticating-user categorical series from auth events.

    Each auth event (``log_type == "authlog"``) with a non-empty ``user``
    contributes one sample. Non-auth events and auth events without a user are
    excluded.

    Args:
        events: The normalized events to inspect, in pipeline order.

    Returns:
        The list of user samples, in event order.
    """
    return [
        event.user
        for event in events
        if event.log_type == _AUTH_LOG_TYPE and event.user
    ]


class RareEventDetector:
    """Flag categorical values whose relative frequency is rare (LOW).

    For each documented categorical series (HTTP ``status`` for web events and
    authenticating ``user`` for auth events), this detector counts each distinct
    value, computes its relative frequency ``count / total``, and yields one
    :class:`~loganalyze.models.Finding` per value whose relative frequency is
    *strictly below* ``config.statistical.rare_cutoff`` (Requirement 6.4). A
    series with fewer than ``config.statistical.min_observations`` samples is
    skipped entirely and produces no Finding (Requirement 6.7).

    Severity is :attr:`~loganalyze.models.Severity.LOW`: a rare value is a weak,
    context-free anomaly signal (a single unusual status or user) rather than a
    confirmed attack, so it is ranked below the signature detectors while still
    surfacing for review.

    The detector is pure: :meth:`detect` inspects only the events and the
    injected configuration, performs no I/O, raises no alerts, and returns an
    identical result for identical inputs. It is invoked directly by the
    Statistical_Engine rather than through the shared detector registry (see the
    module docstring).

    Attributes:
        rule_id: The stable identifier ``"stat.rare_event"`` carried onto every
            Finding this detector produces.
    """

    rule_id = RULE_ID

    def detect(self, events: list[Event], config: DetectionConfig) -> list[Finding]:
        """Return rare-event findings across the documented categoricals.

        Each categorical series is evaluated independently: the per-series
        ``min_observations`` guard, counts, total, and rare-value decision are
        computed only from that series' samples. Findings are emitted in a
        deterministic order — categoricals in a fixed order (status, then user)
        and, within a categorical, rare values ordered by ascending count then
        value — so identical inputs always yield an identical result.

        Pure: inspects only ``events`` and ``config``; performs no I/O.

        Args:
            events: The normalized events to inspect, in pipeline order.
            config: The injected detection configuration supplying
                ``statistical.rare_cutoff`` and ``statistical.min_observations``.

        Returns:
            One Finding per rare categorical value; an empty list when no value
            is rare or when every series is below ``min_observations``.
        """
        statistical = config.statistical
        cutoff = statistical.rare_cutoff
        min_observations = statistical.min_observations

        findings: list[Finding] = []
        series_specs = (
            ("status", "HTTP status code", _status_series(events)),
            ("user", "authenticating user", _user_series(events)),
        )
        for categorical, label, samples in series_specs:
            findings.extend(
                self._detect_series(
                    categorical=categorical,
                    label=label,
                    samples=samples,
                    cutoff=cutoff,
                    min_observations=min_observations,
                    events=events,
                )
            )
        return findings

    def _detect_series(
        self,
        *,
        categorical: str,
        label: str,
        samples: list[str],
        cutoff: float,
        min_observations: int,
        events: list[Event],
    ) -> list[Finding]:
        """Return rare-value findings for one categorical series.

        Args:
            categorical: The short categorical key (``"status"`` / ``"user"``)
                recorded in metadata and used to collect contributing events.
            label: Human-readable categorical name used in ``detail``.
            samples: The extracted samples for this series, in event order.
            cutoff: The rare-event relative-frequency cutoff (exclusive upper
                bound): a value is rare when ``count / total < cutoff``.
            min_observations: Minimum samples required before the series is
                evaluated; below this the series yields nothing (Requirement
                6.7).
            events: The full event list, used to collect the events that
                contributed each rare value onto the Finding.

        Returns:
            Zero or more Findings for this series, ordered by ascending count
            then value for determinism.
        """
        total = len(samples)
        if total < min_observations:
            return []

        counts = Counter(samples)
        # Baseline context: the distribution's size and its most common value's
        # relative frequency, so a reviewer sees what "normal" looks like for
        # this series (Requirement 6.5).
        distinct_values = len(counts)
        most_common_value, most_common_count = counts.most_common(1)[0]
        most_common_frequency = most_common_count / total

        rare = [
            (value, count)
            for value, count in counts.items()
            if count / total < cutoff
        ]
        # Deterministic ordering: ascending count, then value.
        rare.sort(key=lambda item: (item[1], item[0]))

        findings: list[Finding] = []
        for value, count in rare:
            frequency = count / total
            contributing = self._events_for_value(events, categorical, value)
            metadata = {
                "categorical": categorical,
                # Baseline value: overall distribution shape for the series.
                "baseline": {
                    "total_observations": total,
                    "distinct_values": distinct_values,
                    "most_common_value": most_common_value,
                    "most_common_frequency": most_common_frequency,
                },
                # Observed value: the rare value and how often it occurred.
                "observed": {
                    "value": value,
                    "count": count,
                },
                # Score: the rare value's relative frequency.
                "score": frequency,
                # Threshold: the configured rare-event cutoff.
                "threshold": cutoff,
            }
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Rare categorical value",
                    severity=Severity.LOW,
                    events=contributing,
                    detail=(
                        f"{label} {value!r} occurred {count} of {total} times "
                        f"(relative frequency {frequency:.4g}), strictly below "
                        f"the rare-event cutoff {cutoff:.4g}."
                    ),
                    metadata=metadata,
                )
            )
        return findings

    @staticmethod
    def _events_for_value(
        events: list[Event], categorical: str, value: str
    ) -> list[Event]:
        """Collect the events that contributed a given rare categorical value.

        Args:
            events: The full event list, in pipeline order.
            categorical: Which categorical to read (``"status"`` / ``"user"``).
            value: The rendered categorical value to match.

        Returns:
            The events, in pipeline order, whose categorical equals ``value``.
        """
        if categorical == "status":
            return [
                event
                for event in events
                if event.log_type in _WEB_LOG_TYPES
                and event.status is not None
                and str(event.status) == value
            ]
        return [
            event
            for event in events
            if event.log_type == _AUTH_LOG_TYPE and event.user == value
        ]
