"""Windowed threshold detectors: brute force and HTTP status-code spike.

Unlike the single-line signature detectors in this package, these two
detectors reason over *sequences* of events across a sliding time window. Both
are pure functions of their inputs (the event list plus the injected
:class:`~loganalyze.config.DetectionConfig`): they perform no I/O, raise no
alerts, and return identical results for identical inputs regardless of the
order in which events arrive (Requirements 7.1, 7.2).

Determinism over an arbitrary input order is achieved by sorting the
contributing events by :attr:`~loganalyze.models.Event.timestamp` and sliding a
fixed, *half-open* window ``[t, t + window)``: an event at exactly
``t + window`` falls into the next window, not the current one. For each
candidate start event the detector counts how many later events fall inside the
window and fires a single :class:`~loganalyze.models.Finding` the first time the
count reaches or exceeds the configured threshold, so a sustained burst yields
one finding rather than one per event (Requirements 5.4, 5.5, 5.10).

Detectors registered here
-------------------------
* ``auth.bruteforce`` (:data:`~loganalyze.models.Severity.HIGH`) — failed-auth
  events (authlog Events with ``fields["event"] == "failed_login"``) grouped by
  ``client_ip``; fires when at least ``config.rules.brute_force_threshold``
  (default 5) such events for one IP fall within
  ``config.rules.brute_force_window_seconds`` (default 60s).
* ``web.status_spike`` (:data:`~loganalyze.models.Severity.MEDIUM`) — HTTP
  error-status events (Events with ``status is not None and status >= 400``);
  fires when at least ``config.rules.status_spike_threshold`` (default 20) fall
  within ``config.rules.status_spike_window_seconds`` (default 60s).

On mixed aware/naive timestamps within a single run, this module assumes the
run's events are consistently naive or aware (the pipeline emits a separate
mixed-timezone warning). Should a :class:`TypeError` arise from comparing an
aware and a naive datetime during sorting, the detector degrades gracefully by
falling back to a normalized, string-based sort key rather than raising.
"""

from __future__ import annotations

from datetime import timedelta

from loganalyze.config import DetectionConfig
from loganalyze.models import Event, Finding, Severity
from loganalyze.registry import register_detector

#: HTTP status at or above which a response is treated as an error for the
#: status-code-spike detector.
_HTTP_ERROR_STATUS = 400


def _sorted_by_timestamp(events: list[Event]) -> list[Event]:
    """Return ``events`` sorted ascending by timestamp, deterministically.

    Sorting first on the raw :class:`~datetime.datetime` gives correct temporal
    ordering for a run whose events are consistently naive or consistently
    aware. If the list mixes aware and naive datetimes, comparing them raises
    :class:`TypeError`; in that case we fall back to a stable string key so the
    detector still produces a deterministic (if timezone-agnostic) ordering
    instead of propagating the error.

    Args:
        events: The events to order; not mutated.

    Returns:
        A new list containing the same events in ascending timestamp order.
    """
    try:
        return sorted(events, key=lambda e: e.timestamp)
    except TypeError:
        # Mixed aware/naive timestamps in one run: sort on the ISO string,
        # which is total across both kinds and keeps results deterministic.
        return sorted(events, key=lambda e: e.timestamp.isoformat())


def _first_window_reaching_threshold(
    events: list[Event], window: timedelta, threshold: int
) -> list[Event] | None:
    """Find the earliest half-open window containing ``threshold`` events.

    ``events`` must already be sorted ascending by timestamp. For each event
    treated as a window start ``t``, count the contiguous run of events whose
    timestamp lies in ``[t, t + window)``. The first start whose window holds at
    least ``threshold`` events returns exactly those contributing events.

    Because the input is sorted, the events inside any window form a contiguous
    slice, so a single forward scan per start suffices and the result does not
    depend on the original iteration order (Requirement 5.10).

    Args:
        events: Candidate events, pre-sorted ascending by timestamp.
        window: The window span; the window is half-open ``[t, t + window)``.
        threshold: Minimum number of in-window events required to fire.

    Returns:
        The list of contributing events for the earliest qualifying window, or
        ``None`` if no window reaches the threshold.
    """
    if threshold <= 0:
        # A non-positive threshold would fire on empty input; guard so the
        # detectors never produce a finding for a threshold that cannot be
        # meaningfully exceeded.
        return None
    n = len(events)
    if n < threshold:
        return None

    for start in range(n - threshold + 1):
        window_end = events[start].timestamp + window
        count = 0
        for probe in range(start, n):
            # Half-open window: an event exactly at the boundary belongs to the
            # next window, not this one.
            if events[probe].timestamp < window_end:
                count += 1
            else:
                break
        if count >= threshold:
            return events[start : start + count]
    return None


@register_detector("auth.bruteforce")
class BruteForceDetector:
    """Detect failed-auth bursts from a single client IP within a window.

    Groups failed-login events by ``client_ip`` and fires a single HIGH-severity
    finding per IP whose failed attempts reach the configured threshold inside
    the configured window (Requirements 5.4, 5.8, 5.10).

    Attributes:
        rule_id: The registry key ``"auth.bruteforce"`` carried onto every
            Finding this detector produces.
    """

    rule_id = "auth.bruteforce"

    def detect(self, events: list[Event], config: DetectionConfig) -> list[Finding]:
        """Return brute-force Findings for the given events.

        Pure function of ``events`` and ``config``: no I/O, no alerting, order
        independent. Only authlog events marked ``fields["event"] ==
        "failed_login"`` that carry a ``client_ip`` are considered; events
        without an IP cannot be attributed to a source and are ignored.

        Args:
            events: The normalized events to inspect, in any order.
            config: Injected detection configuration supplying the brute-force
                threshold and window.

        Returns:
            A list of zero or more HIGH-severity Findings, one per offending
            ``client_ip``, ordered by that IP for determinism.
        """
        threshold = config.rules.brute_force_threshold
        window = timedelta(seconds=config.rules.brute_force_window_seconds)

        # Group candidate failed-login events by their source IP. Guard against
        # empty input implicitly: an empty mapping yields no findings.
        by_ip: dict[str, list[Event]] = {}
        for event in events:
            if (
                event.fields.get("event") == "failed_login"
                and event.client_ip is not None
            ):
                by_ip.setdefault(event.client_ip, []).append(event)

        findings: list[Finding] = []
        # Iterate IPs in sorted order so the output ordering is deterministic
        # regardless of input order.
        for client_ip in sorted(by_ip):
            ordered = _sorted_by_timestamp(by_ip[client_ip])
            contributing = _first_window_reaching_threshold(
                ordered, window, threshold
            )
            if contributing is None:
                continue

            observed = len(contributing)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Brute-force authentication burst",
                    severity=Severity.HIGH,
                    events=contributing,
                    detail=(
                        f"{observed} failed authentication attempts from "
                        f"{client_ip} within "
                        f"{config.rules.brute_force_window_seconds}s "
                        f"(threshold {threshold})"
                    ),
                    metadata={
                        "client_ip": client_ip,
                        "count": observed,
                        "threshold": threshold,
                        "window_seconds": config.rules.brute_force_window_seconds,
                    },
                )
            )
        return findings


@register_detector("web.status_spike")
class StatusSpikeDetector:
    """Detect a spike of HTTP error-status responses within a window.

    Fires a single MEDIUM-severity finding when at least the configured
    threshold of error-status events (``status >= 400``) fall within the
    configured window (Requirements 5.5, 5.8, 5.10).

    Attributes:
        rule_id: The registry key ``"web.status_spike"`` carried onto every
            Finding this detector produces.
    """

    rule_id = "web.status_spike"

    def detect(self, events: list[Event], config: DetectionConfig) -> list[Finding]:
        """Return a status-code-spike Finding for the given events.

        Pure function of ``events`` and ``config``: no I/O, no alerting, order
        independent. Only events carrying an HTTP ``status`` of 400 or greater
        contribute; events without a status (e.g. auth events) are ignored.

        Args:
            events: The normalized events to inspect, in any order.
            config: Injected detection configuration supplying the status-spike
                threshold and window.

        Returns:
            A list with a single MEDIUM-severity Finding when a window reaches
            the threshold, or an empty list otherwise.
        """
        threshold = config.rules.status_spike_threshold
        window = timedelta(seconds=config.rules.status_spike_window_seconds)

        error_events = [
            event
            for event in events
            if event.status is not None and event.status >= _HTTP_ERROR_STATUS
        ]

        ordered = _sorted_by_timestamp(error_events)
        contributing = _first_window_reaching_threshold(ordered, window, threshold)
        if contributing is None:
            return []

        observed = len(contributing)
        return [
            Finding(
                rule_id=self.rule_id,
                title="HTTP error-status spike",
                severity=Severity.MEDIUM,
                events=contributing,
                detail=(
                    f"{observed} HTTP error-status responses within "
                    f"{config.rules.status_spike_window_seconds}s "
                    f"(threshold {threshold})"
                ),
                metadata={
                    "count": observed,
                    "threshold": threshold,
                    "window_seconds": config.rules.status_spike_window_seconds,
                },
            )
        ]
