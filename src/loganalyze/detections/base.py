"""Detector protocol: the shared contract every detector implements.

A detector consumes the normalized :class:`~loganalyze.models.Event` records
produced by the parsers (plus an injected
:class:`~loganalyze.config.DetectionConfig`) and yields explainable
:class:`~loganalyze.models.Finding` results. Detectors are pure functions of
their inputs: they perform no file or network I/O and raise no alerts. All
side effects (console tables, report files, masking) belong to the output
plugins, so a detector can be exercised in isolation and its results are fully
determined by the events and configuration it is given.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from loganalyze.config import DetectionConfig
from loganalyze.models import Event, Finding


@runtime_checkable
class Detector(Protocol):
    """Structural contract for a rule or statistical detector.

    A conforming detector exposes a stable ``rule_id`` and a pure
    :meth:`detect` method. Implementations are registered under a registry key
    and resolved by the engines without changes to the pipeline module.

    Attributes:
        rule_id: Stable identifier carried onto every Finding this detector
            produces (for example ``"web.sqli.probe"``). It is the key the
            aggregator groups and deduplicates on.
    """

    rule_id: str

    def detect(self, events: list[Event], config: DetectionConfig) -> list[Finding]:
        """Return zero or more Findings for the given events.

        The method is pure: it inspects only ``events`` and ``config``,
        performs no I/O, raises no alerts, and returns an identical result for
        identical inputs. An empty list means the detector matched nothing.

        Args:
            events: The normalized events to inspect, in pipeline order.
            config: The injected detection configuration supplying thresholds,
                windows, and statistical parameters.

        Returns:
            A list of zero or more Findings describing what matched.
        """
        ...
