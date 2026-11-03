"""Rule_Engine: run the registered signature/rule detectors over events.

The :class:`RuleEngine` is the thin, deterministic driver for the signature and
windowed-threshold detectors defined under
``loganalyze.detections.rules.signatures``. It resolves those detectors from the
shared plugin registry and runs each over the event list, concatenating every
:class:`~loganalyze.models.Finding` into a single list (design "Rule_Engine",
Requirements 5.8, 5.9).

Detector discovery (how registration is guaranteed)
---------------------------------------------------
A detector only exists in the registry once the module that applies its
``@register_detector`` decorator has been imported. This module imports the
``loganalyze.detections.rules.signatures`` package at import time; that package's
``__init__`` in turn imports its ``auth``, ``web``, and ``windowed`` modules, so
the seven rule detectors are registered before :class:`RuleEngine` ever runs. The
signature modules themselves are left untouched.

Scope (why only rule detectors run)
------------------------------------
``registry.get_detectors()`` returns *every* registered detector, which will one
day include the statistical detectors (tasks 10.x). Those are driven by a
separate ``Statistical_Engine``, so :class:`RuleEngine` must not run them. The
engine therefore keeps only detectors whose implementing class lives under the
``loganalyze.detections.rules.signatures`` package (checked via the class's
``__module__``). This is deterministic, needs no hand-maintained list of
``rule_id`` strings, and automatically excludes any detector registered from
outside the signatures package regardless of import order.

Purity
------
Like the detectors it drives, :meth:`RuleEngine.run` is a pure function of its
inputs: it performs no I/O, raises no alerts, and returns an identical result for
identical ``events``/``config``. Detectors run in the registry's deterministic
(insertion-order) sequence, so the concatenated output order is stable.
"""

from __future__ import annotations

from loganalyze.config import DetectionConfig
from loganalyze.models import Event, Finding
from loganalyze.registry import get_detectors

# Importing the signatures package runs each signature module's
# ``@register_detector`` decorator, populating the registry with the rule
# detectors before :class:`RuleEngine` resolves them. Imported for this
# registration side effect.
from loganalyze.detections.rules import signatures as _signatures  # noqa: F401

#: Dotted prefix of the package whose detectors the rule engine owns. A detector
#: is treated as a rule detector when its implementing class's ``__module__``
#: starts with this prefix, which cleanly separates the signature/windowed
#: detectors from the statistical ones driven by the Statistical_Engine.
_SIGNATURES_PACKAGE = "loganalyze.detections.rules.signatures"


def _is_rule_detector(detector: object) -> bool:
    """Return whether ``detector`` is implemented in the signatures package.

    The check inspects the detector instance's class ``__module__`` and keeps
    only those defined under :data:`_SIGNATURES_PACKAGE`. This excludes the
    statistical detectors (run by the Statistical_Engine) and any future
    detector registered from elsewhere, without relying on a hard-coded list of
    rule identifiers.

    Args:
        detector: A detector instance resolved from the registry.

    Returns:
        ``True`` if the detector's class is defined in the signatures package
        (including its submodules), ``False`` otherwise.
    """
    module = type(detector).__module__
    return module == _SIGNATURES_PACKAGE or module.startswith(
        _SIGNATURES_PACKAGE + "."
    )


class RuleEngine:
    """Resolve and run the registered signature/rule detectors.

    The engine holds no mutable state; it resolves a fresh set of detector
    instances from the registry on each :meth:`run` call and drives them in the
    registry's deterministic order. Only detectors implemented under the
    ``loganalyze.detections.rules.signatures`` package are run, so the
    statistical detectors (owned by the Statistical_Engine) are never invoked
    here even though they share one registry (Requirement 5.9).
    """

    def run(
        self, events: list[Event], config: DetectionConfig
    ) -> list[Finding]:
        """Run every rule detector over ``events`` and collect their Findings.

        Pure function of ``events`` and ``config``: it performs no I/O, raises
        no alerts, and returns an identical result for identical inputs. Each
        detector's :meth:`detect` result is concatenated in the registry's
        deterministic order, and each :class:`~loganalyze.models.Finding`
        carries exactly one :class:`~loganalyze.models.Severity` (guaranteed by
        the detectors themselves, Requirement 5.8).

        Args:
            events: The normalized events to inspect, in pipeline order.
            config: The injected detection configuration supplying rule
                thresholds and windows.

        Returns:
            A flat list of every Finding produced by the rule detectors; an
            empty list when nothing matched.
        """
        findings: list[Finding] = []
        for detector in get_detectors().values():
            if not _is_rule_detector(detector):
                continue
            findings.extend(detector.detect(events, config))
        return findings
