"""Individual signature definitions.

Importing this package imports every signature module so that each module's
``@register_detector`` decorator runs and populates the shared registry. The
:class:`~loganalyze.detections.rules.engine.RuleEngine` imports this package for
exactly that side effect, so it can resolve the rule detectors purely by key
without naming any detector class (Requirement 5.9).

The modules are imported for their registration side effect only; the names are
re-exported so that ``from ... import signatures`` consumers and static tools
can see them, and so linters do not flag the imports as unused.
"""

from __future__ import annotations

from loganalyze.detections.rules.signatures import auth, web, windowed

__all__ = ["auth", "web", "windowed"]
