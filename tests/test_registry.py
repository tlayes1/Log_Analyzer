"""Unit tests for the plugin registry (``loganalyze.registry``).

The registry stores parsers, detectors, and outputs in three module-global
``dict`` objects (``_PARSERS``, ``_DETECTORS``, ``_OUTPUTS``) that real plugin
modules populate at import time. These tests must not depend on, or disturb,
that real content.

Isolation approach:
    * Every test registers under unique, test-only keys (prefixed ``test_``)
      and uses throwaway dummy classes, so a test key can never collide with a
      real plugin key.
    * An autouse fixture snapshots the three global dicts before each test and
      restores them afterwards, so any key a test registers is rolled back and
      does not leak into other tests or the real registry.
    * Assertions check only the keys a test itself registered (membership,
      relative ordering of test keys). They never assert the exact global
      contents, which depend on which real plugin modules happened to import.

Covers Requirements 3.10 (resolution by key, no pipeline edits), 3.11
(duplicate-key registration is rejected), 5.9, and 8.14.
"""
from __future__ import annotations

import pytest

from loganalyze import registry
from loganalyze.registry import (
    RegistryConflictError,
    get_detectors,
    get_outputs,
    get_parser,
    get_parsers,
    register_detector,
    register_output,
    register_parser,
)


@pytest.fixture(autouse=True)
def _isolate_registries():
    """Snapshot and restore the module-global registries around each test.

    Copies the three backing dicts before the test and rewrites their contents
    afterwards, so test-only keys registered during a test never leak into the
    real registry or into sibling tests.
    """
    saved_parsers = dict(registry._PARSERS)
    saved_detectors = dict(registry._DETECTORS)
    saved_outputs = dict(registry._OUTPUTS)
    try:
        yield
    finally:
        registry._PARSERS.clear()
        registry._PARSERS.update(saved_parsers)
        registry._DETECTORS.clear()
        registry._DETECTORS.update(saved_detectors)
        registry._OUTPUTS.clear()
        registry._OUTPUTS.update(saved_outputs)


# --- Dummy plugin classes --------------------------------------------------
# Minimal stand-ins that satisfy the structural protocols enough for the
# registry (which only stores the class and instantiates it with no args).


class _DummyParser:
    """A no-op parser stand-in; the registry only stores and instantiates it."""

    log_type = "dummy"

    def parse(self, raw_line):  # pragma: no cover - never invoked here
        return None


class _DummyDetector:
    """A no-op detector stand-in."""

    rule_id = "dummy.rule"

    def detect(self, events, config):  # pragma: no cover - never invoked here
        return []


class _DummyOutput:
    """A no-op output stand-in."""

    def render(self, findings, target):  # pragma: no cover - never invoked here
        return None


# --- Registration + lookup by key ------------------------------------------


def test_register_and_get_parser_resolves_and_instantiates():
    """A registered parser is resolved by key and returned as an instance."""
    register_parser("test_parser_a")(_DummyParser)

    instance = get_parser("test_parser_a")

    assert isinstance(instance, _DummyParser)
    # get_parser instantiates fresh each call rather than returning the class.
    assert instance is not get_parser("test_parser_a")


def test_get_parsers_contains_registered_key_as_instance():
    """get_parsers includes the registered test key, mapped to an instance."""
    register_parser("test_parser_b")(_DummyParser)

    parsers = get_parsers()

    assert "test_parser_b" in parsers
    assert isinstance(parsers["test_parser_b"], _DummyParser)


def test_register_and_get_detectors_resolves_and_instantiates():
    """A registered detector appears in get_detectors as an instance."""
    register_detector("test_detector_a")(_DummyDetector)

    detectors = get_detectors()

    assert "test_detector_a" in detectors
    assert isinstance(detectors["test_detector_a"], _DummyDetector)


def test_register_and_get_outputs_resolves_and_instantiates():
    """A registered output appears in get_outputs as an instance."""
    register_output("test_output_a")(_DummyOutput)

    outputs = get_outputs()

    assert "test_output_a" in outputs
    assert isinstance(outputs["test_output_a"], _DummyOutput)


# --- Deterministic ordering -------------------------------------------------


def test_get_parsers_preserves_insertion_order_of_test_keys():
    """Several test parsers resolve in the order they were registered."""
    keys = ["test_order_c", "test_order_a", "test_order_b"]

    for key in keys:
        # A distinct subclass per key keeps the dummy classes independent.
        register_parser(key)(type(f"P_{key}", (_DummyParser,), {}))

    # Filter get_parsers() down to only this test's keys, preserving the dict's
    # (insertion) ordering, then compare to the registration order.
    resolved = [k for k in get_parsers() if k in keys]

    assert resolved == keys


# --- Duplicate-key registration rejected (Requirement 3.11) ----------------


def test_duplicate_parser_key_raises_conflict():
    """Re-registering a parser key raises RegistryConflictError, no override."""
    register_parser("test_dup_parser")(_DummyParser)

    with pytest.raises(RegistryConflictError):
        register_parser("test_dup_parser")(
            type("OtherParser", (_DummyParser,), {})
        )

    # The original class is still the one registered (no silent override).
    assert isinstance(get_parser("test_dup_parser"), _DummyParser)


def test_duplicate_detector_key_raises_conflict():
    """Re-registering a detector key raises RegistryConflictError."""
    register_detector("test_dup_detector")(_DummyDetector)

    with pytest.raises(RegistryConflictError):
        register_detector("test_dup_detector")(
            type("OtherDetector", (_DummyDetector,), {})
        )


def test_duplicate_output_key_raises_conflict():
    """Re-registering an output key raises RegistryConflictError."""
    register_output("test_dup_output")(_DummyOutput)

    with pytest.raises(RegistryConflictError):
        register_output("test_dup_output")(
            type("OtherOutput", (_DummyOutput,), {})
        )


# --- Missing key ------------------------------------------------------------


def test_get_parser_missing_key_returns_none():
    """Resolving an unregistered key yields None rather than raising."""
    assert get_parser("definitely_missing_key") is None
