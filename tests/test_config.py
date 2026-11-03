"""Unit tests for frozen configuration models and validation helpers.

Covers the defaults mandated by the requirements, immutability of the frozen
dataclasses, and the pure validation helpers (``validate_max_line_bytes``,
``validate_z_threshold``, ``validate_rare_cutoff``).

Requirements: 2.6, 2.7, 6.3, 6.4.
"""
from __future__ import annotations

import dataclasses

import pytest

from loganalyze import config

# --- Defaults (Requirement 2.6) --------------------------------------------


def test_ingest_config_default_max_line_bytes() -> None:
    """IngestConfig defaults its line cap to 64 KiB (65536 bytes)."""
    assert config.IngestConfig().max_line_bytes == 65536


def test_rule_config_defaults() -> None:
    """RuleConfig defaults to 5/60 brute force and 20/60 status-spike."""
    rules = config.RuleConfig()
    assert rules.brute_force_threshold == 5
    assert rules.brute_force_window_seconds == 60
    assert rules.status_spike_threshold == 20
    assert rules.status_spike_window_seconds == 60


def test_statistical_config_defaults() -> None:
    """StatisticalConfig defaults match the statistical requirements."""
    stats = config.StatisticalConfig()
    assert stats.baseline_window_seconds == 60
    assert stats.z_threshold == 3.0
    assert stats.rare_cutoff == 0.01
    assert stats.min_observations == 20


def test_detection_config_nests_fresh_subconfigs() -> None:
    """DetectionConfig nests independent RuleConfig/StatisticalConfig instances."""
    detection = config.DetectionConfig()
    assert isinstance(detection.rules, config.RuleConfig)
    assert isinstance(detection.statistical, config.StatisticalConfig)
    assert detection.rules == config.RuleConfig()
    assert detection.statistical == config.StatisticalConfig()

    # Each DetectionConfig must build its own sub-config objects, not share one.
    other = config.DetectionConfig()
    assert detection.rules is not other.rules
    assert detection.statistical is not other.statistical


# --- Immutability (frozen dataclasses) -------------------------------------


@pytest.mark.parametrize(
    ("instance", "attr", "value"),
    [
        (config.IngestConfig(), "max_line_bytes", 1),
        (config.RuleConfig(), "brute_force_threshold", 10),
        (config.StatisticalConfig(), "z_threshold", 4.0),
        (config.DetectionConfig(), "rules", config.RuleConfig()),
    ],
)
def test_configs_are_frozen(instance: object, attr: str, value: object) -> None:
    """Assigning to any config attribute raises FrozenInstanceError."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(instance, attr, value)


# --- validate_max_line_bytes (Requirement 2.7) -----------------------------


@pytest.mark.parametrize("value", [1, 2, 1024, 65536, 10_000_000])
def test_validate_max_line_bytes_accepts_positive_ints(value: int) -> None:
    """Any integer of at least 1 is accepted and returned unchanged."""
    assert config.validate_max_line_bytes(value) == value


@pytest.mark.parametrize("value", [0, -1, -65536])
def test_validate_max_line_bytes_rejects_non_positive(value: int) -> None:
    """Zero and negative caps are rejected."""
    with pytest.raises(ValueError):
        config.validate_max_line_bytes(value)


@pytest.mark.parametrize("value", [True, 1.0, "64", None])
def test_validate_max_line_bytes_rejects_non_int(value: object) -> None:
    """Booleans and non-integer types are rejected (bool True is not a valid int)."""
    with pytest.raises(ValueError):
        config.validate_max_line_bytes(value)  # type: ignore[arg-type]


# --- validate_z_threshold (Requirement 6.3, inclusive 1.0-10.0) ------------


@pytest.mark.parametrize("value", [1.0, 5.5, 10.0])
def test_validate_z_threshold_accepts_in_range(value: float) -> None:
    """Values within the inclusive range [1.0, 10.0] are accepted."""
    assert config.validate_z_threshold(value) == pytest.approx(value)


@pytest.mark.parametrize("value", [0.99, 10.01])
def test_validate_z_threshold_rejects_out_of_range(value: float) -> None:
    """Values just outside the inclusive bounds are rejected."""
    with pytest.raises(ValueError):
        config.validate_z_threshold(value)


# --- validate_rare_cutoff (Requirement 6.4, open interval (0.0, 1.0)) ------


@pytest.mark.parametrize("value", [0.01, 0.5])
def test_validate_rare_cutoff_accepts_in_interval(value: float) -> None:
    """Values strictly inside the open interval (0.0, 1.0) are accepted."""
    assert config.validate_rare_cutoff(value) == pytest.approx(value)


@pytest.mark.parametrize("value", [0.0, 1.0])
def test_validate_rare_cutoff_rejects_boundaries(value: float) -> None:
    """The open-interval endpoints 0.0 and 1.0 are rejected."""
    with pytest.raises(ValueError):
        config.validate_rare_cutoff(value)
