"""Frozen configuration models and pure validation helpers for loganalyze.

This module is the single source of truth for runtime configuration. Every
dataclass here is frozen and carries defaults that match the requirements
exactly (line cap 64 KiB; brute force 5 events / 60s; status spike 20 events /
60s; baseline window 60s; z-threshold 3.0; rare cutoff 0.01; minimum
observations 20).

The validation helpers are pure and perform no I/O so the CLI can call them to
reject out-of-range configuration before ingest begins. Detectors receive
configuration by injection and never read it from the environment or from files,
per ``coding-conventions.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

#: Default line-length cap in bytes (64 KiB), enforced by ingest before any
#: regex is applied to a line (Requirement 2.6).
MAX_LINE_BYTES_DEFAULT = 65536

#: Inclusive bounds for the statistical z-score threshold (Requirement 6.3).
Z_THRESHOLD_MIN = 1.0
Z_THRESHOLD_MAX = 10.0


@dataclass(frozen=True)
class IngestConfig:
    """Ingest-stage configuration.

    Attributes:
        max_line_bytes: Maximum number of bytes read from a single line before
            the line is truncated and skipped. Defaults to 64 KiB
            (Requirement 2.6).
    """

    max_line_bytes: int = MAX_LINE_BYTES_DEFAULT


@dataclass(frozen=True)
class RuleConfig:
    """Thresholds and windows for the signature/rule detectors.

    Attributes:
        brute_force_threshold: Failed-auth events for one client IP within the
            window that trigger a brute-force finding (default 5, Requirement
            5.4/5.10).
        brute_force_window_seconds: Sliding-window span in seconds for
            brute-force detection (default 60).
        status_spike_threshold: HTTP error-status events within the window that
            trigger a status-code-spike finding (default 20, Requirement
            5.5/5.10).
        status_spike_window_seconds: Sliding-window span in seconds for
            status-code-spike detection (default 60).
    """

    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 60
    status_spike_threshold: int = 20
    status_spike_window_seconds: int = 60


@dataclass(frozen=True)
class StatisticalConfig:
    """Parameters for the statistical anomaly detectors.

    Attributes:
        baseline_window_seconds: Fixed bucket duration in seconds for baselining
            (default 60, Requirement 6.2).
        z_threshold: Z-score at or above which a bucket is flagged as a rate
            spike (default 3.0, configurable within the inclusive range
            1.0-10.0, Requirement 6.3).
        rare_cutoff: Relative-frequency cutoff below which a categorical value is
            flagged as rare (default 0.01, configurable within the open interval
            (0.0, 1.0), Requirement 6.4).
        min_observations: Minimum samples required before rare-event detection
            runs on a categorical series (default 20, Requirement 6.7).
    """

    baseline_window_seconds: int = 60
    z_threshold: float = 3.0
    rare_cutoff: float = 0.01
    min_observations: int = 20


@dataclass(frozen=True)
class DetectionConfig:
    """Aggregate detection configuration injected into the detectors.

    Attributes:
        rules: Signature/rule-engine thresholds and windows.
        statistical: Statistical-engine parameters.
    """

    rules: RuleConfig = field(default_factory=RuleConfig)
    statistical: StatisticalConfig = field(default_factory=StatisticalConfig)


@dataclass(frozen=True)
class RunConfig:
    """Top-level configuration for a single batch run.

    Attributes:
        input_paths: Input files and/or directories supplied at invocation.
        format_override: Registry key of a parser to apply to all input, or
            None to auto-detect per input.
        report_json_path: Resolved path for the JSON report, or None when no
            JSON report is requested.
        report_csv_path: Resolved path for the optional CSV report, or None when
            no CSV report is requested.
        report_html_path: Resolved path for the self-contained HTML report, or
            None when no HTML report is requested.
        ingest: Ingest-stage configuration.
        detection: Detection-stage configuration.
    """

    input_paths: list[Path]
    format_override: str | None
    report_json_path: Path | None
    report_csv_path: Path | None
    report_html_path: Path | None = None
    ingest: IngestConfig = field(default_factory=IngestConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)


def validate_max_line_bytes(max_line_bytes: int) -> int:
    """Validate the line-length cap.

    Args:
        max_line_bytes: Candidate cap in bytes.

    Returns:
        The validated cap unchanged.

    Raises:
        ValueError: If the value is not an integer of at least 1
            (Requirement 2.7).
    """
    if isinstance(max_line_bytes, bool) or not isinstance(max_line_bytes, int):
        raise ValueError(
            f"line-length cap must be an integer of at least 1, got "
            f"{max_line_bytes!r}"
        )
    if max_line_bytes < 1:
        raise ValueError(
            f"line-length cap must be at least 1, got {max_line_bytes}"
        )
    return max_line_bytes


def validate_z_threshold(z_threshold: float) -> float:
    """Validate the statistical z-score threshold.

    Args:
        z_threshold: Candidate z-score threshold.

    Returns:
        The validated threshold unchanged.

    Raises:
        ValueError: If the value is outside the inclusive range 1.0-10.0
            (Requirement 6.3).
    """
    if isinstance(z_threshold, bool) or not isinstance(z_threshold, (int, float)):
        raise ValueError(
            f"z-threshold must be a number in [{Z_THRESHOLD_MIN}, "
            f"{Z_THRESHOLD_MAX}], got {z_threshold!r}"
        )
    if not (Z_THRESHOLD_MIN <= z_threshold <= Z_THRESHOLD_MAX):
        raise ValueError(
            f"z-threshold must be within [{Z_THRESHOLD_MIN}, {Z_THRESHOLD_MAX}], "
            f"got {z_threshold}"
        )
    return float(z_threshold)


def validate_rare_cutoff(rare_cutoff: float) -> float:
    """Validate the rare-event relative-frequency cutoff.

    Args:
        rare_cutoff: Candidate cutoff.

    Returns:
        The validated cutoff unchanged.

    Raises:
        ValueError: If the value is not strictly inside the open interval
            (0.0, 1.0) (Requirement 6.4).
    """
    if isinstance(rare_cutoff, bool) or not isinstance(rare_cutoff, (int, float)):
        raise ValueError(
            f"rare-event cutoff must be a number in (0.0, 1.0), got "
            f"{rare_cutoff!r}"
        )
    if not (0.0 < rare_cutoff < 1.0):
        raise ValueError(
            f"rare-event cutoff must be within the open interval (0.0, 1.0), "
            f"got {rare_cutoff}"
        )
    return float(rare_cutoff)
