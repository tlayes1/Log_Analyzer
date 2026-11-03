"""Direct validation of the stdlib ``statistics`` path (task 10.4).

These tests exercise :mod:`loganalyze.detections.statistical.zscore` directly,
comparing its output against the standard-library ``statistics`` module and
against hand-computed values within an absolute tolerance of ``1e-9``
(Requirement 11.6). They also assert the statistical engine stays
``numpy``/``pandas``-free (Requirements 6.1, 6.8, 10.3).
"""

from __future__ import annotations

import importlib
import math
import statistics
import sys

import pytest

from loganalyze.detections.statistical import zscore

ABS_TOL = 1e-9


def _isclose(a: float, b: float) -> bool:
    return math.isclose(a, b, abs_tol=ABS_TOL)


# ---------------------------------------------------------------------------
# mean / pstdev agree with the standard library and hand-computed values
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "counts, hand_mean, hand_pstdev",
    [
        # mean = 15/5 = 3; variance = mean of squared deviations
        #   deviations: -2,-1,0,1,2 -> squares 4,1,0,1,4 = 10; /5 = 2; sqrt(2)
        ([1.0, 2.0, 3.0, 4.0, 5.0], 3.0, math.sqrt(2.0)),
        # all equal -> mean 7, population stdev 0
        ([7.0, 7.0, 7.0], 7.0, 0.0),
        # two buckets: mean 5, deviations -5,5 -> squares 25,25=50;/2=25;sqrt=5
        ([0.0, 10.0], 5.0, 5.0),
    ],
)
def test_mean_and_pstdev_match_stdlib_and_hand_values(counts, hand_mean, hand_pstdev):
    # Agrees with the standard-library statistics module (Requirement 6.1).
    assert _isclose(zscore.mean(counts), statistics.mean(counts))
    assert _isclose(zscore.pstdev(counts), statistics.pstdev(counts))

    # Agrees with independently hand-computed values (Requirement 11.6).
    assert _isclose(zscore.mean(counts), hand_mean)
    assert _isclose(zscore.pstdev(counts), hand_pstdev)


# ---------------------------------------------------------------------------
# z_score is exactly (count - mean) / sigma
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "count, series_mean, sigma",
    [
        (10.0, 4.0, 2.0),
        (0.0, 5.0, 2.5),
        (3.0, 3.0, 1.0),  # on the mean -> z == 0
        (-4.0, 1.0, 5.0),
    ],
)
def test_z_score_is_normalized_distance(count, series_mean, sigma):
    expected = (count - series_mean) / sigma
    assert _isclose(zscore.z_score(count, series_mean, sigma), expected)


# ---------------------------------------------------------------------------
# z_scores matches the per-bucket formula over the whole series
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "counts",
    [
        [1.0, 2.0, 3.0, 4.0, 5.0],
        [0.0, 10.0],
        [2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 7.0, 25.0],
    ],
)
def test_z_scores_match_manual_formula(counts):
    series_mean = statistics.mean(counts)
    sigma = statistics.pstdev(counts)
    expected = [(c - series_mean) / sigma for c in counts]

    result = zscore.z_scores(counts)

    assert len(result) == len(expected)
    for got, want in zip(result, expected):
        assert _isclose(got, want)


def test_z_scores_known_spike_example():
    """A concrete, pre-computed example with a clear spike bucket.

    ``counts`` has nine quiet buckets of 2, one of 7, and one spike of 25.
    """
    counts = [2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 7.0, 25.0]

    # Hand-derived baseline: sum = 50, n = 11 -> mean = 50 / 11.
    expected_mean = 50.0 / 11.0
    assert _isclose(zscore.mean(counts), expected_mean)

    series_mean = statistics.mean(counts)
    sigma = statistics.pstdev(counts)
    scores = zscore.z_scores(counts)

    # The spike bucket is the last one; its z-score is the largest.
    spike_z = scores[-1]
    assert _isclose(spike_z, (25.0 - series_mean) / sigma)
    assert spike_z == max(scores)
    # Buckets below the mean score negative; the quiet "2" buckets do.
    assert scores[0] < 0


# ---------------------------------------------------------------------------
# Guard behavior (Requirement 6.6)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("counts", [[], [5.0]])
def test_z_scores_empty_for_fewer_than_two_buckets(counts):
    assert zscore.z_scores(counts) == []


@pytest.mark.parametrize("counts", [[7.0, 7.0, 7.0], [0.0, 0.0], [3.3, 3.3, 3.3, 3.3]])
def test_z_scores_empty_when_sigma_is_zero(counts):
    # All-equal counts -> population stdev is zero -> no scores (Requirement 6.6).
    assert statistics.pstdev(counts) == 0
    assert zscore.z_scores(counts) == []


# ---------------------------------------------------------------------------
# No numpy / pandas in the statistical path (Requirements 6.1, 6.8, 10.3)
# ---------------------------------------------------------------------------

STATISTICAL_MODULES = [
    "loganalyze.detections.statistical.zscore",
    "loganalyze.detections.statistical.rate_spike",
    "loganalyze.detections.statistical.rare_event",
    "loganalyze.detections.statistical.engine",
]


@pytest.mark.parametrize("module_name", STATISTICAL_MODULES)
def test_statistical_module_imports_without_numpy_or_pandas(module_name):
    """Importing a statistical module must not pull in numpy or pandas.

    We drop any already-loaded ``numpy``/``pandas`` entries, re-import the
    module fresh, and assert neither heavy library was loaded as a side effect
    of that import.
    """
    heavy = {
        name
        for name in list(sys.modules)
        if name == "numpy"
        or name == "pandas"
        or name.startswith("numpy.")
        or name.startswith("pandas.")
    }
    saved = {name: sys.modules[name] for name in heavy}
    for name in heavy:
        del sys.modules[name]

    sys.modules.pop(module_name, None)

    try:
        importlib.import_module(module_name)
        assert "numpy" not in sys.modules, f"{module_name} imported numpy"
        assert "pandas" not in sys.modules, f"{module_name} imported pandas"
    finally:
        # Restore whatever we removed so we don't disturb other tests.
        sys.modules.update(saved)
