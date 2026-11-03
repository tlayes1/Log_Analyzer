"""Pure z-score helpers built on the standard-library ``statistics`` module.

The rate-spike detector baselines a series of per-bucket event counts and asks,
for each bucket, "how many standard deviations above the mean is this count?"
That quantity is the z-score ``z = (count - mean) / sigma`` where ``sigma`` is
the *population* standard deviation of the whole series.

Everything here is a pure function of its argument: no I/O, no mutable global
state, and an identical result for an identical input. Only the standard-library
``statistics`` module is used (``statistics.mean`` for the baseline and
``statistics.pstdev`` for ``sigma``), so the statistical engine stays
``numpy``/``pandas``-free for v1 (Requirements 6.1, 6.8, 10.3). The functions are
deliberately small and side-effect-free so the direct stdlib-validation tests
(task 10.4) can compare their output against hand-computed values within a 1e-9
tolerance (Requirement 11.6).

The core guard lives in :func:`z_scores`: a z-score is only meaningful when the
series has at least two buckets *and* a non-zero spread. With fewer than two
buckets there is no baseline to speak of, and when every bucket holds the same
count ``sigma`` is zero and division is undefined. In both cases the caller is
told "no scores" by an empty return, which the detector translates into "no
rate-spike finding" (Requirement 6.6).
"""

from __future__ import annotations

import statistics

#: Minimum number of baseline buckets required before any z-score can be
#: computed. With a single bucket there is no distribution to measure a bucket
#: against, so the detector must stay silent (Requirement 6.6).
MIN_BUCKETS = 2


def mean(counts: list[float]) -> float:
    """Return the arithmetic mean of ``counts`` using ``statistics.mean``.

    This is a thin, explicit wrapper so the baseline computation has a single
    named home and the direct stdlib-validation tests can target it.

    Args:
        counts: A non-empty sequence of per-bucket counts.

    Returns:
        The arithmetic mean of ``counts``.

    Raises:
        statistics.StatisticsError: If ``counts`` is empty.
    """
    return statistics.mean(counts)


def pstdev(counts: list[float]) -> float:
    """Return the population standard deviation of ``counts``.

    Uses :func:`statistics.pstdev` (population, i.e. dividing by ``N`` not
    ``N - 1``) to match the baseline model: the observed buckets *are* the whole
    series being characterized, not a sample drawn from a larger one.

    Args:
        counts: A non-empty sequence of per-bucket counts.

    Returns:
        The population standard deviation (``sigma``) of ``counts``; ``0.0`` when
        every value is identical.

    Raises:
        statistics.StatisticsError: If ``counts`` is empty.
    """
    return statistics.pstdev(counts)


def z_score(count: float, series_mean: float, sigma: float) -> float:
    """Return a single z-score ``(count - series_mean) / sigma``.

    Args:
        count: The observed bucket count being scored.
        series_mean: The baseline mean of the whole series.
        sigma: The population standard deviation of the whole series; must be
            non-zero (the caller guards this via :func:`z_scores`).

    Returns:
        The number of standard deviations ``count`` lies above (positive) or
        below (negative) ``series_mean``.

    Raises:
        ZeroDivisionError: If ``sigma`` is zero. Callers should use
            :func:`z_scores`, which guards this case per Requirement 6.6.
    """
    return (count - series_mean) / sigma


def z_scores(counts: list[float]) -> list[float]:
    """Return the per-bucket z-scores for ``counts``, or ``[]`` when undefined.

    This is the guarded entry point the rate-spike detector uses. It computes
    the population baseline (:func:`mean`, :func:`pstdev`) once and scores every
    bucket against it. The z-score is only defined when a baseline exists, so the
    function returns an empty list — telling the caller to produce no finding —
    whenever either guard trips (Requirement 6.6):

    * fewer than :data:`MIN_BUCKETS` (two) buckets are available, so there is no
      distribution to measure against; or
    * the population standard deviation is zero (every bucket holds the same
      count), so the z-score ``(count - mean) / sigma`` would divide by zero.

    When scores are returned, ``result[i]`` is the z-score of ``counts[i]`` and
    the output has the same length and order as the input.

    Args:
        counts: Per-bucket event counts in bucket order.

    Returns:
        A list of z-scores parallel to ``counts``, or an empty list when a
        baseline cannot be formed.
    """
    if len(counts) < MIN_BUCKETS:
        return []

    series_mean = mean(counts)
    sigma = pstdev(counts)
    if sigma == 0:
        return []

    return [z_score(count, series_mean, sigma) for count in counts]
