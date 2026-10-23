"""Exponential backoff with jitter for an agent that retries indefinitely."""

import random
from collections.abc import Callable
from typing import Final

Jitter = Callable[[float, float], float]

_SYSTEM_RANDOM: Final = random.SystemRandom()


def default_jitter(low: float, high: float) -> float:
    """Uniformly random value in ``[low, high]``."""
    return _SYSTEM_RANDOM.uniform(low, high)


class Backoff:
    """Delays that double per consecutive failure, capped, with "equal jitter".

    Half of the ceiling is always waited and the other half is random, so many agents
    recovering together do not retry in lockstep. :meth:`reset` after a success.
    """

    def __init__(
        self,
        *,
        initial_seconds: float,
        max_seconds: float,
        multiplier: float = 2.0,
        jitter: Jitter = default_jitter,
    ) -> None:
        if initial_seconds <= 0 or max_seconds < initial_seconds or multiplier < 1:
            raise ValueError("require 0 < initial_seconds <= max_seconds and multiplier >= 1")
        self._initial = initial_seconds
        self._max = max_seconds
        self._multiplier = multiplier
        self._jitter = jitter
        self._failures = 0

    @property
    def failures(self) -> int:
        """Consecutive failures since the last reset."""
        return self._failures

    def next_delay(self) -> float:
        """Record a failure and return how long to wait before the next attempt."""
        ceiling = min(self._max, self._initial * self._multiplier**self._failures)
        self._failures += 1
        return ceiling / 2 + self._jitter(0.0, ceiling / 2)

    def reset(self) -> None:
        """Forget previous failures."""
        self._failures = 0
