"""Bounded retries with exponential backoff and jitter."""

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final, Self

from packages.config import KafkaSettings

Sleep = Callable[[float], Awaitable[None]]
Jitter = Callable[[float, float], float]

_SYSTEM_RANDOM: Final = random.SystemRandom()


def default_jitter(low: float, high: float) -> float:
    """Uniformly random value in ``[low, high]``."""
    return _SYSTEM_RANDOM.uniform(low, high)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """How often and how patiently to retry.

    Attributes:
        max_attempts: Total attempts including the first one.
        initial_backoff_seconds: Backoff ceiling before the first retry.
        max_backoff_seconds: Upper bound of any backoff.
        multiplier: Growth factor of the ceiling per retry.
    """

    max_attempts: int
    initial_backoff_seconds: float
    max_backoff_seconds: float
    multiplier: float = 2.0

    @classmethod
    def from_settings(cls, settings: KafkaSettings) -> Self:
        """Build the policy from ``KAFKA_RETRY_*`` settings."""
        return cls(
            max_attempts=settings.kafka_retry_max_attempts,
            initial_backoff_seconds=settings.kafka_retry_initial_backoff_ms / 1000,
            max_backoff_seconds=settings.kafka_retry_max_backoff_ms / 1000,
        )

    def backoff_seconds(self, retry_number: int, jitter: Jitter = default_jitter) -> float:
        """Delay before the ``retry_number``-th retry (1-based), with "equal jitter".

        Half of the exponential ceiling is always waited; the other half is random, which
        spreads retries from many clients without ever retrying immediately.
        """
        ceiling = min(
            self.max_backoff_seconds,
            self.initial_backoff_seconds * self.multiplier ** (retry_number - 1),
        )
        return ceiling / 2 + jitter(0.0, ceiling / 2)


class RetryError(Exception):
    """An operation failed permanently.

    Attributes:
        attempts: Attempts made, including the first.
        last_error: The exception raised by the final attempt (also ``__cause__``).
    """

    def __init__(self, attempts: int, last_error: Exception) -> None:
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(f"gave up after {attempts} attempt(s): {type(last_error).__name__}")


async def retry_async[T](
    operation: Callable[[], Awaitable[T]],
    *,
    policy: RetryPolicy,
    is_retriable: Callable[[Exception], bool],
    on_retry: Callable[[int, Exception, float], None] | None = None,
    sleep: Sleep = asyncio.sleep,
    jitter: Jitter = default_jitter,
) -> T:
    """Run ``operation`` until it succeeds, retrying retriable failures with backoff.

    Cancellation is never retried or swallowed.

    Args:
        operation: Zero-argument coroutine factory; called once per attempt.
        policy: Attempt limit and backoff.
        is_retriable: Whether an exception is worth another attempt.
        on_retry: Called as ``(attempt, error, delay_seconds)`` before each backoff.
        sleep: Awaitable sleep, injectable for tests.
        jitter: Random source for backoff, injectable for tests.

    Returns:
        The result of the first successful attempt.

    Raises:
        RetryError: When a non-retriable error occurs or attempts are exhausted.
    """
    attempt = 1
    while True:
        try:
            return await operation()
        except Exception as error:
            if attempt >= policy.max_attempts or not is_retriable(error):
                raise RetryError(attempt, error) from error
            delay = policy.backoff_seconds(attempt, jitter)
            if on_retry is not None:
                on_retry(attempt, error, delay)
            await sleep(delay)
            attempt += 1
