"""Retry policy and retry loop."""

import asyncio

import pytest

from packages.config import KafkaSettings
from packages.kafka import RetryError, RetryPolicy, retry_async
from tests.unit.kafka.fakes import RecordingSleep, upper_jitter

POLICY = RetryPolicy(max_attempts=4, initial_backoff_seconds=0.1, max_backoff_seconds=0.3)


class Flaky:
    """Fails ``failures`` times, then returns ``"ok"``."""

    def __init__(self, failures: int, error: Exception | None = None) -> None:
        self.failures = failures
        self.error = error or ConnectionError("transient")
        self.calls = 0

    async def __call__(self) -> str:
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error
        return "ok"


def test_policy_from_settings() -> None:
    settings = KafkaSettings.model_validate(
        {
            "kafka_retry_max_attempts": 7,
            "kafka_retry_initial_backoff_ms": 250,
            "kafka_retry_max_backoff_ms": 4_000,
        }
    )

    assert RetryPolicy.from_settings(settings) == RetryPolicy(
        max_attempts=7, initial_backoff_seconds=0.25, max_backoff_seconds=4.0
    )


def test_backoff_grows_exponentially_and_is_capped() -> None:
    delays = [POLICY.backoff_seconds(n, upper_jitter) for n in range(1, 5)]

    assert delays == pytest.approx([0.1, 0.2, 0.3, 0.3])


def test_backoff_always_waits_at_least_half_the_ceiling() -> None:
    assert POLICY.backoff_seconds(2, lambda low, high: low) == pytest.approx(0.1)


async def test_succeeds_after_transient_failures() -> None:
    operation, sleep = Flaky(failures=2), RecordingSleep()
    retries: list[int] = []

    result = await retry_async(
        operation,
        policy=POLICY,
        is_retriable=lambda error: True,
        on_retry=lambda attempt, error, delay: retries.append(attempt),
        sleep=sleep,
        jitter=upper_jitter,
    )

    assert result == "ok"
    assert operation.calls == 3
    assert retries == [1, 2]
    assert sleep.delays == pytest.approx([0.1, 0.2])


async def test_gives_up_after_max_attempts() -> None:
    operation = Flaky(failures=10)

    with pytest.raises(RetryError) as caught:
        await retry_async(
            operation, policy=POLICY, is_retriable=lambda error: True, sleep=RecordingSleep()
        )

    assert operation.calls == 4
    assert caught.value.attempts == 4
    assert isinstance(caught.value.last_error, ConnectionError)
    assert caught.value.__cause__ is caught.value.last_error


async def test_non_retriable_error_stops_immediately() -> None:
    operation, sleep = Flaky(failures=10, error=ValueError("permanent")), RecordingSleep()

    with pytest.raises(RetryError) as caught:
        await retry_async(
            operation,
            policy=POLICY,
            is_retriable=lambda error: not isinstance(error, ValueError),
            sleep=sleep,
        )

    assert operation.calls == 1
    assert caught.value.attempts == 1
    assert sleep.delays == []


async def test_cancellation_is_not_retried() -> None:
    calls = 0

    async def cancelled() -> None:
        nonlocal calls
        calls += 1
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await retry_async(
            cancelled, policy=POLICY, is_retriable=lambda error: True, sleep=RecordingSleep()
        )

    assert calls == 1
