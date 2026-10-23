"""Redis client: namespaced keys, expiring JSON, atomic windows, failure handling."""

import asyncio

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from packages.config import RedisSettings
from packages.redis import RedisClient, RedisUnavailableError
from tests.unit.redis.fakes import FakeRedis


def _client(fake: FakeRedis, namespace: str = "api") -> RedisClient:
    return RedisClient(fake, prefix="adis", namespace=namespace, health_timeout_seconds=0.05)


def test_keys_are_prefixed_and_namespaced() -> None:
    assert _client(FakeRedis()).key("ratelimit", "agent-a") == "adis:api:ratelimit:agent-a"


@pytest.mark.parametrize("part", ["", "has space", "a:b", "x" * 201, "new\nline"])
def test_key_parts_cannot_forge_other_keys(part: str) -> None:
    with pytest.raises(ValueError, match="key parts"):
        _client(FakeRedis()).key("ratelimit", part)


def test_namespaces_are_validated() -> None:
    with pytest.raises(ValueError, match="namespace"):
        _client(FakeRedis(), namespace="Bad Namespace")


async def test_json_values_round_trip_and_expire() -> None:
    fake = FakeRedis()
    client = _client(fake)

    await client.set_json("cache", "k", value={"a": [1, 2]}, ttl_seconds=0.05)
    stored = await client.get_json("cache", "k")
    await asyncio.sleep(0.08)
    expired = await client.get_json("cache", "k")

    assert stored == {"a": [1, 2]}
    assert expired is None


async def test_values_must_expire() -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        await _client(FakeRedis()).set_json("cache", "k", value=1, ttl_seconds=0)


async def test_delete_reports_whether_the_key_existed() -> None:
    client = _client(FakeRedis())
    await client.set_json("cache", "k", value=1, ttl_seconds=10)

    assert (await client.delete("cache", "k"), await client.delete("cache", "k")) == (True, False)


async def test_windows_spend_atomically_and_refuse_without_spending() -> None:
    client = _client(FakeRedis())

    first = await client.consume_window("rl", "a", cost=6, limit=10, window_seconds=60)
    refused = await client.consume_window("rl", "a", cost=5, limit=10, window_seconds=60)
    fits = await client.consume_window("rl", "a", cost=4, limit=10, window_seconds=60)

    assert (first.allowed, first.used) == (True, 6)
    assert (refused.allowed, refused.used) == (False, 6)  # nothing spent
    assert (fits.allowed, fits.used) == (True, 10)
    assert 0 < first.reset_in_seconds <= 60


async def test_failures_surface_as_unavailable() -> None:
    fake = FakeRedis()
    fake.failure = RedisConnectionError("connection refused")
    client = _client(fake)

    with pytest.raises(RedisUnavailableError, match="ConnectionError"):
        await client.get_json("cache", "k")
    with pytest.raises(RedisUnavailableError):
        await client.consume_window("rl", "a", cost=1, limit=1, window_seconds=1)


async def test_health_check_never_raises() -> None:
    fake = FakeRedis()
    client = _client(fake)

    healthy = await client.health_check()
    fake.failure = RedisConnectionError("down")
    down = await client.health_check()
    fake.failure, fake.hang = None, True
    slow = await client.health_check()

    assert healthy.healthy
    assert (down.healthy, down.error) == (False, "ConnectionError")
    assert (slow.healthy, slow.error) == (False, "TimeoutError")


async def test_close_releases_the_pool() -> None:
    fake = FakeRedis()
    await _client(fake).close()

    assert fake.closed == 1


def test_from_settings_connects_lazily() -> None:
    settings = RedisSettings.model_validate(
        {"redis_url": "redis://:pw@127.0.0.1:1/0", "redis_key_prefix": "lab"}
    )

    client = RedisClient.from_settings(settings, namespace="api")  # no connection yet

    assert client.key("x") == "lab:api:x"
