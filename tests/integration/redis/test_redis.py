"""The Redis client and the shared rate limiter against a real Redis."""

import asyncio
import random

import pytest

from apps.api.rate_limit import RedisRateLimiter, TokenBucketRateLimiter
from packages.config import RedisSettings, load_settings
from packages.redis import RedisClient, RedisUnavailableError

pytestmark = pytest.mark.integration


def _limiter(client: RedisClient, *, capacity: int, window_seconds: float) -> RedisRateLimiter:
    fallback = TokenBucketRateLimiter(capacity=capacity, window_seconds=window_seconds)
    return RedisRateLimiter(
        client, capacity=capacity, window_seconds=window_seconds, fallback=fallback
    )


async def test_health_check_reports_a_reachable_server(redis_client: RedisClient) -> None:
    health = await redis_client.health_check()

    assert (health.healthy, health.error) == (True, None)


async def test_json_values_round_trip_and_expire(redis_client: RedisClient) -> None:
    await redis_client.set_json("memory", "sig-1", value={"score": 0.9}, ttl_seconds=0.3)

    assert await redis_client.get_json("memory", "sig-1") == {"score": 0.9}
    await asyncio.sleep(0.6)
    assert await redis_client.get_json("memory", "sig-1") is None


async def test_delete_reports_whether_the_key_existed(redis_client: RedisClient) -> None:
    await redis_client.set_json("state", "x", value=[1, 2], ttl_seconds=30)

    assert await redis_client.delete("state", "x") is True
    assert await redis_client.delete("state", "x") is False


async def test_window_is_atomic_under_concurrency(redis_client: RedisClient) -> None:
    # 50 concurrent spends of 3 against a window of 100: exactly 33 fit (99 units).
    results = await asyncio.gather(
        *(
            redis_client.consume_window("window", "k", cost=3, limit=100, window_seconds=30)
            for _ in range(50)
        )
    )

    assert sum(result.allowed for result in results) == 33
    assert max(result.used for result in results) == 99
    assert all(0 < result.reset_in_seconds <= 30 for result in results)


async def test_window_resets_after_it_expires(redis_client: RedisClient) -> None:
    first = await redis_client.consume_window("window", "r", cost=5, limit=5, window_seconds=0.3)
    refused = await redis_client.consume_window("window", "r", cost=1, limit=5, window_seconds=0.3)
    await asyncio.sleep(0.6)
    later = await redis_client.consume_window("window", "r", cost=1, limit=5, window_seconds=0.3)

    assert (first.allowed, refused.allowed, later.allowed) == (True, False, True)
    assert later.used == 1


async def test_replicas_share_one_budget(
    redis_client: RedisClient, redis_settings: RedisSettings
) -> None:
    other_replica = RedisClient.from_settings(redis_settings, namespace="it")
    try:
        first = _limiter(redis_client, capacity=10, window_seconds=30)
        second = _limiter(other_replica, capacity=10, window_seconds=30)

        spent = await first.acquire("agent-a", 6)
        refused = await second.acquire("agent-a", 6)  # the in-memory limiter would allow it
        rest = await second.acquire("agent-a", 4)
        other_client = await second.acquire("agent-b", 6)
    finally:
        await other_replica.close()

    assert (spent.allowed, spent.remaining) == (True, 4)
    assert (refused.allowed, refused.remaining) == (False, 4)
    assert refused.retry_after_seconds > 0
    assert (rest.allowed, rest.remaining) == (True, 0)
    assert other_client.allowed


async def test_unreachable_server_degrades_to_the_fallback(
    redis_settings: RedisSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Nothing listens on port 1: commands fail fast and the limiter falls back.
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    client = RedisClient.from_settings(load_settings(RedisSettings), namespace="it")
    fallbacks: list[None] = []
    limiter = RedisRateLimiter(
        client,
        capacity=5,
        window_seconds=30,
        fallback=TokenBucketRateLimiter(capacity=5, window_seconds=30),
        on_fallback=lambda: fallbacks.append(None),
    )
    try:
        health = await client.health_check()
        with pytest.raises(RedisUnavailableError):
            await client.get_json("anything")
        decision = await limiter.acquire("agent-a", 1)
    finally:
        await client.close()

    assert health.healthy is False
    assert decision.allowed
    assert fallbacks == [None]


async def test_versioned_values_never_go_back(redis_client: RedisClient) -> None:
    assert await redis_client.set_json_versioned("m", value={"v": "a"}, version=2, ttl_seconds=60)
    assert not await redis_client.set_json_versioned(
        "m", value={"v": "b"}, version=2, ttl_seconds=60
    )
    assert not await redis_client.set_json_versioned(
        "m", value={"v": "c"}, version=1, ttl_seconds=60
    )
    assert await redis_client.get_json("m") == {"v": "a", "version": 2}
    assert await redis_client.set_json_versioned("m", value={"v": "d"}, version=3, ttl_seconds=60)
    assert await redis_client.get_json("m") == {"v": "d", "version": 3}


async def test_a_fence_blocks_older_values_and_yields_to_its_own(
    redis_client: RedisClient,
) -> None:
    assert await redis_client.set_json_versioned("m", value={}, version=1, ttl_seconds=60)
    assert await redis_client.set_json_versioned(
        "m", value={}, version=2, ttl_seconds=60, fence=True
    )
    assert not await redis_client.set_json_versioned(
        "m", value={"old": True}, version=1, ttl_seconds=60
    )
    assert not await redis_client.set_json_versioned(
        "m", value={}, version=2, ttl_seconds=60, fence=True
    )
    assert await redis_client.get_json("m") == {"version": 2, "fence": True}
    assert await redis_client.set_json_versioned(
        "m", value={"new": True}, version=2, ttl_seconds=60
    )
    assert await redis_client.get_json("m") == {"new": True, "version": 2}
    # A fence never replaces an equal or newer value.
    assert not await redis_client.set_json_versioned(
        "m", value={}, version=2, ttl_seconds=60, fence=True
    )


async def test_versioned_writes_replace_garbage_and_expire(redis_client: RedisClient) -> None:
    raw = redis_client.key("m")
    connection = redis_client._connection
    await connection.set(raw, b"\xff not json", px=60_000)
    assert await redis_client.set_json_versioned("m", value={}, version=1, ttl_seconds=0.2)
    await connection.set(raw, b'{"version": "9"}', px=60_000)  # a non-numeric version
    assert await redis_client.set_json_versioned("m", value={}, version=1, ttl_seconds=0.2)
    await asyncio.sleep(0.4)
    assert await redis_client.get_json("m") is None
    with pytest.raises(ValueError, match="positive"):
        await redis_client.set_json_versioned("m", value={}, version=1, ttl_seconds=0)
    with pytest.raises(ValueError, match="non-negative"):
        await redis_client.set_json_versioned("m", value={}, version=-1, ttl_seconds=1)


async def test_concurrent_versioned_writes_keep_the_newest(redis_client: RedisClient) -> None:
    versions = list(range(1, 41))
    random.Random(3).shuffle(versions)
    await asyncio.gather(
        *(
            redis_client.set_json_versioned("m", value={"n": n}, version=n, ttl_seconds=60)
            for n in versions
        )
    )
    assert await redis_client.get_json("m") == {"n": 40, "version": 40}
