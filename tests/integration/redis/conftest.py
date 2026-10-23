"""Integration fixtures backed by a real Redis.

Set ``TEST_REDIS_URL`` (for example ``redis://:<password>@localhost:6379/15`` with the
compose Redis) to enable these tests. Every test uses its own key prefix and deletes its
keys afterwards, so a shared development Redis is left as it was.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from packages.config import RedisSettings, load_settings
from packages.redis import RedisClient
from tests.services import require_variable

TEST_REDIS_VARIABLE = "TEST_REDIS_URL"


@pytest.fixture
def redis_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> RedisSettings:
    """Settings pointing at the test Redis with a unique key prefix; skips when unset."""
    url = require_variable(TEST_REDIS_VARIABLE)
    monkeypatch.chdir(tmp_path)  # ignore the developer's .env
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("REDIS_URL", url)
    monkeypatch.setenv("REDIS_KEY_PREFIX", f"adis-it-{uuid4().hex[:8]}")
    return load_settings(RedisSettings)


@pytest.fixture
async def redis_client(redis_settings: RedisSettings) -> AsyncIterator[RedisClient]:
    """A client in namespace ``it``; every key under the test's prefix is removed after."""
    client = RedisClient.from_settings(redis_settings, namespace="it")
    try:
        yield client
    finally:
        await client.close()
        raw = Redis.from_url(redis_settings.redis_url.get_secret_value())
        try:
            keys = [key async for key in raw.scan_iter(f"{redis_settings.redis_key_prefix}:*")]
            if keys:
                await raw.delete(*keys)
        finally:
            await raw.aclose()
