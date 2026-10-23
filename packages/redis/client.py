"""Async Redis access: namespaced keys, expiring (and versioned) JSON values, windows, health."""

import asyncio
import json
import logging
import re
import time
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol, Self, cast

from pydantic import JsonValue
from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError
from redis.exceptions import TimeoutError as RedisTimeoutError

from packages.config import RedisSettings

logger = logging.getLogger(__name__)

_KEY_PART: Final = re.compile(r"^[A-Za-z0-9._@-]{1,200}$")
_NAMESPACE: Final = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_RECONNECT_ATTEMPTS: Final = 2

# Atomically: refuse if the window cannot afford ``cost``, otherwise add it; the counter
# expires with its window. Returns {allowed, used, milliseconds until the window resets}.
_CONSUME_WINDOW: Final = """
local used = tonumber(redis.call('GET', KEYS[1]) or '0')
local cost = tonumber(ARGV[1])
if used + cost > tonumber(ARGV[2]) then
  local ttl = redis.call('PTTL', KEYS[1])
  if ttl < 0 then ttl = tonumber(ARGV[3]) end
  return {0, used, ttl}
end
used = redis.call('INCRBY', KEYS[1], cost)
if used == cost then redis.call('PEXPIRE', KEYS[1], ARGV[3]) end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then ttl = tonumber(ARGV[3]) end
return {1, used, ttl}
"""

# Atomically: store a JSON value that carries a numeric "version", unless the key already
# holds an equal or newer version. A fence (a revision about to be committed) blocks every
# older value and yields to a value of its own version. Anything undecodable, or without a
# numeric version, counts as absent. Returns 1 when stored, 0 when refused.
_SET_VERSIONED: Final = """
local current = redis.call('GET', KEYS[1])
local version = tonumber(ARGV[2])
if current then
  local ok, held = pcall(cjson.decode, current)
  if ok and type(held) == 'table' and type(held['version']) == 'number' then
    local stored = held['version']
    if ARGV[4] == 'fence' then
      if stored >= version then return 0 end
    elseif held['fence'] == true then
      if stored > version then return 0 end
    elseif stored >= version then
      return 0
    end
  end
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
return 1
"""


class RedisUnavailableError(Exception):
    """Redis could not answer; callers degrade instead of failing their own work."""


@dataclass(frozen=True, slots=True)
class RedisHealth:
    """Outcome of a Redis health check.

    Attributes:
        healthy: Whether ``PING`` succeeded within the timeout.
        latency_ms: Time spent on the check.
        error: Exception type name when unhealthy (messages may carry addresses).
    """

    healthy: bool
    latency_ms: float
    error: str | None = None


@dataclass(frozen=True, slots=True)
class WindowUsage:
    """Result of :meth:`RedisClient.consume_window`."""

    allowed: bool
    used: int
    reset_in_seconds: float


class RedisConnection(Protocol):
    """The subset of ``redis.asyncio.Redis`` used here."""

    async def get(self, name: str) -> bytes | None:
        """Read a key."""
        ...

    async def set(self, name: str, value: bytes, *, px: int) -> object:
        """Write a key that expires after ``px`` milliseconds."""
        ...

    async def delete(self, *names: str) -> int:
        """Delete keys."""
        ...

    async def ping(self) -> object:
        """Round trip to the server."""
        ...

    async def eval(self, script: str, numkeys: int, *keys_and_args: str | int) -> object:
        """Run a Lua script."""
        ...

    async def aclose(self) -> None:
        """Close every pooled connection."""
        ...


class RedisClient:
    """One namespace of a shared Redis. Redis is never a source of truth.

    - Keys are ``<REDIS_KEY_PREFIX>:<namespace>:<part>:...``. Parts are validated, so
      input such as a client id cannot forge another namespace's key.
    - Values are JSON and **always** expire: Redis holds cache and transient state only.
    - :meth:`set_json_versioned` never replaces a value with an older version, so a cache
      filled from an old read cannot overwrite a newer one.
    - Commands have connect and socket timeouts (``REDIS_*_TIMEOUT_SECONDS``). Dropped
      connections are re-established transparently, with a couple of quick retries.
    - Failures surface as :class:`RedisUnavailableError`, so callers can degrade.
    - :meth:`health_check` never raises.

    Nothing connects until the first command.
    """

    def __init__(
        self,
        connection: RedisConnection,
        *,
        prefix: str,
        namespace: str,
        health_timeout_seconds: float,
    ) -> None:
        if not _NAMESPACE.match(namespace) or not _NAMESPACE.match(prefix):
            raise ValueError("prefix and namespace must match [a-z][a-z0-9_-]{0,31}")
        self._connection = connection
        self._prefix = prefix
        self._namespace = namespace
        self._health_timeout_seconds = health_timeout_seconds

    @classmethod
    def from_settings(cls, settings: RedisSettings, *, namespace: str) -> Self:
        """A client for ``namespace`` from ``REDIS_*`` settings."""
        connection = Redis.from_url(
            settings.redis_url.get_secret_value(),
            socket_connect_timeout=settings.redis_connect_timeout_seconds,
            socket_timeout=settings.redis_socket_timeout_seconds,
            retry=Retry(ExponentialBackoff(cap=0.5, base=0.05), _RECONNECT_ATTEMPTS),
            retry_on_error=[RedisConnectionError, RedisTimeoutError],
            health_check_interval=30,
        )
        return cls(
            cast("RedisConnection", connection),
            prefix=settings.redis_key_prefix,
            namespace=namespace,
            health_timeout_seconds=settings.redis_health_check_timeout_seconds,
        )

    def key(self, *parts: str) -> str:
        """The full key for ``parts``.

        Raises:
            ValueError: If a part is empty or contains characters outside
                ``[A-Za-z0-9._@-]``.
        """
        if not parts or not all(_KEY_PART.match(part) for part in parts):
            raise ValueError("key parts must be 1-200 characters of [A-Za-z0-9._@-]")
        return ":".join((self._prefix, self._namespace, *parts))

    async def get_json(self, *parts: str) -> JsonValue | None:
        """The JSON value stored under ``parts``, or ``None``."""
        raw = await self._call(self._connection.get(self.key(*parts)))
        return None if raw is None else cast("JsonValue", json.loads(raw))

    async def set_json(self, *parts: str, value: JsonValue, ttl_seconds: float) -> None:
        """Store ``value`` under ``parts`` for ``ttl_seconds`` (mandatory, > 0)."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive: Redis only holds transient data")
        payload = json.dumps(value, separators=(",", ":")).encode()
        await self._call(
            self._connection.set(self.key(*parts), payload, px=max(1, round(ttl_seconds * 1000)))
        )

    async def set_json_versioned(
        self,
        *parts: str,
        value: Mapping[str, JsonValue],
        version: int,
        ttl_seconds: float,
        fence: bool = False,
    ) -> bool:
        """Store ``value`` unless the key holds an equal or newer version (atomic).

        The stored document is ``value`` with ``version`` (and ``fence: true`` for a
        fence) set. A fence of version *n* refuses every value older than *n* and yields
        to a value of version *n*: a writer fences a revision before committing it, so a
        reader still holding the previous revision cannot cache it afterwards. Returns
        whether the value was stored.
        """
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive: Redis only holds transient data")
        if isinstance(version, bool) or version < 0:
            raise ValueError("version must be a non-negative integer")
        document: dict[str, JsonValue] = {**value, "version": version}
        if fence:
            document["fence"] = True
        payload = json.dumps(document, separators=(",", ":"))
        reply: object = await self._call(
            self._connection.eval(
                _SET_VERSIONED,
                1,
                self.key(*parts),
                payload,
                version,
                max(1, round(ttl_seconds * 1000)),
                "fence" if fence else "value",
            )
        )
        return bool(reply)

    async def delete(self, *parts: str) -> bool:
        """Delete the key under ``parts``; whether it existed."""
        return bool(await self._call(self._connection.delete(self.key(*parts))))

    async def consume_window(
        self, *parts: str, cost: int, limit: int, window_seconds: float
    ) -> WindowUsage:
        """Atomically spend ``cost`` from a fixed window of ``limit`` units.

        Nothing is spent when the window cannot afford ``cost``. The counter expires with
        its window, so idle keys disappear on their own.
        """
        if cost < 1 or limit < 1 or window_seconds <= 0:
            raise ValueError("cost, limit and window_seconds must be positive")
        window_ms = max(1, round(window_seconds * 1000))
        reply: object = await self._call(
            self._connection.eval(_CONSUME_WINDOW, 1, self.key(*parts), cost, limit, window_ms)
        )
        allowed, used, reset_ms = cast("list[int]", reply)
        return WindowUsage(bool(allowed), int(used), int(reset_ms) / 1000)

    async def health_check(self) -> RedisHealth:
        """``PING`` within the health-check timeout. Never raises."""
        started = time.perf_counter()
        try:
            async with asyncio.timeout(self._health_timeout_seconds):
                await self._connection.ping()
        except Exception as error:  # a health check reports failures, it never raises
            return RedisHealth(False, _elapsed_ms(started), type(error).__name__)
        return RedisHealth(True, _elapsed_ms(started))

    async def close(self) -> None:
        """Close every pooled connection. Safe to call more than once."""
        await self._connection.aclose()

    async def _call[T](self, operation: Awaitable[T]) -> T:
        try:
            return await operation
        except (RedisError, OSError, TimeoutError) as error:
            raise RedisUnavailableError(f"redis command failed: {type(error).__name__}") from error


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)
