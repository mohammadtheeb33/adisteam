"""Rate limiting architecture of the ingestion API.

Limits are expressed in **events** per client (a batch of 50 costs 50), which is what
downstream capacity depends on. :class:`RateLimiter` is the extension point:

- :class:`TokenBucketRateLimiter` keeps buckets in process memory, which is exact for a
  single API instance; with several replicas each enforces its own budget.
- :class:`RedisRateLimiter` (``API_RATE_LIMIT_BACKEND=redis``) shares one budget per
  client between every replica, in atomic fixed windows. When Redis cannot answer, it
  falls back to the in-memory limiter, so ingestion never depends on Redis, and leaves
  Redis alone for a few seconds, so an outage never adds its timeouts to every request.
"""

import logging
import math
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol, Self

from packages.config import ApiSettings
from packages.redis import RedisClient, RedisUnavailableError

logger = logging.getLogger(__name__)

DEFAULT_MAX_TRACKED_CLIENTS: Final = 10_000
FALLBACK_LOG_INTERVAL_SECONDS: Final = 30.0
REDIS_RETRY_INTERVAL_SECONDS: Final = 5.0


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Outcome of charging a client."""

    allowed: bool
    limit: int
    remaining: int
    reset_after_seconds: float
    retry_after_seconds: float

    def headers(self) -> dict[str, str]:
        """IETF ``RateLimit-*`` headers (draft-ietf-httpapi-ratelimit-headers)."""
        return {
            "RateLimit-Limit": str(self.limit),
            "RateLimit-Remaining": str(self.remaining),
            "RateLimit-Reset": str(math.ceil(self.reset_after_seconds)),
        }


class RateLimiter(Protocol):
    """Charges ``cost`` units to ``key`` and says whether that is allowed."""

    async def acquire(self, key: str, cost: int) -> RateLimitDecision:
        """Charge ``cost``; nothing is charged when the decision is not allowed."""
        ...


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class TokenBucketRateLimiter:
    """In-process token bucket per key.

    Each key may spend ``capacity`` units at once and regains them at
    ``capacity / window_seconds`` per second. The least recently used keys are evicted
    beyond ``max_keys``, which bounds memory.
    """

    def __init__(
        self,
        *,
        capacity: int,
        window_seconds: float,
        max_keys: int = DEFAULT_MAX_TRACKED_CLIENTS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capacity < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("capacity, window_seconds and max_keys must be positive")
        self._capacity = capacity
        self._refill_per_second = capacity / window_seconds
        self._max_keys = max_keys
        self._clock = clock
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()

    @classmethod
    def from_settings(cls, settings: ApiSettings) -> Self:
        """``API_RATE_LIMIT_EVENTS`` per ``API_RATE_LIMIT_WINDOW_SECONDS``."""
        return cls(
            capacity=settings.api_rate_limit_events,
            window_seconds=settings.api_rate_limit_window_seconds,
        )

    async def acquire(self, key: str, cost: int) -> RateLimitDecision:
        """Charge ``cost`` units to ``key``."""
        if cost < 1:
            raise ValueError("cost must be positive")
        now = self._clock()
        bucket = self._buckets.pop(key, None) or _Bucket(tokens=self._capacity, updated=now)
        bucket.tokens = min(
            self._capacity, bucket.tokens + (now - bucket.updated) * self._refill_per_second
        )
        bucket.updated = now
        allowed = cost <= bucket.tokens
        if allowed:
            bucket.tokens -= cost
        self._buckets[key] = bucket
        while len(self._buckets) > self._max_keys:
            self._buckets.popitem(last=False)
        return RateLimitDecision(
            allowed=allowed,
            limit=self._capacity,
            remaining=math.floor(bucket.tokens),
            reset_after_seconds=(self._capacity - bucket.tokens) / self._refill_per_second,
            retry_after_seconds=0.0
            if allowed
            else (cost - bucket.tokens) / self._refill_per_second,
        )


class RedisRateLimiter:
    """One budget per client shared by every API replica, kept in Redis.

    Each client may spend ``capacity`` units per fixed window of ``window_seconds``; the
    check and the spend are one atomic Lua script, and nothing is spent when a request
    does not fit. If Redis fails, the decision is taken by ``fallback`` (per process)
    and ``on_fallback`` is called, so a Redis outage degrades limiting but never blocks
    ingestion. After a failure, Redis is not tried again for ``retry_interval_seconds``:
    meanwhile requests go straight to ``fallback`` instead of each waiting for the
    connect timeout of an unreachable server.
    """

    def __init__(
        self,
        redis: RedisClient,
        *,
        capacity: int,
        window_seconds: float,
        fallback: RateLimiter,
        on_fallback: Callable[[], None] = lambda: None,
        retry_interval_seconds: float = REDIS_RETRY_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capacity < 1 or window_seconds <= 0 or retry_interval_seconds < 0:
            raise ValueError(
                "capacity and window_seconds must be positive, retry_interval_seconds >= 0"
            )
        self._redis = redis
        self._capacity = capacity
        self._window_seconds = window_seconds
        self._fallback = fallback
        self._on_fallback = on_fallback
        self._retry_interval_seconds = retry_interval_seconds
        self._clock = clock
        self._last_warning = float("-inf")
        self._redis_retry_at = float("-inf")

    async def acquire(self, key: str, cost: int) -> RateLimitDecision:
        """Charge ``cost`` units to ``key`` in Redis, or in memory if Redis fails."""
        if cost < 1:
            raise ValueError("cost must be positive")
        if self._clock() < self._redis_retry_at:  # Redis failed moments ago
            self._on_fallback()
            return await self._fallback.acquire(key, cost)
        try:
            usage = await self._redis.consume_window(
                "ratelimit",
                key,
                cost=cost,
                limit=self._capacity,
                window_seconds=self._window_seconds,
            )
        except RedisUnavailableError as error:
            self._on_fallback()
            now = self._clock()
            self._redis_retry_at = now + self._retry_interval_seconds
            if now - self._last_warning >= FALLBACK_LOG_INTERVAL_SECONDS:
                self._last_warning = now
                logger.warning(
                    "redis unavailable; rate limiting per process meanwhile",
                    extra={"action": "api_rate_limit_fallback", "error_type": type(error).__name__},
                )
            return await self._fallback.acquire(key, cost)
        return RateLimitDecision(
            allowed=usage.allowed,
            limit=self._capacity,
            remaining=max(0, self._capacity - usage.used),
            reset_after_seconds=usage.reset_in_seconds,
            retry_after_seconds=0.0 if usage.allowed else usage.reset_in_seconds,
        )
