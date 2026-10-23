"""Redis access for ingestion rate counters and transient state.

Redis is never a source of truth; Supabase PostgreSQL is. Every value expires, and
callers must keep working (degraded) when Redis is unavailable.
"""

from packages.redis.client import (
    RedisClient,
    RedisConnection,
    RedisHealth,
    RedisUnavailableError,
    WindowUsage,
)

__all__ = [
    "RedisClient",
    "RedisConnection",
    "RedisHealth",
    "RedisUnavailableError",
    "WindowUsage",
]
