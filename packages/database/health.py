"""Database health check."""

import asyncio
import logging
import time
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DatabaseHealth:
    """Outcome of a database health check.

    Attributes:
        healthy: Whether a round trip to the database succeeded within the timeout.
        latency_ms: Time spent on the check, in milliseconds.
        error: Exception type name when unhealthy. Error messages are deliberately omitted
            because they can contain connection details.
    """

    healthy: bool
    latency_ms: float
    error: str | None = None


async def check_database_health(engine: AsyncEngine, *, timeout_seconds: float) -> DatabaseHealth:
    """Run ``SELECT 1`` through the pool and report the outcome. Never raises.

    Args:
        engine: Engine to check.
        timeout_seconds: Upper bound for acquiring a connection and running the query.

    Returns:
        The health outcome.
    """
    started = time.perf_counter()
    try:
        async with asyncio.timeout(timeout_seconds), engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except Exception as error:  # a health check reports failures, it never raises
        health = DatabaseHealth(
            healthy=False, latency_ms=_elapsed_ms(started), error=type(error).__name__
        )
        logger.warning(
            "database health check failed",
            extra={
                "action": "database_health_check",
                "latency_ms": health.latency_ms,
                "error_type": health.error,
            },
        )
        return health
    return DatabaseHealth(healthy=True, latency_ms=_elapsed_ms(started))


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)
