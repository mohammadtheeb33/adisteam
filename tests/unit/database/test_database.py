"""Database lifecycle, session factory and health check behavior without a server."""

import logging
import socket
from collections.abc import Callable
from typing import cast

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from packages.config import DatabaseSettings
from packages.database import Database

MakeSettings = Callable[..., DatabaseSettings]


class _RecordingEngine:
    """Stand-in engine that records disposal."""

    def __init__(self) -> None:
        self.disposals = 0

    async def dispose(self) -> None:
        self.disposals += 1


def _closed_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def _recording_database(engine: _RecordingEngine) -> Database:
    return Database(
        cast(AsyncEngine, engine),
        cast(async_sessionmaker[AsyncSession], object()),
        health_check_timeout_seconds=1.0,
    )


async def test_context_manager_disposes_engine_on_exit() -> None:
    engine = _RecordingEngine()

    async with _recording_database(engine) as database:
        assert database.engine is cast(AsyncEngine, engine)

    assert engine.disposals == 1


async def test_context_manager_disposes_engine_when_body_raises() -> None:
    engine = _RecordingEngine()

    with pytest.raises(RuntimeError, match="boom"):
        async with _recording_database(engine):
            raise RuntimeError("boom")

    assert engine.disposals == 1


async def test_dispose_is_idempotent(make_settings: MakeSettings) -> None:
    database = Database.from_settings(make_settings())

    await database.dispose()
    await database.dispose()


async def test_session_factory_configuration(make_settings: MakeSettings) -> None:
    async with Database.from_settings(make_settings()) as database:
        assert database.session_factory.kw["expire_on_commit"] is False
        assert database.session_factory.kw["autoflush"] is False


async def test_health_check_reports_unreachable_database_without_raising(
    make_settings: MakeSettings, caplog: pytest.LogCaptureFixture
) -> None:
    settings = make_settings(
        SUPABASE_DB_URL=(
            f"postgresql://adis:db-password-sentinel@127.0.0.1:{_closed_local_port()}/postgres"
        ),
        DB_CONNECT_TIMEOUT_SECONDS="1",
        DB_HEALTH_CHECK_TIMEOUT_SECONDS="2",
        DB_SSL_MODE="disable",
    )

    with caplog.at_level(logging.WARNING, logger="packages.database"):
        async with Database.from_settings(settings) as database:
            health = await database.health_check()

    assert health.healthy is False
    assert health.error
    assert health.latency_ms > 0
    assert "sentinel" not in repr(health)
    assert "sentinel" not in caplog.text
    [record] = [r for r in caplog.records if r.getMessage() == "database health check failed"]
    assert record.__dict__["error_type"] == health.error
