"""Engine construction: driver, pooling strategies and secret safety."""

from collections.abc import Callable

import pytest
from sqlalchemy import NullPool
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.pool import AsyncAdaptedQueuePool

from packages.config import DatabaseSettings
from packages.database import async_database_url, create_database_engine, engine_options

MakeSettings = Callable[..., DatabaseSettings]


def _connect_args(options: dict[str, object]) -> dict[str, object]:
    connect_args = options["connect_args"]
    assert isinstance(connect_args, dict)
    return connect_args


@pytest.mark.parametrize("scheme", ["postgres", "postgresql", "postgresql+asyncpg"])
def test_async_database_url_uses_asyncpg_driver(make_settings: MakeSettings, scheme: str) -> None:
    url = async_database_url(
        make_settings(SUPABASE_DB_URL=f"{scheme}://adis:pw@db.example.test:6543/postgres")
    )

    assert url.drivername == "postgresql+asyncpg"
    assert (url.username, url.password, url.host, url.port, url.database) == (
        "adis",
        "pw",
        "db.example.test",
        6543,
        "postgres",
    )


def test_async_database_url_masks_password(make_settings: MakeSettings) -> None:
    url = async_database_url(make_settings())

    assert "sentinel" not in repr(url)
    assert "sentinel" not in str(url)


def test_pooled_engine_options(make_settings: MakeSettings) -> None:
    settings = make_settings(
        DB_POOL_SIZE="7",
        DB_MAX_OVERFLOW="3",
        DB_POOL_TIMEOUT_SECONDS="12.5",
        DB_POOL_RECYCLE_SECONDS="900",
        DB_CONNECT_TIMEOUT_SECONDS="4",
        DB_COMMAND_TIMEOUT_SECONDS="20",
        DB_SSL_MODE="require",
    )

    options = engine_options(settings, application_name="adis-detector")

    assert "poolclass" not in options
    assert options["pool_size"] == 7
    assert options["max_overflow"] == 3
    assert options["pool_timeout"] == 12.5
    assert options["pool_recycle"] == 900
    assert options["pool_pre_ping"] is True
    assert _connect_args(options) == {
        "timeout": 4.0,
        "command_timeout": 20.0,
        "ssl": "require",
        "server_settings": {"application_name": "adis-detector"},
    }


def test_transaction_pooler_engine_options(make_settings: MakeSettings) -> None:
    options = engine_options(
        make_settings(DB_TRANSACTION_POOLER="true"), application_name="adis-detector"
    )
    connect_args = _connect_args(options)

    assert options["poolclass"] is NullPool
    assert "pool_size" not in options
    assert connect_args["statement_cache_size"] == 0
    assert connect_args["prepared_statement_cache_size"] == 0
    name_statement = connect_args["prepared_statement_name_func"]
    assert callable(name_statement)
    first, second = name_statement(), name_statement()
    assert first != second
    assert str(first).startswith("__asyncpg_")


async def test_create_database_engine_builds_pooled_engine(make_settings: MakeSettings) -> None:
    engine = create_database_engine(make_settings(DB_POOL_SIZE="3"))
    try:
        assert isinstance(engine, AsyncEngine)
        assert isinstance(engine.pool, AsyncAdaptedQueuePool)
        assert engine.pool.size() == 3
        assert engine.url.drivername == "postgresql+asyncpg"
        assert "sentinel" not in repr(engine)
    finally:
        await engine.dispose()


async def test_create_database_engine_uses_null_pool_behind_transaction_pooler(
    make_settings: MakeSettings,
) -> None:
    engine = create_database_engine(make_settings(DB_TRANSACTION_POOLER="true"))
    try:
        assert isinstance(engine.pool, NullPool)
    finally:
        await engine.dispose()
