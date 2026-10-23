"""Async SQLAlchemy engine for Supabase PostgreSQL (asyncpg driver)."""

import logging
from typing import Final
from uuid import uuid4

from sqlalchemy import URL, NullPool, make_url
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from packages.config import DatabaseSettings

logger = logging.getLogger(__name__)

ASYNC_DRIVER: Final = "postgresql+asyncpg"


def async_database_url(settings: DatabaseSettings) -> URL:
    """Return ``SUPABASE_DB_URL`` as an SQLAlchemy URL that uses the asyncpg driver.

    The URL's ``repr`` and ``str`` mask the password; never render it with
    ``hide_password=False`` outside of handing it to a driver.
    """
    return make_url(settings.supabase_db_url.get_secret_value()).set(drivername=ASYNC_DRIVER)


def engine_options(settings: DatabaseSettings, *, application_name: str) -> dict[str, object]:
    """Build ``create_async_engine`` keyword arguments from settings.

    Two pooling strategies are supported:

    - **Client-side pool** (default): for direct connections and the Supavisor *session*
      pooler. SQLAlchemy keeps a queue pool with pre-ping and periodic recycling.
    - **Transaction pooler** (``DB_TRANSACTION_POOLER=true``): for the Supavisor
      *transaction* pooler (port 6543). Supavisor owns pooling, so SQLAlchemy uses
      ``NullPool``, and prepared statements are made safe for connection multiplexing.

    Args:
        settings: Database settings.
        application_name: Reported to PostgreSQL (visible in ``pg_stat_activity``).

    Returns:
        Keyword arguments for :func:`sqlalchemy.ext.asyncio.create_async_engine`.
    """
    connect_args: dict[str, object] = {
        "timeout": settings.db_connect_timeout_seconds,
        "command_timeout": settings.db_command_timeout_seconds,
        "ssl": settings.db_ssl_mode.value,
        "server_settings": {"application_name": application_name},
    }
    if settings.db_transaction_pooler:
        connect_args |= {
            "statement_cache_size": 0,
            "prepared_statement_cache_size": 0,
            "prepared_statement_name_func": _unique_prepared_statement_name,
        }
        return {"poolclass": NullPool, "connect_args": connect_args}
    return {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_timeout": settings.db_pool_timeout_seconds,
        "pool_recycle": settings.db_pool_recycle_seconds,
        "pool_pre_ping": True,
        "connect_args": connect_args,
    }


def create_database_engine(
    settings: DatabaseSettings, *, application_name: str = "adis"
) -> AsyncEngine:
    """Create the async engine. No connection is opened until first use.

    Args:
        settings: Database settings.
        application_name: Reported to PostgreSQL; use the service's ``APP_NAME``.

    Returns:
        An engine that must be disposed at shutdown (see ``Database.dispose``).
    """
    url = async_database_url(settings)
    engine = create_async_engine(url, **engine_options(settings, application_name=application_name))
    logger.info(
        "database engine created",
        extra={
            "action": "database_engine_created",
            "db_host": url.host,
            "db_port": url.port,
            "db_name": url.database,
            "db_transaction_pooler": settings.db_transaction_pooler,
        },
    )
    return engine


def _unique_prepared_statement_name() -> str:
    return f"__asyncpg_{uuid4()}__"
