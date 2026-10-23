"""Alembic migrations run end to end against real PostgreSQL."""

import asyncio
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from packages.config import DatabaseSettings
from packages.database import ADIS_SCHEMA, Database, async_database_url, engine_options
from tests.integration.database.conftest import alembic_config

pytestmark = pytest.mark.integration

ALEMBIC_INI = Path(__file__).resolve().parents[3] / "alembic.ini"


async def test_upgrade_head_creates_the_adis_schema(database: Database) -> None:
    # env.py drives its own event loop, so run Alembic in a worker thread.
    await asyncio.to_thread(command.upgrade, Config(str(ALEMBIC_INI)), "head")

    async with database.session() as session:
        schema = (
            await session.execute(
                text("SELECT schema_name FROM information_schema.schemata WHERE schema_name = :s"),
                {"s": ADIS_SCHEMA},
            )
        ).scalar()

    assert schema == ADIS_SCHEMA


async def test_migrations_refuse_a_connection_defaulting_to_the_adis_schema(
    database_settings: DatabaseSettings, migrated_database: Database
) -> None:
    # What a role named "adis" gets from the default search_path ("$user", public).
    options = engine_options(database_settings, application_name="adis-migration-guard-test")
    base_args = options["connect_args"]
    assert isinstance(base_args, dict)
    connect_args = {**base_args, "server_settings": {"search_path": f"{ADIS_SCHEMA}, public"}}
    engine = create_async_engine(
        async_database_url(database_settings), **{**options, "connect_args": connect_args}
    )
    config = alembic_config()

    def upgrade(connection: Connection) -> None:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")

    try:
        async with engine.connect() as connection:
            with pytest.raises(RuntimeError, match="default schema is 'adis'"):
                await connection.run_sync(upgrade)
    finally:
        await engine.dispose()
