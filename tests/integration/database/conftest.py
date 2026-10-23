"""Integration fixtures backed by a real, disposable PostgreSQL database.

Set ``TEST_DATABASE_URL`` to enable these tests. It must point at a throwaway database
(local Supabase CLI or a local PostgreSQL container), never staging or production: the
tests create and drop tables and run migrations.
"""

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Column, Integer, MetaData, Table, text

from packages.config import DatabaseSettings, load_settings
from packages.database import Database
from tests.services import require_variable

TEST_DATABASE_URL_VARIABLE = "TEST_DATABASE_URL"
MIGRATIONS = Path(__file__).resolve().parents[3] / "packages/database/migrations"


def alembic_config() -> Config:
    """Alembic configuration without logging setup (``alembic.ini`` would reconfigure it)."""
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    config.set_main_option("path_separator", "os")
    return config


@pytest.fixture
def database_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> DatabaseSettings:
    """Settings pointing at ``TEST_DATABASE_URL``; skips the test when it is not set."""
    url = require_variable(TEST_DATABASE_URL_VARIABLE)
    monkeypatch.chdir(tmp_path)  # ignore the developer's .env
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SUPABASE_DB_URL", url)
    return load_settings(DatabaseSettings)


@pytest.fixture
async def database(database_settings: DatabaseSettings) -> AsyncIterator[Database]:
    """A ``Database`` connected to the test database, disposed after the test."""
    async with Database.from_settings(
        database_settings, application_name="adis-integration-tests"
    ) as db:
        yield db


@pytest.fixture
async def scratch_table(database: Database) -> AsyncIterator[Table]:
    """A uniquely named throwaway table, dropped after the test."""
    table = Table(
        f"adis_it_{uuid4().hex[:12]}", MetaData(), Column("id", Integer, primary_key=True)
    )
    async with database.engine.begin() as connection:
        await connection.run_sync(table.create)
    try:
        yield table
    finally:
        async with database.engine.begin() as connection:
            await connection.run_sync(table.drop)


@pytest.fixture
async def migrated_database(database: Database) -> Database:
    """The test database migrated to head, with every ADIS table emptied first."""
    # env.py drives its own event loop, so Alembic runs in a worker thread.
    await asyncio.to_thread(command.upgrade, alembic_config(), "head")
    async with database.transaction() as session:
        await session.execute(text("TRUNCATE adis.security_events, adis.agents"))
    return database
