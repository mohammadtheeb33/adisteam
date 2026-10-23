"""Connectivity, transactions, the session dependency and repositories on real PostgreSQL."""

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import pytest
from sqlalchemy import Table, insert, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from packages.config import DatabaseSettings
from packages.database import Database, Repository

pytestmark = pytest.mark.integration


class _ScratchBase(DeclarativeBase):
    """Declarative base for throwaway test models (kept out of ADIS metadata)."""


class ScratchItem(_ScratchBase):
    """Throwaway model for repository round trips."""

    __tablename__ = "adis_it_repository_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str]


class ScratchItemRepository(Repository[ScratchItem]):
    """Repository under test."""

    model = ScratchItem


async def _ids(database: Database, table: Table) -> list[int]:
    async with database.session() as session:
        return list((await session.scalars(select(table.c.id).order_by(table.c.id))).all())


async def _insert_then_fail(database: Database, table: Table, row_id: int) -> None:
    async with database.transaction() as session:
        await session.execute(insert(table).values(id=row_id))
        raise RuntimeError("abort unit of work")


async def test_health_check_succeeds(database: Database) -> None:
    health = await database.health_check()

    assert health.healthy is True
    assert health.error is None


async def test_session_round_trip_reports_application_name(
    database: Database, database_settings: DatabaseSettings
) -> None:
    async with database.session() as session:
        one: object = (await session.execute(text("SELECT 1"))).scalar_one()
        name = (await session.execute(text("SELECT current_setting('application_name')"))).scalar()

    assert one == 1
    # Supabase's Supavisor pooler replaces the client's application_name with its own, so
    # pg_stat_activity cannot tell ADIS services apart behind it (docs/DEVELOPMENT.md).
    behind_supavisor = (
        urlsplit(database_settings.supabase_db_url.get_secret_value()).hostname or ""
    ).endswith(".pooler.supabase.com")
    assert name == ("Supavisor" if behind_supavisor else "adis-integration-tests")


async def test_transaction_commits_on_success_and_rolls_back_on_error(
    database: Database, scratch_table: Table
) -> None:
    async with database.transaction() as session:
        await session.execute(insert(scratch_table).values(id=1))

    with pytest.raises(RuntimeError, match="abort unit of work"):
        await _insert_then_fail(database, scratch_table, row_id=2)

    assert await _ids(database, scratch_table) == [1]


async def test_session_dependency_commits_after_consumer_finishes(
    database: Database, scratch_table: Table
) -> None:
    provider = database.provide_session()
    session = await anext(provider)
    await session.execute(insert(scratch_table).values(id=1))

    with pytest.raises(StopAsyncIteration):
        await anext(provider)

    assert await _ids(database, scratch_table) == [1]


async def test_session_dependency_rolls_back_when_consumer_fails(
    database: Database, scratch_table: Table
) -> None:
    provider = database.provide_session()
    session = await anext(provider)
    await session.execute(insert(scratch_table).values(id=1))

    with pytest.raises(RuntimeError, match="request failed"):
        await provider.athrow(RuntimeError("request failed"))

    assert await _ids(database, scratch_table) == []


@pytest.fixture
async def scratch_items(database: Database) -> AsyncIterator[None]:
    async with database.engine.begin() as connection:
        await connection.run_sync(_ScratchBase.metadata.create_all)
    try:
        yield
    finally:
        async with database.engine.begin() as connection:
            await connection.run_sync(_ScratchBase.metadata.drop_all)


@pytest.mark.usefixtures("scratch_items")
async def test_repository_round_trip(database: Database) -> None:
    async with database.transaction() as session:
        ScratchItemRepository(session).add(ScratchItem(id=1, label="first"))

    async with database.session() as session:
        stored = await ScratchItemRepository(session).get(1)

    assert stored is not None
    assert stored.label == "first"
