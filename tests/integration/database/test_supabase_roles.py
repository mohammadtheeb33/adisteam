"""Supabase fidelity: the Data API roles can never reach the ``adis`` schema.

Supabase serves its Data API as the ``anon`` and ``authenticated`` roles. They exist only
on Supabase (a project, ``supabase start`` or the ``supabase/postgres`` image), so on
plain PostgreSQL these tests are skipped, unless ``TEST_DATABASE_IS_SUPABASE=1`` says
the database must be Supabase, which turns a missing role into a failure.
"""

import os
from typing import Final

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from packages.database import Base, Database, models
from packages.database.repositories import SecurityEventRepository
from packages.events.canonical import parse_canonical_event
from tests.unit.events.canonical.samples import system

pytestmark = pytest.mark.integration
API_ROLES: Final = ("anon", "authenticated")
assert models
TABLES: Final = tuple(
    sorted({table.fullname for table in Base.metadata.sorted_tables} | {"adis.alembic_version"})
)
PRIVILEGES: Final = "SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER"


@pytest.fixture
async def api_roles(migrated_database: Database) -> tuple[str, ...]:
    """The Supabase API roles present in the test database; skips on plain PostgreSQL."""
    async with migrated_database.session() as session:
        rows = await session.execute(
            text("SELECT rolname FROM pg_roles WHERE rolname = ANY(:roles)"),
            {"roles": list(API_ROLES)},
        )
        present = {str(name) for (name,) in rows}
    if present == set(API_ROLES):
        return API_ROLES
    message = f"Supabase roles missing: {sorted(set(API_ROLES) - present)}"
    if os.environ.get("TEST_DATABASE_IS_SUPABASE", "").strip() in {"1", "true", "yes"}:
        pytest.fail(message, pytrace=False)
    pytest.skip(f"{message} (plain PostgreSQL)")


async def test_api_roles_have_no_privilege_on_adis(
    migrated_database: Database, api_roles: tuple[str, ...]
) -> None:
    granted: list[str] = []
    async with migrated_database.session() as session:
        for role in api_roles:
            if await session.scalar(
                text("SELECT has_schema_privilege(:role, 'adis', 'USAGE, CREATE')"), {"role": role}
            ):
                granted.append(f"{role}: schema adis")
            for table in TABLES:
                if await session.scalar(
                    text("SELECT has_table_privilege(:role, :table, :privileges)"),
                    {"role": role, "table": table, "privileges": PRIVILEGES},
                ):
                    granted.append(f"{role}: {table}")
    assert granted == []


async def test_row_level_security_backs_up_the_missing_grants(
    migrated_database: Database, api_roles: tuple[str, ...]
) -> None:
    async with migrated_database.session() as session:
        rows = await session.execute(
            text(
                "SELECT c.relname, c.relrowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'adis' AND c.relkind = 'r'"
            )
        )
        protected = {f"adis.{name}": bool(enabled) for name, enabled in rows}
    assert protected == dict.fromkeys(TABLES, True)


async def test_api_roles_cannot_read_stored_events(
    migrated_database: Database, api_roles: tuple[str, ...]
) -> None:
    async with migrated_database.transaction() as session:
        await SecurityEventRepository(session).store_events_batch([parse_canonical_event(system())])
    for role in api_roles:
        async with migrated_database.session() as session:
            if not await session.scalar(
                text("SELECT pg_has_role(current_user, :role, 'MEMBER')"), {"role": role}
            ):
                pytest.skip(f"the test user cannot act as {role}")
            await session.execute(text(f'SET LOCAL ROLE "{role}"'))
            with pytest.raises(ProgrammingError, match="permission denied"):
                await session.execute(text("SELECT count(*) FROM adis.security_events"))
