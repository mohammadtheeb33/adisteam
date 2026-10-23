"""Alembic environment for the ADIS application schema.

- The connection comes from ``DatabaseSettings`` (``SUPABASE_DB_URL`` and ``DB_*``), so
  migrations follow the same validation and fail-fast rules as the services.
- Everything lives in the ``adis`` schema, including the ``alembic_version`` table.
  Autogenerate is restricted to that schema so it never proposes changes to
  Supabase-managed schemas (``auth``, ``storage``, ``public`` and others).
- Run migrations over a direct connection or the Supavisor session pooler, never the
  transaction pooler.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from alembic.runtime.environment import NameFilterParentNames, NameFilterType
from sqlalchemy.engine import Connection
from sqlalchemy.schema import CreateSchema

from packages.config import DatabaseSettings, load_settings
from packages.database import (
    ADIS_SCHEMA,
    Base,
    create_database_engine,
    models,  # registers every table on Base.metadata
)

_ = models  # imported for its side effect

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def include_name(
    name: str | None, type_: NameFilterType, parent_names: NameFilterParentNames
) -> bool:
    """Limit autogenerate to the ADIS schema."""
    if type_ == "schema":
        return name == ADIS_SCHEMA
    return True


def _run_migrations(connection: Connection | None) -> None:
    """Configure the migration context and apply migrations in one transaction.

    Without a connection (offline mode) SQL is rendered for PostgreSQL instead.
    """
    offline = connection is None
    if connection is not None and connection.dialect.default_schema_name == ADIS_SCHEMA:
        # Autogenerate treats the default schema as "no schema" and would propose
        # re-creating every ADIS table. This happens when the role is named like the
        # schema, because the default search_path starts with "$user".
        raise RuntimeError(
            f"the database role's default schema is '{ADIS_SCHEMA}'; migrations need "
            f"another default schema (connect as a role not named '{ADIS_SCHEMA}', or "
            "run: ALTER ROLE <role> SET search_path = public)"
        )
    context.configure(
        connection=connection,
        dialect_name="postgresql" if offline else None,
        literal_binds=offline,
        target_metadata=target_metadata,
        include_schemas=True,
        include_name=include_name,
        version_table_schema=ADIS_SCHEMA,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        # The schema must exist before Alembic creates its version table inside it.
        context.execute(CreateSchema(ADIS_SCHEMA, if_not_exists=True))
        context.run_migrations()


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting (``alembic upgrade head --sql``)."""
    _run_migrations(None)


async def _run_async_migrations() -> None:
    settings = load_settings(DatabaseSettings)
    engine = create_database_engine(settings, application_name="adis-migrations")
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run_migrations)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    """Apply migrations over a live connection.

    A caller may supply its own connection via ``config.attributes["connection"]``.
    """
    connection = config.attributes.get("connection")
    if connection is None:
        asyncio.run(_run_async_migrations())
    else:
        _run_migrations(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
