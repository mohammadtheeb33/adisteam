"""Supabase PostgreSQL access through SQLAlchemy 2 async and asyncpg.

Supabase PostgreSQL is the ADIS source of truth. Business logic depends on this package
(sessions and repositories), never on the Supabase Python SDK.

ORM models live in ``packages.database.models`` and repositories in
``packages.database.repositories``.
"""

from packages.database.base import ADIS_SCHEMA, NAMING_CONVENTION, Base
from packages.database.database import Database
from packages.database.engine import async_database_url, create_database_engine, engine_options
from packages.database.health import DatabaseHealth, check_database_health
from packages.database.ids import uuid7
from packages.database.repository import Repository
from packages.database.session import create_session_factory

__all__ = [
    "ADIS_SCHEMA",
    "NAMING_CONVENTION",
    "Base",
    "Database",
    "DatabaseHealth",
    "Repository",
    "async_database_url",
    "check_database_health",
    "create_database_engine",
    "create_session_factory",
    "engine_options",
    "uuid7",
]
