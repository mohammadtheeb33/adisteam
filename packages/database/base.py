"""Declarative base shared by every ADIS ORM model."""

from datetime import datetime
from typing import ClassVar, Final

from sqlalchemy import DateTime, MetaData
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.types import TypeEngine

ADIS_SCHEMA: Final = "adis"
"""PostgreSQL schema that holds all ADIS tables.

Supabase exposes the ``public`` schema through its Data API (PostgREST) to holders of the
anon key. ADIS tables live in a dedicated schema that is *not* exposed, so they are only
reachable through backend services.
"""

NAMING_CONVENTION: Final = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
"""Deterministic constraint names, so Alembic migrations are stable across environments."""


class Base(AsyncAttrs, DeclarativeBase):
    """Base class for ADIS ORM models.

    - Tables are created in the :data:`ADIS_SCHEMA` schema.
    - Constraints follow :data:`NAMING_CONVENTION`.
    - ``datetime`` annotations map to ``TIMESTAMP WITH TIME ZONE``.
    - ``AsyncAttrs`` provides ``await model.awaitable_attrs.<relationship>`` for lazy loads.
    """

    metadata = MetaData(schema=ADIS_SCHEMA, naming_convention=NAMING_CONVENTION)
    type_annotation_map: ClassVar[dict[type, TypeEngine[datetime]]] = {
        datetime: DateTime(timezone=True)
    }
