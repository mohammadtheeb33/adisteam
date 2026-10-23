"""Database lifecycle: connection pool, sessions, transactions, health and shutdown."""

import logging
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from types import TracebackType
from typing import Self

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from packages.config import DatabaseSettings
from packages.database.engine import create_database_engine
from packages.database.health import DatabaseHealth, check_database_health
from packages.database.session import create_session_factory

logger = logging.getLogger(__name__)


class Database:
    """Async access to Supabase PostgreSQL for one process.

    Create one instance at start-up, share it through dependency injection, and dispose it
    at shutdown (or use it as an async context manager)::

        async with Database.from_settings(settings, application_name=settings.app_name) as db:
            async with db.transaction() as session:
                ...
    """

    def __init__(
        self,
        engine: AsyncEngine,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        health_check_timeout_seconds: float,
    ) -> None:
        self._engine = engine
        self._session_factory = session_factory
        self._health_check_timeout_seconds = health_check_timeout_seconds

    @classmethod
    def from_settings(cls, settings: DatabaseSettings, *, application_name: str = "adis") -> Self:
        """Build the engine and session factory from settings.

        Args:
            settings: Database settings.
            application_name: Reported to PostgreSQL; use the service's ``APP_NAME``.
        """
        engine = create_database_engine(settings, application_name=application_name)
        return cls(
            engine,
            create_session_factory(engine),
            health_check_timeout_seconds=settings.db_health_check_timeout_seconds,
        )

    @property
    def engine(self) -> AsyncEngine:
        """The underlying engine (connection pool)."""
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """The session factory, for components that manage sessions themselves."""
        return self._session_factory

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a session without an explicit transaction boundary.

        Suitable for reads. Any implicit transaction is rolled back when the session
        closes; use :meth:`transaction` to write.
        """
        async with self._session_factory() as session:
            yield session

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[AsyncSession]:
        """Yield a session inside one transaction (unit of work).

        Commits when the block exits normally and rolls back if it raises.
        """
        async with self._session_factory() as session, session.begin():
            yield session

    async def provide_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Dependency provider yielding one transactional session per unit of work.

        Framework-agnostic; with FastAPI use ``Depends(database.provide_session)``. The
        transaction commits after the consumer finishes and rolls back if an exception is
        thrown into the generator.
        """
        async with self.transaction() as session:
            yield session

    async def health_check(self) -> DatabaseHealth:
        """Check connectivity with a bounded ``SELECT 1``. Never raises."""
        return await check_database_health(
            self._engine, timeout_seconds=self._health_check_timeout_seconds
        )

    async def dispose(self) -> None:
        """Close every pooled connection. Safe to call more than once."""
        await self._engine.dispose()
        logger.info("database engine disposed", extra={"action": "database_engine_disposed"})

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.dispose()
