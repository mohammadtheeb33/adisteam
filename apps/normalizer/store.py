"""Units of work over the event store (Supabase PostgreSQL)."""

from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import datetime
from typing import Protocol
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from packages.database import Database
from packages.database.repositories import (
    AgentRegistration,
    AgentRepository,
    BatchStoreResult,
    SecurityEventRepository,
)
from packages.events.canonical import AnyCanonicalEvent


class EventWriter(Protocol):
    """What the pipeline does inside one unit of work."""

    async def store_events_batch(self, events: Sequence[AnyCanonicalEvent]) -> BatchStoreResult:
        """Store events; those whose ``event_id`` is already stored are reported, not written."""
        ...

    async def find_payloads(self, event_ids: Iterable[UUID]) -> dict[UUID, dict[str, object]]:
        """Stored payloads of the given events, for comparing duplicates."""
        ...

    async def register_agents(self, registrations: Sequence[AgentRegistration]) -> int:
        """Insert or refresh agents from registration events."""
        ...

    async def touch_agents(self, seen: Mapping[UUID, datetime]) -> None:
        """Move ``last_seen`` of registered agents forward."""
        ...


class EventStore(Protocol):
    """Opens units of work: committed when the block exits normally, rolled back otherwise."""

    def unit_of_work(self) -> AbstractAsyncContextManager[EventWriter]:
        """One transaction."""
        ...


class DatabaseWriter:
    """The event and agent repositories sharing one transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self._events = SecurityEventRepository(session)
        self._agents = AgentRepository(session)

    async def store_events_batch(self, events: Sequence[AnyCanonicalEvent]) -> BatchStoreResult:
        """See :meth:`SecurityEventRepository.store_events_batch`."""
        return await self._events.store_events_batch(events)

    async def find_payloads(self, event_ids: Iterable[UUID]) -> dict[UUID, dict[str, object]]:
        """See :meth:`SecurityEventRepository.find_payloads`."""
        return await self._events.find_payloads(event_ids)

    async def register_agents(self, registrations: Sequence[AgentRegistration]) -> int:
        """See :meth:`AgentRepository.register_agents`."""
        return await self._agents.register_agents(registrations)

    async def touch_agents(self, seen: Mapping[UUID, datetime]) -> None:
        """See :meth:`AgentRepository.touch_agents`."""
        await self._agents.touch_agents(seen)


class DatabaseEventStore:
    """Each unit of work is one database transaction."""

    def __init__(self, database: Database) -> None:
        self._database = database

    @asynccontextmanager
    async def unit_of_work(self) -> AsyncIterator[DatabaseWriter]:
        """A writer bound to a new transaction."""
        async with self._database.transaction() as session:
            yield DatabaseWriter(session)
