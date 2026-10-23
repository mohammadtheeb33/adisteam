"""Persistence of canonical security events."""

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Final, Self
from uuid import UUID

from sqlalchemy import Tuple, literal, select, tuple_
from sqlalchemy.dialects.postgresql import insert

from packages.database.ids import uuid7
from packages.database.models import AgentRecord, SecurityEventRecord
from packages.database.repository import Repository
from packages.events.canonical import AnyCanonicalEvent

logger = logging.getLogger(__name__)

DEFAULT_QUERY_LIMIT: Final = 100
MAX_QUERY_LIMIT: Final = 1_000


@dataclass(frozen=True, slots=True)
class BatchStoreResult:
    """Outcome of storing a batch, in input order.

    Attributes:
        inserted: ``event_id`` of every event written by this call.
        duplicates: ``event_id`` of every input that was already stored, or that repeated
            an earlier event of the same batch.
    """

    inserted: tuple[UUID, ...]
    duplicates: tuple[UUID, ...]


@dataclass(frozen=True, slots=True)
class EventCursor:
    """Where a page of events ended: pass it as ``after`` to read the next page.

    Pages are keyset-paginated on ``(timestamp, id)``, so reading page N costs the same
    as reading the first one, and events inserted meanwhile never shift a page.
    """

    timestamp: datetime
    id: UUID

    @classmethod
    def after_record(cls, record: SecurityEventRecord) -> Self:
        """The cursor positioned after ``record`` (the last of a page)."""
        return cls(timestamp=record.timestamp, id=record.id)


def security_event_row(event: AnyCanonicalEvent, *, agent_id: UUID | None) -> dict[str, object]:
    """Column values for ``event``.

    Args:
        event: The canonical event; stored whole in ``payload``.
        agent_id: The registered agent to link, or ``None``.
    """
    return {
        "id": uuid7(),
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "received_at": event.received_at,
        "event_type": event.event_type,
        "source_type": event.source_type,
        "source_name": event.source_name,
        "agent_id": agent_id,
        "host_id": event.host_id,
        "severity_hint": None if event.severity_hint is None else event.severity_hint.value,
        "src_ip": _inet(getattr(event, "src_ip", None)),
        "dst_ip": _inet(getattr(event, "dst_ip", None)),
        "src_port": getattr(event, "src_port", None),
        "dst_port": getattr(event, "dst_port", None),
        "protocol": _enum_value(getattr(event, "protocol", None)),
        "payload": event.model_dump(mode="json"),
    }


class SecurityEventRepository(Repository[SecurityEventRecord]):
    """Stores and queries canonical security events.

    Storage is idempotent on ``event_id``, so events redelivered by Kafka are skipped
    rather than duplicated. Like every repository, it never commits: call it inside a
    unit of work (``Database.transaction()``).
    """

    model = SecurityEventRecord

    async def store_event(self, event: AnyCanonicalEvent) -> bool:
        """Store one event. Returns ``False`` if an event with its ``event_id`` exists."""
        result = await self.store_events_batch([event])
        return bool(result.inserted)

    async def store_events_batch(self, events: Sequence[AnyCanonicalEvent]) -> BatchStoreResult:
        """Store events in one round trip per page; already-stored events are skipped.

        ``agent_id`` is linked only when the canonical ``agent_id`` is the UUID of a
        registered agent. Otherwise the column is NULL and the original value remains in
        ``payload``, so an unknown or spoofed agent id never makes a batch fail.
        """
        first_occurrences: dict[UUID, AnyCanonicalEvent] = {}
        for event in events:
            first_occurrences.setdefault(event.event_id, event)
        if not first_occurrences:
            return BatchStoreResult(inserted=(), duplicates=())
        unique = list(first_occurrences.values())
        registered = await self._registered_agents(unique)
        rows = [
            security_event_row(event, agent_id=_linked_agent(event.agent_id, registered))
            for event in unique
        ]
        statement = (
            insert(SecurityEventRecord)
            .on_conflict_do_nothing(index_elements=[SecurityEventRecord.event_id])
            .returning(SecurityEventRecord.event_id)
        )
        written = set((await self.session.execute(statement, rows)).scalars())

        inserted: list[UUID] = []
        duplicates: list[UUID] = []
        for event in events:
            if event.event_id in written:
                written.discard(event.event_id)  # later repeats in the batch are duplicates
                inserted.append(event.event_id)
            else:
                duplicates.append(event.event_id)
        return BatchStoreResult(inserted=tuple(inserted), duplicates=tuple(duplicates))

    async def find_payloads(self, event_ids: Iterable[UUID]) -> dict[UUID, dict[str, object]]:
        """The stored canonical payload of each of ``event_ids`` that exists."""
        wanted = list(dict.fromkeys(event_ids))
        if not wanted:
            return {}
        statement = select(SecurityEventRecord.event_id, SecurityEventRecord.payload).where(
            SecurityEventRecord.event_id.in_(wanted)
        )
        rows = await self.session.execute(statement)
        return {event_id: dict(payload) for event_id, payload in rows}

    async def find_event(self, event_id: UUID) -> SecurityEventRecord | None:
        """The stored event with canonical ``event_id``, if any."""
        statement = select(SecurityEventRecord).where(SecurityEventRecord.event_id == event_id)
        return (await self.session.execute(statement)).scalar_one_or_none()

    async def find_events_by_host(
        self,
        host_id: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_QUERY_LIMIT,
        after: EventCursor | None = None,
    ) -> list[SecurityEventRecord]:
        """Events of ``host_id``, newest first, with ``since <= timestamp < until``.

        Pass ``after=EventCursor.after_record(page[-1])`` to read the next page.
        """
        _check_limit(limit)
        statement = select(SecurityEventRecord).where(SecurityEventRecord.host_id == host_id)
        if since is not None:
            statement = statement.where(SecurityEventRecord.timestamp >= _aware(since, "since"))
        if until is not None:
            statement = statement.where(SecurityEventRecord.timestamp < _aware(until, "until"))
        if after is not None:
            statement = statement.where(_position() < _cursor(after))
        statement = statement.order_by(
            SecurityEventRecord.timestamp.desc(), SecurityEventRecord.id.desc()
        ).limit(limit)
        return list((await self.session.execute(statement)).scalars())

    async def find_host_history(
        self,
        host_id: str,
        *,
        since: datetime,
        received_until: datetime,
        limit: int = MAX_QUERY_LIMIT,
        after: EventCursor | None = None,
    ) -> list[SecurityEventRecord]:
        """Events of ``host_id`` with ``timestamp > since`` and ``received_at <= received_until``.

        Oldest first, keyset-paginated on ``(timestamp, id)``: pass
        ``after=EventCursor.after_record(page[-1])`` for the next page. Selecting on
        ``timestamp`` returns every event whose feature event time
        (``min(timestamp, received_at)``) is after ``since``, and some earlier ones, which
        callers filter.
        """
        _check_limit(limit)
        statement = select(SecurityEventRecord).where(
            SecurityEventRecord.host_id == host_id,
            SecurityEventRecord.timestamp > _aware(since, "since"),
            SecurityEventRecord.received_at <= _aware(received_until, "received_until"),
        )
        if after is not None:
            statement = statement.where(_position() > _cursor(after))
        statement = statement.order_by(
            SecurityEventRecord.timestamp.asc(), SecurityEventRecord.id.asc()
        ).limit(limit)
        return list((await self.session.execute(statement)).scalars())

    async def find_events_by_time_range(
        self,
        start: datetime,
        end: datetime,
        *,
        event_type: str | None = None,
        limit: int = DEFAULT_QUERY_LIMIT,
        newest_first: bool = True,
        after: EventCursor | None = None,
    ) -> list[SecurityEventRecord]:
        """Events with ``start <= timestamp < end``, optionally of one ``event_type``.

        Pass ``after=EventCursor.after_record(page[-1])`` to read the next page.
        """
        _check_limit(limit)
        start, end = _aware(start, "start"), _aware(end, "end")
        if start >= end:
            raise ValueError("start must be earlier than end")
        statement = select(SecurityEventRecord).where(
            SecurityEventRecord.timestamp >= start, SecurityEventRecord.timestamp < end
        )
        if event_type is not None:
            statement = statement.where(SecurityEventRecord.event_type == event_type)
        if after is not None:
            beyond = _position() < _cursor(after) if newest_first else _position() > _cursor(after)
            statement = statement.where(beyond)
        ordering = (
            (SecurityEventRecord.timestamp.desc(), SecurityEventRecord.id.desc())
            if newest_first
            else (SecurityEventRecord.timestamp.asc(), SecurityEventRecord.id.asc())
        )
        statement = statement.order_by(*ordering).limit(limit)
        return list((await self.session.execute(statement)).scalars())

    async def _registered_agents(self, events: Iterable[AnyCanonicalEvent]) -> frozenset[UUID]:
        candidates = {uuid for event in events if (uuid := _as_uuid(event.agent_id)) is not None}
        if not candidates:
            return frozenset()
        statement = select(AgentRecord.id).where(AgentRecord.id.in_(candidates))
        registered = frozenset((await self.session.execute(statement)).scalars())
        unknown = len(candidates - registered)
        if unknown:
            logger.warning(
                "events reference unregistered agents",
                extra={"action": "security_events_unregistered_agents", "agent_count": unknown},
            )
        return registered


def _linked_agent(agent_id: str | None, registered: frozenset[UUID]) -> UUID | None:
    uuid = _as_uuid(agent_id)
    return uuid if uuid in registered else None


def _as_uuid(value: str | None) -> UUID | None:
    if value is None:
        return None
    try:
        return UUID(value)
    except ValueError:
        return None


def _inet(address: object) -> IPv4Address | IPv6Address | None:
    """PostgreSQL ``inet`` has no IPv6 zone ids; the payload keeps the full address."""
    if isinstance(address, IPv6Address) and address.scope_id is not None:
        return IPv6Address(int(address))
    if isinstance(address, IPv4Address | IPv6Address):
        return address
    return None


def _enum_value(value: object) -> str | None:
    return None if value is None else str(value)


def _position() -> Tuple:
    return tuple_(SecurityEventRecord.timestamp, SecurityEventRecord.id)


def _cursor(after: EventCursor) -> Tuple:
    return tuple_(literal(_aware(after.timestamp, "after.timestamp")), literal(after.id))


def _check_limit(limit: int) -> None:
    if not 1 <= limit <= MAX_QUERY_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_QUERY_LIMIT}")


def _aware(moment: datetime, name: str) -> datetime:
    if moment.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return moment
