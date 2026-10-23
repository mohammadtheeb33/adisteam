"""Persistence of telemetry agents."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import cast
from uuid import UUID

from sqlalchemy import Table, bindparam, case, func, update
from sqlalchemy.dialects.postgresql import insert

from packages.database.models import AgentRecord
from packages.database.models.agents import AgentStatus, OsType
from packages.database.repository import Repository


@dataclass(frozen=True, slots=True)
class AgentRegistration:
    """An agent's announcement of itself, from a ``system.agent_registered`` event."""

    agent_id: UUID
    name: str
    hostname: str
    os_type: OsType
    agent_version: str
    seen_at: datetime


class AgentRepository(Repository[AgentRecord]):
    """Agents: ``get``/``add``/``delete`` from :class:`Repository`, plus the registry."""

    model = AgentRecord

    async def register_agents(self, registrations: Sequence[AgentRegistration]) -> int:
        """Insert or refresh agents from their registrations; returns the rows written.

        - New agents become ``active`` with ``first_seen = last_seen = seen_at``.
        - Known agents get their current name, host name, OS and version. ``first_seen``
          only moves earlier and ``last_seen`` only later, so replayed or out-of-order
          registrations never rewind history.
        - A ``decommissioned`` agent stays decommissioned.
        """
        latest: dict[UUID, AgentRegistration] = {}
        for registration in sorted(registrations, key=lambda item: item.seen_at):
            latest[registration.agent_id] = registration
        if not latest:
            return 0
        statement = insert(AgentRecord)
        statement = statement.on_conflict_do_update(
            index_elements=[AgentRecord.id],
            set_={
                "name": statement.excluded.name,
                "hostname": statement.excluded.hostname,
                "os_type": statement.excluded.os_type,
                "agent_version": statement.excluded.agent_version,
                "status": case(
                    (AgentRecord.status == AgentStatus.DECOMMISSIONED.value, AgentRecord.status),
                    else_=statement.excluded.status,
                ),
                "first_seen": func.least(
                    func.coalesce(AgentRecord.first_seen, statement.excluded.first_seen),
                    statement.excluded.first_seen,
                ),
                "last_seen": func.greatest(
                    func.coalesce(AgentRecord.last_seen, statement.excluded.last_seen),
                    statement.excluded.last_seen,
                ),
                "updated_at": func.now(),
            },
        )
        rows = [
            {
                "id": item.agent_id,
                "name": item.name,
                "hostname": item.hostname,
                "os_type": item.os_type,
                "agent_version": item.agent_version,
                "status": AgentStatus.ACTIVE,
                "first_seen": item.seen_at,
                "last_seen": item.seen_at,
            }
            for item in latest.values()
        ]
        await self.session.execute(statement, rows)
        return len(rows)

    async def touch_agents(self, seen: Mapping[UUID, datetime]) -> None:
        """Move ``last_seen`` of registered agents forward; unknown ids are ignored."""
        if not seen:
            return
        table = cast("Table", AgentRecord.__table__)
        statement = (
            update(table)
            .where(table.c.id == bindparam("agent_key"))
            .values(
                last_seen=func.greatest(
                    func.coalesce(table.c.last_seen, bindparam("seen_at")), bindparam("seen_at")
                ),
                first_seen=func.coalesce(table.c.first_seen, bindparam("seen_at")),
            )
        )
        await self.session.execute(
            statement,
            [{"agent_key": agent_id, "seen_at": moment} for agent_id, moment in seen.items()],
        )
