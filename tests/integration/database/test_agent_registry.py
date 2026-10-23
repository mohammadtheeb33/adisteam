"""The agent registry (``adis.agents``) kept by registration events, on real PostgreSQL."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from apps.normalizer.store import DatabaseEventStore
from packages.database import Database
from packages.database.models import AgentRecord, AgentStatus, OsType
from packages.database.repositories import (
    AgentRegistration,
    AgentRepository,
    SecurityEventRepository,
)
from packages.events.canonical import parse_canonical_event
from tests.unit.events.canonical.samples import system

pytestmark = pytest.mark.integration

T0 = datetime(2026, 9, 25, 12, tzinfo=UTC)


def _registration(
    agent_id: UUID, minutes: int, *, version: str = "1.0.0", name: str = "agent-web-1"
) -> AgentRegistration:
    return AgentRegistration(
        agent_id=agent_id,
        name=name,
        hostname="web-1",
        os_type=OsType.LINUX,
        agent_version=version,
        seen_at=T0 + timedelta(minutes=minutes),
    )


async def _register(database: Database, *registrations: AgentRegistration) -> int:
    async with database.transaction() as session:
        return await AgentRepository(session).register_agents(list(registrations))


async def _agent(database: Database, agent_id: UUID) -> AgentRecord:
    async with database.session() as session:
        agent = await AgentRepository(session).get(agent_id)
    assert agent is not None
    return agent


async def test_registration_creates_an_active_agent(migrated_database: Database) -> None:
    agent_id = uuid4()

    written = await _register(migrated_database, _registration(agent_id, 0))

    agent = await _agent(migrated_database, agent_id)
    assert written == 1
    assert (agent.name, agent.hostname, agent.os_type, agent.agent_version) == (
        "agent-web-1",
        "web-1",
        OsType.LINUX,
        "1.0.0",
    )
    assert agent.status == AgentStatus.ACTIVE
    assert agent.first_seen == agent.last_seen == T0


async def test_events_stored_with_their_registration_are_linked(
    migrated_database: Database,
) -> None:
    agent_id = uuid4()
    event = parse_canonical_event(system(agent_id=str(agent_id)))
    store = DatabaseEventStore(migrated_database)

    # What the normalizer does for a batch holding a registration and telemetry.
    async with store.unit_of_work() as writer:
        await writer.register_agents([_registration(agent_id, 0)])
        await writer.store_events_batch([event])

    async with migrated_database.session() as session:
        record = await SecurityEventRepository(session).find_event(event.event_id)
    assert record is not None
    assert record.agent_id == agent_id


async def test_reregistration_refreshes_attributes_without_rewinding_history(
    migrated_database: Database,
) -> None:
    agent_id = uuid4()
    await _register(migrated_database, _registration(agent_id, 10))

    await _register(migrated_database, _registration(agent_id, 20, version="1.1.0"))
    await _register(migrated_database, _registration(agent_id, 5, version="1.1.0"))  # replayed

    agent = await _agent(migrated_database, agent_id)
    assert agent.agent_version == "1.1.0"
    assert agent.first_seen == T0 + timedelta(minutes=5)
    assert agent.last_seen == T0 + timedelta(minutes=20)


async def test_duplicate_registrations_in_one_batch_keep_the_latest(
    migrated_database: Database,
) -> None:
    agent_id = uuid4()

    written = await _register(
        migrated_database,
        _registration(agent_id, 3, name="agent-new"),
        _registration(agent_id, 1, name="agent-old"),
    )

    agent = await _agent(migrated_database, agent_id)
    assert written == 1
    assert agent.name == "agent-new"
    assert agent.first_seen == agent.last_seen == T0 + timedelta(minutes=3)


async def test_decommissioned_agents_stay_decommissioned(migrated_database: Database) -> None:
    agent_id = uuid4()
    await _register(migrated_database, _registration(agent_id, 0))
    async with migrated_database.transaction() as session:
        stored = await AgentRepository(session).get(agent_id)
        assert stored is not None
        stored.status = AgentStatus.DECOMMISSIONED

    await _register(migrated_database, _registration(agent_id, 30, version="2.0.0"))

    agent = await _agent(migrated_database, agent_id)
    assert agent.status == AgentStatus.DECOMMISSIONED
    assert agent.agent_version == "2.0.0"
    assert agent.last_seen == T0 + timedelta(minutes=30)


async def test_touch_moves_last_seen_forward_only(migrated_database: Database) -> None:
    agent_id = uuid4()
    await _register(migrated_database, _registration(agent_id, 10))

    async with migrated_database.transaction() as session:
        repository = AgentRepository(session)
        await repository.touch_agents({agent_id: T0 + timedelta(minutes=15), uuid4(): T0})
        await repository.touch_agents({agent_id: T0 + timedelta(minutes=12)})  # older

    agent = await _agent(migrated_database, agent_id)
    assert agent.first_seen == T0 + timedelta(minutes=10)
    assert agent.last_seen == T0 + timedelta(minutes=15)
    async with migrated_database.session() as session:
        agents = await session.scalar(select(func.count()).select_from(AgentRecord))
    assert agents == 1  # unknown ids are ignored
