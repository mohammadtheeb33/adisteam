"""SecurityEventRepository logic that does not need a database."""

from collections.abc import Sequence
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import AsyncMock, MagicMock, create_autospec
from uuid import UUID, uuid4

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from packages.database.repositories import (
    MAX_QUERY_LIMIT,
    EventCursor,
    SecurityEventRepository,
    security_event_row,
)
from packages.events.canonical import AnyCanonicalEvent, parse_canonical_event
from tests.unit.events.canonical.samples import (
    authentication,
    network,
    process,
    security,
    system,
)

START = datetime(2026, 9, 25, tzinfo=UTC)
END = datetime(2026, 9, 26, tzinfo=UTC)


def _result(values: Sequence[object]) -> MagicMock:
    result = MagicMock()
    result.scalars.return_value = list(values)
    return result


def _session(*results: Sequence[object]) -> MagicMock:
    session: MagicMock = create_autospec(AsyncSession, instance=True)
    session.execute = AsyncMock(side_effect=[_result(values) for values in results])
    return session


def _events(*documents: dict[str, object]) -> list[AnyCanonicalEvent]:
    return [parse_canonical_event(document) for document in documents]


# ------------------------------------------------------------------------------ row mapping


def test_row_projects_network_fields_and_keeps_the_full_payload() -> None:
    event = parse_canonical_event(network(severity_hint="HIGH"))

    row = security_event_row(event, agent_id=None)

    assert row["event_id"] == event.event_id
    assert row["timestamp"] == event.timestamp
    assert row["received_at"] == event.received_at
    assert row["event_type"] == "network.flow"
    assert (row["source_type"], row["source_name"], row["host_id"]) == (
        "agent",
        "adis-agent@web-1",
        "web-1",
    )
    assert row["severity_hint"] == "high"
    assert (row["src_ip"], row["dst_ip"]) == (IPv4Address("10.0.0.5"), IPv4Address("10.0.0.9"))
    assert (row["src_port"], row["dst_port"], row["protocol"]) == (51_514, 443, "tcp")
    assert row["payload"] == event.model_dump(mode="json")
    assert isinstance(row["id"], UUID)
    assert row["id"].version == 7


@pytest.mark.parametrize("builder", [system, process])
def test_row_of_an_event_without_network_context(builder: object) -> None:
    event = parse_canonical_event(builder())  # type: ignore[operator]

    row = security_event_row(event, agent_id=None)

    assert {row[key] for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")} == {None}


def test_ipv6_zone_ids_are_dropped_from_columns_but_kept_in_payload() -> None:
    event = parse_canonical_event(authentication(src_ip="fe80::1%eth0", dst_ip="fe80::2%eth0"))

    row = security_event_row(event, agent_id=None)

    assert row["src_ip"] == IPv6Address("fe80::1")
    assert row["payload"]["src_ip"] == "fe80::1%eth0"  # type: ignore[index]


def test_row_links_the_given_agent() -> None:
    agent = uuid4()

    row = security_event_row(parse_canonical_event(security()), agent_id=agent)

    assert row["agent_id"] == agent


# ---------------------------------------------------------------------------- batch storage


async def test_empty_batch_touches_nothing() -> None:
    session = _session()

    result = await SecurityEventRepository(session).store_events_batch([])

    assert (result.inserted, result.duplicates) == ((), ())
    session.execute.assert_not_awaited()


async def test_batch_reports_inserted_and_duplicate_events_in_input_order() -> None:
    first, second, third = _events(system(), network(), process())
    session = _session([first.event_id, third.event_id])  # "second" was already stored

    result = await SecurityEventRepository(session).store_events_batch(
        [first, second, first, third]
    )

    assert result.inserted == (first.event_id, third.event_id)
    assert result.duplicates == (second.event_id, first.event_id)
    [(statement, rows), _] = session.execute.await_args
    assert [row["event_id"] for row in rows] == [
        first.event_id,
        second.event_id,
        third.event_id,
    ]
    sql = str(statement.compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]
    assert "ON CONFLICT (event_id) DO NOTHING" in sql
    assert "RETURNING adis.security_events.event_id" in sql


async def test_only_registered_agents_are_linked() -> None:
    registered, unknown = uuid4(), uuid4()
    events = _events(
        system(agent_id=str(registered)),
        system(agent_id=str(unknown)),
        system(agent_id="not-a-uuid"),
        system(agent_id=None),
    )
    session = _session([registered], [event.event_id for event in events])

    await SecurityEventRepository(session).store_events_batch(events)

    agent_query, insert = session.execute.await_args_list
    rows = insert.args[1]
    assert [row["agent_id"] for row in rows] == [registered, None, None, None]
    assert "adis.agents" in str(agent_query.args[0])


async def test_agents_are_not_queried_when_no_event_names_a_uuid_agent() -> None:
    events = _events(system(agent_id="agent-7"))
    session = _session([events[0].event_id])

    await SecurityEventRepository(session).store_events_batch(events)

    assert session.execute.await_count == 1


async def test_store_event_reports_whether_it_was_new() -> None:
    [event] = _events(system())

    assert await SecurityEventRepository(_session([event.event_id])).store_event(event) is True
    assert await SecurityEventRepository(_session([])).store_event(event) is False


# ------------------------------------------------------------------------------ query guards


@pytest.mark.parametrize("limit", [0, -1, MAX_QUERY_LIMIT + 1])
async def test_query_limits_are_bounded(limit: int) -> None:
    repository = SecurityEventRepository(_session())

    with pytest.raises(ValueError, match="limit"):
        await repository.find_events_by_host("web-1", limit=limit)
    with pytest.raises(ValueError, match="limit"):
        await repository.find_events_by_time_range(START, END, limit=limit)


async def test_naive_datetimes_are_rejected() -> None:
    repository = SecurityEventRepository(_session())
    naive = datetime(2026, 9, 25)  # naive on purpose

    with pytest.raises(ValueError, match="timezone-aware"):
        await repository.find_events_by_host("web-1", since=naive)
    with pytest.raises(ValueError, match="timezone-aware"):
        await repository.find_events_by_time_range(naive, END)


@pytest.mark.parametrize(("start", "end"), [(END, START), (START, START)])
async def test_time_range_must_be_non_empty(start: datetime, end: datetime) -> None:
    with pytest.raises(ValueError, match="earlier"):
        await SecurityEventRepository(_session()).find_events_by_time_range(start, end)


# ------------------------------------------------------------------------------ pagination


def _query_sql(session: MagicMock) -> str:
    statement = session.execute.await_args.args[0]
    return str(statement.compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]


async def test_host_pages_continue_after_the_cursor() -> None:
    session = _session([])
    cursor = EventCursor(timestamp=START, id=uuid4())

    await SecurityEventRepository(session).find_events_by_host("web-1", after=cursor)

    sql = _query_sql(session)
    assert "(adis.security_events.timestamp, adis.security_events.id) < (" in sql
    assert "ORDER BY adis.security_events.timestamp DESC, adis.security_events.id DESC" in sql


@pytest.mark.parametrize(("newest_first", "operator"), [(True, "<"), (False, ">")])
async def test_time_range_pages_follow_the_ordering(newest_first: bool, operator: str) -> None:
    session = _session([])
    cursor = EventCursor(timestamp=START, id=uuid4())

    await SecurityEventRepository(session).find_events_by_time_range(
        START, END, newest_first=newest_first, after=cursor
    )

    assert f"(adis.security_events.timestamp, adis.security_events.id) {operator} (" in _query_sql(
        session
    )


async def test_cursors_must_be_timezone_aware() -> None:
    cursor = EventCursor(timestamp=datetime(2026, 9, 25), id=uuid4())  # naive on purpose

    with pytest.raises(ValueError, match="timezone-aware"):
        await SecurityEventRepository(_session([])).find_events_by_host("web-1", after=cursor)
