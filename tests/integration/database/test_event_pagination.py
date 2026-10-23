"""Keyset pagination of stored events beyond the per-query limit, on real PostgreSQL."""

from datetime import UTC, datetime, timedelta

import pytest

from packages.database import Database
from packages.database.models import SecurityEventRecord
from packages.database.repositories import (
    MAX_QUERY_LIMIT,
    EventCursor,
    SecurityEventRepository,
)
from packages.events.canonical import AnyCanonicalEvent, parse_canonical_event
from tests.unit.events.canonical.samples import system

pytestmark = pytest.mark.integration

T0 = datetime(2026, 9, 25, 12, tzinfo=UTC)
EVENTS = 2_500  # more than two pages of MAX_QUERY_LIMIT
PAGE = 700


def _events(host_id: str) -> list[AnyCanonicalEvent]:
    # Groups of three share a timestamp, so pages must break ties on id.
    return [
        parse_canonical_event(
            system(host_id=host_id, timestamp=(T0 + timedelta(seconds=i // 3)).isoformat())
        )
        for i in range(EVENTS)
    ]


async def _stored(database: Database, events: list[AnyCanonicalEvent]) -> None:
    async with database.transaction() as session:
        result = await SecurityEventRepository(session).store_events_batch(events)
    assert len(result.inserted) == len(events)


def _keys(records: list[SecurityEventRecord]) -> list[tuple[datetime, str]]:
    return [(record.timestamp, str(record.id)) for record in records]


async def test_host_pages_cover_every_event_once_newest_first(
    migrated_database: Database,
) -> None:
    await _stored(migrated_database, _events("pager-1"))
    pages: list[list[SecurityEventRecord]] = []
    after: EventCursor | None = None

    async with migrated_database.session() as session:
        repository = SecurityEventRepository(session)
        while page := await repository.find_events_by_host("pager-1", limit=PAGE, after=after):
            pages.append(page)
            after = EventCursor.after_record(page[-1])

    everything = [record for page in pages for record in page]
    assert [len(page) for page in pages] == [700, 700, 700, 400]
    assert len({record.event_id for record in everything}) == EVENTS
    keys = _keys(everything)
    assert keys == sorted(keys, reverse=True)


async def test_time_range_pages_in_both_directions(migrated_database: Database) -> None:
    await _stored(migrated_database, _events("pager-2"))
    start, end = T0, T0 + timedelta(hours=1)

    async def read_all(*, newest_first: bool) -> list[SecurityEventRecord]:
        found: list[SecurityEventRecord] = []
        after: EventCursor | None = None
        async with migrated_database.session() as session:
            repository = SecurityEventRepository(session)
            while page := await repository.find_events_by_time_range(
                start, end, limit=MAX_QUERY_LIMIT, newest_first=newest_first, after=after
            ):
                found.extend(page)
                after = EventCursor.after_record(page[-1])
        return found

    oldest_first = await read_all(newest_first=False)
    newest_first = await read_all(newest_first=True)

    assert len(oldest_first) == len(newest_first) == EVENTS
    assert _keys(oldest_first) == sorted(_keys(oldest_first))
    assert _keys(newest_first) == list(reversed(_keys(oldest_first)))


async def test_events_inserted_meanwhile_never_shift_a_page(migrated_database: Database) -> None:
    await _stored(migrated_database, _events("pager-3"))

    async with migrated_database.session() as session:
        first = await SecurityEventRepository(session).find_events_by_host("pager-3", limit=PAGE)
    # A newer event lands between two page reads.
    newer = parse_canonical_event(
        system(host_id="pager-3", timestamp=(T0 + timedelta(days=1)).isoformat())
    )
    await _stored(migrated_database, [newer])
    async with migrated_database.session() as session:
        second = await SecurityEventRepository(session).find_events_by_host(
            "pager-3", limit=PAGE, after=EventCursor.after_record(first[-1])
        )

    assert {r.event_id for r in first}.isdisjoint(r.event_id for r in second)
    assert _keys(second)[0] < _keys(first)[-1]
    assert newer.event_id not in {r.event_id for r in second}
