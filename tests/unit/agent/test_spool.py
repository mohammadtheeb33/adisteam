"""Durable spool: FIFO, capacity, deduplication, checkpoints and quarantine."""

import asyncio
from pathlib import Path

import pytest

from apps.agent.spool import Spool, SpoolFullError
from tests.unit.agent.fakes import open_spool, spooled_payload
from tests.unit.log_capture import JsonLogCapture


def _records(count: int) -> list[tuple[str, bytes]]:
    return [spooled_payload() for _ in range(count)]


async def test_events_come_out_in_arrival_order(tmp_path: Path) -> None:
    records = _records(5)
    with open_spool(tmp_path) as spool:
        await spool.append(records[:2])
        await spool.append(records[2:])

        peeked = await spool.peek(10)

    assert [event.event_id for event in peeked] == [event_id for event_id, _ in records]
    assert peeked[0].payload == records[0][1]


async def test_peek_does_not_remove_and_acknowledge_does(tmp_path: Path) -> None:
    with open_spool(tmp_path) as spool:
        await spool.append(_records(3))
        first = await spool.peek(2)
        again = await spool.peek(2)
        deleted = await spool.acknowledge([event.seq for event in first])
        remaining = await spool.peek(10)

    assert first == again
    assert deleted == 2
    assert len(remaining) == 1


async def test_events_survive_reopening(tmp_path: Path) -> None:
    records = _records(3)
    with open_spool(tmp_path) as spool:
        await spool.append(records, {"logfile:x": "42"})

    with open_spool(tmp_path) as reopened:
        events = await reopened.peek(10)
        checkpoint = await reopened.checkpoint("logfile:x")

    assert [event.event_id for event in events] == [event_id for event_id, _ in records]
    assert checkpoint == "42"


async def test_capacity_is_enforced_without_partial_writes(tmp_path: Path) -> None:
    with open_spool(tmp_path, max_events=3) as spool:
        await spool.append(_records(2))

        with pytest.raises(SpoolFullError) as caught:
            await spool.append(_records(2), {"logfile:x": "must-not-be-stored"})

        stats = await spool.stats()
        checkpoint = await spool.checkpoint("logfile:x")

    assert (caught.value.queued, caught.value.requested, caught.value.capacity) == (2, 2, 3)
    assert stats.queued == 2
    assert checkpoint is None


async def test_capacity_frees_up_after_acknowledgement(tmp_path: Path) -> None:
    with open_spool(tmp_path, max_events=2) as spool:
        await spool.append(_records(2))
        await spool.acknowledge([event.seq for event in await spool.peek(1)])

        result = await spool.append(_records(1))

    assert result.added == 1


async def test_duplicates_are_skipped_and_do_not_use_capacity(tmp_path: Path) -> None:
    records = _records(2)
    with open_spool(tmp_path, max_events=2) as spool:
        await spool.append(records)

        result = await spool.append([records[0], records[1], records[0]])

    assert (result.added, result.duplicates) == (0, 3)


async def test_checkpoints_are_committed_with_their_events(tmp_path: Path) -> None:
    with open_spool(tmp_path) as spool:
        await spool.append(_records(1), {"logfile:a": "1"})
        await spool.append([], {"logfile:a": "2", "logfile:b": "7"})

        values = (await spool.checkpoint("logfile:a"), await spool.checkpoint("logfile:b"))

    assert values == ("2", "7")


async def test_quarantine_keeps_rejected_events_with_their_reason(tmp_path: Path) -> None:
    with open_spool(tmp_path) as spool:
        await spool.append(_records(3))
        [first, second, _] = await spool.peek(3)

        result = await spool.quarantine({first.seq: "validation_failed: src_port"})
        stats = await spool.stats()
        recent = await spool.quarantined(5)
        queued = await spool.peek(10)

    assert (result.moved, result.evicted) == (1, 0)
    assert (stats.queued, stats.quarantined) == (2, 1)
    assert recent == [(first.event_id, "validation_failed: src_port")]
    assert queued[0].seq == second.seq


async def test_quarantine_overflow_is_counted_persistently(tmp_path: Path) -> None:
    with open_spool(tmp_path, max_quarantined=2) as spool:
        await spool.append(_records(3))
        seqs = [event.seq for event in await spool.peek(3)]
        result = await spool.quarantine(dict.fromkeys(seqs, "rejected"))

    with open_spool(tmp_path, max_quarantined=2) as reopened:
        stats = await reopened.stats()

    assert (result.moved, result.evicted) == (3, 1)
    assert (stats.quarantined, stats.quarantine_evicted) == (2, 1)


async def test_concurrent_appends_respect_capacity(tmp_path: Path) -> None:
    with open_spool(tmp_path, max_events=50) as spool:
        outcomes = await asyncio.gather(
            *(spool.append(_records(10)) for _ in range(8)), return_exceptions=True
        )
        stats = await spool.stats()

    assert sum(1 for outcome in outcomes if isinstance(outcome, SpoolFullError)) == 3
    assert stats.queued == 50


def test_capacity_must_be_positive(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="positive"):
        Spool(tmp_path / "s.sqlite3", max_events=0)


async def test_a_corrupt_spool_is_preserved_and_replaced(
    tmp_path: Path, json_logs: JsonLogCapture
) -> None:
    path = tmp_path / "spool.sqlite3"
    path.write_bytes(b"this is not a sqlite database " * 100)

    with Spool.open(path, max_events=10) as spool:
        await spool.append(_records(1))
        stats = await spool.stats()

    preserved = _corrupt_copies(tmp_path)
    [line] = json_logs.with_message(
        "local spool is corrupt; it was preserved and replaced by an empty one"
    )
    assert stats.queued == 1  # the agent keeps collecting
    assert len(preserved) == 1
    assert (tmp_path / preserved[0]).read_bytes().startswith(b"this is not a sqlite database")
    assert line["level"] == "ERROR"
    assert line["action"] == "agent_spool_corrupt"


async def test_a_healthy_spool_is_opened_as_is(tmp_path: Path) -> None:
    records = _records(2)
    with open_spool(tmp_path) as spool:
        await spool.append(records)

    with Spool.open(tmp_path / "spool.sqlite3", max_events=1_000) as reopened:
        assert len(await reopened.peek(10)) == 2
    assert not _corrupt_copies(tmp_path)


def _corrupt_copies(directory: Path) -> list[str]:
    return [path.name for path in directory.iterdir() if ".corrupt-" in path.name]
