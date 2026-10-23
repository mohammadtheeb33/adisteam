"""Batcher: acknowledgement, quarantine, splitting and retries."""

import asyncio
from pathlib import Path

import pytest

from apps.agent.backoff import Backoff
from apps.agent.batcher import Batcher
from apps.agent.client import Outcome, SendResult
from apps.agent.spool import Spool
from tests.unit.agent.fakes import ScriptedSender, delivered, open_spool, spooled_payload

FLUSH_INTERVAL = 30.0


def _batcher(spool: Spool, sender: ScriptedSender, *, batch_size: int = 3) -> Batcher:
    return Batcher(
        spool,
        sender,
        batch_size=batch_size,
        flush_interval_seconds=FLUSH_INTERVAL,
        backoff=Backoff(initial_seconds=1, max_seconds=8, jitter=lambda low, high: high),
    )


async def _filled(tmp_path: Path, count: int) -> tuple[Spool, list[str]]:
    spool = open_spool(tmp_path)
    records = [spooled_payload() for _ in range(count)]
    await spool.append(records)
    return spool, [event_id for event_id, _ in records]


async def test_drains_the_spool_in_batches(tmp_path: Path) -> None:
    spool, ids = await _filled(tmp_path, 7)
    sender = ScriptedSender()

    with spool:
        delay, backing_off = await _batcher(spool, sender).flush()
        stats = await spool.stats()

    assert [len(batch) for batch in sender.batches] == [3, 3, 1]
    assert sender.sent_ids() == ids
    assert (delay, backing_off, stats.queued) == (FLUSH_INTERVAL, False, 0)


async def test_empty_spool_waits_for_the_flush_interval(tmp_path: Path) -> None:
    sender = ScriptedSender()

    with open_spool(tmp_path) as spool:
        assert await _batcher(spool, sender).flush() == (FLUSH_INTERVAL, False)

    assert sender.batches == []


async def test_rejected_events_are_quarantined_and_the_rest_acknowledged(tmp_path: Path) -> None:
    spool, ids = await _filled(tmp_path, 3)
    sender = ScriptedSender([delivered(3, rejected={1: "validation_failed: src_port"})])

    with spool:
        await _batcher(spool, sender).flush()
        stats = await spool.stats()
        quarantined = await spool.quarantined(5)

    assert (stats.queued, stats.quarantined) == (0, 1)
    assert quarantined == [(ids[1], "validation_failed: src_port")]


async def test_fully_rejected_batch_is_quarantined(tmp_path: Path) -> None:
    spool, _ = await _filled(tmp_path, 2)
    rejected = SendResult(Outcome.REJECTED, status=422, rejected={0: "bad", 1: "bad"})
    sender = ScriptedSender([rejected])

    with spool:
        await _batcher(spool, sender).flush()
        stats = await spool.stats()

    assert (stats.queued, stats.quarantined) == (0, 2)


@pytest.mark.parametrize(
    "result",
    [
        SendResult(Outcome.UNAVAILABLE, status=503),
        SendResult(Outcome.UNAVAILABLE, detail="ConnectError"),
        SendResult(Outcome.UNAUTHORIZED, status=401),
        SendResult(Outcome.MISCONFIGURED, status=404),
    ],
)
async def test_failures_keep_every_event_and_back_off(tmp_path: Path, result: SendResult) -> None:
    spool, ids = await _filled(tmp_path, 3)
    sender = ScriptedSender([result, result])
    batcher = _batcher(spool, sender)

    with spool:
        first = await batcher.flush()
        second = await batcher.flush()
        queued = [event.event_id for event in await spool.peek(10)]

    assert (first, second) == ((1, True), (2, True))
    assert queued == ids


async def test_success_resets_the_backoff(tmp_path: Path) -> None:
    spool, _ = await _filled(tmp_path, 1)
    unavailable = SendResult(Outcome.UNAVAILABLE, status=503)
    sender = ScriptedSender([unavailable, unavailable])
    batcher = _batcher(spool, sender)

    with spool:
        await batcher.flush()
        await batcher.flush()
        await batcher.flush()  # delivered
        await spool.append([spooled_payload()])
        sender.script.append(unavailable)
        delay, _ = await batcher.flush()

    assert delay == 1


async def test_rate_limit_honours_retry_after(tmp_path: Path) -> None:
    spool, _ = await _filled(tmp_path, 1)
    sender = ScriptedSender([SendResult(Outcome.RATE_LIMITED, status=429, retry_after=42)])

    with spool:
        assert await _batcher(spool, sender).flush() == (42, True)
        assert (await spool.stats()).queued == 1


async def test_server_retry_after_is_used_when_unavailable(tmp_path: Path) -> None:
    spool, _ = await _filled(tmp_path, 1)
    sender = ScriptedSender([SendResult(Outcome.UNAVAILABLE, status=503, retry_after=5)])

    with spool:
        assert await _batcher(spool, sender).flush() == (5, True)


async def test_too_large_batches_are_halved_until_accepted(tmp_path: Path) -> None:
    spool, ids = await _filled(tmp_path, 4)
    too_large = SendResult(Outcome.TOO_LARGE, status=413, code="batch_too_large")
    sender = ScriptedSender([too_large])
    batcher = _batcher(spool, sender, batch_size=4)

    with spool:
        await batcher.flush()
        stats = await spool.stats()

    assert [len(batch) for batch in sender.batches] == [4, 2, 2]
    assert batcher.batch_size == 2
    assert sender.sent_ids()[4:] == ids
    assert stats.queued == 0


async def test_single_event_too_large_is_quarantined(tmp_path: Path) -> None:
    spool, ids = await _filled(tmp_path, 2)
    too_large = SendResult(Outcome.TOO_LARGE, status=413, code="payload_too_large")
    sender = ScriptedSender([too_large])

    with spool:
        await _batcher(spool, sender, batch_size=1).flush()
        quarantined = await spool.quarantined(5)
        stats = await spool.stats()

    assert quarantined == [(ids[0], "payload_too_large")]
    assert stats.queued == 0


async def test_malformed_event_is_isolated_and_quarantined(tmp_path: Path) -> None:
    spool, ids = await _filled(tmp_path, 2)

    def reject_bad(payloads: object) -> SendResult:
        batch = list(payloads)  # type: ignore[call-overload]
        if ids[0].encode() in b"".join(batch):
            return SendResult(Outcome.MALFORMED, status=400, code="invalid_json")
        return delivered(len(batch))

    sender = ScriptedSender([reject_bad, reject_bad, reject_bad])
    batcher = _batcher(spool, sender, batch_size=2)

    with spool:
        await batcher.flush()
        quarantined = await spool.quarantined(5)
        stats = await spool.stats()

    assert [len(batch) for batch in sender.batches] == [2, 1, 1]
    assert quarantined == [(ids[0], "invalid_json")]
    assert stats.queued == 0
    assert batcher.batch_size == 2


async def test_batch_size_is_restored_after_an_oversized_event_is_quarantined(
    tmp_path: Path,
) -> None:
    # One oversized event among 1,011 used to leave the batch size at 1 for good: the
    # remaining 1,010 events then cost one request each (deep audit C-1).
    records = [spooled_payload() for _ in range(1_011)]
    oversized = records[0][0].encode()

    def refuse_oversized(payloads: object) -> SendResult:
        batch = list(payloads)  # type: ignore[call-overload]
        if oversized in b"".join(batch):
            return SendResult(Outcome.TOO_LARGE, status=413, code="event_too_large")
        return delivered(len(batch))

    sender = ScriptedSender([refuse_oversized] * 100)
    batcher = _batcher(spool := open_spool(tmp_path, max_events=2_000), sender, batch_size=500)

    with spool:
        await spool.append(records)
        await batcher.flush()
        quarantined = await spool.quarantined(5)
        stats = await spool.stats()

    assert quarantined == [(records[0][0], "event_too_large")]
    assert stats.queued == 0
    assert batcher.batch_size == 500
    # 500, 250, ..., 3, 1 to isolate it, then the other 1,010 events in full batches.
    assert [len(batch) for batch in sender.batches] == [
        *(500, 250, 125, 62, 31, 15, 7, 3, 1),
        *(500, 500, 10),
    ]


async def test_unresolved_events_stay_queued_and_back_off(tmp_path: Path) -> None:
    spool, ids = await _filled(tmp_path, 2)
    partial = SendResult(Outcome.DELIVERED, status=202, accepted=frozenset({0}))
    sender = ScriptedSender([partial])

    with spool:
        delay, backing_off = await _batcher(spool, sender, batch_size=5).flush()
        queued = [event.event_id for event in await spool.peek(10)]

    assert (delay, backing_off) == (1, True)
    assert queued == [ids[1]]
    assert len(sender.batches) == 1


async def test_run_flushes_on_wake_and_stops(tmp_path: Path) -> None:
    sender = ScriptedSender()
    stop = asyncio.Event()

    with open_spool(tmp_path) as spool:
        batcher = _batcher(spool, sender)
        task = asyncio.create_task(batcher.run(stop))
        await asyncio.sleep(0.01)
        await spool.append([spooled_payload()])
        batcher.wake.set()
        for _ in range(100):
            if sender.batches:
                break
            await asyncio.sleep(0.01)
        stop.set()
        await asyncio.wait_for(task, timeout=2)

    assert len(sender.batches) == 1
