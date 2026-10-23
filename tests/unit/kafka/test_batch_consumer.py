"""Batch consumer: one handler call per poll, commits only after the handler succeeded."""

import asyncio
from collections.abc import Sequence

import pytest
from aiokafka.errors import CommitFailedError, KafkaConnectionError

from packages.kafka import (
    BatchAbortedError,
    ConsumerRecordLike,
    KafkaBatchConsumer,
    RetryPolicy,
    Topic,
)
from tests.unit.kafka.fakes import ConsumerRecord, FakeConsumerClient

SYSTEM = ("system_logs", 0)
AUTH = ("auth_events", 1)


def _record(partition: tuple[str, int], offset: int) -> ConsumerRecord:
    return ConsumerRecord(topic=partition[0], partition=partition[1], offset=offset, value=b"{}")


class Handler:
    """Records batches; optionally raises on a given call (1-based)."""

    def __init__(self, *, fail_on: int | None = None, error: Exception | None = None) -> None:
        self.batches: list[list[tuple[str, int]]] = []
        self.fail_on = fail_on
        self.error = error or RuntimeError("handler bug")

    async def __call__(self, records: Sequence[ConsumerRecordLike]) -> None:
        self.batches.append([(record.topic, record.offset) for record in records])
        if len(self.batches) == self.fail_on:
            raise self.error


def _consumer(client: FakeConsumerClient) -> KafkaBatchConsumer:
    consumer = KafkaBatchConsumer(
        lambda: client,
        topics=[Topic.SYSTEM_EVENTS, Topic.AUTH_EVENTS],
        group_id="adis-normalizer",
    )
    client.on_drained = consumer.request_stop
    return consumer


async def test_each_poll_is_one_batch_committed_after_the_handler() -> None:
    client = FakeConsumerClient(
        batches=[
            {SYSTEM: [_record(SYSTEM, 0), _record(SYSTEM, 1)], AUTH: [_record(AUTH, 7)]},
            {SYSTEM: [_record(SYSTEM, 2)]},
        ]
    )
    handler = Handler()

    await _consumer(client).run(handler)

    assert handler.batches == [
        [("system_logs", 0), ("system_logs", 1), ("auth_events", 7)],
        [("system_logs", 2)],
    ]
    assert client.commits == [{SYSTEM: 2, AUTH: 8}, {SYSTEM: 3}]
    assert (client.started, client.stopped) == (1, 1)


async def test_empty_polls_do_not_reach_the_handler() -> None:
    client = FakeConsumerClient(batches=[{}, {SYSTEM: []}])
    handler = Handler()

    await _consumer(client).run(handler)

    assert (handler.batches, client.commits) == ([], [])


async def test_an_aborted_batch_is_not_committed_and_consumption_stops() -> None:
    client = FakeConsumerClient(
        batches=[{SYSTEM: [_record(SYSTEM, 0)]}, {SYSTEM: [_record(SYSTEM, 1)]}]
    )
    handler = Handler(fail_on=1, error=BatchAbortedError())
    consumer = _consumer(client)

    await consumer.run(handler)

    assert client.commits == []
    assert len(handler.batches) == 1
    assert client.stopped == 1
    assert not consumer.running


async def test_a_failing_handler_ends_the_run_without_committing() -> None:
    client = FakeConsumerClient(
        batches=[{SYSTEM: [_record(SYSTEM, 0)]}, {SYSTEM: [_record(SYSTEM, 1)]}]
    )

    with pytest.raises(RuntimeError, match="handler bug"):
        await _consumer(client).run(Handler(fail_on=2))

    assert client.commits == [{SYSTEM: 1}]  # only the batch that succeeded
    assert client.stopped == 1


async def test_commits_refused_by_a_rebalance_are_not_fatal() -> None:
    class RebalancingClient(FakeConsumerClient):
        async def commit(self, offsets: object = None) -> None:
            raise CommitFailedError("group rebalanced")

    client = RebalancingClient(
        batches=[{SYSTEM: [_record(SYSTEM, 0)]}, {SYSTEM: [_record(SYSTEM, 1)]}]
    )
    handler = Handler()

    await _consumer(client).run(handler)

    assert len(handler.batches) == 2  # kept consuming; the records will be redelivered


async def test_cannot_run_twice_concurrently() -> None:
    client = FakeConsumerClient(batches=[])
    consumer = KafkaBatchConsumer(lambda: client, topics=[Topic.SYSTEM_EVENTS], group_id="g-1")

    async def blocking(records: Sequence[ConsumerRecordLike]) -> None:
        raise AssertionError("no records expected")

    running = asyncio.create_task(consumer.run(blocking))
    await asyncio.sleep(0)
    with pytest.raises(RuntimeError, match="already running"):
        await consumer.run(blocking)
    await consumer.stop()
    await running


@pytest.mark.parametrize(
    ("topics", "group_id", "options"),
    [
        ([], "adis-normalizer", {}),
        ([Topic.DEADLETTER], "adis-normalizer", {}),
        ([Topic.SYSTEM_EVENTS], "bad group", {}),
        ([Topic.SYSTEM_EVENTS], "adis-normalizer", {"max_records": 0}),
        ([Topic.SYSTEM_EVENTS], "adis-normalizer", {"poll_timeout_ms": -1}),
    ],
)
def test_invalid_configuration_is_rejected(
    topics: list[Topic], group_id: str, options: dict[str, int]
) -> None:
    with pytest.raises(ValueError, match=r"topic|group_id|max_records"):
        KafkaBatchConsumer(
            lambda: FakeConsumerClient(batches=[]),
            topics=topics,
            group_id=group_id,
            poll_timeout_ms=options.get("poll_timeout_ms", 1_000),
            max_records=options.get("max_records", 500),
        )


FAST_START = RetryPolicy(max_attempts=1, initial_backoff_seconds=0.001, max_backoff_seconds=0.002)


async def test_joining_is_retried_while_the_broker_is_down() -> None:
    attempts: list[FakeConsumerClient] = []

    class DownTwice(FakeConsumerClient):
        async def start(self) -> None:
            await super().start()
            if len(attempts) <= 2:
                raise KafkaConnectionError("broker down")

    def factory() -> FakeConsumerClient:
        client = DownTwice(batches=[{SYSTEM: [_record(SYSTEM, 0)]}])
        attempts.append(client)
        client.on_drained = consumer.request_stop
        return client

    consumer = KafkaBatchConsumer(
        factory, topics=[Topic.SYSTEM_EVENTS], group_id="g-1", start_backoff=FAST_START
    )
    handler = Handler()

    await consumer.run(handler)

    assert len(attempts) == 3
    assert [client.stopped for client in attempts[:2]] == [1, 1]  # failed clients released
    assert handler.batches == [[("system_logs", 0)]]


async def test_stopping_while_waiting_for_the_broker() -> None:
    class Down(FakeConsumerClient):
        async def start(self) -> None:
            raise KafkaConnectionError("broker down")

    consumer = KafkaBatchConsumer(
        lambda: Down(batches=[]),
        topics=[Topic.SYSTEM_EVENTS],
        group_id="g-1",
        start_backoff=FAST_START,
    )
    running = asyncio.create_task(consumer.run(Handler()))
    await asyncio.sleep(0.05)
    await asyncio.wait_for(consumer.stop(), timeout=2)
    await running

    assert not consumer.connected


async def test_non_transient_start_errors_are_raised() -> None:
    class Misconfigured(FakeConsumerClient):
        async def start(self) -> None:
            raise ValueError("bad option")

    consumer = KafkaBatchConsumer(
        lambda: Misconfigured(batches=[]), topics=[Topic.SYSTEM_EVENTS], group_id="g-1"
    )

    with pytest.raises(ValueError, match="bad option"):
        await consumer.run(Handler())


async def test_lag_is_reported_per_partition() -> None:
    client = FakeConsumerClient(batches=[{SYSTEM: [_record(SYSTEM, 0)]}])
    client.assigned = {SYSTEM, AUTH}
    client.highwaters = {SYSTEM: 120, AUTH: 7}
    client.positions = {SYSTEM: 100, AUTH: 7}
    consumer = _consumer(client)

    await consumer.run(Handler())

    assert consumer.lag == {"system_logs:0": 20, "auth_events:1": 0}


async def test_a_stop_requested_before_run_is_honoured() -> None:
    client = FakeConsumerClient(batches=[{SYSTEM: [_record(SYSTEM, 0)]}])
    consumer = _consumer(client)
    consumer.request_stop()
    handler = Handler()

    await consumer.run(handler)

    assert handler.batches == []
    assert client.commits == []


class PositionsHandler:
    """Returns queued commit positions, one per call; records every call."""

    def __init__(self, *positions: dict[tuple[str, int], int] | None) -> None:
        self.positions = list(positions)
        self.calls: list[int] = []

    async def __call__(
        self, records: Sequence[ConsumerRecordLike]
    ) -> dict[tuple[str, int], int] | None:
        self.calls.append(len(records))
        return self.positions.pop(0) if self.positions else {}


async def test_returned_positions_are_committed_instead_of_the_batch_end() -> None:
    client = FakeConsumerClient(
        batches=[{SYSTEM: [_record(SYSTEM, 0), _record(SYSTEM, 1)], AUTH: [_record(AUTH, 7)]}],
        assigned={SYSTEM, AUTH},
    )
    handler = PositionsHandler({SYSTEM: 1, AUTH: 8})

    await _consumer(client).run(handler)

    assert client.commits == [{SYSTEM: 1, AUTH: 8}]


async def test_positions_of_partitions_no_longer_assigned_are_not_committed() -> None:
    client = FakeConsumerClient(batches=[{SYSTEM: [_record(SYSTEM, 0)]}], assigned={SYSTEM})
    handler = PositionsHandler({SYSTEM: 1, AUTH: 3})

    await _consumer(client).run(handler)

    assert client.commits == [{SYSTEM: 1}]


async def test_empty_positions_commit_nothing() -> None:
    client = FakeConsumerClient(batches=[{SYSTEM: [_record(SYSTEM, 0)]}], assigned={SYSTEM})

    await _consumer(client).run(PositionsHandler({}))

    assert client.commits == []


async def test_idle_calls_reach_the_handler_with_no_records() -> None:
    client = FakeConsumerClient(batches=[{}, {SYSTEM: [_record(SYSTEM, 0)]}, {}], assigned={SYSTEM})
    consumer = KafkaBatchConsumer(
        lambda: client,
        topics=[Topic.SYSTEM_EVENTS, Topic.AUTH_EVENTS],
        group_id="adis-feature-generator",
        idle_calls=True,
    )
    client.on_drained = consumer.request_stop
    handler = PositionsHandler({SYSTEM: 0}, {SYSTEM: 1}, None)

    await consumer.run(handler)

    assert handler.calls[:3] == [0, 1, 0]
    assert client.commits == [{SYSTEM: 0}, {SYSTEM: 1}]


async def test_idle_consumers_know_which_partitions_are_caught_up() -> None:
    """A partition is caught up only when its position reached the fetched high watermark."""
    never_fetched = ("system_logs", 1)
    client = FakeConsumerClient(
        batches=[{SYSTEM: [_record(SYSTEM, 99)]}, {}],
        assigned={SYSTEM, AUTH, never_fetched},
        highwaters={SYSTEM: 120, AUTH: 7},
        positions={SYSTEM: 100, AUTH: 7, never_fetched: 0},
    )
    consumer = KafkaBatchConsumer(
        lambda: client,
        topics=[Topic.SYSTEM_EVENTS, Topic.AUTH_EVENTS],
        group_id="adis-feature-generator",
        idle_calls=True,
    )
    client.on_drained = consumer.request_stop
    seen: list[tuple[bool, bool, bool]] = []

    async def handler(records: Sequence[ConsumerRecordLike]) -> None:
        seen.append(
            (
                consumer.is_caught_up(SYSTEM),
                consumer.is_caught_up(AUTH),
                consumer.is_caught_up(never_fetched),
            )
        )
        client.positions[SYSTEM] = 120  # the backlog drains before the next poll

    await consumer.run(handler)

    assert seen[:2] == [(False, True, False), (True, True, False)]
    assert not consumer.is_caught_up(("auth_events", 9))  # not assigned
