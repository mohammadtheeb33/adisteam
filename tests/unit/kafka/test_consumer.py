"""KafkaConsumer processing, retries, dead-lettering, commits and shutdown."""

import asyncio
import logging

import pytest
from aiokafka.errors import CommitFailedError, KafkaConnectionError

from packages.events import EventEnvelope
from packages.kafka import (
    DeadLetterPublisher,
    DeadLetterRecord,
    KafkaConsumer,
    MessageContext,
    NonRetriableError,
    PublishError,
    Topic,
    serialize_envelope,
)
from packages.observability import current_log_context
from tests.unit.kafka.fakes import (
    NO_RETRY_DELAY,
    ConsumerRecord,
    FakeConsumerClient,
    FakeProducerClient,
    RecordingSleep,
    fake_producer,
    make_envelope,
    upper_jitter,
)
from tests.unit.log_capture import JsonLogCapture

PARTITION = ("adis.security.events", 0)


class Handler:
    """Records calls; fails according to ``failures`` (one entry per call)."""

    def __init__(self, failures: list[Exception | None] | None = None) -> None:
        self.failures = list(failures or [])
        self.calls: list[tuple[EventEnvelope, MessageContext]] = []

    async def __call__(self, event: EventEnvelope, context: MessageContext) -> None:
        self.calls.append((event, context))
        failure = self.failures.pop(0) if self.failures else None
        if failure is not None:
            raise failure


class Harness:
    """A consumer wired to fake clients that stops once its batches are drained."""

    def __init__(
        self,
        records: list[ConsumerRecord],
        *,
        dead_letter_failures: list[Exception] | None = None,
    ) -> None:
        self.dead_letter_client = FakeProducerClient(failures=dead_letter_failures or [])
        self.producer = fake_producer(self.dead_letter_client)
        self.client = FakeConsumerClient(batches=[{PARTITION: records}])
        self.sleep = RecordingSleep()
        self.consumer = KafkaConsumer(
            lambda: self.client,
            topics=[Topic.SECURITY_EVENTS],
            group_id="adis-test",
            dead_letter=DeadLetterPublisher(self.producer),
            retry_policy=NO_RETRY_DELAY,
            sleep=self.sleep,
            jitter=upper_jitter,
        )
        self.client.on_drained = self.consumer.request_stop

    async def run(self, handler: Handler) -> None:
        async with self.producer:
            await asyncio.wait_for(self.consumer.run(handler), timeout=5)

    def dead_letters(self) -> list[DeadLetterRecord]:
        return [
            DeadLetterRecord.from_message(key=r.key, value=r.value, headers=tuple(r.headers))
            for r in self.dead_letter_client.sent
        ]


def _record(offset: int, value: bytes | None, key: bytes | None = None) -> ConsumerRecord:
    return ConsumerRecord(topic=PARTITION[0], partition=0, offset=offset, value=value, key=key)


async def test_valid_records_are_handled_in_order_and_committed() -> None:
    first, second = make_envelope(), make_envelope()
    harness = Harness(
        [_record(10, serialize_envelope(first), b"k"), _record(11, serialize_envelope(second))]
    )
    handler = Handler()

    await harness.run(handler)

    assert [event for event, _ in handler.calls] == [first, second]
    context = handler.calls[0][1]
    assert (context.topic, context.partition, context.offset, context.key) == (
        "adis.security.events",
        0,
        10,
        b"k",
    )
    assert harness.client.commits == [{PARTITION: 12}]  # one commit per partition per poll
    assert harness.dead_letters() == []
    assert (harness.client.started, harness.client.stopped) == (1, 1)


async def test_poison_record_is_dead_lettered_without_calling_the_handler() -> None:
    harness = Harness([_record(5, b"not json", b"host-1")])
    handler = Handler()

    await harness.run(handler)

    assert handler.calls == []
    [dead_letter] = harness.dead_letters()
    assert dead_letter.value == b"not json"
    assert dead_letter.key == b"host-1"
    assert dead_letter.error_type == "DeserializationError"
    assert dead_letter.attempts == 1
    assert (dead_letter.original_topic, dead_letter.original_offset) == ("adis.security.events", 5)
    assert dead_letter.consumer_group == "adis-test"
    assert harness.client.commits == [{PARTITION: 6}]


async def test_transient_handler_failures_are_retried() -> None:
    harness = Harness([_record(0, serialize_envelope(make_envelope()))])
    handler = Handler(failures=[ConnectionError("db down"), None])

    await harness.run(handler)

    assert len(handler.calls) == 2
    assert len(harness.sleep.delays) == 1
    assert harness.dead_letters() == []
    assert harness.client.commits == [{PARTITION: 1}]


async def test_record_is_dead_lettered_after_retries_are_exhausted() -> None:
    envelope = make_envelope()
    harness = Harness([_record(0, serialize_envelope(envelope))])
    handler = Handler(failures=[ValueError("unexpected payload")] * 3)

    await harness.run(handler)

    assert len(handler.calls) == 3
    [dead_letter] = harness.dead_letters()
    assert dead_letter.attempts == 3
    assert dead_letter.error_type == "ValueError"
    assert dead_letter.value == serialize_envelope(envelope)
    assert harness.client.commits == [{PARTITION: 1}]


async def test_non_retriable_failure_is_dead_lettered_immediately() -> None:
    harness = Harness([_record(0, serialize_envelope(make_envelope()))])
    handler = Handler(failures=[NonRetriableError("unsupported event_version")])

    await harness.run(handler)

    assert len(handler.calls) == 1
    [dead_letter] = harness.dead_letters()
    assert (dead_letter.error_type, dead_letter.attempts) == ("NonRetriableError", 1)
    assert harness.sleep.delays == []


async def test_nothing_is_committed_when_dead_lettering_fails() -> None:
    harness = Harness([_record(0, b"not json")], dead_letter_failures=[KafkaConnectionError()] * 3)

    with pytest.raises(PublishError):
        await harness.run(Handler())

    assert harness.client.commits == []
    assert harness.client.stopped == 1
    assert not harness.consumer.running


async def test_stop_request_leaves_remaining_records_uncommitted() -> None:
    harness = Harness(
        [
            _record(0, serialize_envelope(make_envelope())),
            _record(1, serialize_envelope(make_envelope())),
        ]
    )

    class StopAfterFirst(Handler):
        async def __call__(self, event: EventEnvelope, context: MessageContext) -> None:
            await super().__call__(event, context)
            harness.consumer.request_stop()

    handler = StopAfterFirst()
    await harness.run(handler)

    assert len(handler.calls) == 1
    assert harness.client.commits == [{PARTITION: 1}]
    assert harness.client.stopped == 1


async def test_stop_waits_for_run_to_return() -> None:
    harness = Harness([])
    harness.client.on_drained = None  # keep polling until stopped

    async with harness.producer:
        task = asyncio.create_task(harness.consumer.run(Handler()))
        await asyncio.sleep(0.01)
        running_before_stop = harness.consumer.running
        await asyncio.wait_for(harness.consumer.stop(), timeout=5)
        await task

    assert (running_before_stop, harness.consumer.running) == (True, False)
    assert harness.client.stopped == 1


async def test_running_twice_concurrently_is_rejected() -> None:
    harness = Harness([])
    harness.client.on_drained = None

    async with harness.producer:
        task = asyncio.create_task(harness.consumer.run(Handler()))
        await asyncio.sleep(0.01)
        with pytest.raises(RuntimeError, match="already running"):
            await harness.consumer.run(Handler())
        await harness.consumer.stop()
        await task


@pytest.mark.parametrize(
    ("topics", "group_id", "message"),
    [
        ([], "adis-test", "at least one topic"),
        ([Topic.DEADLETTER], "adis-test", "dead-letter"),
        ([Topic.SYSTEM_EVENTS], "bad group", "group_id"),
    ],
)
def test_invalid_configuration_is_rejected(
    topics: list[Topic], group_id: str, message: str
) -> None:
    producer = fake_producer(FakeProducerClient())

    with pytest.raises(ValueError, match=message):
        KafkaConsumer(
            lambda: FakeConsumerClient(batches=[]),
            topics=topics,
            group_id=group_id,
            dead_letter=DeadLetterPublisher(producer),
            retry_policy=NO_RETRY_DELAY,
        )


async def test_handler_runs_inside_the_event_trace_context(json_logs: JsonLogCapture) -> None:
    envelope = make_envelope()
    harness = Harness([_record(0, serialize_envelope(envelope))])
    observed: list[tuple[str | None, str | None, str]] = []

    class Observing(Handler):
        async def __call__(self, event: EventEnvelope, context: MessageContext) -> None:
            await super().__call__(event, context)
            derived = make_envelope(event_type="detector.anomaly_detected")
            bound = current_log_context()
            observed.append((bound.trace_id, bound.event_id, derived.trace_id))
            logging.getLogger("tests.handler").info("handled")

    await harness.run(Observing())

    assert observed == [(envelope.trace_id, str(envelope.event_id), envelope.trace_id)]
    [handled] = json_logs.with_message("handled")
    assert handled["trace_id"] == envelope.trace_id
    assert handled["event_id"] == str(envelope.event_id)
    assert current_log_context().trace_id is None


async def test_retries_and_dead_letters_are_logged_with_the_event_trace(
    json_logs: JsonLogCapture,
) -> None:
    envelope = make_envelope()
    harness = Harness([_record(0, serialize_envelope(envelope))])

    await harness.run(Handler(failures=[ValueError("unexpected payload")] * 3))

    retries = json_logs.with_message("event handler failed; retrying")
    [dead_lettered] = json_logs.with_message("record dead-lettered")
    assert len(retries) == 2
    for record in (*retries, dead_lettered):
        assert record["trace_id"] == envelope.trace_id
        assert record["event_id"] == str(envelope.event_id)


async def test_poison_record_is_correlated_through_its_trace_header(
    json_logs: JsonLogCapture,
) -> None:
    trace = "4bf92f3577b34da6a3ce929d0e0e4736"
    poison = ConsumerRecord(
        topic=PARTITION[0],
        partition=0,
        offset=0,
        value=b"not json",
        headers=(("adis-trace-id", trace.encode()),),
    )
    harness = Harness([poison])

    await harness.run(Handler())

    [dead_lettered] = json_logs.with_message("record dead-lettered")
    assert dead_lettered["trace_id"] == trace
    assert dead_lettered["event_id"] is None


async def test_outages_are_retried_until_they_recover_never_dead_lettered() -> None:
    envelope = make_envelope()
    harness = Harness([_record(0, serialize_envelope(envelope))])
    handler = Handler(failures=[ConnectionError("db down")] * 10)

    await harness.run(handler)

    assert len(handler.calls) == 11  # ten failures, then success
    assert harness.dead_letters() == []
    assert harness.client.commits == [{PARTITION: 1}]


async def test_a_stop_during_an_outage_leaves_the_record_uncommitted() -> None:
    harness = Harness([_record(0, serialize_envelope(make_envelope()))])

    class DownForever(Handler):
        async def __call__(self, event: EventEnvelope, context: MessageContext) -> None:
            await super().__call__(event, context)
            if len(self.calls) == 5:
                harness.consumer.request_stop()
            raise TimeoutError("database unreachable")

    await harness.run(DownForever())

    assert harness.dead_letters() == []
    assert harness.client.commits == []


async def test_settled_records_are_committed_when_a_later_one_cannot_be_dead_lettered() -> None:
    harness = Harness(
        [_record(0, serialize_envelope(make_envelope())), _record(1, b"not json")],
        dead_letter_failures=[KafkaConnectionError()] * 3,
    )

    with pytest.raises(PublishError):
        await harness.run(Handler())

    assert harness.client.commits == [{PARTITION: 1}]  # only the handled record


async def test_rebalance_refused_commits_are_not_fatal(json_logs: JsonLogCapture) -> None:
    harness = Harness([_record(0, serialize_envelope(make_envelope()))])

    async def refuse(offsets: object = None) -> None:
        raise CommitFailedError("rebalanced")

    harness.client.commit = refuse  # type: ignore[method-assign]
    await harness.run(Handler())

    assert json_logs.with_message(
        "offsets not committed because the group rebalanced; the records will be redelivered"
    )


async def test_a_stop_requested_before_run_is_honoured() -> None:
    harness = Harness([_record(0, serialize_envelope(make_envelope()))])
    harness.consumer.request_stop()
    handler = Handler()

    await harness.run(handler)
    later = await asyncio.wait_for(_second_run(harness), timeout=5)

    assert handler.calls == []
    assert later == 1  # the flag was cleared when the first run returned


async def _second_run(harness: Harness) -> int:
    harness.client.batches = [{PARTITION: [_record(0, serialize_envelope(make_envelope()))]}]
    handler = Handler()
    await harness.run(handler)
    return len(handler.calls)
