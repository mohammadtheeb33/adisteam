"""Producer, consumer, dead-lettering and topic provisioning against a real broker."""

import asyncio
from uuid import uuid4

import pytest
from aiokafka import AIOKafkaConsumer
from aiokafka.admin import AIOKafkaAdminClient
from aiokafka.structs import TopicPartition

from packages.config import KafkaSettings
from packages.events import EventEnvelope
from packages.kafka import (
    DeadLetterPublisher,
    DeadLetterRecord,
    KafkaConsumer,
    KafkaProducer,
    MessageContext,
    Topic,
    ensure_topics,
    serialize_envelope,
)
from packages.observability import current_trace_id, log_context
from tests.integration.kafka.helpers import (
    WAIT_SECONDS,
    commit_group_offsets,
    end_offsets,
    read_until,
)

pytestmark = pytest.mark.integration


def _envelope() -> EventEnvelope:
    return EventEnvelope(
        event_type="security.integration_probe",
        event_version=1,
        producer="adis-integration-tests",
        payload={"probe": uuid4().hex},
    )


class Collector:
    """Handler that records every event and signals when a target event arrives."""

    def __init__(self, target_event_id: object, *, fail_target: bool = False) -> None:
        self.target_event_id = target_event_id
        self.fail_target = fail_target
        self.target_calls: list[MessageContext] = []
        self.bound_trace_ids: list[str | None] = []
        self.seen_target = asyncio.Event()

    async def __call__(self, event: EventEnvelope, context: MessageContext) -> None:
        if event.event_id != self.target_event_id:
            return  # records from earlier runs of the suite
        self.target_calls.append(context)
        self.bound_trace_ids.append(current_trace_id())
        if self.fail_target:
            raise RuntimeError("simulated handler failure")
        self.seen_target.set()


def _consumer(
    settings: KafkaSettings, producer: KafkaProducer, group_id: str, topic: Topic
) -> KafkaConsumer:
    return KafkaConsumer.from_settings(
        settings, topics=[topic], group_id=group_id, dead_letter=DeadLetterPublisher(producer)
    )


@pytest.mark.usefixtures("topics")
async def test_every_topic_exists_and_provisioning_is_idempotent(
    kafka_settings: KafkaSettings,
) -> None:
    assert await ensure_topics(kafka_settings) == ()

    admin = AIOKafkaAdminClient(bootstrap_servers=kafka_settings.kafka_bootstrap_servers)
    await admin.start()
    try:
        existing = set(await admin.list_topics())
    finally:
        await admin.close()
    assert {topic.value for topic in Topic} <= existing


async def test_published_event_is_consumed_and_committed(
    kafka_settings: KafkaSettings, producer: KafkaProducer, unique_group: str
) -> None:
    trace = "4bf92f3577b34da6a3ce929d0e0e4736"
    with log_context(trace_id=trace):  # e.g. the HTTP request that caused the event
        envelope = _envelope()
    # Start the group at the current end, so the test reads only its own record.
    await commit_group_offsets(
        kafka_settings, unique_group, await end_offsets(kafka_settings, [Topic.SECURITY_EVENTS])
    )
    published = await producer.publish(Topic.SECURITY_EVENTS, envelope, key="host-it")
    consumer = _consumer(kafka_settings, producer, unique_group, Topic.SECURITY_EVENTS)
    handler = Collector(envelope.event_id)

    run = asyncio.create_task(consumer.run(handler))
    try:
        await asyncio.wait_for(handler.seen_target.wait(), WAIT_SECONDS)
    finally:
        await consumer.stop()
        await run

    [context] = handler.target_calls
    assert (context.partition, context.offset) == (published.partition, published.offset)
    assert context.key == b"host-it"
    assert dict(context.headers)["adis-event-id"] == str(envelope.event_id).encode()
    # The trace crossed the broker: in the envelope, in the header, and bound in the handler.
    assert envelope.trace_id == trace
    assert dict(context.headers)["adis-trace-id"] == trace.encode()
    assert handler.bound_trace_ids == [trace]

    committed = await _committed_offset(kafka_settings, unique_group, context)
    assert committed is not None
    assert committed >= context.offset + 1


async def test_poison_record_is_dead_lettered(
    kafka_settings: KafkaSettings, producer: KafkaProducer, unique_group: str
) -> None:
    marker = f"poison-{uuid4().hex}".encode()
    start = await end_offsets(kafka_settings, [Topic.SYSTEM_EVENTS])
    dead_start = await end_offsets(kafka_settings, [Topic.DEADLETTER])
    await commit_group_offsets(kafka_settings, unique_group, start)
    await producer.send_raw(Topic.SYSTEM_EVENTS, b"{not json", key=marker, headers=[])
    consumer = _consumer(kafka_settings, producer, unique_group, Topic.SYSTEM_EVENTS)

    run = asyncio.create_task(consumer.run(Collector(target_event_id=None)))
    try:
        record = await read_until(kafka_settings, dead_start, lambda r: r.key == marker)
    finally:
        await consumer.stop()
        await run

    dead_letter = DeadLetterRecord.from_message(
        key=record.key, value=record.value, headers=tuple(record.headers)
    )
    assert dead_letter.value == b"{not json"
    assert dead_letter.original_topic == Topic.SYSTEM_EVENTS.value
    assert dead_letter.error_type == "DeserializationError"
    assert dead_letter.attempts == 1
    assert dead_letter.consumer_group == unique_group


async def test_failing_handler_is_dead_lettered_after_retries(
    kafka_settings: KafkaSettings, producer: KafkaProducer, unique_group: str
) -> None:
    envelope = _envelope()
    marker = f"failing-{uuid4().hex}"
    await commit_group_offsets(
        kafka_settings, unique_group, await end_offsets(kafka_settings, [Topic.AUTH_EVENTS])
    )
    dead_start = await end_offsets(kafka_settings, [Topic.DEADLETTER])
    await producer.publish(Topic.AUTH_EVENTS, envelope, key=marker)
    consumer = _consumer(kafka_settings, producer, unique_group, Topic.AUTH_EVENTS)
    handler = Collector(envelope.event_id, fail_target=True)

    run = asyncio.create_task(consumer.run(handler))
    try:
        record = await read_until(kafka_settings, dead_start, lambda r: r.key == marker.encode())
    finally:
        await consumer.stop()
        await run

    dead_letter = DeadLetterRecord.from_message(
        key=record.key, value=record.value, headers=tuple(record.headers)
    )
    assert len(handler.target_calls) == kafka_settings.kafka_retry_max_attempts
    assert dead_letter.attempts == kafka_settings.kafka_retry_max_attempts
    assert dead_letter.error_type == "RuntimeError"
    assert dead_letter.value == serialize_envelope(envelope)
    assert dict(dead_letter.original_headers)["adis-event-id"] == str(envelope.event_id).encode()


async def _committed_offset(
    settings: KafkaSettings, group_id: str, context: MessageContext
) -> int | None:
    reader = AIOKafkaConsumer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=group_id,
        enable_auto_commit=False,
    )
    await reader.start()
    try:
        offset: int | None = await reader.committed(
            TopicPartition(context.topic, context.partition)
        )
    finally:
        await reader.stop()
    return offset
