"""KafkaProducer behavior over an in-memory client."""

import pytest
from aiokafka.errors import KafkaConnectionError, MessageSizeTooLargeError

from packages.kafka import PublishError, Topic, deserialize_envelope
from tests.unit.kafka.fakes import FakeProducerClient, RecordingSleep, fake_producer, make_envelope


async def test_publish_sends_serialized_envelope_with_key_and_headers() -> None:
    client = FakeProducerClient()
    envelope = make_envelope()

    async with fake_producer(client) as producer:
        published = await producer.publish(Topic.SECURITY_EVENTS, envelope, key="host-42")

    [record] = client.sent
    assert record.topic == "adis.security.events"
    assert record.key == b"host-42"
    assert deserialize_envelope(record.value) == envelope
    assert dict(record.headers)["adis-event-id"] == str(envelope.event_id).encode()
    assert (published.topic, published.partition, published.offset) == (
        "adis.security.events",
        0,
        0,
    )


async def test_transient_failures_are_retried() -> None:
    client = FakeProducerClient(failures=[KafkaConnectionError(), KafkaConnectionError()])
    sleep = RecordingSleep()

    async with fake_producer(client, sleep) as producer:
        await producer.publish(Topic.AUTH_EVENTS, make_envelope())

    assert len(client.sent) == 1
    assert len(sleep.delays) == 2


async def test_publish_error_after_exhausting_retries() -> None:
    client = FakeProducerClient(failures=[KafkaConnectionError()] * 5)

    async with fake_producer(client) as producer:
        with pytest.raises(PublishError) as caught:
            await producer.publish(Topic.AUTH_EVENTS, make_envelope())

    assert caught.value.attempts == 3
    assert caught.value.topic == "auth_events"
    assert isinstance(caught.value.__cause__, KafkaConnectionError)
    assert client.sent == []


async def test_permanent_failures_are_not_retried() -> None:
    client = FakeProducerClient(failures=[MessageSizeTooLargeError()])
    sleep = RecordingSleep()

    async with fake_producer(client, sleep) as producer:
        with pytest.raises(PublishError) as caught:
            await producer.publish(Topic.AUTH_EVENTS, make_envelope())

    assert caught.value.attempts == 1
    assert sleep.delays == []


async def test_publishing_to_the_dead_letter_topic_directly_is_rejected() -> None:
    async with fake_producer(FakeProducerClient()) as producer:
        with pytest.raises(ValueError, match="DeadLetterPublisher"):
            await producer.publish(Topic.DEADLETTER, make_envelope())


async def test_publish_before_start_is_rejected() -> None:
    producer = fake_producer(FakeProducerClient())

    with pytest.raises(RuntimeError, match="start"):
        await producer.publish(Topic.AUTH_EVENTS, make_envelope())


async def test_start_and_stop_are_idempotent() -> None:
    client = FakeProducerClient()
    producer = fake_producer(client)

    await producer.start()
    await producer.start()
    started_while_running = producer.started
    await producer.stop()
    await producer.stop()

    assert (started_while_running, producer.started) == (True, False)
    assert (client.started, client.stopped) == (1, 1)


async def test_context_manager_stops_on_error() -> None:
    client = FakeProducerClient()

    with pytest.raises(RuntimeError, match="boom"):
        async with fake_producer(client):
            raise RuntimeError("boom")

    assert client.stopped == 1


async def test_extra_headers_follow_the_envelope_headers() -> None:
    client = FakeProducerClient()

    async with fake_producer(client) as producer:
        await producer.publish(
            Topic.AUTH_EVENTS, make_envelope(), headers=[("adis-request-id", b"r-1")]
        )

    names = [name for name, _ in client.sent[0].headers]
    assert names[0] == "content-type"
    assert names[-1] == "adis-request-id"


async def test_partitions_for_reports_topic_partitions() -> None:
    async with fake_producer(FakeProducerClient()) as producer:
        assert await producer.partitions_for(Topic.SYSTEM_EVENTS) == {0, 1, 2}


async def test_partitions_for_requires_a_started_producer() -> None:
    with pytest.raises(RuntimeError, match="start"):
        await fake_producer(FakeProducerClient()).partitions_for(Topic.SYSTEM_EVENTS)


async def test_ping_asks_a_broker_every_time() -> None:
    client = FakeProducerClient()
    async with fake_producer(client) as producer:
        await producer.ping()
        client.client.failures.append(KafkaConnectionError())
        with pytest.raises(KafkaConnectionError):
            await producer.ping()

    assert client.client.requests == 2


async def test_ping_requires_a_started_producer() -> None:
    with pytest.raises(RuntimeError, match="start"):
        await fake_producer(FakeProducerClient()).ping()
