"""Dead-letter record format and publisher."""

import pytest

from packages.kafka import DeadLetterHeader, DeadLetterPublisher, DeadLetterRecord, MessageContext
from tests.unit.kafka.fakes import FakeProducerClient, fake_producer

CONTEXT = MessageContext(
    topic="network_flows",
    partition=2,
    offset=41,
    timestamp_ms=1_790_000_000_000,
    key=b"host-7",
    headers=(("adis-event-type", b"network.flow"), ("adis-dlq-attempts", b"9")),
)


async def test_publish_preserves_value_key_and_headers_and_adds_failure_context() -> None:
    client = FakeProducerClient()
    async with fake_producer(client) as producer:
        await DeadLetterPublisher(producer).publish(
            CONTEXT,
            b"\x00raw bytes",
            ValueError("bad payload"),
            attempts=3,
            consumer_group="adis-detector",
        )

    [sent] = client.sent
    assert sent.topic == "adis.deadletter"
    assert sent.value == b"\x00raw bytes"
    assert sent.key == b"host-7"

    parsed = DeadLetterRecord.from_message(
        key=sent.key, value=sent.value, headers=tuple(sent.headers)
    )
    assert parsed.original_topic == "network_flows"
    assert (parsed.original_partition, parsed.original_offset) == (2, 41)
    assert parsed.original_timestamp_ms == 1_790_000_000_000
    assert parsed.consumer_group == "adis-detector"
    assert (parsed.error_type, parsed.error_message) == ("ValueError", "bad payload")
    assert parsed.attempts == 3
    # Stale failure headers from an earlier dead-lettering are replaced, not duplicated.
    assert parsed.original_headers == (("adis-event-type", b"network.flow"),)
    assert [name for name, _ in sent.headers].count(DeadLetterHeader.ATTEMPTS) == 1


async def test_error_message_is_truncated() -> None:
    client = FakeProducerClient()
    async with fake_producer(client) as producer:
        await DeadLetterPublisher(producer, max_error_message_length=10).publish(
            CONTEXT, b"{}", RuntimeError("x" * 100), attempts=1, consumer_group="g"
        )

    headers = dict(client.sent[0].headers)
    assert headers[DeadLetterHeader.ERROR_MESSAGE] == b"x" * 10


def test_parsing_a_regular_record_is_rejected() -> None:
    with pytest.raises(ValueError, match="not a dead-letter record"):
        DeadLetterRecord.from_message(key=None, value=b"{}", headers=(("content-type", b"x"),))
