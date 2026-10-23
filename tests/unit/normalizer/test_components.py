"""Output publisher and failure classification."""

import asyncio
import json

import pytest
from aiokafka.errors import KafkaConnectionError, MessageSizeTooLargeError
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from apps.normalizer.errors import PersistenceError, is_transient_error
from apps.normalizer.normalization import Provenance, normalize_record
from apps.normalizer.publisher import KafkaNormalizedEventPublisher
from packages.kafka import MessageContext, PublishError
from tests.unit.events.canonical.samples import network
from tests.unit.kafka.fakes import FakeProducerClient, fake_producer
from tests.unit.normalizer.fakes import API_HEADERS, NOW, data_error, envelope_of, transient_error


def _normalized(**overrides: object) -> object:
    envelope = envelope_of(network(**overrides))
    context = MessageContext("network_flows", 0, 3, 0, None, API_HEADERS)
    return normalize_record(
        envelope, Provenance.of(envelope, context), normalizer="adis-normalizer", now=NOW
    )


# ------------------------------------------------------------------------ publisher


async def test_normalized_events_go_to_the_security_events_topic() -> None:
    client = FakeProducerClient()
    normalized = _normalized()
    async with fake_producer(client) as producer:
        publisher = KafkaNormalizedEventPublisher(
            producer, producer_name="adis-normalizer", timeout_seconds=1
        )
        await publisher.publish([normalized])  # type: ignore[list-item]

    [sent] = client.sent
    envelope = json.loads(sent.value or b"")
    headers = dict(sent.headers)
    assert sent.topic == "adis.security.events"
    assert sent.key == b"web-1"
    assert envelope["producer"] == "adis-normalizer"
    assert envelope["payload"]["metadata"]["adis_ingestion"]["source_offset"] == 3
    assert headers["adis-ingest-client"] == b"agent-a"
    assert headers["adis-event-id"] == envelope["event_id"].encode()


async def test_nothing_to_publish_sends_nothing() -> None:
    client = FakeProducerClient()
    async with fake_producer(client) as producer:
        await KafkaNormalizedEventPublisher(producer, producer_name="n", timeout_seconds=1).publish(
            []
        )

    assert client.sent == []


async def test_publishing_is_bounded_in_time() -> None:
    class SlowClient(FakeProducerClient):
        async def send_and_wait(self, *args: object, **kwargs: object) -> object:  # type: ignore[override]
            await asyncio.sleep(10)
            raise AssertionError("unreachable")

    async with fake_producer(SlowClient()) as producer:
        publisher = KafkaNormalizedEventPublisher(producer, producer_name="n", timeout_seconds=0.05)
        with pytest.raises(TimeoutError):
            await publisher.publish([_normalized()])  # type: ignore[list-item]


# ------------------------------------------------------------------- classification


class _DriverError(Exception):
    def __init__(self, sqlstate: str) -> None:
        super().__init__("value 'secret' is invalid")
        self.sqlstate = sqlstate


@pytest.mark.parametrize(
    "error",
    [
        transient_error(),
        PoolTimeoutError(),
        TimeoutError(),
        ConnectionRefusedError(),
        PublishError("adis.security.events", 5),
        KafkaConnectionError(),
        DBAPIError("SELECT 1", {}, _DriverError("08006")),
        DBAPIError("SELECT 1", {}, _DriverError("40P01")),
        DBAPIError("SELECT 1", {}, _DriverError("40001")),
        DBAPIError("SELECT 1", {}, _DriverError("53300")),
        DBAPIError("SELECT 1", {}, _DriverError("57014")),
        DBAPIError("SELECT 1", {}, Exception(), connection_invalidated=True),
        ExceptionGroup("publish", [PublishError("t", 1), TimeoutError()]),
    ],
    ids=lambda error: type(error).__name__,
)
def test_outages_are_transient(error: BaseException) -> None:
    assert is_transient_error(error)


@pytest.mark.parametrize(
    "error",
    [
        data_error(),
        IntegrityError("INSERT", {}, _DriverError("23503")),
        ProgrammingError("INSERT", {}, _DriverError("42P01")),
        MessageSizeTooLargeError(),
        RuntimeError("bug"),
        ExceptionGroup("publish", [PublishError("t", 1), RuntimeError("bug")]),
    ],
    ids=lambda error: type(error).__name__,
)
def test_data_errors_and_bugs_are_not_transient(error: BaseException) -> None:
    assert not is_transient_error(error)


def test_persistence_errors_never_quote_the_database_message() -> None:
    error = PersistenceError.from_error(IntegrityError("INSERT", {}, _DriverError("23503")))

    assert str(error) == "event could not be stored: IntegrityError (SQLSTATE 23503)"
    assert str(PersistenceError.from_error(RuntimeError("secret"))) == (
        "event could not be stored: RuntimeError"
    )
