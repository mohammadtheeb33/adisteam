"""Consumer, pipeline, producer and dead-letter topic working together (in memory)."""

import asyncio
from pathlib import Path

import pytest

from apps.normalizer import __main__ as cli
from apps.normalizer.pipeline import NormalizationPipeline
from apps.normalizer.publisher import KafkaNormalizedEventPublisher
from apps.normalizer.service import NormalizerService
from apps.normalizer.settings import NormalizerServiceSettings
from packages.config import DatabaseSettings
from packages.database import Database
from packages.kafka import DeadLetterPublisher, KafkaBatchConsumer, KafkaProducer, Topic
from tests.unit.events.canonical.samples import network
from tests.unit.kafka.fakes import (
    ConsumerRecord,
    FakeConsumerClient,
    FakeProducerClient,
    fake_producer,
)
from tests.unit.log_capture import JsonLogCapture
from tests.unit.normalizer.fakes import (
    FAST_RETRIES,
    GROUP,
    NOW,
    MemoryEventStore,
    envelope_of,
    record_of,
    transient_error,
)

NETWORK = ("network_flows", 0)


def _pipeline(
    store: MemoryEventStore, producer: KafkaProducer, stopping: asyncio.Event
) -> NormalizationPipeline:
    return NormalizationPipeline(
        store=store,
        publisher=KafkaNormalizedEventPublisher(
            producer, producer_name="adis-normalizer", timeout_seconds=1
        ),
        dead_letter=DeadLetterPublisher(producer),
        consumer_group=GROUP,
        normalizer_name="adis-normalizer",
        retry_policy=FAST_RETRIES,
        stopping=stopping,
        clock=lambda: NOW,
    )


def _consumer(client: FakeConsumerClient) -> KafkaBatchConsumer:
    return KafkaBatchConsumer(
        lambda: client,
        topics=[Topic.SYSTEM_EVENTS, Topic.AUTH_EVENTS, Topic.NETWORK_EVENTS],
        group_id=GROUP,
    )


def _batch() -> list[ConsumerRecord]:
    duplicate = envelope_of(network())
    return [
        record_of(envelope_of(network()), offset=0),
        record_of(duplicate, offset=1),
        record_of(duplicate, offset=2),
        record_of(b"not an envelope", offset=3),
    ]


def _topics(client: FakeProducerClient) -> list[str]:
    return [record.topic for record in client.sent]


async def test_records_are_stored_published_or_dead_lettered_then_committed() -> None:
    records = _batch()
    client = FakeConsumerClient(batches=[{NETWORK: records}, {NETWORK: records}])
    consumer = _consumer(client)
    client.on_drained = consumer.request_stop
    producer_client = FakeProducerClient()
    store = MemoryEventStore()

    async with fake_producer(producer_client) as producer:
        await consumer.run(_pipeline(store, producer, asyncio.Event()))

    # The second poll redelivers the same records: no new rows or publications, but the
    # malformed record is dead-lettered again (dead letters are at-least-once too).
    assert len(store.rows) == 2
    assert _topics(producer_client).count("adis.security.events") == 2
    assert _topics(producer_client).count("adis.deadletter") == 2
    assert client.commits == [{NETWORK: 4}, {NETWORK: 4}]


async def test_offsets_are_not_committed_while_processing_cannot_complete() -> None:
    client = FakeConsumerClient(batches=[{NETWORK: _batch()}])
    consumer = _consumer(client)
    store = MemoryEventStore(store_failures=[transient_error()] * 100_000)
    stopping = asyncio.Event()

    async def shut_down_soon() -> None:
        await asyncio.sleep(0.05)
        stopping.set()
        consumer.request_stop()

    async with fake_producer(FakeProducerClient()) as producer:
        stopper = asyncio.create_task(shut_down_soon())
        await consumer.run(_pipeline(store, producer, stopping))
        await stopper

    assert client.commits == []
    assert store.rows == {}


def _database() -> Database:
    settings = DatabaseSettings.model_validate(
        {"supabase_db_url": "postgresql://adis:unused@127.0.0.1:1/adis"}
    )
    return Database.from_settings(settings)  # connects lazily; never used here


async def test_service_runs_until_stopped_then_shuts_down(json_logs: JsonLogCapture) -> None:
    client = FakeConsumerClient(batches=[{NETWORK: _batch()}])
    producer_client = FakeProducerClient()
    stopping = asyncio.Event()
    producer = fake_producer(producer_client)
    service = NormalizerService(
        consumer=_consumer(client),
        pipeline=_pipeline(MemoryEventStore(), producer, stopping),
        producer=producer,
        database=_database(),
        stopping=stopping,
    )
    stop = asyncio.Event()
    client.on_drained = stop.set  # the batch is processed and committed by then

    await asyncio.wait_for(service.run(stop), timeout=5)

    assert client.commits == [{NETWORK: 4}]
    assert stopping.is_set()
    assert (producer_client.started, producer_client.stopped) == (1, 1)
    [summary] = json_logs.with_message("normalizer stopped")
    assert (summary["published"], summary["duplicates"], summary["dead_lettered"]) == (2, 1, 1)


async def test_service_errors_propagate_after_cleanup() -> None:
    class BrokenClient(FakeConsumerClient):
        async def start(self) -> None:
            raise RuntimeError("cannot join group")

    producer_client = FakeProducerClient()
    producer = fake_producer(producer_client)
    stopping = asyncio.Event()
    service = NormalizerService(
        consumer=_consumer(BrokenClient(batches=[])),
        pipeline=_pipeline(MemoryEventStore(), producer, stopping),
        producer=producer,
        database=_database(),
        stopping=stopping,
    )

    with pytest.raises(RuntimeError, match="cannot join group"):
        await service.run(asyncio.Event())

    assert producer_client.stopped == 1


def test_missing_configuration_exits_with_code_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)  # no .env
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    monkeypatch.setenv("APP_ENV", "development")

    assert cli.main() == cli.EXIT_CONFIGURATION


def test_service_is_wired_from_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    settings = NormalizerServiceSettings.model_validate(
        {
            "app_name": "adis-normalizer",
            "supabase_db_url": "postgresql://adis:unused@127.0.0.1:1/adis",
            "normalizer_consumer_group": "adis-normalizer-7",
            "normalizer_max_attempts": 5,
        }
    )

    service = NormalizerService.from_settings(settings)  # connects to nothing yet

    assert service.pipeline.stats.records == 0
    assert service._consumer.group_id == "adis-normalizer-7"
    assert service.pipeline._retry_policy.max_attempts == 5
