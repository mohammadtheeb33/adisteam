"""Normalizer remediation: agent registry, conflicting duplicates, skew, logs, metrics, health."""

import asyncio
import json
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from aiokafka.errors import KafkaConnectionError

from apps.normalizer.errors import ConflictingDuplicateError
from apps.normalizer.metrics import NormalizerMetrics
from apps.normalizer.normalization import INGESTION_METADATA_KEY
from apps.normalizer.service import NormalizerService
from packages.config import DatabaseSettings
from packages.database import Database
from packages.database.models.agents import OsType
from packages.events.canonical import parse_canonical_event, to_envelope
from packages.kafka import KafkaBatchConsumer, RetryPolicy, Topic
from tests.unit.events.canonical.samples import network, system
from tests.unit.kafka.fakes import FakeConsumerClient, FakeProducerClient, fake_producer
from tests.unit.log_capture import JsonLogCapture
from tests.unit.normalizer.fakes import NOW, Harness, envelope_of, raw_envelope, record_of

AGENT = uuid4()


def _registration(**metadata: object) -> dict[str, object]:
    values: dict[str, object] = {
        "name": "edge-7",
        "hostname": "edge-7.lab",
        "os_type": "linux",
        "agent_version": "0.2.0",
        **metadata,
    }
    return system(
        event_type="system.agent_registered",
        agent_id=str(AGENT),
        received_at=(NOW - timedelta(minutes=5)).isoformat(),
        metadata=values,
    )


# ------------------------------------------------------------------------ agent registry


async def test_registrations_populate_the_agent_registry() -> None:
    harness = Harness()
    telemetry = network(agent_id=str(AGENT), received_at=NOW.isoformat())

    await harness.pipeline(
        [
            record_of(envelope_of(_registration()), offset=0),
            record_of(envelope_of(telemetry), offset=1),
        ]
    )

    agent = harness.store.agents[AGENT]
    assert (agent.name, agent.hostname, agent.os_type, agent.agent_version) == (
        "edge-7",
        "edge-7.lab",
        OsType.LINUX,
        "0.2.0",
    )
    assert harness.store.last_seen[AGENT] == NOW  # moved forward by the later event
    assert harness.pipeline.stats.agent_registrations == 1


@pytest.mark.parametrize(
    "overrides",
    [{"name": None}, {"os_type": ""}, {"agent_version": 7}],
    ids=["missing name", "blank os", "numeric version"],
)
async def test_incomplete_registrations_are_stored_but_not_registered(
    overrides: dict[str, object],
) -> None:
    harness = Harness()

    await harness.pipeline([record_of(envelope_of(_registration(**overrides)))])

    assert harness.store.agents == {}
    assert len(harness.store.rows) == 1


async def test_unknown_operating_systems_register_as_other() -> None:
    harness = Harness()

    await harness.pipeline([record_of(envelope_of(_registration(os_type="plan9")))])

    assert harness.store.agents[AGENT].os_type is OsType.OTHER


async def test_events_of_unregistered_agents_do_not_create_agents() -> None:
    harness = Harness()

    await harness.pipeline([record_of(envelope_of(network(agent_id=str(uuid4()))))])

    assert (harness.store.agents, harness.store.last_seen) == ({}, {})


# ---------------------------------------------------------------- conflicting duplicates


async def test_a_resubmission_with_the_same_content_is_a_plain_duplicate() -> None:
    harness = Harness()
    event = parse_canonical_event(network())
    later = event.model_copy(
        update={"received_at": event.received_at + timedelta(minutes=1), "trace_id": "b" * 32}
    )

    await harness.pipeline([record_of(to_envelope(event, producer="adis-api"), offset=0)])
    await harness.pipeline([record_of(to_envelope(later, producer="adis-api"), offset=1)])

    assert harness.dead_letter.records == []
    assert (harness.pipeline.stats.duplicates, harness.pipeline.stats.conflicts) == (1, 0)


async def test_a_stored_event_id_with_different_content_is_dead_lettered() -> None:
    harness = Harness()
    event_id = str(uuid4())
    original = envelope_of(network(event_id=event_id, dst_port=443))
    forged = envelope_of(network(event_id=event_id, dst_port=22))

    await harness.pipeline([record_of(original, offset=0)])
    await harness.pipeline([record_of(forged, offset=1)])

    [dead] = harness.dead_letter.records
    assert isinstance(dead.error, ConflictingDuplicateError)
    assert dead.offset == 1
    kept = harness.store.rows[UUID(event_id)]
    assert getattr(kept, "dst_port", None) == 443  # the first write wins
    assert len(harness.publisher.events) == 1
    assert harness.pipeline.stats.conflicts == 1


async def test_conflicting_repeats_inside_one_batch_are_dead_lettered() -> None:
    harness = Harness()
    event_id = str(uuid4())
    records = [
        record_of(envelope_of(network(event_id=event_id, bytes_sent=1)), offset=0),
        record_of(envelope_of(network(event_id=event_id, bytes_sent=1)), offset=1),
        record_of(envelope_of(network(event_id=event_id, bytes_sent=999)), offset=2),
    ]

    await harness.pipeline(records)

    assert [record.offset for record in harness.dead_letter.records] == [2]
    assert (harness.pipeline.stats.duplicates, harness.pipeline.stats.conflicts) == (1, 1)
    assert len(harness.store.rows) == 1


# -------------------------------------------------------------------- future timestamps


async def test_future_timestamps_are_kept_and_flagged() -> None:
    harness = Harness(max_future_skew_seconds=300)
    ahead = (NOW + timedelta(days=30)).isoformat()
    received = NOW.isoformat()

    await harness.pipeline([record_of(envelope_of(system(timestamp=ahead, received_at=received)))])

    [stored] = harness.store.rows.values()
    block = stored.metadata[INGESTION_METADATA_KEY]
    assert isinstance(block, dict)
    assert block["timestamp_skew_seconds"] == pytest.approx(30 * 86_400)
    assert harness.pipeline.stats.future_timestamps == 1


async def test_small_clock_skew_is_not_flagged() -> None:
    harness = Harness(max_future_skew_seconds=300)

    await harness.pipeline(
        [
            record_of(
                envelope_of(
                    system(
                        timestamp=(NOW + timedelta(seconds=60)).isoformat(),
                        received_at=NOW.isoformat(),
                    )
                )
            )
        ]
    )

    [stored] = harness.store.rows.values()
    block = stored.metadata[INGESTION_METADATA_KEY]
    assert isinstance(block, dict)
    assert "timestamp_skew_seconds" not in block


# ------------------------------------------------------------------ lifecycle logging


async def test_every_event_is_logged_with_its_ids(json_logs: JsonLogCapture) -> None:
    harness = Harness(log_events=True)
    envelope = envelope_of(network(trace_id="c" * 32))

    await harness.pipeline([record_of(envelope, offset=0), record_of(envelope, offset=1)])

    [stored] = json_logs.with_message("event stored and published")
    [duplicate] = json_logs.with_message("duplicate event suppressed")
    for line in (stored, duplicate):
        assert (line["event_id"], line["trace_id"], line["host_id"]) == (
            str(envelope.event_id),
            "c" * 32,
            "web-1",
        )
    assert (stored["source_offset"], duplicate["source_offset"]) == (0, 1)


async def test_dead_letter_logs_carry_the_record_ids(json_logs: JsonLogCapture) -> None:
    harness = Harness()
    envelope = raw_envelope(network(src_ip="999.0.0.1"), trace_id="d" * 32)

    await harness.pipeline([record_of(envelope)])

    [line] = json_logs.with_message("record dead-lettered")
    assert (line["trace_id"], line["event_id"]) == ("d" * 32, str(envelope.event_id))


# ------------------------------------------------------------------------------ metrics


async def test_metrics_count_outcomes() -> None:
    metrics = NormalizerMetrics()
    harness = Harness(metrics=metrics)
    envelope = envelope_of(network())

    await harness.pipeline(
        [record_of(envelope, offset=0), record_of(envelope, offset=1), record_of(b"junk", offset=2)]
    )

    def value(outcome: str) -> float:
        sample = metrics.registry.get_sample_value(
            "adis_normalizer_events_total", {"outcome": outcome}
        )
        return sample or 0.0

    assert (value("published"), value("duplicate"), value("dead_lettered")) == (1, 1, 1)
    assert metrics.registry.get_sample_value("adis_normalizer_records_total") == 3


# ------------------------------------------------------------------- service and health


def _database() -> Database:
    return Database.from_settings(
        DatabaseSettings.model_validate({"supabase_db_url": "postgresql://a:b@127.0.0.1:1/adis"})
    )


async def _get(port: int, path: str) -> tuple[int, dict[str, object] | str]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: test\r\n\r\n".encode())
    await writer.drain()
    raw = await reader.read()
    writer.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body.decode()


async def test_health_ready_and_metrics_are_served() -> None:
    client = FakeConsumerClient(batches=[])
    consumer = KafkaBatchConsumer(lambda: client, topics=[Topic.SYSTEM_EVENTS], group_id="g")
    producer = fake_producer(FakeProducerClient())
    stopping = asyncio.Event()
    metrics = NormalizerMetrics()
    service = NormalizerService(
        consumer=consumer,
        pipeline=Harness(metrics=metrics).pipeline,
        producer=producer,
        database=_database(),
        stopping=stopping,
        metrics=metrics,
        health_host="127.0.0.1",
        health_port=0,
    )
    stop = asyncio.Event()
    running = asyncio.create_task(service.run(stop))
    async with asyncio.timeout(5):
        while True:
            if consumer.connected:
                break
            await asyncio.sleep(0.01)
    assert service.health is not None
    port = service.health.port

    health = await _get(port, "/health")
    ready = await _get(port, "/ready")
    page = await _get(port, "/metrics")
    missing = await _get(port, "/nope")
    stop.set()
    await asyncio.wait_for(running, timeout=5)

    assert health == (200, {"status": "ok"})
    status, body = ready
    assert status == 503  # the fake database URL is unreachable
    assert isinstance(body, dict)
    assert body["checks"] == {
        "kafka_consumer": "ok",
        "kafka_producer": "ok",
        "database": "unavailable",
    }
    assert page[0] == 200
    assert "adis_normalizer_records_total" in str(page[1])
    assert missing[0] == 404


async def test_the_service_waits_for_kafka_instead_of_exiting() -> None:
    class DownThenUp(FakeProducerClient):
        attempts = 0

        async def start(self) -> None:
            DownThenUp.attempts += 1
            if DownThenUp.attempts <= 2:
                raise KafkaConnectionError("broker down")
            await super().start()

    consumer_client = FakeConsumerClient(batches=[])
    consumer = KafkaBatchConsumer(
        lambda: consumer_client, topics=[Topic.SYSTEM_EVENTS], group_id="g"
    )
    stop = asyncio.Event()
    consumer_client.on_drained = stop.set
    service = NormalizerService(
        consumer=consumer,
        pipeline=Harness().pipeline,
        producer=fake_producer(DownThenUp()),
        database=_database(),
        stopping=asyncio.Event(),
        connect_backoff=RetryPolicy(
            max_attempts=1, initial_backoff_seconds=0.01, max_backoff_seconds=0.02
        ),
    )

    await asyncio.wait_for(service.run(stop), timeout=5)

    assert DownThenUp.attempts == 3
    assert consumer_client.started == 1  # consumed once Kafka answered
