"""The normalization pipeline against a real broker and a real database."""

import asyncio
import contextlib
import json
import socket
from collections.abc import Awaitable, Callable
from typing import Final
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from apps.agent.identity import AgentIdentity
from apps.agent.registration import registration_event
from apps.normalizer.service import NormalizerService
from apps.normalizer.settings import NormalizerServiceSettings
from packages.config import KafkaSettings, load_settings
from packages.database import Database
from packages.database.models import AgentStatus, OsType, SecurityEventRecord
from packages.database.repositories import AgentRepository, SecurityEventRepository
from packages.events import EventEnvelope
from packages.events.canonical import parse_canonical_event, to_envelope
from packages.kafka import RAW_TELEMETRY_TOPICS, KafkaProducer, Topic
from packages.kafka.consumer import ConsumerRecordLike
from tests.integration.kafka.helpers import (
    WAIT_SECONDS,
    commit_group_offsets,
    end_offsets,
    read_from,
)
from tests.unit.events.canonical.samples import authentication

pytestmark = pytest.mark.integration

PROVENANCE: Final = [("adis-ingest-client", b"agent-it")]
SETTLE_SECONDS: Final = 2.0


def _settings(
    monkeypatch: pytest.MonkeyPatch, group: str, *, health_port: int = 0
) -> NormalizerServiceSettings:
    monkeypatch.setenv("NORMALIZER_CONSUMER_GROUP", group)
    monkeypatch.setenv("NORMALIZER_POLL_TIMEOUT_MS", "200")
    monkeypatch.setenv("NORMALIZER_RETRY_INITIAL_BACKOFF_SECONDS", "0.05")
    monkeypatch.setenv("NORMALIZER_RETRY_MAX_BACKOFF_SECONDS", "0.5")
    monkeypatch.setenv("NORMALIZER_HEALTH_PORT", str(health_port))
    return load_settings(NormalizerServiceSettings)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


async def _get(port: int, path: str) -> tuple[int, bytes]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        await writer.drain()
        response = await reader.read()
    finally:
        writer.close()
        await writer.wait_closed()
    head, _, body = response.partition(b"\r\n\r\n")
    return int(head.split()[1]), body


async def _rows(database: Database, event_id: UUID) -> int:
    async with database.session() as session:
        statement = select(func.count()).where(SecurityEventRecord.event_id == event_id)
        return int((await session.execute(statement)).scalar_one())


Condition = Callable[[NormalizerService], Awaitable[bool]]


async def _run_until(settings: NormalizerServiceSettings, done: Condition) -> NormalizerService:
    """Run a normalizer until ``done(service)`` holds, then stop it."""
    service = NormalizerService.from_settings(settings)
    stop = asyncio.Event()
    running = asyncio.create_task(service.run(stop))
    try:
        async with asyncio.timeout(WAIT_SECONDS):
            while not await done(service):
                if running.done():
                    running.result()  # surface a crash
                await asyncio.sleep(0.2)
        await asyncio.sleep(SETTLE_SECONDS)  # let any unexpected extra output arrive
    finally:
        stop.set()
        await asyncio.wait_for(running, timeout=WAIT_SECONDS)
    return service


def _event_id(record: ConsumerRecordLike) -> UUID | None:
    try:
        return UUID(json.loads(record.value or b"")["event_id"])
    except (ValueError, KeyError, TypeError):
        return None


async def test_normalize_deduplicate_store_publish_and_dead_letter(
    monkeypatch: pytest.MonkeyPatch,
    kafka_settings: KafkaSettings,
    producer: KafkaProducer,
    migrated_database: Database,
    unique_group: str,
) -> None:
    canonical = to_envelope(parse_canonical_event(authentication()), producer="adis-api")
    source_shaped = EventEnvelope(
        event_type="network.flow",
        event_version=1,
        producer="zeek-connector",
        payload={
            "source_type": "zeek",
            "source_name": "zeek@sensor-it",
            "host_id": "web-1",
            "timestamp": 1_790_000_000_123,  # epoch milliseconds
            "src_ip": "[10.0.0.5]",
            "dst_ip": "10.0.0.9",
            "src_port": "51514",
            "dst_port": "443",
            "protocol": "TCP",
        },
    )
    poison = f"not an envelope {uuid4().hex}".encode()
    await commit_group_offsets(
        kafka_settings, unique_group, await end_offsets(kafka_settings, RAW_TELEMETRY_TOPICS)
    )
    output_start = await end_offsets(kafka_settings, [Topic.SECURITY_EVENTS])
    dead_start = await end_offsets(kafka_settings, [Topic.DEADLETTER])
    await producer.publish(Topic.AUTH_EVENTS, canonical, key="web-1", headers=PROVENANCE)
    await producer.publish(Topic.AUTH_EVENTS, canonical, key="web-1", headers=PROVENANCE)
    await producer.publish(Topic.NETWORK_EVENTS, source_shaped, key="web-1")
    await producer.send_raw(Topic.SYSTEM_EVENTS, poison, key=None, headers=[])
    ours = {canonical.event_id, source_shaped.event_id}

    async def both_stored(_: NormalizerService) -> bool:
        return all([await _rows(migrated_database, event_id) for event_id in ours])

    service = await _run_until(_settings(monkeypatch, unique_group), both_stored)

    assert service.pipeline.stats.duplicates >= 1
    for event_id in ours:
        assert await _rows(migrated_database, event_id) == 1
    published = await read_from(
        kafka_settings, output_start, lambda record: _event_id(record) in ours
    )
    assert sorted(str(_event_id(record)) for record in published) == sorted(map(str, ours))
    [flow] = [record for record in published if _event_id(record) == source_shaped.event_id]
    payload = json.loads(flow.value or b"")["payload"]
    assert (payload["src_ip"], payload["src_port"], payload["protocol"]) == (
        "10.0.0.5",
        51514,
        "tcp",
    )
    assert payload["timestamp"] == "2026-09-21T14:13:20.123000Z"
    assert payload["metadata"]["adis_ingestion"]["normalized_fields"] == [
        "timestamp",
        "src_ip",
        "src_port",
        "dst_port",
        "protocol",
    ]
    [auth] = [record for record in published if _event_id(record) == canonical.event_id]
    assert dict(auth.headers)["adis-ingest-client"] == b"agent-it"
    dead = await read_from(kafka_settings, dead_start, lambda record: record.value == poison)
    assert len(dead) == 1
    assert dict(dead[0].headers)["adis-dlq-consumer-group"] == unique_group.encode()


async def test_replaying_everything_creates_no_duplicates(
    monkeypatch: pytest.MonkeyPatch,
    kafka_settings: KafkaSettings,
    producer: KafkaProducer,
    migrated_database: Database,
    unique_group: str,
) -> None:
    envelope = to_envelope(parse_canonical_event(authentication()), producer="adis-api")
    start = await end_offsets(kafka_settings, RAW_TELEMETRY_TOPICS)
    output_start = await end_offsets(kafka_settings, [Topic.SECURITY_EVENTS])
    await commit_group_offsets(kafka_settings, unique_group, start)
    # The replay group re-reads everything from where this test began, like a group
    # whose offsets were lost.
    await commit_group_offsets(kafka_settings, f"{unique_group}-replay", start)
    await producer.publish(Topic.AUTH_EVENTS, envelope, key="web-1")

    async def stored(_: NormalizerService) -> bool:
        return await _rows(migrated_database, envelope.event_id) == 1

    async def replayed(service: NormalizerService) -> bool:
        return service.pipeline.stats.duplicates >= 1

    await _run_until(_settings(monkeypatch, unique_group), stored)
    replay = await _run_until(_settings(monkeypatch, f"{unique_group}-replay"), replayed)

    assert await _rows(migrated_database, envelope.event_id) == 1
    assert replay.pipeline.stats.duplicates >= 1
    published = await read_from(
        kafka_settings, output_start, lambda record: _event_id(record) == envelope.event_id
    )
    assert len(published) == 1


async def test_conflicting_duplicate_is_dead_lettered_and_the_stored_event_kept(
    monkeypatch: pytest.MonkeyPatch,
    kafka_settings: KafkaSettings,
    producer: KafkaProducer,
    migrated_database: Database,
    unique_group: str,
) -> None:
    original = parse_canonical_event(authentication(host_id="web-conflict"))
    tampered = original.model_copy(update={"host_id": "web-other"})  # same event_id
    await commit_group_offsets(
        kafka_settings, unique_group, await end_offsets(kafka_settings, RAW_TELEMETRY_TOPICS)
    )
    dead_start = await end_offsets(kafka_settings, [Topic.DEADLETTER])
    settings = _settings(monkeypatch, unique_group)
    await producer.publish(
        Topic.AUTH_EVENTS, to_envelope(original, producer="adis-api"), key="web-conflict"
    )

    async def stored(_: NormalizerService) -> bool:
        return await _rows(migrated_database, original.event_id) == 1

    async def conflicted(service: NormalizerService) -> bool:
        return service.pipeline.stats.conflicts >= 1

    await _run_until(settings, stored)
    await producer.publish(
        Topic.AUTH_EVENTS, to_envelope(tampered, producer="adis-api"), key="web-conflict"
    )
    service = await _run_until(settings, conflicted)

    assert service.pipeline.stats.conflicts == 1
    async with migrated_database.session() as session:
        record = await SecurityEventRepository(session).find_event(original.event_id)
    assert record is not None
    assert record.host_id == "web-conflict"
    [dead] = await read_from(
        kafka_settings,
        dead_start,
        lambda r: _event_id(r) == original.event_id,
    )
    headers = dict(dead.headers)
    assert headers["adis-dlq-error-type"] == b"ConflictingDuplicateError"
    assert headers["adis-dlq-consumer-group"] == unique_group.encode()


async def test_registration_fills_the_agent_registry_and_links_telemetry(
    monkeypatch: pytest.MonkeyPatch,
    kafka_settings: KafkaSettings,
    producer: KafkaProducer,
    migrated_database: Database,
    unique_group: str,
) -> None:
    identity = AgentIdentity(
        agent_id=uuid4(),
        name="agent-it",
        hostname="it-host",
        host_id="it-host",
        os_type="linux",
        agent_version="1.2.3",
    )
    announcement = registration_event(identity)
    telemetry = parse_canonical_event(
        authentication(host_id="it-host", agent_id=str(identity.agent_id))
    )
    await commit_group_offsets(
        kafka_settings, unique_group, await end_offsets(kafka_settings, RAW_TELEMETRY_TOPICS)
    )
    await producer.publish(
        Topic.SYSTEM_EVENTS, to_envelope(announcement, producer="adis-api"), key="it-host"
    )

    async def registered(service: NormalizerService) -> bool:
        return service.pipeline.stats.agent_registrations >= 1

    async def linked(_: NormalizerService) -> bool:
        return await _rows(migrated_database, telemetry.event_id) == 1

    await _run_until(_settings(monkeypatch, unique_group), registered)
    await producer.publish(
        Topic.AUTH_EVENTS, to_envelope(telemetry, producer="adis-api"), key="it-host"
    )
    await _run_until(_settings(monkeypatch, unique_group), linked)

    async with migrated_database.session() as session:
        agent = await AgentRepository(session).get(identity.agent_id)
        record = await SecurityEventRepository(session).find_event(telemetry.event_id)
    assert agent is not None
    assert (agent.name, agent.hostname, agent.os_type, agent.agent_version) == (
        "agent-it",
        "it-host",
        OsType.LINUX,
        "1.2.3",
    )
    assert agent.status == AgentStatus.ACTIVE
    assert agent.first_seen is not None
    assert agent.last_seen is not None
    assert agent.last_seen >= agent.first_seen
    assert record is not None
    assert record.agent_id == identity.agent_id


async def test_health_readiness_and_metrics_endpoints(
    monkeypatch: pytest.MonkeyPatch,
    kafka_settings: KafkaSettings,
    migrated_database: Database,
    unique_group: str,
) -> None:
    await commit_group_offsets(
        kafka_settings, unique_group, await end_offsets(kafka_settings, RAW_TELEMETRY_TOPICS)
    )
    port = _free_port()
    service = NormalizerService.from_settings(
        _settings(monkeypatch, unique_group, health_port=port)
    )
    stop = asyncio.Event()
    running = asyncio.create_task(service.run(stop))
    try:
        async with asyncio.timeout(WAIT_SECONDS):
            while True:
                with contextlib.suppress(OSError):
                    status, body = await _get(port, "/ready")
                    if status == 200:
                        break
                if running.done():
                    running.result()
                await asyncio.sleep(0.2)
        health = await _get(port, "/health")
        metrics_status, metrics = await _get(port, "/metrics")
    finally:
        stop.set()
        await asyncio.wait_for(running, timeout=WAIT_SECONDS)

    assert json.loads(body) == {
        "status": "ready",
        "checks": {"kafka_consumer": "ok", "kafka_producer": "ok", "database": "ok"},
    }
    assert health[0] == 200
    assert metrics_status == 200
    assert b"adis_normalizer_records_total" in metrics
