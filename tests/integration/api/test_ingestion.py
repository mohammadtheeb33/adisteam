"""HTTP ingestion lands in Kafka with its envelope, provenance and trace intact."""

from datetime import UTC, datetime
from uuid import uuid4

import httpx2
import pytest

from apps.api.settings import ApiServiceSettings
from packages.events.canonical import from_envelope
from packages.kafka import Topic, deserialize_envelope
from tests.integration.api.helpers import AUTH
from tests.integration.kafka.helpers import end_offsets, read_until
from tests.unit.events.canonical.samples import authentication, network, process

pytestmark = pytest.mark.integration

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


async def test_ready_when_kafka_is_reachable(api: httpx2.AsyncClient) -> None:
    response = await api.get("/ready")

    assert (response.status_code, response.json()["checks"]) == (200, {"kafka": "ok"})


async def test_accepted_event_is_in_kafka_with_provenance(
    api: httpx2.AsyncClient, api_settings: ApiServiceSettings
) -> None:
    host = f"it-host-{uuid4().hex[:8]}"
    before = datetime.now(UTC)
    start = await end_offsets(api_settings, [Topic.AUTH_EVENTS])

    response = await api.post(
        "/api/v1/events",
        json=authentication(host_id=host, received_at="2000-01-01T00:00:00Z"),
        headers={**AUTH, "traceparent": f"00-{TRACE}-00f067aa0ba902b7-01"},
    )

    assert response.status_code == 202
    record = await read_until(api_settings, start, lambda r: r.key == host.encode())
    headers = dict(record.headers)
    assert headers["adis-ingest-client"] == b"agent-it"
    assert headers["adis-request-id"] == response.headers["X-Request-ID"].encode()
    assert headers["adis-trace-id"] == TRACE.encode()
    envelope = deserialize_envelope(record.value)
    event = from_envelope(envelope)
    assert str(event.event_id) == response.json()["event_id"]
    assert envelope.producer == "adis-api-it"
    assert event.trace_id == TRACE
    assert event.received_at >= before


async def test_batch_events_reach_their_topics(
    api: httpx2.AsyncClient, api_settings: ApiServiceSettings
) -> None:
    host = f"it-host-{uuid4().hex[:8]}"
    events = [network(host_id=host), process(host_id=host), network(host_id=host, src_port=-1)]
    network_start = await end_offsets(api_settings, [Topic.NETWORK_EVENTS])
    system_start = await end_offsets(api_settings, [Topic.SYSTEM_EVENTS])

    response = await api.post("/api/v1/events/batch", json={"events": events}, headers=AUTH)

    body = response.json()
    assert (response.status_code, body["status"]) == (202, "partially_accepted")
    accepted = {item["event_id"] for item in body["accepted"]}
    network_record = await read_until(api_settings, network_start, lambda r: r.key == host.encode())
    process_record = await read_until(api_settings, system_start, lambda r: r.key == host.encode())
    delivered = {
        str(deserialize_envelope(record.value).event_id)
        for record in (network_record, process_record)
    }
    assert delivered == accepted
