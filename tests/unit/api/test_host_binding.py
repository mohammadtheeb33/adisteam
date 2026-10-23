"""Host-bound clients may only write the hosts they are configured for (OD-34).

The agent binding pins ``agent_id``; it says nothing about ``host_id``, which is what
detection, threats and recommendations are keyed by. ``API_INGEST_CLIENT_HOSTS`` closes
that gap for the clients it lists.
"""

from contextlib import AbstractContextManager
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from apps.api.auth import IngestClient, TokenAuthenticator
from apps.api.publisher import IngestContext, KafkaEventPublisher
from packages.events.canonical import parse_canonical_event
from tests.unit.api.fakes import RecordingPublisher, api_client
from tests.unit.events.canonical.samples import network, system
from tests.unit.kafka.fakes import FakeProducerClient, fake_producer

TOKEN = "h" * 40
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
AGENT_ID = uuid4()
AGENT_CLIENT = f"agent-{AGENT_ID}"


def _bound(hosts: str = "web-1") -> AbstractContextManager[tuple[TestClient, RecordingPublisher]]:
    """An application whose only client is the agent, restricted to ``hosts``."""
    return api_client(
        api_ingest_tokens=f"{AGENT_CLIENT}:{TOKEN}",
        api_ingest_client_hosts=f"{AGENT_CLIENT}={hosts}",
    )


def test_a_host_bound_client_may_submit_its_own_hosts() -> None:
    with _bound("web-1|web-2") as (client, publisher):
        first = client.post(
            "/api/v1/events",
            json=system(agent_id=str(AGENT_ID), host_id="web-1"),
            headers=HEADERS,
        )
        second = client.post(
            "/api/v1/events",
            json=network(agent_id=str(AGENT_ID), host_id="web-2"),
            headers=HEADERS,
        )

    assert (first.status_code, second.status_code) == (202, 202)
    assert [event.host_id for event in publisher.events] == ["web-1", "web-2"]


def test_a_host_bound_client_cannot_write_another_hosts_telemetry() -> None:
    with _bound() as (client, publisher):
        response = client.post(
            "/api/v1/events",
            json=system(agent_id=str(AGENT_ID), host_id="someone-elses-production-db"),
            headers=HEADERS,
        )

    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "host_mismatch"
    assert body["details"] == [
        {
            "index": None,
            "code": "host_mismatch",
            "issues": ["host_id: must be a host this client is bound to"],
        }
    ]
    assert "someone-elses-production-db" not in response.text  # no echo of the claimed host
    assert publisher.events == []


def test_a_host_bound_client_cannot_omit_the_host() -> None:
    with _bound() as (client, publisher):
        response = client.post(
            "/api/v1/events",
            json=system(agent_id=str(AGENT_ID), host_id=None),
            headers=HEADERS,
        )

    assert (response.status_code, response.json()["error"]["code"]) == (422, "host_mismatch")
    assert publisher.events == []


def test_a_batch_is_partially_accepted_per_host() -> None:
    events = [
        system(agent_id=str(AGENT_ID), host_id="web-1"),
        system(agent_id=str(AGENT_ID), host_id="victim-host"),
        system(agent_id=str(AGENT_ID), host_id="web-1"),
    ]
    with _bound() as (client, publisher):
        response = client.post("/api/v1/events/batch", json={"events": events}, headers=HEADERS)

    assert response.status_code == 202
    body = response.json()
    assert (body["status"], body["accepted_count"], body["rejected_count"]) == (
        "partially_accepted",
        2,
        1,
    )
    assert body["rejected"] == [
        {
            "index": 1,
            "code": "host_mismatch",
            "issues": ["host_id: must be a host this client is bound to"],
        }
    ]
    assert [event.host_id for event in publisher.events] == ["web-1", "web-1"]


def test_the_agent_binding_is_checked_before_the_host_binding() -> None:
    with _bound() as (client, _):
        response = client.post(
            "/api/v1/events",
            json=system(agent_id=str(uuid4()), host_id="victim-host"),
            headers=HEADERS,
        )

    assert (response.status_code, response.json()["error"]["code"]) == (422, "agent_mismatch")


def test_clients_without_hosts_remain_unrestricted() -> None:
    """Unlisted clients (connectors, development agents) keep today's behavior."""
    with api_client(
        api_ingest_tokens=f"{AGENT_CLIENT}:{TOKEN},zeek.1:{'z' * 40}",
        api_ingest_client_hosts=f"{AGENT_CLIENT}=web-1",
    ) as (client, publisher):
        response = client.post(
            "/api/v1/events",
            json=network(host_id="any-host-at-all"),
            headers={"Authorization": f"Bearer {'z' * 40}"},
        )

    assert response.status_code == 202
    assert [event.host_id for event in publisher.events] == ["any-host-at-all"]


def test_the_authenticator_attaches_hosts_to_the_right_client() -> None:
    authenticator = TokenAuthenticator(
        {AGENT_CLIENT: TOKEN, "zeek.1": "z" * 40},
        {AGENT_CLIENT: frozenset({"web-1"})},
    )

    assert authenticator.authenticate(TOKEN) == IngestClient(AGENT_CLIENT, frozenset({"web-1"}))
    assert authenticator.authenticate("z" * 40) == IngestClient("zeek.1", None)
    assert authenticator.authenticate("unknown") is None


# ------------------------------------------------------------------------ host scope


def test_the_host_scope_reflects_how_many_hosts_a_client_may_write() -> None:
    assert IngestClient("zeek.1").host_scope == "unbound"
    assert IngestClient(AGENT_CLIENT, frozenset({"web-1"})).host_scope == "exclusive"
    assert IngestClient("zeek.1", frozenset({"web-1", "web-2"})).host_scope == "shared"


@pytest.mark.parametrize(
    ("hosts", "scope"),
    [(None, b"unbound"), ("web-1", b"exclusive"), ("web-1|web-2", b"shared")],
)
async def test_every_published_event_carries_its_host_scope(
    hosts: str | None, scope: bytes
) -> None:
    client = FakeProducerClient()
    publisher = KafkaEventPublisher(
        fake_producer(client), producer_name="adis-api", timeout_seconds=1
    )
    ingest = IngestClient(AGENT_CLIENT, None if hosts is None else frozenset(hosts.split("|")))
    event = parse_canonical_event(system(agent_id=str(AGENT_ID), host_id="web-1"))
    await publisher.start()
    await publisher.publish(
        [event],
        IngestContext(client_id=ingest.client_id, request_id=None, host_scope=ingest.host_scope),
    )
    await publisher.stop()

    [record] = client.sent
    assert dict(record.headers)["adis-ingest-host-scope"] == scope
