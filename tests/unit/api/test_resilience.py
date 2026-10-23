"""API remediation features: Redis limiting, agent binding, metrics, readiness, start-up."""

import asyncio
from uuid import uuid4

import pytest
from aiokafka.errors import KafkaConnectionError
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from apps.api.app import create_app
from apps.api.auth import IngestClient
from apps.api.publisher import IngestContext, KafkaEventPublisher, PublishUnavailableError
from apps.api.rate_limit import RedisRateLimiter, TokenBucketRateLimiter
from packages.events.canonical import parse_canonical_event
from packages.kafka import RetryPolicy
from packages.redis import RedisClient
from tests.unit.api.fakes import AUTH, RecordingPublisher, api_client, api_settings
from tests.unit.events.canonical.samples import network, system
from tests.unit.kafka.fakes import FakeProducerClient, fake_producer
from tests.unit.log_capture import JsonLogCapture
from tests.unit.redis.fakes import FakeRedis

FAST = RetryPolicy(max_attempts=1, initial_backoff_seconds=0.01, max_backoff_seconds=0.02)


def _redis(fake: FakeRedis) -> RedisClient:
    return RedisClient(fake, prefix="adis", namespace="api", health_timeout_seconds=0.1)


# ----------------------------------------------------------------- Redis rate limiting


async def test_redis_budget_is_shared_between_limiter_instances() -> None:
    fake = FakeRedis()
    replicas = [
        RedisRateLimiter(
            _redis(fake),
            capacity=10,
            window_seconds=60,
            fallback=TokenBucketRateLimiter(capacity=10, window_seconds=60),
        )
        for _ in range(2)
    ]

    first = await replicas[0].acquire("agent-a", 7)
    second = await replicas[1].acquire("agent-a", 7)  # the other replica sees the spend
    other_client = await replicas[1].acquire("agent-b", 7)

    assert (first.allowed, second.allowed, other_client.allowed) == (True, False, True)
    assert second.remaining == 3
    assert second.retry_after_seconds > 0


async def test_redis_outage_falls_back_to_the_local_budget() -> None:
    fake = FakeRedis()
    fake.failure = RedisConnectionError("down")
    fallbacks: list[int] = []
    limiter = RedisRateLimiter(
        _redis(fake),
        capacity=10,
        window_seconds=60,
        fallback=TokenBucketRateLimiter(capacity=5, window_seconds=60),
        on_fallback=lambda: fallbacks.append(1),
    )

    allowed = await limiter.acquire("agent-a", 5)
    refused = await limiter.acquire("agent-a", 1)

    assert (allowed.allowed, refused.allowed) == (True, False)  # the fallback's own budget
    assert len(fallbacks) == 2


async def test_redis_is_left_alone_for_a_while_after_a_failure() -> None:
    fake = FakeRedis()
    fake.failure = RedisConnectionError("down")
    now = [100.0]
    fallbacks: list[int] = []
    limiter = RedisRateLimiter(
        _redis(fake),
        capacity=10,
        window_seconds=60,
        fallback=TokenBucketRateLimiter(capacity=10, window_seconds=60),
        on_fallback=lambda: fallbacks.append(1),
        retry_interval_seconds=5,
        clock=lambda: now[0],
    )

    await limiter.acquire("agent-a", 1)  # fails and opens the retry interval
    fake.failure = None  # Redis is back, but the limiter does not know yet
    now[0] += 4.9
    await limiter.acquire("agent-a", 1)
    untouched = dict(fake.values)
    now[0] += 0.2
    shared = await limiter.acquire("agent-a", 1)

    assert untouched == {}  # nothing was sent to Redis inside the interval
    assert len(fallbacks) == 2
    assert (shared.allowed, shared.remaining) == (True, 9)  # back on the shared budget
    assert list(fake.values) == ["adis:api:ratelimit:agent-a"]


def test_redis_limiting_serves_requests_and_readiness_reports_redis() -> None:
    fake = FakeRedis()
    app = create_app(
        api_settings(api_rate_limit_events=5, api_max_batch_size=5),
        publisher=RecordingPublisher(),
        redis=_redis(fake),
    )
    with TestClient(app) as client:
        statuses = [
            client.post("/api/v1/events", json=system(), headers=AUTH).status_code for _ in range(6)
        ]
        healthy = client.get("/ready").json()
        fake.failure = RedisConnectionError("down")
        degraded = client.get("/ready")
        after_outage = client.post("/api/v1/events", json=system(), headers=AUTH).status_code

    assert statuses == [202] * 5 + [429]
    assert healthy["checks"] == {"kafka": "ok", "redis": "ok"}
    assert degraded.status_code == 200  # Redis alone never makes the API unready
    assert degraded.json()["checks"]["redis"] == "unavailable"
    assert after_outage == 202  # fell back to the per-process budget
    assert fake.closed == 1  # closed at shutdown


# ------------------------------------------------------------------------ agent binding


def test_agent_bound_clients_may_only_submit_their_own_events() -> None:
    agent_id = uuid4()
    client_token = "t" * 40
    with api_client(api_ingest_tokens=f"agent-{agent_id}:{client_token}") as (client, publisher):
        headers = {"Authorization": f"Bearer {client_token}"}
        own = client.post("/api/v1/events", json=system(agent_id=str(agent_id)), headers=headers)
        foreign = client.post("/api/v1/events", json=system(agent_id=str(uuid4())), headers=headers)
        batch = client.post(
            "/api/v1/events/batch",
            json={"events": [system(agent_id=str(agent_id)), system(agent_id=None)]},
            headers=headers,
        )

    assert own.status_code == 202
    assert foreign.status_code == 422
    assert foreign.json()["error"]["code"] == "agent_mismatch"
    assert batch.status_code == 202
    assert batch.json()["rejected"] == [
        {
            "index": 1,
            "code": "agent_mismatch",
            "issues": ["agent_id: must be the agent this client is bound to"],
        }
    ]
    assert [str(event.agent_id) for event in publisher.events] == [str(agent_id)] * 2


def test_unbound_clients_may_submit_for_any_agent() -> None:
    assert IngestClient("zeek-connector").bound_agent_id is None
    assert IngestClient("agent-not-a-uuid").bound_agent_id is None
    agent_id = uuid4()
    assert IngestClient(f"agent-{agent_id}").bound_agent_id == agent_id


# ------------------------------------------------------------------------------- metrics


def test_metrics_count_events_and_requests() -> None:
    with api_client() as (client, _):
        client.post("/api/v1/events", json=system(), headers=AUTH)
        client.post("/api/v1/events", json=system(src_ip="999.1.1.1"), headers=AUTH)
        client.post("/api/v1/events/batch", json={"events": [system(), network()]}, headers=AUTH)
        text = client.get("/metrics").text

    assert 'adis_api_events_total{outcome="accepted"} 3.0' in text
    assert 'adis_api_events_total{outcome="rejected"} 1.0' in text
    assert (
        'adis_api_http_requests_total{method="POST",route="/api/v1/events",status="202"} 1.0'
        in text
    )


def test_metrics_can_be_disabled() -> None:
    with api_client(prometheus_enabled=False) as (client, _):
        assert client.get("/metrics").status_code == 404


def test_unknown_paths_share_one_metrics_label() -> None:
    with api_client() as (client, _):
        client.get("/definitely/not/here")
        client.get("/another/probe")
        text = client.get("/metrics").text

    assert 'route="unmatched",status="404"} 2.0' in text


# ----------------------------------------------------------------- lifecycle logging


def test_every_accepted_event_is_logged_with_its_ids(json_logs: JsonLogCapture) -> None:
    event_id = str(uuid4())
    with api_client() as (client, _):
        client.post(
            "/api/v1/events", json=system(event_id=event_id, trace_id="a" * 32), headers=AUTH
        )

    [line] = json_logs.with_message("event accepted")
    assert (line["event_id"], line["trace_id"], line["host_id"]) == (event_id, "a" * 32, "web-1")
    assert line["action"] == "api_event_accepted"


def test_lifecycle_logging_can_be_turned_off(json_logs: JsonLogCapture) -> None:
    with api_client(log_event_lifecycle=False) as (client, _):
        client.post("/api/v1/events", json=system(), headers=AUTH)

    assert json_logs.with_message("event accepted") == []


def test_publish_failures_are_logged_without_stack_traces(json_logs: JsonLogCapture) -> None:
    failing = RecordingPublisher(failure=PublishUnavailableError("timed out enqueuing events"))
    with api_client(failing) as (client, _):
        response = client.post("/api/v1/events", json=system(), headers=AUTH)

    [line] = json_logs.with_message("events could not be enqueued")
    assert response.status_code == 503
    assert line["level"] == "WARNING"
    assert "exception" not in line
    assert line["reason"] == "timed out enqueuing events"


# ---------------------------------------------------------------- start without Kafka


async def test_api_starts_without_kafka_and_connects_in_the_background() -> None:
    class DownThenUp(FakeProducerClient):
        attempts = 0

        async def start(self) -> None:
            DownThenUp.attempts += 1
            if DownThenUp.attempts <= 2:
                raise KafkaConnectionError("broker down")
            await super().start()

    client = DownThenUp()
    publisher = KafkaEventPublisher(
        fake_producer(client), producer_name="adis-api", timeout_seconds=1, connect_backoff=FAST
    )
    context = IngestContext(client_id="agent-a", request_id=None)
    event = parse_canonical_event(system())

    await publisher.start()  # does not raise
    unready = await publisher.ready()
    with pytest.raises(PublishUnavailableError, match="not connected"):
        await publisher.publish([event], context)
    async with asyncio.timeout(2):
        while True:
            if await publisher.ready():
                break
            await asyncio.sleep(0.01)
    await publisher.publish([event], context)
    await publisher.stop()

    assert unready is False
    assert DownThenUp.attempts == 3
    assert client.stopped >= 2  # failed attempts were released too
