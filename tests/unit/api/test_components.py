"""Authenticator, rate limiter and Kafka publisher in isolation."""

import asyncio

import pytest
from aiokafka.errors import KafkaConnectionError, MessageSizeTooLargeError

from apps.api.auth import TokenAuthenticator
from apps.api.publisher import IngestContext, KafkaEventPublisher, PublishUnavailableError
from apps.api.rate_limit import TokenBucketRateLimiter
from packages.events.canonical import AnyCanonicalEvent, from_envelope, parse_canonical_event
from packages.kafka import deserialize_envelope
from tests.unit.events.canonical.samples import authentication, network, process
from tests.unit.kafka.fakes import FakeProducerClient, RecordMetadata, fake_producer

CONTEXT = IngestContext(client_id="agent-a", request_id="r-1")


# ---------------------------------------------------------------------------- authenticator


def test_authenticator_resolves_known_tokens_only() -> None:
    authenticator = TokenAuthenticator({"agent-a": "a" * 32, "agent-b": "b" * 32})

    assert authenticator.authenticate("a" * 32) is not None
    assert authenticator.authenticate("b" * 32).client_id == "agent-b"  # type: ignore[union-attr]
    assert authenticator.authenticate("c" * 32) is None
    assert authenticator.authenticate("") is None


def test_authenticator_does_not_retain_tokens() -> None:
    authenticator = TokenAuthenticator({"agent-a": "sentinel-token-" + "a" * 20})

    assert "sentinel" not in repr(vars(authenticator))


# ----------------------------------------------------------------------------- rate limiter


class Clock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


async def test_bucket_spends_and_refills() -> None:
    clock = Clock()
    limiter = TokenBucketRateLimiter(capacity=10, window_seconds=10, clock=clock)

    spent = await limiter.acquire("a", 10)
    refused = await limiter.acquire("a", 1)
    clock.now = 3.0
    refilled = await limiter.acquire("a", 3)

    assert (spent.allowed, spent.remaining) == (True, 0)
    assert refused.allowed is False
    assert refused.retry_after_seconds == pytest.approx(1.0)
    assert (refilled.allowed, refilled.remaining) == (True, 0)


async def test_refused_requests_are_not_charged() -> None:
    limiter = TokenBucketRateLimiter(capacity=5, window_seconds=60, clock=Clock())

    await limiter.acquire("a", 4)
    refused = await limiter.acquire("a", 2)
    allowed = await limiter.acquire("a", 1)

    assert (refused.allowed, allowed.allowed, allowed.remaining) == (False, True, 0)


async def test_buckets_never_exceed_capacity() -> None:
    clock = Clock()
    limiter = TokenBucketRateLimiter(capacity=5, window_seconds=5, clock=clock)
    await limiter.acquire("a", 1)
    clock.now = 1_000.0

    decision = await limiter.acquire("a", 1)

    assert decision.remaining == 4
    assert decision.headers() == {
        "RateLimit-Limit": "5",
        "RateLimit-Remaining": "4",
        "RateLimit-Reset": "1",
    }


async def test_least_recently_used_clients_are_evicted() -> None:
    limiter = TokenBucketRateLimiter(capacity=1, window_seconds=3_600, max_keys=2, clock=Clock())
    await limiter.acquire("a", 1)
    await limiter.acquire("b", 1)
    await limiter.acquire("c", 1)  # evicts "a"

    assert (await limiter.acquire("a", 1)).allowed is True
    assert (await limiter.acquire("c", 1)).allowed is False


@pytest.mark.parametrize(
    "options",
    [
        {"capacity": 0, "window_seconds": 1},
        {"capacity": 1, "window_seconds": 0},
        {"capacity": 1, "window_seconds": 1, "max_keys": 0},
    ],
)
def test_invalid_limiter_configuration(options: dict[str, float]) -> None:
    with pytest.raises(ValueError, match="positive"):
        TokenBucketRateLimiter(**options)  # type: ignore[arg-type]


async def test_cost_must_be_positive() -> None:
    with pytest.raises(ValueError, match="cost"):
        await TokenBucketRateLimiter(capacity=1, window_seconds=1).acquire("a", 0)


# -------------------------------------------------------------------------------- publisher


def _publisher(client: FakeProducerClient, timeout: float = 1.0) -> KafkaEventPublisher:
    return KafkaEventPublisher(
        fake_producer(client), producer_name="adis-api", timeout_seconds=timeout
    )


async def _published(
    events: list[AnyCanonicalEvent], context: IngestContext = CONTEXT
) -> FakeProducerClient:
    client = FakeProducerClient()
    publisher = _publisher(client)
    await publisher.start()
    await publisher.publish(events, context)
    await publisher.stop()
    return client


async def test_events_are_routed_to_their_telemetry_topics() -> None:
    events = [parse_canonical_event(d) for d in (authentication(), network(), process())]

    client = await _published(events)

    assert sorted(record.topic for record in client.sent) == [
        "auth_events",
        "network_flows",
        "system_logs",
    ]


async def test_records_are_keyed_by_host_and_carry_provenance() -> None:
    event = parse_canonical_event(network())

    [record] = (await _published([event])).sent

    headers = dict(record.headers)
    assert record.key == b"web-1"
    assert headers["adis-ingest-client"] == b"agent-a"
    assert headers["adis-request-id"] == b"r-1"
    envelope = deserialize_envelope(record.value)
    assert envelope.producer == "adis-api"
    assert from_envelope(envelope) == event


async def test_request_id_header_is_omitted_when_unknown() -> None:
    event = parse_canonical_event(network())

    [record] = (await _published([event], IngestContext("agent-a", None))).sent

    assert "adis-request-id" not in dict(record.headers)


async def test_broker_rejection_is_reported_as_unavailable() -> None:
    publisher = _publisher(FakeProducerClient(failures=[MessageSizeTooLargeError()]))
    await publisher.start()

    with pytest.raises(PublishUnavailableError):
        await publisher.publish([parse_canonical_event(network())], CONTEXT)


class SlowProducerClient(FakeProducerClient):
    """Never acknowledges within the test's timeout."""

    async def send_and_wait(self, *args: object, **kwargs: object) -> RecordMetadata:
        await asyncio.sleep(10)
        raise AssertionError("unreachable")


async def test_slow_acknowledgements_time_out() -> None:
    publisher = _publisher(SlowProducerClient(), timeout=0.05)
    await publisher.start()

    with pytest.raises(PublishUnavailableError, match="timed out"):
        await publisher.publish([parse_canonical_event(network())], CONTEXT)


async def test_unexpected_errors_are_not_masked(monkeypatch: pytest.MonkeyPatch) -> None:
    publisher = _publisher(FakeProducerClient())
    await publisher.start()

    async def broken(*args: object) -> None:
        raise ValueError("bug")

    monkeypatch.setattr(publisher, "_publish_one", broken)

    with pytest.raises(ExceptionGroup):
        await publisher.publish([parse_canonical_event(network())], CONTEXT)


async def test_readiness() -> None:
    client = FakeProducerClient()
    publisher = _publisher(client)

    not_started = await publisher.ready()
    await publisher.start()
    started = await publisher.ready()
    client.client.failures.append(KafkaConnectionError())
    broker_down = await publisher.ready()
    recovered = await publisher.ready()

    assert (not_started, started, broker_down, recovered) == (False, True, False, True)
    assert client.client.requests == 3  # every check asks a broker
