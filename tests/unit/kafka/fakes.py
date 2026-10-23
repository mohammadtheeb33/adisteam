"""In-memory stand-ins for aiokafka clients, used by the Kafka unit tests."""

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from packages.events import EventEnvelope
from packages.kafka import KafkaProducer, RetryPolicy

NO_RETRY_DELAY = RetryPolicy(max_attempts=3, initial_backoff_seconds=0.1, max_backoff_seconds=1)


def make_envelope(**overrides: object) -> EventEnvelope:
    """A valid envelope with optional field overrides."""
    fields: dict[str, object] = {
        "event_type": "security.alert_raised",
        "event_version": 1,
        "producer": "adis-test",
        "payload": {"rule": "R-1"},
    }
    fields.update(overrides)
    return EventEnvelope.model_validate(fields)


def upper_jitter(low: float, high: float) -> float:
    """Deterministic jitter: always the upper bound."""
    return high


class RecordingSleep:
    """Records requested delays instead of sleeping."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


@dataclass(frozen=True)
class RecordMetadata:
    """Minimal ``aiokafka`` RecordMetadata."""

    topic: str
    partition: int
    offset: int


@dataclass(frozen=True)
class SentRecord:
    """A record captured by :class:`FakeProducerClient`."""

    topic: str
    value: bytes | None
    key: bytes | None
    headers: list[tuple[str, bytes]]


class FakeMetadataClient:
    """Answers metadata requests; raises queued failures first (a broker round trip)."""

    def __init__(self) -> None:
        self.failures: list[Exception] = []
        self.requests = 0

    async def fetch_all_metadata(self) -> object:
        self.requests += 1
        if self.failures:
            raise self.failures.pop(0)
        return object()


class FakeProducerClient:
    """Captures sent records; raises queued send failures first.

    Like ``AIOKafkaProducer``, ``partitions_for`` answers from cached metadata (it never
    fails once started); ``client.fetch_all_metadata`` is the broker round trip.
    """

    def __init__(self, failures: Sequence[Exception] = ()) -> None:
        self.failures = list(failures)
        self.client = FakeMetadataClient()
        self.sent: list[SentRecord] = []
        self.started = 0
        self.stopped = 0

    async def start(self) -> None:
        self.started += 1

    async def stop(self) -> None:
        self.stopped += 1

    async def partitions_for(self, topic: str) -> set[int]:
        return {0, 1, 2}

    async def send_and_wait(
        self,
        topic: str,
        value: bytes | None = None,
        key: bytes | None = None,
        partition: int | None = None,
        timestamp_ms: int | None = None,
        headers: list[tuple[str, bytes]] | None = None,
    ) -> RecordMetadata:
        if self.failures:
            raise self.failures.pop(0)
        self.sent.append(SentRecord(topic, value, key, list(headers or [])))
        return RecordMetadata(topic, 0, len(self.sent) - 1)


def fake_producer(client: FakeProducerClient, sleep: RecordingSleep | None = None) -> KafkaProducer:
    """A ``KafkaProducer`` over ``client`` with deterministic, instant retries."""
    return KafkaProducer(
        lambda: client,
        retry_policy=NO_RETRY_DELAY,
        sleep=sleep or RecordingSleep(),
        jitter=upper_jitter,
    )


@dataclass(frozen=True)
class ConsumerRecord:
    """Minimal ``aiokafka`` ConsumerRecord."""

    topic: str
    partition: int
    offset: int
    value: bytes | None
    key: bytes | None = None
    timestamp: int = 1_790_000_000_000
    headers: Sequence[tuple[str, bytes]] = ()


@dataclass
class FakeConsumerClient:
    """Serves queued batches, then calls ``on_drained`` (typically ``request_stop``)."""

    batches: list[Mapping[object, Sequence[ConsumerRecord]]]
    on_drained: Callable[[], None] | None = None
    commits: list[dict[object, int]] = field(default_factory=list)
    assigned: set[object] = field(default_factory=set)
    highwaters: dict[object, int] = field(default_factory=dict)
    positions: dict[object, int] = field(default_factory=dict)
    started: int = 0
    stopped: int = 0

    async def start(self) -> None:
        self.started += 1

    async def stop(self) -> None:
        self.stopped += 1

    async def getmany(
        self, *partitions: object, timeout_ms: int = 0, max_records: int | None = None
    ) -> Mapping[object, Sequence[ConsumerRecord]]:
        if self.batches:
            return self.batches.pop(0)
        if self.on_drained is not None:
            self.on_drained()
        await asyncio.sleep(0)
        return {}

    async def commit(self, offsets: Mapping[object, int] | None = None) -> None:
        self.commits.append(dict(offsets or {}))

    def assignment(self) -> set[object]:
        return set(self.assigned)

    def highwater(self, partition: object) -> int | None:
        return self.highwaters.get(partition)

    async def position(self, partition: object) -> int:
        return self.positions.get(partition, 0)
