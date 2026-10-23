"""Test doubles for the normalization pipeline."""

import asyncio
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from sqlalchemy.exc import DataError, OperationalError

from apps.normalizer.metrics import NormalizerMetrics
from apps.normalizer.normalization import NormalizedEvent
from apps.normalizer.pipeline import NormalizationPipeline
from packages.database.repositories import AgentRegistration, BatchStoreResult
from packages.events import EventEnvelope
from packages.events.canonical import AnyCanonicalEvent, parse_canonical_event, to_envelope
from packages.kafka import RetryPolicy, serialize_envelope
from packages.kafka.dead_letter import FailedRecord
from tests.unit.kafka.fakes import ConsumerRecord

NOW: Final = datetime(2026, 9, 25, 12, 30, tzinfo=UTC)
GROUP: Final = "adis-normalizer-test"
FAST_RETRIES: Final = RetryPolicy(
    max_attempts=3, initial_backoff_seconds=0.001, max_backoff_seconds=0.002
)
API_HEADERS: Final = (
    ("adis-ingest-client", b"agent-a"),
    ("adis-request-id", b"0123456789abcdef0123456789abcdef"),
)


def envelope_of(document: dict[str, object], *, producer: str = "adis-api") -> EventEnvelope:
    """The envelope the ingestion API publishes for a valid canonical document."""
    return to_envelope(parse_canonical_event(document), producer=producer)


def raw_envelope(payload: dict[str, object], **fields: object) -> EventEnvelope:
    """An envelope around an arbitrary (possibly non-canonical) payload."""
    values: dict[str, object] = {
        "event_type": payload.get("event_type", "network.flow"),
        "event_version": 1,
        "producer": "zeek-connector",
        "payload": payload,
        **fields,
    }
    return EventEnvelope.model_validate(values)


def record_of(
    envelope: EventEnvelope | bytes | None,
    *,
    topic: str = "network_flows",
    partition: int = 0,
    offset: int = 0,
    headers: Sequence[tuple[str, bytes]] = API_HEADERS,
) -> ConsumerRecord:
    """A consumed record carrying ``envelope`` (or raw bytes)."""
    value = serialize_envelope(envelope) if isinstance(envelope, EventEnvelope) else envelope
    return ConsumerRecord(
        topic=topic,
        partition=partition,
        offset=offset,
        value=value,
        key=b"web-1",
        headers=tuple(headers),
    )


def transient_error() -> OperationalError:
    """What SQLAlchemy raises when the database connection is lost."""
    return OperationalError("INSERT ...", {}, ConnectionResetError("connection lost"))


class _DriverError(Exception):
    sqlstate = "22P02"


def data_error() -> DataError:
    """A permanent, row-specific database error quoting the offending value."""
    return DataError("INSERT ...", {}, _DriverError('invalid input syntax: "secret-value"'))


@dataclass
class MemoryEventStore:
    """Units of work over a dict, with the repository's idempotent-insert semantics.

    - Rows staged in a unit of work are committed only if the block exits normally.
    - ``store_failures`` are raised by ``store_events_batch``, in order (``None`` means
      "succeed this time").
    - ``commit_failures`` are raised at commit: ``(error, applied)`` where ``applied``
      says whether the rows were committed anyway (an ambiguous commit).
    - Batches containing a ``poison`` event id fail with a permanent data error.
    """

    rows: dict[UUID, AnyCanonicalEvent] = field(default_factory=dict)
    agents: dict[UUID, AgentRegistration] = field(default_factory=dict)
    last_seen: dict[UUID, datetime] = field(default_factory=dict)
    store_failures: list[BaseException | None] = field(default_factory=list)
    commit_failures: list[tuple[BaseException, bool]] = field(default_factory=list)
    poison: set[UUID] = field(default_factory=set)
    store_calls: int = 0
    commits: int = 0
    rollbacks: int = 0

    @asynccontextmanager
    async def unit_of_work(self) -> AsyncIterator["MemoryWriter"]:
        writer = MemoryWriter(self)
        try:
            yield writer
        except BaseException:
            self.rollbacks += 1
            raise
        if self.commit_failures:
            error, applied = self.commit_failures.pop(0)
            if applied:
                writer.apply()
            raise error
        writer.apply()
        self.commits += 1


@dataclass
class MemoryWriter:
    """The writer of one unit of work."""

    store: MemoryEventStore
    staged: dict[UUID, AnyCanonicalEvent] = field(default_factory=dict)
    staged_agents: dict[UUID, AgentRegistration] = field(default_factory=dict)
    staged_seen: dict[UUID, datetime] = field(default_factory=dict)

    def apply(self) -> None:
        self.store.rows.update(self.staged)
        self.store.agents.update(self.staged_agents)
        for agent_id, moment in self.staged_seen.items():
            if agent_id in self.store.agents:
                previous = self.store.last_seen.get(agent_id)
                self.store.last_seen[agent_id] = max(moment, previous) if previous else moment

    async def find_payloads(self, event_ids: Iterable[UUID]) -> dict[UUID, dict[str, object]]:
        return {
            event_id: self.store.rows[event_id].model_dump(mode="json")
            for event_id in event_ids
            if event_id in self.store.rows
        }

    async def register_agents(self, registrations: Sequence[AgentRegistration]) -> int:
        for item in registrations:
            self.staged_agents[item.agent_id] = item
        return len({item.agent_id for item in registrations})

    async def touch_agents(self, seen: Mapping[UUID, datetime]) -> None:
        self.staged_seen.update(seen)

    async def store_events_batch(self, events: Sequence[AnyCanonicalEvent]) -> BatchStoreResult:
        self.store.store_calls += 1
        if self.store.store_failures:
            error = self.store.store_failures.pop(0)
            if error is not None:
                raise error
        if any(event.event_id in self.store.poison for event in events):
            raise data_error()
        inserted: list[UUID] = []
        duplicates: list[UUID] = []
        for event in events:
            if event.event_id in self.store.rows or event.event_id in self.staged:
                duplicates.append(event.event_id)
            else:
                self.staged[event.event_id] = event
                inserted.append(event.event_id)
        return BatchStoreResult(inserted=tuple(inserted), duplicates=tuple(duplicates))


@dataclass
class RecordingPublisher:
    """Records published batches; raises queued failures first."""

    failures: list[BaseException] = field(default_factory=list)
    batches: list[list[NormalizedEvent]] = field(default_factory=list)
    attempts: int = 0

    async def publish(self, events: Sequence[NormalizedEvent]) -> None:
        self.attempts += 1
        if self.failures:
            raise self.failures.pop(0)
        self.batches.append(list(events))

    @property
    def events(self) -> list[NormalizedEvent]:
        """Every successfully published event, in order."""
        return [event for batch in self.batches for event in batch]

    def event_ids(self) -> list[UUID]:
        return [normalized.event.event_id for normalized in self.events]


@dataclass(frozen=True)
class DeadLetter:
    """A record written to the recording dead-letter sink."""

    topic: str
    offset: int
    value: bytes | None
    error: BaseException
    attempts: int
    consumer_group: str


@dataclass
class RecordingDeadLetter:
    """Records dead letters; raises queued failures first."""

    failures: list[BaseException] = field(default_factory=list)
    records: list[DeadLetter] = field(default_factory=list)

    async def publish(
        self,
        record: FailedRecord,
        value: bytes | None,
        error: BaseException,
        *,
        attempts: int,
        consumer_group: str,
    ) -> object:
        if self.failures:
            raise self.failures.pop(0)
        self.records.append(
            DeadLetter(record.topic, record.offset, value, error, attempts, consumer_group)
        )
        return None

    def error_types(self) -> list[str]:
        return [type(record.error).__name__ for record in self.records]


@dataclass
class Harness:
    """A pipeline wired to in-memory collaborators."""

    store: MemoryEventStore = field(default_factory=MemoryEventStore)
    publisher: RecordingPublisher = field(default_factory=RecordingPublisher)
    dead_letter: RecordingDeadLetter = field(default_factory=RecordingDeadLetter)
    stopping: asyncio.Event = field(default_factory=asyncio.Event)
    retry_policy: RetryPolicy = FAST_RETRIES
    log_events: bool = False
    max_future_skew_seconds: float | None = None
    metrics: NormalizerMetrics | None = None

    def __post_init__(self) -> None:
        self.pipeline = NormalizationPipeline(
            store=self.store,
            publisher=self.publisher,
            dead_letter=self.dead_letter,
            consumer_group=GROUP,
            normalizer_name="adis-normalizer",
            retry_policy=self.retry_policy,
            stopping=self.stopping,
            max_future_skew_seconds=self.max_future_skew_seconds,
            log_events=self.log_events,
            metrics=self.metrics,
            clock=lambda: NOW,
            jitter=lambda low, high: high,
        )
