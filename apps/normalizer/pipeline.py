"""Batch processing of accepted telemetry: normalize, deduplicate, store, publish.

For each polled batch:

1. **Normalize** every record. A record that is not a valid envelope, or cannot become a
   valid canonical event, is rejected.
2. **Deduplicate** by ``event_id`` within the batch; the first occurrence wins. A repeat
   whose content differs from the first is a *conflicting duplicate* and is rejected.
3. **Store and publish** in one database transaction:
   - refresh ``adis.agents`` from agent registrations in the batch;
   - insert the events (skipping those already stored);
   - compare every already stored event with the stored copy (conflicting duplicates
     are rejected);
   - move ``last_seen`` of the reporting agents forward;
   - publish only the newly inserted events to ``adis.security.events``, wait for the
     broker acknowledgements, then commit.

   A stored row therefore implies that its event was published, which is what makes
   duplicate suppression safe:
   - an event already stored is a duplicate and is neither stored nor published again;
   - if publishing fails, the transaction rolls back and the retry publishes again;
   - if the process dies after publishing but before committing, the redelivered
     record is published a second time (at-least-once) and stored once.
4. **Dead-letter** rejected records to ``adis.deadletter`` with their original bytes.

The batch consumer commits Kafka offsets only after this returns. Outages are retried
until they recover, and a stop request interrupts the wait (``BatchAbortedError``, batch
uncommitted). Any other failure splits the batch: each event is retried up to
``max_attempts`` times alone, and an event that still fails is dead-lettered.
"""

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from typing import Final, Protocol
from uuid import UUID

from apps.normalizer.errors import (
    ConflictingDuplicateError,
    NormalizationError,
    PersistenceError,
    is_transient_error,
)
from apps.normalizer.metrics import NormalizerMetrics
from apps.normalizer.normalization import (
    INGESTION_METADATA_KEY,
    NormalizedEvent,
    Provenance,
    normalize_record,
)
from apps.normalizer.publisher import NormalizedEventPublisher
from apps.normalizer.store import EventStore
from packages.database.models.agents import OsType
from packages.database.repositories import AgentRegistration
from packages.events import agents as registration
from packages.events.canonical import AnyCanonicalEvent, CanonicalEventError
from packages.kafka import (
    BatchAbortedError,
    ConsumerRecordLike,
    DeserializationError,
    MessageContext,
    RetryPolicy,
    deserialize_envelope,
    trace_id_from_headers,
)
from packages.kafka.dead_letter import FailedRecord
from packages.kafka.retry import Jitter, default_jitter
from packages.observability import log_context

logger = logging.getLogger(__name__)

# Caps the exponent of the backoff so outages of any length never overflow it.
_MAX_BACKOFF_EXPONENT: Final = 32
_REJECTABLE: Final = (DeserializationError, CanonicalEventError, NormalizationError)
# Fields that legitimately differ between submissions of the same event.
_VOLATILE_FIELDS: Final = ("received_at", "trace_id")
_MAX_IDENTITY_LENGTH: Final = 255
_MAX_VERSION_LENGTH: Final = 64


class DeadLetterSink(Protocol):
    """Dead-letters a record (``packages.kafka.DeadLetterPublisher``)."""

    async def publish(
        self,
        record: FailedRecord,
        value: bytes | None,
        error: BaseException,
        *,
        attempts: int,
        consumer_group: str,
    ) -> object:
        """Write the record to the dead-letter topic, or raise."""
        ...


@dataclass(slots=True)
class PipelineStats:
    """Running totals since the pipeline was created.

    Attributes:
        records: Records handled, including duplicates and rejections.
        published: Events stored and published to ``adis.security.events``.
        duplicates: Records whose ``event_id`` was already stored or earlier in the batch,
            with the same content.
        conflicts: Duplicates whose content differs from the stored event (dead-lettered).
        dead_lettered: Records written to the dead-letter topic (conflicts included).
        retries: Failed attempts that were retried.
        future_timestamps: Events flagged for a timestamp too far ahead of receipt.
        agent_registrations: Agent registrations applied to ``adis.agents``.
    """

    records: int = 0
    published: int = 0
    duplicates: int = 0
    conflicts: int = 0
    dead_lettered: int = 0
    retries: int = 0
    future_timestamps: int = 0
    agent_registrations: int = 0


@dataclass(frozen=True, slots=True)
class _Accepted:
    context: MessageContext
    value: bytes | None
    normalized: NormalizedEvent

    @property
    def event(self) -> AnyCanonicalEvent:
        return self.normalized.event

    @property
    def event_id(self) -> UUID:
        return self.normalized.event.event_id


@dataclass(frozen=True, slots=True)
class _Rejected:
    context: MessageContext
    value: bytes | None
    error: Exception
    attempts: int = 1
    trace_id: str | None = None
    event_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class _Written:
    inserted: frozenset[UUID] = frozenset()
    duplicates: frozenset[UUID] = frozenset()
    failed: tuple[_Rejected, ...] = ()
    registrations: int = 0


@dataclass(slots=True)
class _WriteResult:
    inserted: set[UUID] = field(default_factory=set)
    duplicates: set[UUID] = field(default_factory=set)
    conflicts: list[_Accepted] = field(default_factory=list)
    registrations: int = 0


class NormalizationPipeline:
    """The normalizer's :class:`~packages.kafka.BatchHandler`.

    Args:
        store: Opens database units of work.
        publisher: Publishes normalized events.
        dead_letter: Dead-letters rejected records.
        consumer_group: Recorded in dead-letter headers.
        normalizer_name: Recorded as ``normalizer`` in the ingestion metadata.
        retry_policy: Backoff of every retry, and attempts per event for failures that
            are not outages.
        stopping: Set on shutdown; interrupts retries.
        max_future_skew_seconds: Events timestamped further ahead of receipt are flagged.
        log_events: Log one line per event (stored or duplicate) with its ids.
        metrics: Prometheus metrics, if exposed.
        clock: Current time, for ``normalized_at``.
        jitter: Random source of the backoff.
    """

    def __init__(
        self,
        *,
        store: EventStore,
        publisher: NormalizedEventPublisher,
        dead_letter: DeadLetterSink,
        consumer_group: str,
        normalizer_name: str,
        retry_policy: RetryPolicy,
        stopping: asyncio.Event,
        max_future_skew_seconds: float | None = None,
        log_events: bool = False,
        metrics: NormalizerMetrics | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        jitter: Jitter = default_jitter,
    ) -> None:
        self._store = store
        self._publisher = publisher
        self._dead_letter_sink = dead_letter
        self._consumer_group = consumer_group
        self._normalizer_name = normalizer_name
        self._retry_policy = retry_policy
        self._stopping = stopping
        self._max_future_skew_seconds = max_future_skew_seconds
        self._log_events = log_events
        self._metrics = metrics
        self._clock = clock
        self._jitter = jitter
        self.stats = PipelineStats()

    async def __call__(self, records: Sequence[ConsumerRecordLike]) -> None:
        """Settle every record of the batch: stored and published, duplicate, or dead-lettered.

        Raises:
            BatchAbortedError: If stopping was requested before the batch was settled.
        """
        started = time.perf_counter()
        accepted, rejected = self._normalize(records)
        unique, repeats = _first_occurrences(accepted)
        in_batch_conflicts = [item for item, first in repeats if not _same_content(item, first)]
        written = await self._store_and_publish(unique)
        rejected.extend(_conflict(item) for item in in_batch_conflicts)
        rejected.extend(written.failed)
        await self._dead_letter(rejected)

        conflicts = len(in_batch_conflicts) + sum(
            1 for item in written.failed if isinstance(item.error, ConflictingDuplicateError)
        )
        duplicates = len(repeats) - len(in_batch_conflicts) + len(written.duplicates)
        self._log_lifecycle(unique, repeats, written)
        self._count(records, written, duplicates, conflicts, rejected, started)
        logger.info(
            "batch normalized",
            extra={
                "action": "normalizer_batch_processed",
                "records": len(records),
                "published": len(written.inserted),
                "duplicates": duplicates,
                "conflicts": conflicts,
                "dead_lettered": len(rejected),
                "agent_registrations": written.registrations,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )

    # -------------------------------------------------------------------- normalize

    def _normalize(
        self, records: Sequence[ConsumerRecordLike]
    ) -> tuple[list[_Accepted], list[_Rejected]]:
        now = self._clock()
        accepted: list[_Accepted] = []
        rejected: list[_Rejected] = []
        for record in records:
            context = MessageContext.from_record(record)
            header_trace = trace_id_from_headers(context.headers)
            trace_id: str | None = header_trace
            event_id: UUID | None = None
            with log_context(trace_id=header_trace):
                try:
                    envelope = deserialize_envelope(record.value)
                    trace_id, event_id = envelope.trace_id, envelope.event_id
                    with log_context(trace_id=envelope.trace_id, event_id=envelope.event_id):
                        normalized = normalize_record(
                            envelope,
                            Provenance.of(envelope, context),
                            normalizer=self._normalizer_name,
                            now=now,
                            max_future_skew_seconds=self._max_future_skew_seconds,
                        )
                except _REJECTABLE as error:
                    rejected.append(_Rejected(context, record.value, error, 1, trace_id, event_id))
                    continue
                except Exception as error:
                    # A bug, not bad input: dead-letter the record (replayable once fixed)
                    # rather than crash-looping on it. The message may quote input, so
                    # only the type is kept.
                    logger.exception(
                        "unexpected error while normalizing a record",
                        extra={"action": "normalizer_unexpected_error", "topic": context.topic},
                    )
                    failure = NormalizationError(f"unexpected {type(error).__name__}")
                    rejected.append(
                        _Rejected(context, record.value, failure, 1, trace_id, event_id)
                    )
                    continue
            self._note_quirks(normalized)
            accepted.append(_Accepted(context, record.value, normalized))
        return accepted, rejected

    def _note_quirks(self, normalized: NormalizedEvent) -> None:
        event = normalized.event
        with log_context(trace_id=event.trace_id, event_id=event.event_id, host_id=event.host_id):
            if not normalized.enriched:
                logger.warning(
                    "ingestion metadata left out: the event's metadata is at its size limit",
                    extra={"action": "normalizer_enrichment_dropped"},
                )
            if normalized.timestamp_skew_seconds is not None:
                self.stats.future_timestamps += 1
                if self._metrics is not None:
                    self._metrics.future_timestamps.inc()
                logger.warning(
                    "event timestamp is ahead of its receipt; kept and flagged",
                    extra={
                        "action": "normalizer_future_timestamp",
                        "skew_seconds": normalized.timestamp_skew_seconds,
                    },
                )

    # ---------------------------------------------------------------- store/publish

    async def _store_and_publish(self, unique: Sequence[_Accepted]) -> _Written:
        if not unique:
            return _Written()
        try:
            result = await self._attempt(lambda: self._write(unique), bounded=False)
        except BatchAbortedError:
            raise
        except Exception as error:
            logger.warning(
                "batch could not be stored; retrying its events one by one",
                extra={
                    "action": "normalizer_batch_isolated",
                    "events": len(unique),
                    "error_type": type(error).__name__,
                },
            )
            return await self._store_and_publish_each(unique)
        return _written(result)

    async def _store_and_publish_each(self, unique: Sequence[_Accepted]) -> _Written:
        combined = _WriteResult()
        failed: list[_Rejected] = []
        for item in unique:
            try:
                result = await self._attempt(partial(self._write, [item]), bounded=True)
            except BatchAbortedError:
                raise
            except Exception as error:
                failed.append(
                    _Rejected(
                        item.context,
                        item.value,
                        PersistenceError.from_error(error),
                        self._retry_policy.max_attempts,
                        item.event.trace_id,
                        item.event_id,
                    )
                )
            else:
                combined.inserted |= result.inserted
                combined.duplicates |= result.duplicates
                combined.conflicts.extend(result.conflicts)
                combined.registrations += result.registrations
        written = _written(combined)
        return _Written(
            written.inserted, written.duplicates, (*written.failed, *failed), written.registrations
        )

    async def _write(self, items: Sequence[_Accepted]) -> _WriteResult:
        async with self._store.unit_of_work() as writer:
            registrations = [
                found for item in items if (found := _registration(item.event)) is not None
            ]
            registered = await writer.register_agents(registrations) if registrations else 0
            result = await writer.store_events_batch([item.event for item in items])
            inserted = set(result.inserted)
            already = [item for item in items if item.event_id not in inserted]
            stored = await writer.find_payloads(item.event_id for item in already)
            conflicts = [
                item
                for item in already
                if item.event_id in stored and not _matches_stored(item, stored[item.event_id])
            ]
            await writer.touch_agents(
                _last_seen(item for item in items if item.event_id in inserted)
            )
            await self._publisher.publish(
                [item.normalized for item in items if item.event_id in inserted]
            )
        conflicting = {item.event_id for item in conflicts}
        return _WriteResult(
            inserted=inserted,
            duplicates={item.event_id for item in already} - conflicting,
            conflicts=conflicts,
            registrations=registered,
        )

    # ----------------------------------------------------------------- dead letters

    async def _dead_letter(self, rejected: Sequence[_Rejected]) -> None:
        for item in rejected:

            async def publish(item: _Rejected = item) -> object:
                return await self._dead_letter_sink.publish(
                    item.context,
                    item.value,
                    item.error,
                    attempts=item.attempts,
                    consumer_group=self._consumer_group,
                )

            await self._attempt(publish, bounded=False)
            with log_context(trace_id=item.trace_id, event_id=item.event_id):
                logger.warning(
                    "record dead-lettered",
                    extra={
                        "action": "normalizer_record_dead_lettered",
                        "topic": item.context.topic,
                        "partition": item.context.partition,
                        "offset": item.context.offset,
                        "error_type": type(item.error).__name__,
                        "reason": str(item.error),
                    },
                )

    # ---------------------------------------------------------------- bookkeeping

    def _log_lifecycle(
        self,
        unique: Sequence[_Accepted],
        repeats: Sequence[tuple[_Accepted, _Accepted]],
        written: _Written,
    ) -> None:
        if not self._log_events:
            return
        dead_lettered = _ids(written.failed)
        entries = [(item, item.event_id in written.inserted) for item in unique] + [
            (repeat, False) for repeat, first in repeats if _same_content(repeat, first)
        ]
        for item, stored in entries:
            if not stored and item.event_id in dead_lettered and item in unique:
                continue  # logged as dead-lettered
            event = item.event
            with log_context(
                trace_id=event.trace_id, event_id=event.event_id, host_id=event.host_id
            ):
                logger.info(
                    "event stored and published" if stored else "duplicate event suppressed",
                    extra={
                        "action": "normalizer_event_stored"
                        if stored
                        else "normalizer_event_duplicate",
                        "source_topic": item.context.topic,
                        "source_offset": item.context.offset,
                    },
                )

    def _count(
        self,
        records: Sequence[ConsumerRecordLike],
        written: _Written,
        duplicates: int,
        conflicts: int,
        rejected: Sequence[_Rejected],
        started: float,
    ) -> None:
        stats = self.stats
        stats.records += len(records)
        stats.published += len(written.inserted)
        stats.duplicates += duplicates
        stats.conflicts += conflicts
        stats.dead_lettered += len(rejected)
        stats.agent_registrations += written.registrations
        metrics = self._metrics
        if metrics is None:
            return
        metrics.records.inc(len(records))
        metrics.events.labels("published").inc(len(written.inserted))
        metrics.events.labels("duplicate").inc(duplicates)
        metrics.events.labels("conflict").inc(conflicts)
        metrics.events.labels("dead_lettered").inc(len(rejected))
        metrics.agents_registered.inc(written.registrations)
        metrics.batch_duration.observe(time.perf_counter() - started)

    # -------------------------------------------------------------------- retrying

    async def _attempt[T](self, operation: Callable[[], Awaitable[T]], *, bounded: bool) -> T:
        """Run ``operation`` until it succeeds.

        Outages are retried until they recover. Other failures are raised at once, or,
        when ``bounded``, after ``max_attempts`` attempts.
        """
        failures = 0
        attempts = 0
        while True:
            try:
                return await operation()
            except Exception as error:
                transient = is_transient_error(error)
                if not transient:
                    attempts += 1
                    if not bounded or attempts >= self._retry_policy.max_attempts:
                        raise
                failures += 1
                delay = self._retry_policy.backoff_seconds(
                    min(failures, _MAX_BACKOFF_EXPONENT), self._jitter
                )
                self.stats.retries += 1
                if self._metrics is not None:
                    self._metrics.retries.labels("outage" if transient else "other").inc()
                logger.warning(
                    "normalizer operation failed; retrying",
                    extra={
                        "action": "normalizer_retry",
                        "error_type": type(error).__name__,
                        "transient": transient,
                        "attempt": failures,
                        "retry_in_ms": round(delay * 1000),
                    },
                )
                await self._pause(delay)

    async def _pause(self, seconds: float) -> None:
        """Wait before a retry; a stop request ends the wait and aborts the batch."""
        if not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=seconds)
            except TimeoutError:
                return
        raise BatchAbortedError("stopping before the batch was settled")


# ------------------------------------------------------------------------ helpers


def _written(result: _WriteResult) -> _Written:
    conflicts = tuple(_conflict(item) for item in result.conflicts)
    return _Written(
        frozenset(result.inserted), frozenset(result.duplicates), conflicts, result.registrations
    )


def _conflict(item: _Accepted) -> _Rejected:
    return _Rejected(
        item.context, item.value, ConflictingDuplicateError(), 1, item.event.trace_id, item.event_id
    )


def _ids(rejected: Sequence[_Rejected]) -> set[UUID]:
    return {item.event_id for item in rejected if item.event_id is not None}


def _first_occurrences(
    accepted: Sequence[_Accepted],
) -> tuple[list[_Accepted], list[tuple[_Accepted, _Accepted]]]:
    """The first record of each ``event_id``, and each repeat with its first record."""
    unique: dict[UUID, _Accepted] = {}
    repeats: list[tuple[_Accepted, _Accepted]] = []
    for item in accepted:
        first = unique.setdefault(item.event_id, item)
        if first is not item:
            repeats.append((item, first))
    return list(unique.values()), repeats


def _content(document: Mapping[str, object]) -> str:
    """The event's content, ignoring what legitimately differs between submissions."""
    kept = {key: value for key, value in document.items() if key not in _VOLATILE_FIELDS}
    metadata = kept.get("metadata")
    if isinstance(metadata, Mapping):
        kept["metadata"] = {k: v for k, v in metadata.items() if k != INGESTION_METADATA_KEY}
    return json.dumps(kept, sort_keys=True, separators=(",", ":"), default=str)


def _same_content(item: _Accepted, other: _Accepted) -> bool:
    return _content(item.event.model_dump(mode="json")) == _content(
        other.event.model_dump(mode="json")
    )


def _matches_stored(item: _Accepted, stored: Mapping[str, object]) -> bool:
    return _content(item.event.model_dump(mode="json")) == _content(stored)


def _registration(event: AnyCanonicalEvent) -> AgentRegistration | None:
    """The agent registration an event announces, if it is a valid one."""
    if event.event_type != registration.AGENT_REGISTERED_EVENT_TYPE or event.agent_id is None:
        return None
    try:
        agent_id = UUID(event.agent_id)
    except ValueError:
        return None
    metadata = event.metadata
    keys = (
        registration.REGISTRATION_NAME,
        registration.REGISTRATION_HOSTNAME,
        registration.REGISTRATION_OS_TYPE,
        registration.REGISTRATION_VERSION,
    )
    values = [metadata.get(key) for key in keys]
    if not all(isinstance(value, str) and value.strip() for value in values):
        return None
    name, hostname, os_type, version = (str(value) for value in values)
    known = {item.value for item in OsType}
    return AgentRegistration(
        agent_id=agent_id,
        name=name[:_MAX_IDENTITY_LENGTH],
        hostname=hostname[:_MAX_IDENTITY_LENGTH],
        os_type=OsType(os_type) if os_type in known else OsType.OTHER,
        agent_version=version[:_MAX_VERSION_LENGTH],
        seen_at=event.received_at,
    )


def _last_seen(items: Iterable[_Accepted]) -> dict[UUID, datetime]:
    """Latest ``received_at`` per reporting agent (unregistered ids are ignored later)."""
    seen: dict[UUID, datetime] = {}
    for item in items:
        agent_id = item.event.agent_id
        if agent_id is None:
            continue
        try:
            key = UUID(agent_id)
        except ValueError:
            continue
        moment = item.event.received_at
        if key not in seen or moment > seen[key]:
            seen[key] = moment
    return seen
