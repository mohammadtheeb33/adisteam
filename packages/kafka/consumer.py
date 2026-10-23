"""Event consumer with retries, dead-lettering and graceful shutdown."""

import asyncio
import logging
import re
from collections.abc import Callable, Mapping, Sequence, Set
from dataclasses import dataclass
from typing import Final, Protocol, Self

from aiokafka import AIOKafkaConsumer
from aiokafka.errors import CommitFailedError, IllegalStateError

from packages.config import KafkaSettings
from packages.events import EventEnvelope
from packages.kafka.clients import (
    OffsetReset,
    consumer_options,
    is_transient_transport_error,
)
from packages.kafka.dead_letter import DeadLetterPublisher
from packages.kafka.errors import DeserializationError, NonRetriableError
from packages.kafka.rebalance import RebalanceLogger
from packages.kafka.retry import Jitter, RetryError, RetryPolicy, Sleep, default_jitter, retry_async
from packages.kafka.serialization import deserialize_envelope, trace_id_from_headers
from packages.kafka.topics import Topic
from packages.observability import log_context

logger = logging.getLogger(__name__)

_GROUP_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ConsumerRecordLike(Protocol):
    """The subset of ``aiokafka.structs.ConsumerRecord`` used here."""

    @property
    def topic(self) -> str:
        """Topic name."""
        ...

    @property
    def partition(self) -> int:
        """Partition number."""
        ...

    @property
    def offset(self) -> int:
        """Offset within the partition."""
        ...

    @property
    def timestamp(self) -> int:
        """Record timestamp, epoch milliseconds."""
        ...

    @property
    def key(self) -> bytes | None:
        """Record key."""
        ...

    @property
    def value(self) -> bytes | None:
        """Record value."""
        ...

    @property
    def headers(self) -> Sequence[tuple[str, bytes]]:
        """Record headers."""
        ...


class ConsumerClient(Protocol):
    """The subset of ``AIOKafkaConsumer`` used here."""

    async def start(self) -> None:
        """Join the consumer group."""
        ...

    async def stop(self) -> None:
        """Leave the consumer group and disconnect."""
        ...

    async def getmany(
        self, *partitions: object, timeout_ms: int = 0, max_records: int | None = None
    ) -> Mapping[object, Sequence[ConsumerRecordLike]]:
        """Fetch available records grouped by topic partition."""
        ...

    async def commit(self, offsets: Mapping[object, int] | None = None) -> None:
        """Commit the next offsets to read, per topic partition."""
        ...

    def assignment(self) -> Set[object]:
        """The partitions currently assigned to this member."""
        ...

    def highwater(self, partition: object) -> int | None:
        """The partition's end offset from the last fetch, if known."""
        ...

    async def position(self, partition: object) -> int:
        """The next offset this member will read from the partition."""
        ...


@dataclass(frozen=True, slots=True)
class MessageContext:
    """Transport details of the record being handled."""

    topic: str
    partition: int
    offset: int
    timestamp_ms: int
    key: bytes | None
    headers: tuple[tuple[str, bytes], ...]

    @classmethod
    def from_record(cls, record: ConsumerRecordLike) -> Self:
        """Capture the details of a consumed record."""
        return cls(
            topic=record.topic,
            partition=record.partition,
            offset=record.offset,
            timestamp_ms=record.timestamp,
            key=record.key,
            headers=tuple(record.headers),
        )


class MessageHandler(Protocol):
    """Processes one event.

    Raise :class:`~packages.kafka.errors.NonRetriableError` for failures that retrying
    cannot fix. Outages (``is_outage``) are retried until they recover and never
    dead-lettered. Any other exception is retried with backoff and dead-lettered once
    attempts are exhausted. Handlers must be idempotent: a record can be delivered more
    than once.
    """

    async def __call__(self, event: EventEnvelope, context: MessageContext) -> None:
        """Handle ``event``."""
        ...


class KafkaConsumer:
    """Consumes ADIS topics with at-least-once semantics.

    For each record, in partition order:

    1. Decode the envelope. Undecodable records are dead-lettered immediately.
    2. Call the handler, retrying failures (``KAFKA_RETRY_*``).
       - Outages (``is_outage``, by default broker and network errors) are retried
         until they recover, so valid events are never dead-lettered because a
         dependency was down.
       - A ``NonRetriableError``, or exhausted retries, dead-letters the record.
    3. After each partition's records of a poll, commit past the last settled record
       (handled or dead-lettered): one commit per partition per poll instead of one per
       record. If the dead-letter topic is unreachable, the error propagates and only
       the records settled before it are committed.

    A commit refused because the group rebalanced is logged; the records are
    redelivered to the partition's new owner. ``request_stop()`` (or ``stop()``)
    finishes the record in progress, commits what was settled and leaves the group. A
    stop requested before :meth:`run` starts makes it return right away.
    """

    def __init__(
        self,
        client_factory: Callable[[], ConsumerClient],
        *,
        topics: Sequence[Topic],
        group_id: str,
        dead_letter: DeadLetterPublisher,
        retry_policy: RetryPolicy,
        poll_timeout_ms: int = 1_000,
        max_records: int = 100,
        sleep: Sleep = asyncio.sleep,
        jitter: Jitter = default_jitter,
        is_outage: Callable[[Exception], bool] = is_transient_transport_error,
    ) -> None:
        validate_subscription(topics, group_id)
        self._is_outage = is_outage
        self._client_factory = client_factory
        self._topics = tuple(topics)
        self._group_id = group_id
        self._dead_letter = dead_letter
        self._retry_policy = retry_policy
        self._poll_timeout_ms = poll_timeout_ms
        self._max_records = max_records
        self._sleep = sleep
        self._jitter = jitter
        self._stop_requested = asyncio.Event()
        self._stopped = asyncio.Event()
        self._stopped.set()

    @classmethod
    def from_settings(
        cls,
        settings: KafkaSettings,
        *,
        topics: Sequence[Topic],
        group_id: str,
        dead_letter: DeadLetterPublisher,
        client_id: str | None = None,
        auto_offset_reset: OffsetReset = "earliest",
    ) -> Self:
        """Create a consumer backed by ``AIOKafkaConsumer``.

        Args:
            settings: Kafka settings.
            topics: Topics to subscribe to.
            group_id: Consumer group; one per logical consumer (e.g. ``adis-detector``).
            dead_letter: Publisher for records that cannot be processed.
            client_id: Overrides ``KAFKA_CLIENT_ID``.
            auto_offset_reset: Where a new group starts reading.
        """
        options = consumer_options(
            settings, group_id=group_id, client_id=client_id, auto_offset_reset=auto_offset_reset
        )
        subscribed = [topic.value for topic in topics]

        def create_client() -> ConsumerClient:
            consumer = AIOKafkaConsumer(**options)
            consumer.subscribe(subscribed, listener=RebalanceLogger(group_id))
            client: ConsumerClient = consumer
            return client

        return cls(
            create_client,
            topics=topics,
            group_id=group_id,
            dead_letter=dead_letter,
            retry_policy=RetryPolicy.from_settings(settings),
        )

    @property
    def group_id(self) -> str:
        """The consumer group."""
        return self._group_id

    @property
    def running(self) -> bool:
        """Whether :meth:`run` is active."""
        return not self._stopped.is_set()

    def request_stop(self) -> None:
        """Ask :meth:`run` to return after the record in progress. Safe from signal handlers."""
        self._stop_requested.set()

    async def stop(self) -> None:
        """Request a graceful stop and wait until :meth:`run` has returned."""
        self.request_stop()
        await self._stopped.wait()

    async def run(self, handler: MessageHandler) -> None:
        """Consume until a stop is requested.

        Raises:
            RuntimeError: If already running.
            PublishError: If a record could not be dead-lettered; nothing is committed.
        """
        if self.running:
            raise RuntimeError("KafkaConsumer is already running")
        self._stopped.clear()
        client = self._client_factory()
        try:
            await client.start()
            logger.info(
                "kafka consumer started",
                extra={
                    "action": "kafka_consumer_started",
                    "group_id": self._group_id,
                    "topics": [topic.value for topic in self._topics],
                },
            )
            while not self._stop_requested.is_set():
                batches = await client.getmany(
                    timeout_ms=self._poll_timeout_ms, max_records=self._max_records
                )
                await self._process_batches(client, batches, handler)
        finally:
            try:
                await client.stop()
            finally:
                self._stop_requested.clear()  # a later run() starts afresh
                self._stopped.set()
                logger.info(
                    "kafka consumer stopped",
                    extra={"action": "kafka_consumer_stopped", "group_id": self._group_id},
                )

    async def _process_batches(
        self,
        client: ConsumerClient,
        batches: Mapping[object, Sequence[ConsumerRecordLike]],
        handler: MessageHandler,
    ) -> None:
        for partition, records in batches.items():
            settled: int | None = None
            try:
                for record in records:
                    if self._stop_requested.is_set():
                        break  # the rest is uncommitted and will be redelivered
                    await self._process(record, handler)
                    settled = record.offset
            except _StopDuringOutage:
                pass
            finally:
                if settled is not None:
                    await self._commit(client, {partition: settled + 1})
            if self._stop_requested.is_set():
                return

    async def _commit(self, client: ConsumerClient, offsets: Mapping[object, int]) -> None:
        try:
            await client.commit(offsets)
        except (CommitFailedError, IllegalStateError) as error:
            logger.warning(
                "offsets not committed because the group rebalanced; the records will be "
                "redelivered",
                extra={
                    "action": "kafka_commit_failed",
                    "group_id": self._group_id,
                    "error_type": type(error).__name__,
                },
            )

    async def _process(self, record: ConsumerRecordLike, handler: MessageHandler) -> None:
        context = MessageContext.from_record(record)
        # The trace header correlates even records whose value cannot be decoded.
        with log_context(trace_id=trace_id_from_headers(context.headers)):
            try:
                event = deserialize_envelope(record.value)
            except DeserializationError as error:
                await self._dead_letter_record(context, record.value, error, attempts=1)
                return
            # Everything the handler logs or publishes inherits the event's trace.
            with log_context(trace_id=event.trace_id, event_id=event.event_id):
                await self._handle(event, context, record.value, handler)

    async def _handle(
        self,
        event: EventEnvelope,
        context: MessageContext,
        value: bytes | None,
        handler: MessageHandler,
    ) -> None:
        async def handle() -> None:
            await handler(event, context)

        def log_retry(attempt: int, error: Exception, delay: float) -> None:
            logger.warning(
                "event handler failed; retrying",
                extra={
                    "action": "kafka_handler_retry",
                    "topic": context.topic,
                    "attempt": attempt,
                    "error_type": type(error).__name__,
                    "retry_in_ms": round(delay * 1000),
                },
            )

        outages = 0
        while True:
            try:
                await retry_async(
                    handle,
                    policy=self._retry_policy,
                    is_retriable=_is_retriable_handler_error,
                    on_retry=log_retry,
                    sleep=self._sleep,
                    jitter=self._jitter,
                )
                return
            except RetryError as failure:
                error = failure.last_error
                if isinstance(error, NonRetriableError) or not self._is_outage(error):
                    await self._dead_letter_record(context, value, error, attempts=failure.attempts)
                    return
                outages += 1
                delay = self._retry_policy.backoff_seconds(min(outages, 32), self._jitter)
                logger.warning(
                    "event handler hit an outage; retrying until it recovers",
                    extra={
                        "action": "kafka_handler_outage",
                        "topic": context.topic,
                        "error_type": type(error).__name__,
                        "retry_in_ms": round(delay * 1000),
                    },
                )
                if self._stop_requested.is_set():
                    raise _StopDuringOutage from error
                await self._sleep(delay)
                if self._stop_requested.is_set():
                    raise _StopDuringOutage from error

    async def _dead_letter_record(
        self, context: MessageContext, value: bytes | None, error: Exception, *, attempts: int
    ) -> None:
        await self._dead_letter.publish(
            context, value, error, attempts=attempts, consumer_group=self._group_id
        )
        logger.error(
            "record dead-lettered",
            extra={
                "action": "kafka_record_dead_lettered",
                "topic": context.topic,
                "partition": context.partition,
                "offset": context.offset,
                "group_id": self._group_id,
                "attempts": attempts,
                "error_type": type(error).__name__,
            },
        )


class _StopDuringOutage(Exception):  # noqa: N818 - control flow, not an error
    """A stop was requested while a record waited for an outage to end."""


def validate_subscription(topics: Sequence[Topic], group_id: str) -> None:
    """Check the topics and consumer group of a consumer.

    Raises:
        ValueError: If there are no topics, the dead-letter topic is included, or the
            group id is malformed.
    """
    if not topics:
        raise ValueError("at least one topic is required")
    if Topic.DEADLETTER in topics:
        raise ValueError("the dead-letter topic is read by triage tooling, not by consumers")
    if not _GROUP_ID_PATTERN.match(group_id):
        raise ValueError("group_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _is_retriable_handler_error(error: Exception) -> bool:
    return not isinstance(error, NonRetriableError)
