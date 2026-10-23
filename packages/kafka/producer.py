"""Event producer."""

import asyncio
import contextlib
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Protocol, Self

from aiokafka import AIOKafkaProducer

from packages.config import KafkaSettings
from packages.events import EventEnvelope
from packages.kafka.clients import is_retriable_kafka_error, producer_options
from packages.kafka.errors import PublishError
from packages.kafka.retry import Jitter, RetryError, RetryPolicy, Sleep, default_jitter, retry_async
from packages.kafka.serialization import encode_key, envelope_headers, serialize_envelope
from packages.kafka.topics import Topic

logger = logging.getLogger(__name__)


class RecordMetadataLike(Protocol):
    """Where the broker stored a record."""

    @property
    def partition(self) -> int:
        """Partition number."""
        ...

    @property
    def offset(self) -> int:
        """Offset within the partition."""
        ...


class MetadataClient(Protocol):
    """The subset of ``aiokafka``'s cluster client used here."""

    async def fetch_all_metadata(self) -> object:
        """Request cluster metadata from a broker; raises ``KafkaError`` if none answers."""
        ...


class ProducerClient(Protocol):
    """The subset of ``AIOKafkaProducer`` used here."""

    @property
    def client(self) -> MetadataClient:
        """The underlying cluster client."""
        ...

    async def start(self) -> None:
        """Connect to the cluster."""
        ...

    async def stop(self) -> None:
        """Flush pending records and disconnect."""
        ...

    async def partitions_for(self, topic: str) -> set[int]:
        """Partition ids of ``topic``, fetching cluster metadata if needed."""
        ...

    async def send_and_wait(
        self,
        topic: str,
        value: bytes | None = None,
        key: bytes | None = None,
        partition: int | None = None,
        timestamp_ms: int | None = None,
        headers: list[tuple[str, bytes]] | None = None,
    ) -> RecordMetadataLike:
        """Send one record and wait for the broker acknowledgement."""
        ...


@dataclass(frozen=True, slots=True)
class PublishedRecord:
    """Location of a published record."""

    topic: str
    partition: int
    offset: int


class KafkaProducer:
    """Publishes event envelopes to ADIS topics.

    - Durable: ``acks=all`` with an idempotent producer.
    - Transient failures are retried with backoff (``KAFKA_RETRY_*``); a retried send can
      still produce a duplicate, so delivery is **at-least-once** and consumers
      deduplicate by ``event_id``.
    - ``stop()`` flushes pending records before disconnecting.

    Use as an async context manager, or call ``start()``/``stop()`` around its lifetime.
    """

    def __init__(
        self,
        client_factory: Callable[[], ProducerClient],
        *,
        retry_policy: RetryPolicy,
        sleep: Sleep = asyncio.sleep,
        jitter: Jitter = default_jitter,
    ) -> None:
        self._client_factory = client_factory
        self._retry_policy = retry_policy
        self._sleep = sleep
        self._jitter = jitter
        self._client: ProducerClient | None = None

    @classmethod
    def from_settings(cls, settings: KafkaSettings, *, client_id: str | None = None) -> Self:
        """Create a producer backed by ``AIOKafkaProducer``."""

        def create_client() -> ProducerClient:
            client: ProducerClient = AIOKafkaProducer(
                **producer_options(settings, client_id=client_id)
            )
            return client

        return cls(create_client, retry_policy=RetryPolicy.from_settings(settings))

    @property
    def started(self) -> bool:
        """Whether the producer is connected."""
        return self._client is not None

    async def start(self) -> None:
        """Connect. Calling it again while started does nothing."""
        if self._client is not None:
            return
        client = self._client_factory()
        try:
            await client.start()
        except BaseException:
            # A failed start leaves sockets and tasks behind; release them before raising.
            with contextlib.suppress(Exception):
                await client.stop()
            raise
        self._client = client
        logger.info("kafka producer started", extra={"action": "kafka_producer_started"})

    async def stop(self) -> None:
        """Flush pending records and disconnect. Safe to call more than once."""
        if self._client is None:
            return
        client, self._client = self._client, None
        await client.stop()
        logger.info("kafka producer stopped", extra={"action": "kafka_producer_stopped"})

    async def partitions_for(self, topic: Topic) -> frozenset[int]:
        """Partition ids of ``topic``.

        Answered from cached cluster metadata once the topic is known, so it says nothing
        about broker reachability; use :meth:`ping` for that.

        Raises:
            RuntimeError: If the producer has not been started.
        """
        client = self._client
        if client is None:
            raise RuntimeError("KafkaProducer.start() must be called before use")
        return frozenset(await client.partitions_for(topic.value))

    async def ping(self) -> None:
        """Request cluster metadata from a broker: a real round trip, for readiness checks.

        Raises:
            RuntimeError: If the producer has not been started.
            KafkaError: If no broker answered.
        """
        client = self._client
        if client is None:
            raise RuntimeError("KafkaProducer.start() must be called before use")
        await client.client.fetch_all_metadata()

    async def publish(
        self,
        topic: Topic,
        envelope: EventEnvelope,
        *,
        key: str | None = None,
        headers: Sequence[tuple[str, bytes]] = (),
    ) -> PublishedRecord:
        """Publish one event.

        Args:
            topic: Destination topic. The dead-letter topic is reserved for
                :class:`~packages.kafka.dead_letter.DeadLetterPublisher`.
            envelope: The event.
            key: Partition key (for example a host id). Events with the same key keep
                their order.
            headers: Extra headers (e.g. provenance), appended after the envelope headers.

        Raises:
            ValueError: If ``topic`` is the dead-letter topic.
            PublishError: If the record could not be published after all retries.
        """
        if topic is Topic.DEADLETTER:
            raise ValueError("publish to the dead-letter topic through DeadLetterPublisher")
        record = await self.send_raw(
            topic,
            serialize_envelope(envelope),
            key=encode_key(key),
            headers=[*envelope_headers(envelope), *headers],
        )
        logger.debug(
            "event published",
            extra={
                "action": "kafka_event_published",
                "topic": topic.value,
                "event_id": str(envelope.event_id),
                "trace_id": envelope.trace_id,
            },
        )
        return record

    async def send_raw(
        self,
        topic: Topic,
        value: bytes | None,
        *,
        key: bytes | None,
        headers: Sequence[tuple[str, bytes]],
    ) -> PublishedRecord:
        """Send pre-serialized bytes with retries. Prefer :meth:`publish` for events.

        Raises:
            RuntimeError: If the producer has not been started.
            PublishError: If the record could not be published after all retries.
        """
        client = self._client
        if client is None:
            raise RuntimeError("KafkaProducer.start() must be called before publishing")

        async def send() -> RecordMetadataLike:
            return await client.send_and_wait(
                topic.value, value=value, key=key, headers=list(headers)
            )

        def log_retry(attempt: int, error: Exception, delay: float) -> None:
            logger.warning(
                "kafka publish failed; retrying",
                extra={
                    "action": "kafka_publish_retry",
                    "topic": topic.value,
                    "attempt": attempt,
                    "error_type": type(error).__name__,
                    "retry_in_ms": round(delay * 1000),
                },
            )

        try:
            metadata = await retry_async(
                send,
                policy=self._retry_policy,
                is_retriable=is_retriable_kafka_error,
                on_retry=log_retry,
                sleep=self._sleep,
                jitter=self._jitter,
            )
        except RetryError as failure:
            raise PublishError(topic.value, failure.attempts) from failure.last_error
        return PublishedRecord(topic.value, metadata.partition, metadata.offset)

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.stop()
