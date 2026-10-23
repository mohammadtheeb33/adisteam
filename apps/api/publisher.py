"""Hand-off of accepted events to Kafka."""

import asyncio
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol, Self

from aiokafka.errors import KafkaError

from apps.api.settings import ApiServiceSettings
from packages.events.canonical import AnyCanonicalEvent, to_envelope
from packages.kafka import (
    HEADER_INGEST_CLIENT,
    HEADER_INGEST_HOST_SCOPE,
    HEADER_REQUEST_ID,
    HostScope,
    KafkaProducer,
    PublishError,
    RetryPolicy,
    telemetry_topic,
)

__all__ = [
    "HEADER_INGEST_CLIENT",
    "HEADER_INGEST_HOST_SCOPE",
    "HEADER_REQUEST_ID",
    "EventPublisher",
    "IngestContext",
    "KafkaEventPublisher",
    "PublishUnavailableError",
]

logger = logging.getLogger(__name__)

DEFAULT_CONNECT_BACKOFF: Final = RetryPolicy(
    max_attempts=1, initial_backoff_seconds=0.5, max_backoff_seconds=30.0
)


@dataclass(frozen=True, slots=True)
class IngestContext:
    """Provenance of a submission, recorded as Kafka headers."""

    client_id: str
    request_id: str | None
    host_scope: HostScope = "unbound"


class PublishUnavailableError(Exception):
    """Events could not be enqueued in time; the client should retry."""


class EventPublisher(Protocol):
    """Durably enqueues accepted canonical events."""

    async def start(self) -> None:
        """Connect; called once at application start-up."""
        ...

    async def stop(self) -> None:
        """Flush and disconnect; called once at shutdown."""
        ...

    async def ready(self) -> bool:
        """Whether events can currently be enqueued."""
        ...

    async def publish(self, events: Sequence[AnyCanonicalEvent], context: IngestContext) -> None:
        """Enqueue every event, or raise :class:`PublishUnavailableError`."""
        ...


class KafkaEventPublisher:
    """Publishes canonical events to their telemetry topics.

    - Each event travels in an ``EventEnvelope`` on ``telemetry_topic(category)``, keyed
      by ``host_id`` so a host's events stay ordered.
    - ``publish`` returns once the broker acknowledged every record (``acks=all``), within
      ``timeout_seconds``. Records are sent concurrently so the producer can batch them.
    - If Kafka is unreachable at start-up, the API still starts: the connection is
      retried in the background (``connect_backoff``), ``ready()`` is ``False`` and
      ``publish`` raises :class:`PublishUnavailableError` (``503``) until it succeeds.
    """

    def __init__(
        self,
        producer: KafkaProducer,
        *,
        producer_name: str,
        timeout_seconds: float,
        connect_backoff: RetryPolicy = DEFAULT_CONNECT_BACKOFF,
    ) -> None:
        self._producer = producer
        self._producer_name = producer_name
        self._timeout_seconds = timeout_seconds
        self._connect_backoff = connect_backoff
        self._connecting: asyncio.Task[None] | None = None

    @classmethod
    def from_settings(cls, settings: ApiServiceSettings) -> Self:
        """Producer named after ``APP_NAME``, bounded by ``API_PUBLISH_TIMEOUT_SECONDS``."""
        return cls(
            KafkaProducer.from_settings(settings, client_id=settings.app_name),
            producer_name=settings.app_name,
            timeout_seconds=settings.api_publish_timeout_seconds,
            connect_backoff=RetryPolicy.from_settings(settings),
        )

    async def start(self) -> None:
        """Connect the producer, or keep trying in the background if Kafka is down."""
        try:
            await self._producer.start()
        except (KafkaError, OSError) as error:
            logger.warning(
                "kafka unavailable at start-up; connecting in the background",
                extra={"action": "api_kafka_unavailable", "error_type": type(error).__name__},
            )
            self._connecting = asyncio.create_task(self._connect_in_background())

    async def _connect_in_background(self) -> None:
        attempt = 0
        while True:
            attempt += 1
            await asyncio.sleep(self._connect_backoff.backoff_seconds(min(attempt, 32)))
            try:
                await self._producer.start()
            except (KafkaError, OSError) as error:
                logger.warning(
                    "kafka still unavailable; retrying",
                    extra={
                        "action": "api_kafka_connect_retry",
                        "attempt": attempt,
                        "error_type": type(error).__name__,
                    },
                )
                continue
            logger.info("kafka connected", extra={"action": "api_kafka_connected"})
            return

    async def stop(self) -> None:
        """Stop connecting, flush pending records and disconnect."""
        if self._connecting is not None:
            self._connecting.cancel()
            await asyncio.gather(self._connecting, return_exceptions=True)
        await self._producer.stop()

    async def ready(self) -> bool:
        """Whether the producer is connected and a broker answers a metadata request."""
        if not self._producer.started:
            return False
        try:
            async with asyncio.timeout(self._timeout_seconds):
                await self._producer.ping()
        except (KafkaError, TimeoutError, OSError) as error:
            logger.warning(
                "kafka readiness check failed",
                extra={"action": "api_readiness_kafka", "error_type": type(error).__name__},
            )
            return False
        return True

    async def publish(self, events: Sequence[AnyCanonicalEvent], context: IngestContext) -> None:
        """Enqueue ``events`` and wait for the broker acknowledgements."""
        if not self._producer.started:
            raise PublishUnavailableError("not connected to Kafka yet")
        headers = [
            (HEADER_INGEST_CLIENT, context.client_id.encode()),
            (HEADER_INGEST_HOST_SCOPE, context.host_scope.encode()),
        ]
        if context.request_id is not None:
            headers.append((HEADER_REQUEST_ID, context.request_id.encode()))
        try:
            async with asyncio.timeout(self._timeout_seconds), asyncio.TaskGroup() as group:
                for event in events:
                    group.create_task(self._publish_one(event, headers))
        except TimeoutError as error:
            raise PublishUnavailableError("timed out enqueuing events") from error
        except ExceptionGroup as failures:
            _, unexpected = failures.split(PublishError)
            if unexpected is not None:
                raise
            raise PublishUnavailableError("the broker rejected events") from failures

    async def _publish_one(
        self, event: AnyCanonicalEvent, headers: list[tuple[str, bytes]]
    ) -> None:
        await self._producer.publish(
            telemetry_topic(event.category),
            to_envelope(event, producer=self._producer_name),
            key=event.host_id,
            headers=headers,
        )
