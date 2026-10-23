"""Publication of normalized events to ``adis.security.events``."""

import asyncio
from collections.abc import Sequence
from typing import Protocol

from apps.normalizer.normalization import NormalizedEvent
from packages.events.canonical import to_envelope
from packages.kafka import NORMALIZED_EVENTS_TOPIC, KafkaProducer


class NormalizedEventPublisher(Protocol):
    """Durably publishes normalized events, or raises."""

    async def publish(self, events: Sequence[NormalizedEvent]) -> None:
        """Publish every event and wait for the broker acknowledgements."""
        ...


class KafkaNormalizedEventPublisher:
    """Publishes normalized events in ``EventEnvelope`` form.

    - Records are keyed by ``host_id`` (so a host's events stay ordered within a
      partition) and carry the ingestion provenance headers of their source record.
    - ``publish`` returns once the broker acknowledged every record (``acks=all``). It
      raises ``TimeoutError`` after ``timeout_seconds``, or the publish failures (an
      ``ExceptionGroup`` of ``PublishError``) otherwise.
    """

    def __init__(
        self, producer: KafkaProducer, *, producer_name: str, timeout_seconds: float
    ) -> None:
        self._producer = producer
        self._producer_name = producer_name
        self._timeout_seconds = timeout_seconds

    async def publish(self, events: Sequence[NormalizedEvent]) -> None:
        """Publish ``events`` concurrently so the producer can batch them."""
        if not events:
            return
        async with asyncio.timeout(self._timeout_seconds), asyncio.TaskGroup() as group:
            for normalized in events:
                group.create_task(
                    self._producer.publish(
                        NORMALIZED_EVENTS_TOPIC,
                        to_envelope(normalized.event, producer=self._producer_name),
                        key=normalized.event.host_id,
                        headers=normalized.provenance.forwarded_headers(),
                    )
                )
