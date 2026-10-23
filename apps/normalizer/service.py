"""Normalizer service: wires Kafka, the database, the pipeline and the health listener."""

import asyncio
import contextlib
import json
import logging
from typing import Final, Self

from aiokafka.errors import KafkaError

from apps.normalizer.metrics import NormalizerMetrics
from apps.normalizer.pipeline import NormalizationPipeline
from apps.normalizer.publisher import KafkaNormalizedEventPublisher
from apps.normalizer.settings import NormalizerServiceSettings
from apps.normalizer.store import DatabaseEventStore
from packages.database import Database
from packages.kafka import (
    RAW_TELEMETRY_TOPICS,
    DeadLetterPublisher,
    KafkaBatchConsumer,
    KafkaProducer,
    RetryPolicy,
)
from packages.observability.health_server import (
    DEFAULT_ROUTE_TIMEOUT_SECONDS,
    HealthServer,
    HttpResult,
)
from packages.observability.metrics import METRICS_CONTENT_TYPE, render

logger = logging.getLogger(__name__)

DEFAULT_CONNECT_BACKOFF: Final = RetryPolicy(
    max_attempts=1, initial_backoff_seconds=0.5, max_backoff_seconds=30.0
)


_READINESS_MARGIN_SECONDS: Final = 2.0


class NormalizerService:
    """Consumes the raw telemetry topics with :class:`NormalizationPipeline`.

    - One producer serves both the normalized output and the dead-letter topic.
    - Kafka may be down at start-up: the producer and the consumer keep retrying until
      it is reachable (or a stop is requested), instead of exiting.
    - ``/health`` (process alive), ``/ready`` (Kafka consumer and producer connected,
      database answering) and ``/metrics`` are served on
      ``NORMALIZER_HEALTH_HOST:NORMALIZER_HEALTH_PORT``.
    - On stop, the batch in progress is finished; if it is waiting for an outage to
      end, it is abandoned uncommitted and redelivered after restart.
    """

    def __init__(
        self,
        *,
        consumer: KafkaBatchConsumer,
        pipeline: NormalizationPipeline,
        producer: KafkaProducer,
        database: Database,
        stopping: asyncio.Event,
        metrics: NormalizerMetrics | None = None,
        health_host: str | None = None,
        health_port: int = 0,
        health_route_timeout_seconds: float = DEFAULT_ROUTE_TIMEOUT_SECONDS,
        expose_metrics: bool = True,
        connect_backoff: RetryPolicy = DEFAULT_CONNECT_BACKOFF,
    ) -> None:
        self.pipeline = pipeline
        self._consumer = consumer
        self._producer = producer
        self._database = database
        self._stopping = stopping
        self._metrics = metrics
        self._connect_backoff = connect_backoff
        self.health: HealthServer | None = None
        if health_host is not None:
            routes = {"/health": self._health, "/ready": self._ready}
            if metrics is not None and expose_metrics:
                routes["/metrics"] = self._metrics_page
            self.health = HealthServer(
                host=health_host,
                port=health_port,
                routes=routes,
                route_timeout_seconds=health_route_timeout_seconds,
            )

    @classmethod
    def from_settings(cls, settings: NormalizerServiceSettings) -> Self:
        """Build the service; nothing connects until :meth:`run`."""
        producer = KafkaProducer.from_settings(settings, client_id=settings.app_name)
        database = Database.from_settings(settings, application_name=settings.app_name)
        stopping = asyncio.Event()
        metrics = NormalizerMetrics()
        pipeline = NormalizationPipeline(
            store=DatabaseEventStore(database),
            publisher=KafkaNormalizedEventPublisher(
                producer,
                producer_name=settings.app_name,
                timeout_seconds=settings.normalizer_publish_timeout_seconds,
            ),
            dead_letter=DeadLetterPublisher(producer),
            consumer_group=settings.normalizer_consumer_group,
            normalizer_name=settings.app_name,
            retry_policy=RetryPolicy(
                max_attempts=settings.normalizer_max_attempts,
                initial_backoff_seconds=settings.normalizer_retry_initial_backoff_seconds,
                max_backoff_seconds=settings.normalizer_retry_max_backoff_seconds,
            ),
            stopping=stopping,
            max_future_skew_seconds=settings.normalizer_max_future_skew_seconds,
            log_events=settings.log_event_lifecycle,
            metrics=metrics,
        )
        consumer = KafkaBatchConsumer.from_settings(
            settings,
            topics=RAW_TELEMETRY_TOPICS,
            group_id=settings.normalizer_consumer_group,
            client_id=settings.app_name,
            poll_timeout_ms=settings.normalizer_poll_timeout_ms,
            max_records=settings.normalizer_batch_max_records,
        )
        return cls(
            consumer=consumer,
            pipeline=pipeline,
            producer=producer,
            database=database,
            stopping=stopping,
            metrics=metrics,
            health_host=settings.normalizer_health_host
            if settings.normalizer_health_port
            else None,
            health_port=settings.normalizer_health_port,
            # /ready waits on the database health check, which has its own bound.
            health_route_timeout_seconds=settings.db_health_check_timeout_seconds
            + _READINESS_MARGIN_SECONDS,
            expose_metrics=settings.prometheus_enabled,
            connect_backoff=RetryPolicy(
                max_attempts=1,
                initial_backoff_seconds=settings.normalizer_retry_initial_backoff_seconds,
                max_backoff_seconds=settings.normalizer_retry_max_backoff_seconds,
            ),
        )

    async def run(self, stop: asyncio.Event) -> None:
        """Consume until ``stop`` is set, then shut down cleanly.

        Raises:
            Exception: An unrecoverable consumer or pipeline error; nothing uncommitted
                is lost, because it is redelivered after restart.
        """
        if self.health is not None:
            await self.health.start()
        try:
            if not await self._connect_producer(stop):
                return
            consuming = asyncio.create_task(self._consumer.run(self.pipeline))
            stopped = asyncio.create_task(stop.wait())
            await asyncio.wait({consuming, stopped}, return_when=asyncio.FIRST_COMPLETED)
            if not consuming.done():
                self._stopping.set()
                self._consumer.request_stop()
            stopped.cancel()
            await consuming
        finally:
            self._stopping.set()
            await self._producer.stop()
            await self._database.dispose()
            if self.health is not None:
                await self.health.stop()
            stats = self.pipeline.stats
            logger.info(
                "normalizer stopped",
                extra={
                    "action": "normalizer_stopped",
                    "records": stats.records,
                    "published": stats.published,
                    "duplicates": stats.duplicates,
                    "conflicts": stats.conflicts,
                    "dead_lettered": stats.dead_lettered,
                },
            )

    async def _connect_producer(self, stop: asyncio.Event) -> bool:
        """Start the producer, retrying while Kafka is unreachable; ``False`` if stopped."""
        attempt = 0
        while not stop.is_set():
            try:
                await self._producer.start()
            except (KafkaError, OSError) as error:
                attempt += 1
                delay = self._connect_backoff.backoff_seconds(min(attempt, 32))
                logger.warning(
                    "kafka unavailable; retrying the producer connection",
                    extra={
                        "action": "normalizer_kafka_connect_retry",
                        "attempt": attempt,
                        "error_type": type(error).__name__,
                        "retry_in_ms": round(delay * 1000),
                    },
                )
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=delay)
                continue
            return True
        return False

    async def _health(self) -> HttpResult:
        return HttpResult(200, b'{"status": "ok"}')

    async def _ready(self) -> HttpResult:
        database = await self._database.health_check()
        checks = {
            "kafka_consumer": "ok" if self._consumer.connected else "unavailable",
            "kafka_producer": "ok" if self._producer.started else "unavailable",
            "database": "ok" if database.healthy else "unavailable",
        }
        ready = all(state == "ok" for state in checks.values())
        body = {"status": "ready" if ready else "not_ready", "checks": checks}
        return HttpResult(200 if ready else 503, json.dumps(body).encode())

    async def _metrics_page(self) -> HttpResult:
        metrics = self._metrics
        if metrics is None:
            return HttpResult(404, b'{"error": "not found"}')
        metrics.set_lag(self._consumer.lag)
        return HttpResult(200, render(metrics.registry), METRICS_CONTENT_TYPE)
