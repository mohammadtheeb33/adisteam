"""Application factory of the ingestion API."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version
from typing import Any

from fastapi import FastAPI
from pydantic import TypeAdapter

from apps.api.auth import TokenAuthenticator
from apps.api.errors import install_error_handlers, internal_error_body
from apps.api.metrics import ApiMetrics
from apps.api.publisher import EventPublisher, KafkaEventPublisher
from apps.api.rate_limit import RateLimiter, RedisRateLimiter, TokenBucketRateLimiter
from apps.api.routes import events, health
from apps.api.routes import metrics as metrics_routes
from apps.api.services import ApiServices
from apps.api.settings import ApiServiceSettings
from packages.events.canonical import v1
from packages.observability import RequestContextMiddleware
from packages.observability.metrics import HttpMetricsMiddleware
from packages.redis import RedisClient

logger = logging.getLogger(__name__)

DESCRIPTION = """
Entry point for telemetry into ADIS.

Events are validated against the canonical security event schema, stamped with
`received_at`, and enqueued to Kafka; a `202` means the broker has acknowledged them.
Detection happens asynchronously downstream.

* Authenticate with `Authorization: Bearer <token>` (per-client tokens).
* Every response carries `X-Request-ID` and `X-Trace-ID`; send a W3C `traceparent` to
  continue an existing trace.
* Rate limits are per client and counted in events; see the `RateLimit-*` headers.
* Errors share one envelope: `{"error": {"code", "message", "request_id", "details"}}`.
"""


class IngestionApi(FastAPI):
    """FastAPI with the canonical event schemas published in OpenAPI components."""

    def __init__(self, *, max_batch_size: int, **options: Any) -> None:  # noqa: ANN401
        super().__init__(**options)
        self._max_batch_size = max_batch_size

    def openapi(self) -> dict[str, Any]:
        """OpenAPI document, including ``CanonicalEvent`` and ``EventBatch`` schemas."""
        if self.openapi_schema is None:
            document = super().openapi()
            schemas = document.setdefault("components", {}).setdefault("schemas", {})
            schemas.update(_canonical_schemas(self._max_batch_size))
        return self.openapi_schema or {}


def create_app(
    settings: ApiServiceSettings,
    *,
    publisher: EventPublisher | None = None,
    rate_limiter: RateLimiter | None = None,
    redis: RedisClient | None = None,
    metrics: ApiMetrics | None = None,
) -> FastAPI:
    """Build the ingestion API.

    Args:
        settings: Service configuration.
        publisher: Where accepted events go; defaults to Kafka. Started and stopped with
            the application.
        rate_limiter: Per-client limiter. Defaults to Redis-backed limiting when
            ``redis`` is given (``API_RATE_LIMIT_BACKEND=redis``), falling back to an
            in-process token bucket, and to the token bucket alone otherwise.
        redis: Shared Redis for rate limiting; checked by ``/ready`` and closed at
            shutdown.
        metrics: Prometheus metrics; a fresh registry by default.
    """
    metrics = metrics or ApiMetrics()
    if rate_limiter is None:
        local = TokenBucketRateLimiter.from_settings(settings)
        rate_limiter = (
            local
            if redis is None
            else RedisRateLimiter(
                redis,
                capacity=settings.api_rate_limit_events,
                window_seconds=settings.api_rate_limit_window_seconds,
                fallback=local,
                on_fallback=metrics.rate_limit_fallbacks.inc,
            )
        )
    services = ApiServices(
        settings=settings,
        publisher=publisher or KafkaEventPublisher.from_settings(settings),
        rate_limiter=rate_limiter,
        authenticator=TokenAuthenticator(
            settings.ingest_credentials(), settings.ingest_client_hosts()
        ),
        metrics=metrics,
        redis=redis,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await services.publisher.start()
        logger.info("ingestion api started", extra={"action": "api_started"})
        try:
            yield
        finally:
            await services.publisher.stop()
            if services.redis is not None:
                await services.redis.close()
            logger.info("ingestion api stopped", extra={"action": "api_stopped"})

    app = IngestionApi(
        title="ADIS Ingestion API",
        version=version("adis"),
        description=DESCRIPTION,
        lifespan=lifespan,
        max_batch_size=settings.api_max_batch_size,
    )
    app.state.services = services
    install_error_handlers(app)
    app.include_router(health.router)
    app.include_router(events.router)
    if settings.prometheus_enabled:
        app.include_router(metrics_routes.router)
    app.add_middleware(HttpMetricsMiddleware, metrics=metrics.http)
    app.add_middleware(
        RequestContextMiddleware,
        quiet_paths={"/health", "/ready", "/metrics"},
        error_body=internal_error_body,
    )
    return app


def _canonical_schemas(max_batch_size: int) -> dict[str, Any]:
    """Component schemas of the canonical event union and of a batch body."""
    union = TypeAdapter(v1.AnyCanonicalEvent).json_schema(
        ref_template="#/components/schemas/{model}"
    )
    schemas: dict[str, Any] = union.pop("$defs", {})
    schemas["CanonicalEvent"] = {**union, "title": "CanonicalEvent"}
    schemas["EventBatch"] = {
        "title": "EventBatch",
        "type": "object",
        "additionalProperties": False,
        "required": ["events"],
        "properties": {
            "events": {
                "type": "array",
                "minItems": 1,
                "maxItems": max_batch_size,
                "items": {"$ref": events.CANONICAL_EVENT_REF},
            }
        },
    }
    return schemas
