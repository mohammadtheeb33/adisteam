"""Prometheus metrics: per-service registries and HTTP request instrumentation.

Each service owns a :class:`prometheus_client.CollectorRegistry` (no process-global
registry), exposes it at ``/metrics`` when ``PROMETHEUS_ENABLED`` is true, and never
labels metrics with unbounded values such as client ids, event ids or raw paths.
"""

import time
from typing import Final

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram
from prometheus_client import generate_latest as _generate_latest
from starlette.types import ASGIApp, Message, Receive, Scope, Send

LATENCY_BUCKETS: Final = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
METRICS_CONTENT_TYPE: Final = CONTENT_TYPE_LATEST


def render(registry: CollectorRegistry) -> bytes:
    """The registry in the Prometheus text exposition format."""
    return _generate_latest(registry)


class HttpMetrics:
    """Request counts and durations by method, route template and status."""

    def __init__(self, registry: CollectorRegistry, *, namespace: str) -> None:
        self.requests = Counter(
            f"{namespace}_http_requests_total",
            "HTTP requests by method, route template and status code.",
            ["method", "route", "status"],
            registry=registry,
        )
        self.duration = Histogram(
            f"{namespace}_http_request_duration_seconds",
            "HTTP request duration by method and route template.",
            ["method", "route"],
            buckets=LATENCY_BUCKETS,
            registry=registry,
        )


class HttpMetricsMiddleware:
    """Pure ASGI middleware recording :class:`HttpMetrics` for every HTTP request.

    The route label is the matched route template (``/api/v1/events``); unmatched
    requests share one ``unmatched`` label, so scanners cannot inflate cardinality.
    """

    def __init__(self, app: ASGIApp, *, metrics: HttpMetrics) -> None:
        self._app = app
        self._metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Serve the request, then record its route, status and duration."""
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        started = time.perf_counter()
        status = 500

        async def record_status(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self._app(scope, receive, record_status)
        finally:
            route = getattr(scope.get("route"), "path", None) or "unmatched"
            method = str(scope.get("method", "GET"))
            self._metrics.requests.labels(method, route, str(status)).inc()
            self._metrics.duration.labels(method, route).observe(time.perf_counter() - started)
