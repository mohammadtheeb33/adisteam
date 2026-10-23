"""Prometheus metrics endpoint (unauthenticated, like the probes; no secrets or ids)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response

from apps.api.services import ApiServices, get_services
from packages.observability.metrics import METRICS_CONTENT_TYPE, render

router = APIRouter(tags=["health"])


@router.get(
    "/metrics",
    summary="Prometheus metrics",
    description="Text exposition format; served only when PROMETHEUS_ENABLED is true.",
    response_class=Response,
)
async def metrics(services: Annotated[ApiServices, Depends(get_services)]) -> Response:
    """The API's metrics."""
    return Response(content=render(services.metrics.registry), media_type=METRICS_CONTENT_TYPE)
