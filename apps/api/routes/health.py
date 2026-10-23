"""Liveness and readiness probes (unauthenticated, for orchestrators)."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from apps.api.schemas import HealthResponse, ReadinessResponse
from apps.api.services import ApiServices, get_services

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    summary="Liveness probe",
    description="Always 200 while the process serves requests. Checks no dependencies.",
)
async def health() -> HealthResponse:
    """Report that the process is alive."""
    return HealthResponse()


@router.get(
    "/ready",
    summary="Readiness probe",
    description=(
        "200 when events can be enqueued (Kafka reachable); 503 otherwise. When Redis rate "
        "limiting is enabled, its state is reported too, but a Redis outage alone does not "
        "make the API unready (limiting falls back to per-process budgets)."
    ),
    responses={503: {"model": ReadinessResponse, "description": "Not ready"}},
)
async def ready(services: Annotated[ApiServices, Depends(get_services)]) -> JSONResponse:
    """Report whether accepted events can currently be enqueued."""
    kafka_ok = await services.publisher.ready()
    checks: dict[str, Literal["ok", "unavailable"]] = {"kafka": "ok" if kafka_ok else "unavailable"}
    if services.redis is not None:
        redis_health = await services.redis.health_check()
        checks["redis"] = "ok" if redis_health.healthy else "unavailable"
    body = ReadinessResponse(status="ready" if kafka_ok else "not_ready", checks=checks)
    return JSONResponse(status_code=200 if kafka_ok else 503, content=body.model_dump())
