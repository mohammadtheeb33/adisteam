"""Response models of the ingestion API (request bodies are canonical events)."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from apps.api.errors import EventError


class HealthResponse(BaseModel):
    """Liveness: the process is serving requests."""

    status: Literal["ok"] = "ok"


class ReadinessResponse(BaseModel):
    """Readiness: dependencies needed to accept events are reachable."""

    status: Literal["ready", "not_ready"]
    checks: dict[str, Literal["ok", "unavailable"]] = Field(description="Result per dependency.")


class EventAccepted(BaseModel):
    """The event was durably enqueued for processing."""

    status: Literal["accepted"] = "accepted"
    event_id: UUID
    trace_id: str


class AcceptedEvent(BaseModel):
    """One enqueued event of a batch."""

    index: int = Field(description="Position in the submitted batch.")
    event_id: UUID


class BatchAccepted(BaseModel):
    """Outcome of a batch in which at least one event was enqueued."""

    status: Literal["accepted", "partially_accepted"] = Field(
        description="partially_accepted when some events were rejected."
    )
    accepted_count: int
    rejected_count: int
    accepted: list[AcceptedEvent]
    rejected: list[EventError] = Field(description="Rejected events; fix before resending.")
