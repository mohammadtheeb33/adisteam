"""Event ingestion endpoints.

The request path does only cheap, bounded work: authenticate, bound and parse the body,
validate against the canonical schema, charge the rate limit, and enqueue to Kafka.
Detection and ML inference happen downstream, never in the request.
"""

import logging
import math
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from apps.api.auth import IngestClient
from apps.api.dependencies import enforce_rate_limit, read_json_body, require_client
from apps.api.errors import ApiError, ErrorCode, ErrorResponse, EventError
from apps.api.publisher import IngestContext, PublishUnavailableError
from apps.api.schemas import AcceptedEvent, BatchAccepted, EventAccepted
from apps.api.services import ApiServices, get_services
from packages.events.canonical import (
    AnyCanonicalEvent,
    CanonicalEventError,
    UnsupportedSchemaVersionError,
    parse_canonical_event,
)
from packages.events.canonical.v1 import MAX_EVENT_BYTES
from packages.observability import current_request_id, log_context

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/events", tags=["events"])

CANONICAL_EVENT_REF: Final = "#/components/schemas/CanonicalEvent"
EVENT_BATCH_REF: Final = "#/components/schemas/EventBatch"

Client = Annotated[IngestClient, Depends(require_client)]
Services = Annotated[ApiServices, Depends(get_services)]


def _documented(*statuses: int) -> dict[int | str, dict[str, object]]:
    descriptions = {
        400: "The body is not valid JSON.",
        401: "Missing or unknown bearer token.",
        413: "The body, the event or the batch is too large.",
        415: "Content-Type is not application/json.",
        422: "The event(s) do not match the canonical schema.",
        429: "Rate limit exceeded; see Retry-After.",
        503: "Events could not be enqueued; retry later (ingestion is idempotent).",
    }
    return {
        status: {"model": ErrorResponse, "description": descriptions[status]} for status in statuses
    }


def _json_body(ref: str, description: str) -> dict[str, object]:
    return {
        "requestBody": {
            "required": True,
            "description": description,
            "content": {"application/json": {"schema": {"$ref": ref}}},
        }
    }


@router.post(
    "",
    status_code=202,
    summary="Ingest one canonical event",
    description=(
        "Validates one canonical security event and enqueues it. `schema_version` is "
        "required. `received_at` is set by the server. `trace_id` is kept when provided, "
        "otherwise the request's trace is used."
    ),
    responses=_documented(400, 401, 413, 415, 422, 429, 503),
    openapi_extra=_json_body(CANONICAL_EVENT_REF, "A canonical security event."),
)
async def ingest_event(
    request: Request, response: Response, client: Client, services: Services
) -> EventAccepted:
    """Validate and enqueue one event."""
    started = time.perf_counter()
    settings = services.settings
    document, size = await read_json_body(request, max_bytes=settings.api_max_request_bytes)
    if size > MAX_EVENT_BYTES:
        raise ApiError(
            413,
            ErrorCode.PAYLOAD_TOO_LARGE,
            f"A canonical event may not exceed {MAX_EVENT_BYTES} bytes.",
        )
    await enforce_rate_limit(services, client, cost=1, response=response)
    try:
        event = _received_now(parse_canonical_event(_as_mapping(document)))
    except CanonicalEventError as error:
        services.metrics.events.labels("rejected").inc()
        rejection = _rejection(error, index=None)
        raise ApiError(
            422,
            rejection.code,
            "The event does not match the canonical schema.",
            details=[rejection],
        ) from None
    mismatch = _binding_mismatch(client, event, index=None)
    if mismatch is not None:
        services.metrics.events.labels("rejected").inc()
        raise ApiError(422, mismatch.code, _MISMATCH_MESSAGES[mismatch.code], details=[mismatch])
    await _publish(services, [event], client)
    services.metrics.events.labels("accepted").inc()
    _log_accepted(services, client, [event])
    _log_ingested(client, accepted=1, rejected=0, started=started)
    return EventAccepted(event_id=event.event_id, trace_id=event.trace_id)


@router.post(
    "/batch",
    status_code=202,
    summary="Ingest a batch of canonical events",
    description=(
        "Validates every event and enqueues the valid ones; invalid events are reported "
        "by index (`partially_accepted`). If no event is valid, the response is 422. "
        "Resending a whole batch after a 503 is safe: ingestion is idempotent on "
        "`event_id`. The batch costs one rate-limit unit per event."
    ),
    responses=_documented(400, 401, 413, 415, 422, 429, 503),
    openapi_extra=_json_body(EVENT_BATCH_REF, "Up to API_MAX_BATCH_SIZE canonical events."),
)
async def ingest_batch(
    request: Request, response: Response, client: Client, services: Services
) -> BatchAccepted:
    """Validate a batch and enqueue its valid events."""
    started = time.perf_counter()
    settings = services.settings
    document, _ = await read_json_body(request, max_bytes=settings.api_max_request_bytes)
    items = _batch_items(document)
    if not items:
        raise ApiError(422, ErrorCode.EMPTY_BATCH, "The batch contains no events.")
    if len(items) > settings.api_max_batch_size:
        raise ApiError(
            413,
            ErrorCode.BATCH_TOO_LARGE,
            f"A batch may contain at most {settings.api_max_batch_size} events.",
        )
    await enforce_rate_limit(services, client, cost=len(items), response=response)

    accepted: list[tuple[int, AnyCanonicalEvent]] = []
    rejected: list[EventError] = []
    for index, item in enumerate(items):
        try:
            event = _received_now(parse_canonical_event(_as_mapping(item)))
        except CanonicalEventError as error:
            rejected.append(_rejection(error, index=index))
            continue
        mismatch = _binding_mismatch(client, event, index=index)
        if mismatch is None:
            accepted.append((index, event))
        else:
            rejected.append(mismatch)
    if rejected:
        services.metrics.events.labels("rejected").inc(len(rejected))
    if not accepted:
        raise ApiError(
            422,
            ErrorCode.VALIDATION_FAILED,
            "No event in the batch matches the canonical schema.",
            details=rejected,
        )

    first_by_id: dict[UUID, AnyCanonicalEvent] = {}
    for _, event in accepted:
        first_by_id.setdefault(event.event_id, event)
    await _publish(services, list(first_by_id.values()), client)
    services.metrics.events.labels("accepted").inc(len(accepted))
    _log_accepted(services, client, list(first_by_id.values()))
    _log_ingested(client, accepted=len(accepted), rejected=len(rejected), started=started)
    return BatchAccepted(
        status="partially_accepted" if rejected else "accepted",
        accepted_count=len(accepted),
        rejected_count=len(rejected),
        accepted=[AcceptedEvent(index=index, event_id=event.event_id) for index, event in accepted],
        rejected=rejected,
    )


def _as_mapping(document: object) -> Mapping[str, object]:
    if not isinstance(document, Mapping):
        raise CanonicalEventError("event must be a JSON object")
    return document


def _batch_items(document: object) -> Sequence[object]:
    if (
        not isinstance(document, Mapping)
        or set(document) != {"events"}
        or not isinstance(document["events"], list)
    ):
        raise ApiError(
            422,
            ErrorCode.VALIDATION_FAILED,
            'The body must be an object of the form {"events": [...]}.',
        )
    events: list[object] = document["events"]
    return events


def _received_now(event: AnyCanonicalEvent) -> AnyCanonicalEvent:
    """Stamp ``received_at`` with server time.

    The value comes from the server, never the client: storage retention is keyed on
    it, so a client-chosen value could get events purged early or kept forever.
    """
    return event.model_copy(update={"received_at": datetime.now(UTC)})


def _rejection(error: CanonicalEventError, *, index: int | None) -> EventError:
    code = (
        ErrorCode.UNSUPPORTED_SCHEMA_VERSION
        if isinstance(error, UnsupportedSchemaVersionError)
        else ErrorCode.VALIDATION_FAILED
    )
    return EventError(index=index, code=code, issues=list(error.issues) or [str(error)])


async def _publish(
    services: ApiServices, events: Sequence[AnyCanonicalEvent], client: IngestClient
) -> None:
    context = IngestContext(
        client_id=client.client_id,
        request_id=current_request_id(),
        host_scope=client.host_scope,
    )
    try:
        await services.publisher.publish(events, context)
    except PublishUnavailableError as error:
        services.metrics.publish_failures.inc()
        logger.warning(
            "events could not be enqueued",
            extra={
                "action": "api_publish_failed",
                "client_id": client.client_id,
                "error_type": type(error.__cause__ or error).__name__,
                "reason": str(error),
            },
        )
        logger.debug("publish failure details", exc_info=True)
        retry_after = math.ceil(services.settings.api_publish_timeout_seconds)
        raise ApiError(
            503,
            ErrorCode.SERVICE_UNAVAILABLE,
            "Events could not be enqueued; retry later.",
            headers={"Retry-After": str(retry_after)},
        ) from None


_MISMATCH_MESSAGES = {
    ErrorCode.AGENT_MISMATCH: "The event belongs to another agent.",
    ErrorCode.HOST_MISMATCH: "The event names a host this client may not submit for.",
}


def _binding_mismatch(
    client: IngestClient, event: AnyCanonicalEvent, *, index: int | None
) -> EventError | None:
    """Reject events a bound client submits for another agent, or for a host it may not name."""
    bound = client.bound_agent_id
    if bound is not None and event.agent_id != str(bound):
        return EventError(
            index=index,
            code=ErrorCode.AGENT_MISMATCH,
            issues=["agent_id: must be the agent this client is bound to"],
        )
    if client.allowed_hosts is not None and event.host_id not in client.allowed_hosts:
        return EventError(
            index=index,
            code=ErrorCode.HOST_MISMATCH,
            issues=["host_id: must be a host this client is bound to"],
        )
    return None


def _log_accepted(
    services: ApiServices, client: IngestClient, events: Sequence[AnyCanonicalEvent]
) -> None:
    """One line per accepted event, so each event can be traced from the API onwards."""
    if not services.settings.log_event_lifecycle:
        return
    for event in events:
        with log_context(trace_id=event.trace_id, event_id=event.event_id, host_id=event.host_id):
            logger.info(
                "event accepted",
                extra={
                    "action": "api_event_accepted",
                    "client_id": client.client_id,
                    "event_type": event.event_type,
                },
            )


def _log_ingested(client: IngestClient, *, accepted: int, rejected: int, started: float) -> None:
    logger.info(
        "events ingested",
        extra={
            "action": "api_events_ingested",
            "client_id": client.client_id,
            "accepted": accepted,
            "rejected": rejected,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        },
    )
