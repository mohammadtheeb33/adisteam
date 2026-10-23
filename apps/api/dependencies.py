"""Request-level guards: authentication, rate limiting and bounded body reading."""

import logging
import math
from typing import Annotated

from fastapi import Depends, Request, Response
from fastapi.security import HTTPAuthorizationCredentials
from pydantic_core import from_json

from apps.api.auth import IngestClient, bearer_scheme
from apps.api.errors import ApiError, ErrorCode
from apps.api.services import ApiServices, get_services

logger = logging.getLogger(__name__)

JSON_MEDIA_TYPE = "application/json"


async def require_client(
    services: Annotated[ApiServices, Depends(get_services)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> IngestClient:
    """The authenticated client, or ``401``. Tokens are never logged."""
    client = (
        None
        if credentials is None
        else services.authenticator.authenticate(credentials.credentials)
    )
    if client is None:
        logger.warning(
            "ingestion request rejected",
            extra={"action": "api_auth_rejected", "reason": "missing or unknown token"},
        )
        raise ApiError(
            401,
            ErrorCode.UNAUTHORIZED,
            "A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return client


async def enforce_rate_limit(
    services: ApiServices, client: IngestClient, *, cost: int, response: Response
) -> None:
    """Charge ``cost`` events to ``client``; ``429`` when its budget is exhausted."""
    decision = await services.rate_limiter.acquire(client.client_id, cost)
    headers = decision.headers()
    if not decision.allowed:
        services.metrics.rate_limited.inc()
        logger.warning(
            "ingestion rate limit exceeded",
            extra={"action": "api_rate_limited", "client_id": client.client_id, "cost": cost},
        )
        raise ApiError(
            429,
            ErrorCode.RATE_LIMITED,
            "Rate limit exceeded; retry after the indicated delay.",
            headers={**headers, "Retry-After": str(math.ceil(decision.retry_after_seconds))},
        )
    response.headers.update(headers)


async def read_json_body(request: Request, *, max_bytes: int) -> tuple[object, int]:
    """Read and decode a JSON body of at most ``max_bytes`` bytes.

    The declared ``Content-Length`` is checked before reading, and the streamed size is
    enforced while reading, so oversized bodies are never held in memory.

    Returns:
        The decoded document and the body size in bytes.
    """
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != JSON_MEDIA_TYPE:
        raise ApiError(
            415, ErrorCode.UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json."
        )
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > max_bytes:
        raise _too_large(max_bytes)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            raise _too_large(max_bytes)
        chunks.append(chunk)
    try:
        return from_json(b"".join(chunks)), size
    except ValueError:
        raise ApiError(400, ErrorCode.INVALID_JSON, "The body is not valid JSON.") from None


def _too_large(max_bytes: int) -> ApiError:
    return ApiError(
        413, ErrorCode.PAYLOAD_TOO_LARGE, f"The body exceeds the limit of {max_bytes} bytes."
    )
