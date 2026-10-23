"""HTTP client for the ADIS ingestion API.

Responses are mapped to a :class:`SendResult` rather than raised, so the sender can
decide per outcome whether to acknowledge, quarantine, split or retry.
"""

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import TracebackType
from typing import Final, Protocol, Self
from uuid import uuid4

import httpx2
from pydantic import SecretStr

logger = logging.getLogger(__name__)

EVENTS_PATH: Final = "/api/v1/events"
BATCH_PATH: Final = "/api/v1/events/batch"


class Outcome(StrEnum):
    """What happened to a request."""

    DELIVERED = "delivered"
    """202: accepted events are durable on the server; some may be rejected."""
    REJECTED = "rejected"
    """422: the events are invalid and will never be accepted."""
    TOO_LARGE = "too_large"
    """413: the request is too big; split it."""
    MALFORMED = "malformed"
    """400: the server could not decode the body; isolate the bad event."""
    RATE_LIMITED = "rate_limited"
    """429: wait for ``retry_after``."""
    UNAUTHORIZED = "unauthorized"
    """401/403: the token is wrong; retrying cannot help until it is fixed."""
    MISCONFIGURED = "misconfigured"
    """Other 4xx (404, 405, 415...): the server URL or client is wrong."""
    UNAVAILABLE = "unavailable"
    """5xx, network failure, timeout or unreadable reply: retry later."""


@dataclass(frozen=True, slots=True)
class SendResult:
    """Outcome of one request.

    Attributes:
        outcome: Classification of the response.
        status: HTTP status, if a response was received.
        code: ADIS error code, if any.
        accepted: Indices (within the request) the server accepted.
        rejected: ``{index: reason}`` of events the server rejected permanently.
        retry_after: Seconds the server asked to wait, if any.
        request_id: The ``X-Request-ID`` sent with the request.
        detail: Short description for logs; never contains event data.
    """

    outcome: Outcome
    status: int | None = None
    code: str | None = None
    accepted: frozenset[int] = frozenset()
    rejected: Mapping[int, str] = field(default_factory=dict)
    retry_after: float | None = None
    request_id: str | None = None
    detail: str = ""


class IngestSender(Protocol):
    """What the sender and registration need from a client."""

    async def send_batch(self, payloads: Sequence[bytes]) -> SendResult:
        """Send serialized events as one batch."""
        ...

    async def send_event(self, payload: bytes) -> SendResult:
        """Send one serialized event."""
        ...


class IngestApiClient:
    """Sends serialized canonical events with the agent's bearer token."""

    def __init__(
        self,
        base_url: str,
        token: SecretStr,
        *,
        timeout_seconds: float,
        user_agent: str,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx2.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
            transport=transport,
            headers={
                "Authorization": f"Bearer {token.get_secret_value()}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": user_agent,
            },
        )

    async def send_batch(self, payloads: Sequence[bytes]) -> SendResult:
        """POST a batch body built from already-serialized events."""
        body = b'{"events":[' + b",".join(payloads) + b"]}"
        return await self._post(BATCH_PATH, body, count=len(payloads), batch=True)

    async def send_event(self, payload: bytes) -> SendResult:
        """POST one serialized event."""
        return await self._post(EVENTS_PATH, payload, count=1, batch=False)

    async def close(self) -> None:
        """Close connections."""
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()

    async def _post(self, path: str, body: bytes, *, count: int, batch: bool) -> SendResult:
        request_id = uuid4().hex
        try:
            response = await self._client.post(
                path, content=body, headers={"X-Request-ID": request_id}
            )
        except httpx2.TransportError as error:
            return SendResult(
                Outcome.UNAVAILABLE, request_id=request_id, detail=type(error).__name__
            )
        return _classify(response, count=count, batch=batch, request_id=request_id)


def _classify(response: httpx2.Response, *, count: int, batch: bool, request_id: str) -> SendResult:
    status = response.status_code
    body = _json(response)
    error = body.get("error") if isinstance(body, dict) else None
    raw_code = error.get("code") if isinstance(error, dict) else None
    code = raw_code if isinstance(raw_code, str) else None
    base = SendResult(
        Outcome.UNAVAILABLE,
        status=status,
        code=code,
        retry_after=_retry_after(response.headers.get("Retry-After")),
        request_id=request_id,
        detail=code or f"http {status}",
    )

    if status == 202:
        if not isinstance(body, dict):
            return replace(base, detail="unreadable 202 body")
        if not batch:
            return replace(base, outcome=Outcome.DELIVERED, accepted=frozenset({0}))
        return replace(
            base,
            outcome=Outcome.DELIVERED,
            accepted=frozenset(_indices(body.get("accepted"))),
            rejected=_reasons(body.get("rejected"), count=count),
        )
    if status == 422:
        details = error.get("details") if isinstance(error, dict) else None
        return replace(
            base,
            outcome=Outcome.REJECTED,
            rejected=_reasons(details, count=count, default_all=code or "rejected"),
        )
    outcome = {
        413: Outcome.TOO_LARGE,
        400: Outcome.MALFORMED,
        429: Outcome.RATE_LIMITED,
        401: Outcome.UNAUTHORIZED,
        403: Outcome.UNAUTHORIZED,
    }.get(status)
    if outcome is None:
        outcome = Outcome.UNAVAILABLE if status >= 500 else Outcome.MISCONFIGURED
    return replace(base, outcome=outcome)


def _json(response: httpx2.Response) -> object:
    try:
        return response.json()
    except ValueError:
        return None


def _indices(items: object) -> list[int]:
    if not isinstance(items, list):
        return []
    return [
        item["index"]
        for item in items
        if isinstance(item, dict) and isinstance(item.get("index"), int)
    ]


def _reasons(items: object, *, count: int, default_all: str | None = None) -> dict[int, str]:
    """``{index: "code: issue; issue"}``; index-less details apply to single events."""
    reasons: dict[int, str] = {}
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        index = item.get("index")
        if index is None and count == 1:
            index = 0
        if not isinstance(index, int) or not 0 <= index < count:
            continue
        issues = item.get("issues")
        text = "; ".join(str(issue) for issue in issues) if isinstance(issues, list) else ""
        reasons[index] = f"{item.get('code', 'rejected')}: {text}".strip(": ")
    if not reasons and default_all is not None:
        reasons = dict.fromkeys(range(count), default_all)
    return reasons


def _retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return seconds if seconds >= 0 else None
