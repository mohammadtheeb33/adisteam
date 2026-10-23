"""Request correlation for FastAPI (any ASGI application).

Usage::

    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)
"""

import logging
import time
from collections.abc import Callable, Collection
from typing import Final

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from packages.observability.context import (
    current_request_id,
    is_valid_request_id,
    log_context,
    new_request_id,
    new_trace_id,
    trace_id_from_traceparent,
)

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER: Final = "X-Request-ID"
TRACE_ID_HEADER: Final = "X-Trace-ID"
TRACEPARENT_HEADER: Final = "traceparent"
_SERVER_ERROR: Final = 500
_INTERNAL_ERROR_JSON: Final = b'{"detail":"Internal Server Error"}'


class RequestContextMiddleware:
    """Bind ``request_id`` and ``trace_id`` for every HTTP and WebSocket request.

    - ``request_id``: the client's ``X-Request-ID`` when it is safe
      (1 to 128 of ``[A-Za-z0-9._:-]``), otherwise a new random id.
    - ``trace_id``: continued from a valid W3C ``traceparent`` header, otherwise new.

    Both are bound with :func:`~packages.observability.log_context` for the whole request,
    so logs and any ``EventEnvelope`` created while handling it carry them. They are
    returned as ``X-Request-ID`` and ``X-Trace-ID`` response headers.

    One access-log record is written per HTTP request with ``method``, ``path`` (never the
    query string), ``status_code`` and ``latency_ms``. Request headers are never logged.

    If the application raises before responding, a generic ``500`` JSON response is sent
    (still carrying the correlation headers, never the exception details) and the error
    is re-raised to the server.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        quiet_paths: Collection[str] = (),
        error_body: Callable[[str], bytes] | None = None,
    ) -> None:
        """Wrap ``app``.

        Args:
            app: The ASGI application.
            quiet_paths: Paths (e.g. health checks) whose access logs use DEBUG level.
            error_body: Builds the JSON body of the generic 500 from the request id, so
                applications can keep their own error format. It must not include
                exception details.
        """
        self._app = app
        self._quiet_paths = frozenset(quiet_paths)
        self._error_body = error_body or _default_error_body

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle one ASGI connection."""
        if scope["type"] not in {"http", "websocket"}:
            await self._app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        supplied_request_id = headers.get(REQUEST_ID_HEADER)
        request_id = (
            supplied_request_id if is_valid_request_id(supplied_request_id) else new_request_id()
        )
        trace_id = trace_id_from_traceparent(headers.get(TRACEPARENT_HEADER)) or new_trace_id()
        status_code = _SERVER_ERROR
        response_started = False

        async def send_with_correlation(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                response_headers = MutableHeaders(scope=message)
                response_headers[REQUEST_ID_HEADER] = request_id
                response_headers[TRACE_ID_HEADER] = trace_id
            await send(message)

        started = time.perf_counter()
        with log_context(request_id=request_id, trace_id=trace_id):
            try:
                await self._app(scope, receive, send_with_correlation)
            except Exception:
                self._log_access(scope, _SERVER_ERROR, started, failed=True)
                if scope["type"] == "http" and not response_started:
                    # Answer while the correlation ids are still known. The body never
                    # contains exception details. The error is re-raised so the server
                    # still reports it; Starlette sees the response has started and
                    # does not send a second one.
                    for message in _internal_error_response(self._error_body(request_id)):
                        await send_with_correlation(message)
                raise
            if scope["type"] == "http":
                self._log_access(scope, status_code, started, failed=False)

    def _log_access(self, scope: Scope, status_code: int, started: float, *, failed: bool) -> None:
        path = scope.get("path", "")
        if failed:
            level = logging.ERROR
        elif path in self._quiet_paths:
            level = logging.DEBUG
        elif status_code >= _SERVER_ERROR:
            level = logging.ERROR
        else:
            level = logging.INFO
        logger.log(
            level,
            "http request failed" if failed else "http request completed",
            exc_info=failed,
            extra={
                "action": "http_request",
                "method": scope.get("method", "WEBSOCKET"),
                "path": path,
                "status_code": status_code,
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )


def _default_error_body(request_id: str) -> bytes:
    return _INTERNAL_ERROR_JSON


def _internal_error_response(payload: bytes) -> tuple[Message, Message]:
    """Fresh ASGI messages for a generic 500 (headers are mutated when sent)."""
    start: Message = {
        "type": "http.response.start",
        "status": _SERVER_ERROR,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ],
    }
    body: Message = {"type": "http.response.body", "body": payload}
    return start, body


async def get_request_id() -> str | None:
    """FastAPI dependency returning the current request id: ``Depends(get_request_id)``."""
    return current_request_id()
