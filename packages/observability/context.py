"""Correlation context (request, trace, event, host and threat ids) for logs and events.

Values live in ``contextvars``, so they follow the current asyncio task: set them for the
duration of a request or of an event being handled, and every log record and every
``EventEnvelope`` created inside that scope picks them up.
"""

import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Final, TypeGuard
from uuid import UUID, uuid4

TRACE_ID_PATTERN: Final = r"^[0-9a-f]{32}$"
REQUEST_ID_PATTERN: Final = r"^[A-Za-z0-9._:-]{1,128}$"

_TRACE_ID: Final = re.compile(TRACE_ID_PATTERN)
_REQUEST_ID: Final = re.compile(REQUEST_ID_PATTERN)
_TRACEPARENT: Final = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace_id>[0-9a-f]{32})-(?P<parent_id>[0-9a-f]{16})"
    r"-(?P<flags>[0-9a-f]{2})(?:-.*)?$"
)
_ALL_ZERO_TRACE_ID: Final = "0" * 32
_ALL_ZERO_PARENT_ID: Final = "0" * 16

_request_id: ContextVar[str | None] = ContextVar("adis_request_id", default=None)
_trace_id: ContextVar[str | None] = ContextVar("adis_trace_id", default=None)
_event_id: ContextVar[str | None] = ContextVar("adis_event_id", default=None)
_host_id: ContextVar[str | None] = ContextVar("adis_host_id", default=None)
_threat_id: ContextVar[str | None] = ContextVar("adis_threat_id", default=None)


@dataclass(frozen=True, slots=True)
class LogContext:
    """Snapshot of the correlation ids bound to the current task."""

    request_id: str | None = None
    trace_id: str | None = None
    event_id: str | None = None
    host_id: str | None = None
    threat_id: str | None = None


def new_trace_id() -> str:
    """Return a random W3C Trace Context trace id (32 lowercase hex characters)."""
    return secrets.token_hex(16)


def new_request_id() -> str:
    """Return a random request id (32 lowercase hex characters)."""
    return uuid4().hex


def is_valid_trace_id(value: str | None) -> TypeGuard[str]:
    """Whether ``value`` is a W3C trace id (lowercase hex, not all zeros)."""
    return value is not None and bool(_TRACE_ID.match(value)) and value != _ALL_ZERO_TRACE_ID


def is_valid_request_id(value: str | None) -> TypeGuard[str]:
    """Whether a client-supplied request id is safe to adopt (1-128 of ``[A-Za-z0-9._:-]``).

    Anything else is replaced, which also prevents log injection through the header.
    """
    return value is not None and bool(_REQUEST_ID.match(value))


def trace_id_from_traceparent(header: str | None) -> str | None:
    """Extract the trace id from a W3C ``traceparent`` header, or ``None`` if invalid."""
    if header is None:
        return None
    match = _TRACEPARENT.match(header.strip())
    if match is None or match["version"] == "ff" or match["parent_id"] == _ALL_ZERO_PARENT_ID:
        return None
    trace_id = match["trace_id"]
    return trace_id if is_valid_trace_id(trace_id) else None


def current_log_context() -> LogContext:
    """The correlation ids bound to the current task."""
    return LogContext(
        request_id=_request_id.get(),
        trace_id=_trace_id.get(),
        event_id=_event_id.get(),
        host_id=_host_id.get(),
        threat_id=_threat_id.get(),
    )


def current_request_id() -> str | None:
    """The request id bound to the current task, if any."""
    return _request_id.get()


def current_trace_id() -> str | None:
    """The trace id bound to the current task, if any."""
    return _trace_id.get()


@contextmanager
def log_context(
    *,
    request_id: str | None = None,
    trace_id: str | None = None,
    event_id: str | UUID | None = None,
    host_id: str | None = None,
    threat_id: str | None = None,
) -> Iterator[LogContext]:
    """Bind correlation ids for the duration of a ``with`` block.

    Only the ids that are given are changed; ``None`` leaves the enclosing value in place.
    Previous values are restored on exit, even if the block raises.

    Yields:
        The resulting context.
    """
    updates = (
        (_request_id, request_id),
        (_trace_id, trace_id),
        (_event_id, None if event_id is None else str(event_id)),
        (_host_id, host_id),
        (_threat_id, threat_id),
    )
    tokens = [(variable, variable.set(value)) for variable, value in updates if value is not None]
    try:
        yield current_log_context()
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)
