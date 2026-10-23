"""Structured JSON logging, correlation context and secret redaction for ADIS.

Services call :func:`configure_logging` once at start-up. HTTP services add
:class:`RequestContextMiddleware`; Kafka consumers bind the event's trace automatically.
Prometheus metrics will be added here as services expose them.
"""

from packages.observability.asgi import (
    REQUEST_ID_HEADER,
    TRACE_ID_HEADER,
    TRACEPARENT_HEADER,
    RequestContextMiddleware,
    get_request_id,
)
from packages.observability.context import (
    REQUEST_ID_PATTERN,
    TRACE_ID_PATTERN,
    LogContext,
    current_log_context,
    current_request_id,
    current_trace_id,
    is_valid_request_id,
    is_valid_trace_id,
    log_context,
    new_request_id,
    new_trace_id,
    trace_id_from_traceparent,
)
from packages.observability.formatting import STANDARD_FIELDS, JsonFormatter
from packages.observability.logging_config import StructuredLogHandler, configure_logging
from packages.observability.redaction import REDACTED, is_sensitive_key, redact, redact_text

__all__ = [
    "REDACTED",
    "REQUEST_ID_HEADER",
    "REQUEST_ID_PATTERN",
    "STANDARD_FIELDS",
    "TRACEPARENT_HEADER",
    "TRACE_ID_HEADER",
    "TRACE_ID_PATTERN",
    "JsonFormatter",
    "LogContext",
    "RequestContextMiddleware",
    "StructuredLogHandler",
    "configure_logging",
    "current_log_context",
    "current_request_id",
    "current_trace_id",
    "get_request_id",
    "is_sensitive_key",
    "is_valid_request_id",
    "is_valid_trace_id",
    "log_context",
    "new_request_id",
    "new_trace_id",
    "redact",
    "redact_text",
    "trace_id_from_traceparent",
]
