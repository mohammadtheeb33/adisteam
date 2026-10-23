"""JSON log formatter producing the ADIS log schema."""

import json
import logging
import traceback
from datetime import UTC, datetime
from typing import Final

from packages.observability.context import current_log_context
from packages.observability.redaction import REDACTED, is_sensitive_key, redact, redact_text

CONTEXT_FIELDS: Final = ("request_id", "trace_id", "event_id", "host_id", "threat_id")
RECORD_FIELDS: Final = ("action", "latency_ms")

STANDARD_FIELDS: Final = (
    "timestamp",
    "level",
    "service",
    "environment",
    "message",
    *CONTEXT_FIELDS,
    *RECORD_FIELDS,
)
"""Fields present in every log line, ``null`` when unknown."""

_FIXED_FIELDS: Final = frozenset(
    {"timestamp", "level", "service", "environment", "message", "logger", "exception", "stack"}
)
_LOG_RECORD_ATTRIBUTES: Final = frozenset(
    logging.LogRecord("", 0, "", 0, "", None, None).__dict__
) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Render each record as one JSON object per line.

    Every line contains :data:`STANDARD_FIELDS` (``null`` when unknown), then ``logger``,
    then any extra fields passed with ``extra=``. Correlation ids come from ``extra=``
    first, otherwise from the current :func:`~packages.observability.log_context`.
    Everything is passed through :func:`~packages.observability.redaction.redact`.
    """

    def __init__(self, *, service: str, environment: str) -> None:
        super().__init__()
        self._service = service
        self._environment = environment

    def format(self, record: logging.LogRecord) -> str:
        """Format ``record`` as a JSON line."""
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _LOG_RECORD_ATTRIBUTES and not key.startswith("_")
        }
        context = current_log_context()
        document: dict[str, object] = {
            "timestamp": _timestamp(record.created),
            "level": record.levelname,
            "service": self._service,
            "environment": self._environment,
            "message": redact_text(record.getMessage()),
        }
        for name in CONTEXT_FIELDS:
            value = extras.pop(name, None)
            document[name] = redact(value if value is not None else getattr(context, name))
        for name in RECORD_FIELDS:
            document[name] = redact(extras.pop(name, None))
        document["logger"] = record.name
        for key, value in extras.items():
            if key not in _FIXED_FIELDS:
                document[key] = REDACTED if is_sensitive_key(key) else redact(value)
        if record.exc_info and record.exc_info[1] is not None:
            error = record.exc_info[1]
            document["exception"] = {
                "type": type(error).__name__,
                "message": redact_text(str(error)),
                "stacktrace": redact_text("".join(traceback.format_exception(error))),
            }
        if record.stack_info:
            document["stack"] = redact_text(record.stack_info)
        return json.dumps(document, ensure_ascii=False, default=str)


def _timestamp(created: float) -> str:
    moment = datetime.fromtimestamp(created, UTC)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")
