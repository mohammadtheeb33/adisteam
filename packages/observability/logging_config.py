"""Process-wide logging configuration."""

import logging
import sys
from typing import TextIO

from packages.config import AppSettings
from packages.observability.formatting import JsonFormatter


class StructuredLogHandler(logging.StreamHandler[TextIO]):
    """Stream handler installed by :func:`configure_logging` (one per process)."""


def configure_logging(settings: AppSettings, *, stream: TextIO | None = None) -> None:
    """Send every log record to ``stream`` (stdout by default) as structured JSON.

    Call once at service start-up, before other components log. Calling it again
    replaces the previously installed handler rather than adding a second one. Python
    warnings are routed through logging as well.

    Args:
        settings: Supplies ``service`` (``APP_NAME``), ``environment`` (``APP_ENV``) and
            the level (``LOG_LEVEL``).
        stream: Destination; defaults to ``sys.stdout``.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        if isinstance(handler, StructuredLogHandler):
            root.removeHandler(handler)
            handler.close()
    handler = StructuredLogHandler(stream if stream is not None else sys.stdout)
    handler.setFormatter(
        JsonFormatter(service=settings.app_name, environment=settings.app_env.value)
    )
    root.addHandler(handler)
    root.setLevel(settings.log_level.value)
    logging.captureWarnings(True)
