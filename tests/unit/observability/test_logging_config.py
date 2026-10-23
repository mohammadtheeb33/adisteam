"""Process-wide logging configuration."""

import io
import json
import logging
from collections.abc import Iterator

import pytest

from packages.config import AppSettings
from packages.observability import StructuredLogHandler, configure_logging

SETTINGS = AppSettings.model_validate(
    {"app_name": "adis-detector", "app_env": "staging", "log_level": "WARNING"}
)


@pytest.fixture(autouse=True)
def restore_root_logger() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    try:
        yield
    finally:
        for handler in list(root.handlers):
            if handler not in handlers:
                root.removeHandler(handler)
                handler.close()
        root.setLevel(level)
        logging.captureWarnings(False)


def _structured_handlers() -> list[logging.Handler]:
    return [h for h in logging.getLogger().handlers if isinstance(h, StructuredLogHandler)]


def test_emits_json_with_service_and_environment_from_settings() -> None:
    stream = io.StringIO()

    configure_logging(SETTINGS, stream=stream)
    logging.getLogger("adis.test").warning("configured", extra={"action": "startup"})

    record = json.loads(stream.getvalue().splitlines()[-1])
    assert record["service"] == "adis-detector"
    assert record["environment"] == "staging"
    assert record["action"] == "startup"


def test_applies_log_level() -> None:
    stream = io.StringIO()

    configure_logging(SETTINGS, stream=stream)
    logging.getLogger("adis.test").info("below the configured level")

    assert logging.getLogger().level == logging.WARNING
    assert stream.getvalue() == ""


def test_is_idempotent() -> None:
    first, second = io.StringIO(), io.StringIO()

    configure_logging(SETTINGS, stream=first)
    configure_logging(SETTINGS, stream=second)
    logging.getLogger("adis.test").error("once")

    assert len(_structured_handlers()) == 1
    assert first.getvalue() == ""
    assert len(second.getvalue().splitlines()) == 1
