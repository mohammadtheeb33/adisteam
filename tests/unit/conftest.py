"""Fixtures shared by unit tests."""

import logging
from collections.abc import Iterator

import pytest

from packages.observability import JsonFormatter
from tests.unit.log_capture import JsonLogCapture


@pytest.fixture
def json_logs() -> Iterator[JsonLogCapture]:
    """Route every log record (DEBUG and up) through a ``JsonFormatter`` into memory."""
    capture = JsonLogCapture()
    handler = logging.StreamHandler(capture.stream)
    handler.setFormatter(JsonFormatter(service="adis-test", environment="test"))
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield capture
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)
