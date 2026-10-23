"""Correlation context binding and identifier validation."""

import asyncio
import re
from uuid import UUID

import pytest

from packages.observability import (
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

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


def test_context_is_empty_by_default() -> None:
    assert current_log_context() == LogContext()


def test_log_context_binds_and_restores() -> None:
    with log_context(request_id="req-1", trace_id=TRACE, host_id="host-7") as bound:
        assert bound == LogContext(request_id="req-1", trace_id=TRACE, host_id="host-7")
        assert current_request_id() == "req-1"
        assert current_trace_id() == TRACE

    assert current_log_context() == LogContext()


def test_nested_context_overrides_only_given_fields() -> None:
    with log_context(request_id="outer", trace_id=TRACE):
        with log_context(event_id=UUID(int=1), threat_id="threat-9", trace_id=None):
            inner = current_log_context()
        outer = current_log_context()

    assert inner == LogContext(
        request_id="outer",
        trace_id=TRACE,
        event_id="00000000-0000-0000-0000-000000000001",
        threat_id="threat-9",
    )
    assert outer == LogContext(request_id="outer", trace_id=TRACE)


def test_context_is_restored_when_the_block_raises() -> None:
    with pytest.raises(RuntimeError), log_context(request_id="req-1"):
        raise RuntimeError

    assert current_request_id() is None


async def test_context_is_isolated_between_tasks() -> None:
    async def run(request_id: str) -> str | None:
        with log_context(request_id=request_id):
            await asyncio.sleep(0.01)
            return current_request_id()

    assert list(await asyncio.gather(run("a"), run("b"))) == ["a", "b"]


def test_generated_ids() -> None:
    assert re.fullmatch(TRACE_ID_PATTERN, new_trace_id())
    assert re.fullmatch(REQUEST_ID_PATTERN, new_request_id())
    assert new_trace_id() != new_trace_id()


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        (TRACE, True),
        ("0" * 32, False),
        (TRACE.upper(), False),
        (TRACE[:-1], False),
        (None, False),
    ],
)
def test_trace_id_validation(value: str | None, valid: bool) -> None:
    assert is_valid_trace_id(value) is valid


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("7d1f0e4c-5c1b-4b0c-9a61-2d3b3c1e9f00", True),
        ("gateway:abc.123_x", True),
        ("x" * 128, True),
        ("x" * 129, False),
        ("", False),
        ("has space", False),
        ("line\nbreak", False),
        ('{"forged": "log"}', False),
        (None, False),
    ],
)
def test_request_id_validation(value: str | None, valid: bool) -> None:
    assert is_valid_request_id(value) is valid


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (f"00-{TRACE}-00f067aa0ba902b7-01", TRACE),
        (f" 00-{TRACE}-00f067aa0ba902b7-00 ", TRACE),
        (f"01-{TRACE}-00f067aa0ba902b7-01-future-fields", TRACE),
        (f"ff-{TRACE}-00f067aa0ba902b7-01", None),
        (f"00-{'0' * 32}-00f067aa0ba902b7-01", None),
        (f"00-{TRACE}-{'0' * 16}-01", None),
        (f"00-{TRACE.upper()}-00f067aa0ba902b7-01", None),
        ("garbage", None),
        (None, None),
    ],
)
def test_traceparent_parsing(header: str | None, expected: str | None) -> None:
    assert trace_id_from_traceparent(header) == expected
