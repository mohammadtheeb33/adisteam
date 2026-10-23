"""HTTP client: request format and response classification."""

import httpx2
import pytest
from pydantic import SecretStr

from apps.agent.client import IngestApiClient, Outcome

TOKEN = "agent-token-" + "x" * 32


def _client(handler: httpx2.MockTransport) -> IngestApiClient:
    return IngestApiClient(
        "https://ingest.example.test/",
        SecretStr(TOKEN),
        timeout_seconds=1,
        user_agent="adis-agent/test",
        transport=handler,
    )


def _responding(
    status: int, body: object = None, headers: dict[str, str] | None = None
) -> httpx2.MockTransport:
    def handle(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, json=body, headers=headers)

    return httpx2.MockTransport(handle)


async def test_batch_request_format() -> None:
    seen: list[httpx2.Request] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(202, json={"accepted": [{"index": 0}, {"index": 1}], "rejected": []})

    async with _client(httpx2.MockTransport(handle)) as client:
        result = await client.send_batch([b'{"a":1}', b'{"b":2}'])

    [request] = seen
    assert request.method == "POST"
    assert str(request.url) == "https://ingest.example.test/api/v1/events/batch"
    assert request.content == b'{"events":[{"a":1},{"b":2}]}'
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert request.headers["Content-Type"] == "application/json"
    assert request.headers["User-Agent"] == "adis-agent/test"
    assert request.headers["X-Request-ID"] == result.request_id
    assert (result.outcome, result.accepted) == (Outcome.DELIVERED, frozenset({0, 1}))


async def test_partial_acceptance_is_reported_per_index() -> None:
    body = {
        "accepted": [{"index": 0}],
        "rejected": [{"index": 1, "code": "validation_failed", "issues": ["src_port: too big"]}],
    }

    async with _client(_responding(202, body)) as client:
        result = await client.send_batch([b"{}", b"{}"])

    assert result.accepted == frozenset({0})
    assert result.rejected == {1: "validation_failed: src_port: too big"}


async def test_single_event_request() -> None:
    seen: list[str] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.url.path)
        return httpx2.Response(202, json={"status": "accepted"})

    async with _client(httpx2.MockTransport(handle)) as client:
        result = await client.send_event(b"{}")

    assert seen == ["/api/v1/events"]
    assert (result.outcome, result.accepted) == (Outcome.DELIVERED, frozenset({0}))


async def test_all_invalid_batch_is_rejected_per_index() -> None:
    body = {
        "error": {
            "code": "validation_failed",
            "details": [
                {"index": 0, "code": "validation_failed", "issues": ["a"]},
                {"index": 1, "code": "unsupported_schema_version", "issues": []},
            ],
        }
    }

    async with _client(_responding(422, body)) as client:
        result = await client.send_batch([b"{}", b"{}"])

    assert result.outcome is Outcome.REJECTED
    assert result.rejected == {0: "validation_failed: a", 1: "unsupported_schema_version"}


async def test_rejected_single_event_without_index() -> None:
    body = {
        "error": {
            "code": "validation_failed",
            "details": [{"index": None, "code": "validation_failed", "issues": ["x"]}],
        }
    }

    async with _client(_responding(422, body)) as client:
        result = await client.send_event(b"{}")

    assert result.rejected == {0: "validation_failed: x"}


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        (400, Outcome.MALFORMED),
        (401, Outcome.UNAUTHORIZED),
        (403, Outcome.UNAUTHORIZED),
        (404, Outcome.MISCONFIGURED),
        (415, Outcome.MISCONFIGURED),
        (413, Outcome.TOO_LARGE),
        (429, Outcome.RATE_LIMITED),
        (500, Outcome.UNAVAILABLE),
        (503, Outcome.UNAVAILABLE),
    ],
)
async def test_statuses_are_classified(status: int, outcome: Outcome) -> None:
    body = {"error": {"code": "some_code", "message": "m", "details": []}}

    async with _client(_responding(status, body, {"Retry-After": "7"})) as client:
        result = await client.send_batch([b"{}"])

    assert (result.outcome, result.status, result.code, result.retry_after) == (
        outcome,
        status,
        "some_code",
        7.0,
    )


async def test_network_failures_are_unavailable() -> None:
    def handle(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    async with _client(httpx2.MockTransport(handle)) as client:
        result = await client.send_batch([b"{}"])

    assert (result.outcome, result.status, result.detail) == (
        Outcome.UNAVAILABLE,
        None,
        "ConnectError",
    )


async def test_unreadable_success_is_treated_as_unavailable() -> None:
    def handle(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(202, content=b"not json")

    async with _client(httpx2.MockTransport(handle)) as client:
        result = await client.send_batch([b"{}"])

    assert result.outcome is Outcome.UNAVAILABLE


@pytest.mark.parametrize(
    ("header", "expected"), [("12", 12.0), ("0.5", 0.5), ("soon", None), ("-3", None)]
)
async def test_retry_after_parsing(header: str, expected: float | None) -> None:
    async with _client(_responding(429, {"error": {}}, {"Retry-After": header})) as client:
        result = await client.send_batch([b"{}"])

    assert result.retry_after == expected


async def test_request_ids_are_unique_per_request() -> None:
    seen: list[str] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers["X-Request-ID"])
        return httpx2.Response(202, json={"accepted": [], "rejected": []})

    async with _client(httpx2.MockTransport(handle)) as client:
        await client.send_batch([b"{}"])
        await client.send_batch([b"{}"])

    assert len(set(seen)) == 2
