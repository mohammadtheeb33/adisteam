"""Request id and trace propagation through FastAPI."""

import logging
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient

from packages.events import EventEnvelope
from packages.observability import (
    RequestContextMiddleware,
    current_request_id,
    current_trace_id,
    get_request_id,
    is_valid_request_id,
    is_valid_trace_id,
)
from tests.unit.log_capture import JsonLogCapture

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE}-00f067aa0ba902b7-01"
endpoint_logger = logging.getLogger("tests.api")


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestContextMiddleware, quiet_paths={"/health"})

    @app.get("/context")
    async def context(
        request_id: Annotated[str | None, Depends(get_request_id)],
    ) -> dict[str, str | None]:
        endpoint_logger.info("handling request", extra={"action": "test_endpoint"})
        event = EventEnvelope(
            event_type="api.probe", event_version=1, producer="adis-api", payload={}
        )
        return {
            "request_id": request_id,
            "trace_id": current_trace_id(),
            "event_trace_id": event.trace_id,
        }

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("failed with password=sentinel-in-error")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.websocket("/ws")
    async def websocket(socket: WebSocket) -> None:
        await socket.accept()
        await socket.send_json({"request_id": current_request_id()})
        await socket.close()

    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(_app(), raise_server_exceptions=False)


def test_ids_are_generated_bound_and_returned(client: TestClient) -> None:
    response = client.get("/context")

    body = response.json()
    request_id, trace_id = response.headers["X-Request-ID"], response.headers["X-Trace-ID"]
    assert is_valid_request_id(request_id)
    assert is_valid_trace_id(trace_id)
    assert body == {"request_id": request_id, "trace_id": trace_id, "event_trace_id": trace_id}


def test_safe_client_request_id_is_propagated(client: TestClient) -> None:
    response = client.get("/context", headers={"X-Request-ID": "gateway-7f3a:42"})

    assert response.headers["X-Request-ID"] == "gateway-7f3a:42"
    assert response.json()["request_id"] == "gateway-7f3a:42"


@pytest.mark.parametrize("unsafe", ["has space", "x" * 129, '{"level":"ERROR"}', "<script>"])
def test_unsafe_client_request_id_is_replaced(client: TestClient, unsafe: str) -> None:
    response = client.get("/context", headers={"X-Request-ID": unsafe})

    assert response.headers["X-Request-ID"] != unsafe
    assert is_valid_request_id(response.headers["X-Request-ID"])


def test_traceparent_continues_the_trace(client: TestClient) -> None:
    response = client.get("/context", headers={"traceparent": TRACEPARENT})

    assert response.headers["X-Trace-ID"] == TRACE
    assert response.json()["event_trace_id"] == TRACE


def test_invalid_traceparent_starts_a_new_trace(client: TestClient) -> None:
    response = client.get("/context", headers={"traceparent": "00-not-a-trace"})

    assert is_valid_trace_id(response.headers["X-Trace-ID"])


def test_each_request_gets_its_own_ids(client: TestClient) -> None:
    first, second = client.get("/context"), client.get("/context")

    assert first.headers["X-Request-ID"] != second.headers["X-Request-ID"]
    assert first.headers["X-Trace-ID"] != second.headers["X-Trace-ID"]


def test_logs_carry_request_and_trace_ids(client: TestClient, json_logs: JsonLogCapture) -> None:
    response = client.get("/context?page=2&token=sentinel-query", headers={"X-Request-ID": "r-1"})

    [endpoint_log] = json_logs.with_message("handling request")
    [access_log] = json_logs.with_message("http request completed")
    for record in (endpoint_log, access_log):
        assert record["request_id"] == "r-1"
        assert record["trace_id"] == response.headers["X-Trace-ID"]
    assert access_log["action"] == "http_request"
    assert access_log["method"] == "GET"
    assert access_log["path"] == "/context"
    assert access_log["status_code"] == 200
    assert isinstance(access_log["latency_ms"], float)
    assert access_log["level"] == "INFO"
    assert "sentinel" not in json_logs.text


def test_authorization_and_cookies_are_never_logged(
    client: TestClient, json_logs: JsonLogCapture
) -> None:
    client.get(
        "/context",
        headers={"Authorization": "Bearer sentinel-token", "Cookie": "session=sentinel-cookie"},
    )

    assert json_logs.records()
    assert "sentinel" not in json_logs.text


def test_unhandled_error_returns_generic_500_with_correlation_headers(
    client: TestClient, json_logs: JsonLogCapture
) -> None:
    response = client.get("/boom", headers={"X-Request-ID": "r-500"})

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal Server Error"}
    assert response.headers["X-Request-ID"] == "r-500"
    assert "sentinel" not in response.text
    [failure] = json_logs.with_message("http request failed")
    assert failure["level"] == "ERROR"
    assert failure["request_id"] == "r-500"
    assert failure["status_code"] == 500
    exception = failure["exception"]
    assert isinstance(exception, dict)
    assert exception["type"] == "RuntimeError"
    assert "sentinel" not in json_logs.text


def test_quiet_paths_log_at_debug(client: TestClient, json_logs: JsonLogCapture) -> None:
    client.get("/health")

    [access_log] = json_logs.with_message("http request completed")
    assert access_log["level"] == "DEBUG"


def test_websocket_connections_are_correlated() -> None:
    with (
        TestClient(_app()) as client,
        client.websocket_connect("/ws", headers={"X-Request-ID": "ws-1"}) as socket,
    ):
        assert socket.receive_json() == {"request_id": "ws-1"}


def test_custom_error_body_keeps_the_application_error_format() -> None:
    app = FastAPI()
    app.add_middleware(
        RequestContextMiddleware,
        error_body=lambda request_id: f'{{"error":{{"request_id":"{request_id}"}}}}'.encode(),
    )

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("sentinel detail")

    response = TestClient(app, raise_server_exceptions=False).get(
        "/boom", headers={"X-Request-ID": "r-custom"}
    )

    assert response.status_code == 500
    assert response.json() == {"error": {"request_id": "r-custom"}}
    assert "sentinel" not in response.text
