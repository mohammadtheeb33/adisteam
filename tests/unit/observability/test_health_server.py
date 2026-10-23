"""The worker health listener: routing, methods, malformed requests, failing routes."""

import asyncio

from packages.observability.health_server import HealthServer, HttpResult


async def _ok() -> HttpResult:
    return HttpResult(200, b'{"status": "ok"}')


async def _broken() -> HttpResult:
    raise RuntimeError("bug")


async def _raw(port: int, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    data = await reader.read()
    writer.close()
    return data


async def _served(request: bytes) -> bytes:
    server = HealthServer(host="127.0.0.1", port=0, routes={"/health": _ok, "/broken": _broken})
    await server.start()
    try:
        return await _raw(server.port, request)
    finally:
        await server.stop()


async def test_get_is_answered_with_the_route_result() -> None:
    response = await _served(b"GET /health?probe=1 HTTP/1.1\r\nHost: x\r\n\r\n")

    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Length: 16" in response
    assert response.endswith(b'{"status": "ok"}')


async def test_head_has_no_body() -> None:
    response = await _served(b"HEAD /health HTTP/1.1\r\n\r\n")

    assert response.startswith(b"HTTP/1.1 200 OK")
    assert response.endswith(b"\r\n\r\n")


async def test_unknown_paths_and_methods() -> None:
    assert (await _served(b"GET /nope HTTP/1.1\r\n\r\n")).startswith(b"HTTP/1.1 404")
    assert (await _served(b"POST /health HTTP/1.1\r\n\r\n")).startswith(b"HTTP/1.1 405")


async def test_failing_routes_answer_500() -> None:
    assert (await _served(b"GET /broken HTTP/1.1\r\n\r\n")).startswith(b"HTTP/1.1 500")


async def test_a_route_that_runs_out_of_time_is_answered_503() -> None:
    async def slow() -> HttpResult:
        await asyncio.sleep(5)
        return HttpResult(200, b"{}")

    server = HealthServer(
        host="127.0.0.1", port=0, routes={"/ready": slow}, route_timeout_seconds=0.05
    )
    await server.start()
    try:
        response = await _raw(server.port, b"GET /ready HTTP/1.1\r\n\r\n")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 503")
    assert response.endswith(b'{"status": "timeout"}')


async def test_routes_may_take_longer_than_reading_a_request() -> None:
    async def patient() -> HttpResult:
        await asyncio.sleep(0.2)
        return HttpResult(200, b'{"status": "ready"}')

    server = HealthServer(host="127.0.0.1", port=0, routes={"/ready": patient})
    await server.start()
    try:
        response = await _raw(server.port, b"GET /ready HTTP/1.1\r\n\r\n")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 200")


async def test_malformed_requests_get_no_answer() -> None:
    assert await _served(b"garbage\r\n\r\n") == b""
    assert await _served(b"GET /" + b"x" * 10_000 + b" HTTP/1.1\r\n\r\n") == b""


async def test_stop_is_idempotent() -> None:
    server = HealthServer(host="127.0.0.1", port=0, routes={})
    await server.start()
    await server.stop()
    await server.stop()
