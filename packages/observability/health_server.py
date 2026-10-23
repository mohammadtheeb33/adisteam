"""A minimal HTTP listener for the health, readiness and metrics of worker services.

Workers such as the normalizer have no web framework of their own. This listener
answers ``GET``/``HEAD`` on a fixed set of paths, reads at most a few kilobytes per
request, bounds every request in time, and never installs signal handlers (unlike an
embedded uvicorn), so the service keeps full control of its shutdown.

Reading a request and running its route have separate time limits. A route that runs
out of time (a readiness check waiting on a slow database) is answered ``503``, so a
probe always gets an answer, never a silently closed connection.
"""

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from typing import Final

logger = logging.getLogger(__name__)

_READ_TIMEOUT_SECONDS: Final = 5.0
DEFAULT_ROUTE_TIMEOUT_SECONDS: Final = 10.0
_MAX_LINE_BYTES: Final = 8_192
_MAX_HEADER_LINES: Final = 100


@dataclass(frozen=True, slots=True)
class HttpResult:
    """What a route answers."""

    status: int
    body: bytes
    content_type: str = "application/json"


Route = Callable[[], Awaitable[HttpResult]]


class HealthServer:
    """Serves ``routes`` (path to handler) on ``host:port``; ``port=0`` picks a free one.

    ``route_timeout_seconds`` bounds each route; set it above the slowest dependency
    check a route performs.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        routes: Mapping[str, Route],
        route_timeout_seconds: float = DEFAULT_ROUTE_TIMEOUT_SECONDS,
    ) -> None:
        if route_timeout_seconds <= 0:
            raise ValueError("route_timeout_seconds must be positive")
        self._host = host
        self._port = port
        self._routes = dict(routes)
        self._route_timeout_seconds = route_timeout_seconds
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        """The bound port (after :meth:`start`)."""
        if self._server is None or not self._server.sockets:
            return self._port
        port: int = self._server.sockets[0].getsockname()[1]
        return port

    async def start(self) -> None:
        """Start listening."""
        self._server = await asyncio.start_server(
            self._handle, self._host, self._port, limit=_MAX_LINE_BYTES
        )
        logger.info(
            "health listener started",
            extra={"action": "health_listener_started", "host": self._host, "port": self.port},
        )

    async def stop(self) -> None:
        """Stop listening. Safe to call more than once."""
        server, self._server = self._server, None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            async with asyncio.timeout(_READ_TIMEOUT_SECONDS):
                method, path = await _read_request(reader)
            result = await self._dispatch(method, path)
            async with asyncio.timeout(_READ_TIMEOUT_SECONDS):
                head = (
                    f"HTTP/1.1 {result.status} {HTTPStatus(result.status).phrase}\r\n"
                    f"Content-Type: {result.content_type}\r\n"
                    f"Content-Length: {len(result.body)}\r\n"
                    "Cache-Control: no-store\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("latin-1")
                writer.write(head if method == "HEAD" else head + result.body)
                await writer.drain()
        except (TimeoutError, ValueError, ConnectionError, asyncio.IncompleteReadError):
            pass  # a malformed, slow or dropped request gets no answer
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def _dispatch(self, method: str, path: str) -> HttpResult:
        if method not in {"GET", "HEAD"}:
            return HttpResult(405, b'{"error": "method not allowed"}')
        route = self._routes.get(path)
        if route is None:
            return HttpResult(404, b'{"error": "not found"}')
        try:
            async with asyncio.timeout(self._route_timeout_seconds):
                return await route()
        except TimeoutError:
            logger.warning(
                "health route timed out",
                extra={
                    "action": "health_route_timeout",
                    "path": path,
                    "timeout_seconds": self._route_timeout_seconds,
                },
            )
            return HttpResult(503, b'{"status": "timeout"}')
        except Exception:
            logger.exception("health route failed", extra={"action": "health_route_failed"})
            return HttpResult(500, b'{"error": "internal error"}')


async def _read_request(reader: asyncio.StreamReader) -> tuple[str, str]:
    """Method and path of a request; headers are read and discarded.

    Raises:
        ValueError: If the request line or headers are malformed or too long.
    """
    line = await reader.readline()
    parts = line.decode("latin-1").strip().split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise ValueError("malformed request line")
    for _ in range(_MAX_HEADER_LINES):
        header = await reader.readline()
        if header in {b"\r\n", b"\n", b""}:
            return parts[0].upper(), parts[1].split("?", 1)[0]
    raise ValueError("too many headers")
