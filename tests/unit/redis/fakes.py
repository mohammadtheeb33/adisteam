"""In-memory Redis for unit tests."""

import asyncio
import time


class FakeRedis:
    """In-memory stand-in for the subset of ``redis.asyncio.Redis`` the client uses."""

    def __init__(self) -> None:
        self.values: dict[str, tuple[bytes, float]] = {}
        self.failure: Exception | None = None
        self.closed = 0
        self.hang = False

    def _check(self) -> None:
        if self.failure is not None:
            raise self.failure

    def _alive(self, name: str) -> tuple[bytes, float] | None:
        entry = self.values.get(name)
        if entry is not None and entry[1] <= time.monotonic():
            del self.values[name]
            return None
        return entry

    async def get(self, name: str) -> bytes | None:
        self._check()
        entry = self._alive(name)
        return None if entry is None else entry[0]

    async def set(self, name: str, value: bytes, *, px: int) -> object:
        self._check()
        self.values[name] = (value, time.monotonic() + px / 1000)
        return True

    async def delete(self, *names: str) -> int:
        self._check()
        return sum(1 for name in names if self.values.pop(name, None) is not None)

    async def ping(self) -> object:
        if self.hang:
            await asyncio.sleep(10)
        self._check()
        return True

    async def eval(self, script: str, numkeys: int, *keys_and_args: str | int) -> object:
        self._check()
        key, cost, limit, window_ms = keys_and_args
        entry = self._alive(str(key))
        used = int(entry[0]) if entry else 0
        expires = entry[1] if entry else time.monotonic() + int(window_ms) / 1000
        ttl = max(0, round((expires - time.monotonic()) * 1000))
        if used + int(cost) > int(limit):
            return [0, used, ttl]
        used += int(cost)
        self.values[str(key)] = (str(used).encode(), expires)
        return [1, used, ttl]

    async def aclose(self) -> None:
        self.closed += 1
