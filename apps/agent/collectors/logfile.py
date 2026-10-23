"""Application and system log file collector.

Tails files by polling, without inotify or privileged access:

- Each complete line becomes a ``system.log_entry`` event. A partial last line waits
  for its newline.
- The position (device, inode, rotation generation, offset, fingerprint of the first
  bytes) is checkpointed in the same spool transaction as the events it covers. Restarts
  resume exactly where they stopped.
- Rotation and truncation (renamed, shrunk, or truncated and refilled by copytruncate)
  first read the unread lines of the previous file, then the new content from its
  beginning under a new generation (:mod:`apps.agent.collectors.tail`).
- Event ids are UUIDv5 of the agent id, file identity, generation and offset, so a
  replay after a crash yields the same ids and is deduplicated rather than duplicated.
- Lines are scrubbed of credentials (authorization headers, ``password=``-style pairs,
  URL credentials, private keys, JWTs) before they leave the host, and are capped at
  16 KiB.
- New files start at their end, unless ``read_from_start``; checkpointed files always
  resume from their checkpoint.
"""

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import uuid5

from apps.agent.collectors.base import CollectorContext, EventSink
from apps.agent.collectors.tail import TailPosition, locate, read_lines
from packages.events.canonical import SeverityHint, SystemEvent
from packages.observability import redact_text

logger = logging.getLogger(__name__)

MAX_LINE_BYTES: Final = 16_384
MAX_READ_BYTES: Final = 1_048_576
SOURCE_TYPE: Final = "logfile"
EVENT_TYPE: Final = "system.log_entry"

_SEVERITY_PATTERNS: Final = (
    (re.compile(r"\b(emerg|emergency|alert|crit|critical|fatal|panic)\b", re.I), SeverityHint.HIGH),
    (re.compile(r"\b(err|error|fail|failed|failure)\b", re.I), SeverityHint.MEDIUM),
    (re.compile(r"\b(warn|warning)\b", re.I), SeverityHint.LOW),
)

Sleep = Callable[[float], Awaitable[None]]


FilePosition = TailPosition
"""Where reading resumes in one file (the shared tail position)."""


class LogFileCollector:
    """Tails ``paths`` and emits one event per line."""

    name = "logfile"

    def __init__(
        self,
        paths: Sequence[Path],
        context: CollectorContext,
        *,
        poll_interval_seconds: float,
        read_from_start: bool,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._paths = [Path(path) for path in paths]
        self._context = context
        self._poll_interval = poll_interval_seconds
        self._read_from_start = read_from_start
        self._sleep = sleep
        self._positions: dict[Path, FilePosition] = {}
        self._missing: set[Path] = set()

    async def run(self, sink: EventSink) -> None:
        """Poll every file until cancelled."""
        while True:
            await self.poll(sink)
            await self._sleep(self._poll_interval)

    async def poll(self, sink: EventSink) -> int:
        """Read new complete lines of every file once; returns how many events were spooled."""
        emitted = 0
        for path in self._paths:
            emitted += await self._poll_file(path, sink)
        return emitted

    async def _poll_file(self, path: Path, sink: EventSink) -> int:
        stored = await self._stored(path, sink)
        try:
            source = await asyncio.to_thread(
                locate,
                path,
                stored,
                read_from_start=self._read_from_start,
                action="agent_logfile_rotated",
            )
        except FileNotFoundError:
            if path not in self._missing:
                self._missing.add(path)
                logger.warning(
                    "log file not found; waiting for it",
                    extra={"action": "agent_logfile_missing", "path": str(path)},
                )
            return 0
        self._missing.discard(path)
        position = source.position
        self._positions[path] = position
        if source.size <= position.offset:
            return 0
        lines, consumed = await asyncio.to_thread(
            read_lines, source, limit=MAX_READ_BYTES, max_line=MAX_LINE_BYTES, keep_pieces=True
        )
        if not consumed:
            return 0
        events = [
            self._event(path, line, replace(position, offset=offset))
            for offset, line in lines
            if line.strip()
        ]
        advanced = replace(position, offset=position.offset + consumed)
        await sink.submit(events, checkpoints={_key(path): advanced.encode()})
        self._positions[path] = advanced
        return len(events)

    async def _stored(self, path: Path, sink: EventSink) -> FilePosition | None:
        known = self._positions.get(path)
        if known is not None:
            return known
        stored = await sink.checkpoint(_key(path))
        return FilePosition.decode(stored) if stored is not None else None

    def _event(self, path: Path, raw: bytes, position: FilePosition) -> SystemEvent:
        text = raw.rstrip(b"\r\n").decode("utf-8", errors="replace")
        message = redact_text(text)
        identity = self._context.identity
        return SystemEvent(
            event_id=uuid5(
                identity.agent_id,
                f"logfile:{position.device}:{position.inode}:{position.generation}:{position.offset}",
            ),
            event_type=EVENT_TYPE,
            timestamp=datetime.now(UTC),
            source_type=SOURCE_TYPE,
            source_name=self._context.source_name(self.name),
            host_id=identity.host_id,
            agent_id=self._context.agent_id,
            severity_hint=_severity(message),
            metadata={"path": str(path), "offset": position.offset, "message": message},
        )


def _severity(message: str) -> SeverityHint:
    for pattern, severity in _SEVERITY_PATTERNS:
        if pattern.search(message):
            return severity
    return SeverityHint.INFO


def _key(path: Path) -> str:
    return f"logfile:{path.resolve()}"
