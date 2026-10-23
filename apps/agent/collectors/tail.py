"""Checkpointed reading of append-only line files (log files, GoFlow2 output, audit log, eBPF).

The position (device, inode, rotation generation, offset, and a fingerprint of the file's
first bytes) is stored with the events it covers, a partial last line waits for its
newline, and a file that does not exist yet is waited for.

Rotation never loses the lines written before it:

- **Rename** (``create`` style, auditd): the path gets a new inode. The previous file is
  found next to it by its device and inode, and its unread lines are read first.
- **copytruncate**: the file keeps its inode but shrinks, or is refilled past the old
  offset, which its fingerprint reveals (the first bytes changed). The copy is found by that
  fingerprint and its unread lines are read first.

Only then does reading move to the new content, under a new generation. The last line of a
previous file is read without its newline once that file has been quiet for
:data:`QUIET_SECONDS` (its writer has moved on). Lines a writer appends to a renamed file
after reading has moved on, and previous files moved to another directory or compressed
before they were read, cannot be recovered.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

logger = logging.getLogger(__name__)

MAX_READ_BYTES: Final = 1_048_576
MAX_LINE_BYTES: Final = 65_536
FINGERPRINT_BYTES: Final = 1_024
"""Leading bytes that identify a file's content (lines start with timestamps)."""
QUIET_SECONDS: Final = 5.0
"""A previous file unmodified this long is complete: its last partial line is read."""
MAX_ROTATION_CANDIDATES: Final = 256


@dataclass(frozen=True, slots=True)
class TailPosition:
    """Where reading resumes in one file."""

    device: int
    inode: int
    generation: int
    offset: int
    head_size: int = 0
    """How many leading bytes ``head`` covers (0: no fingerprint yet)."""
    head: str = ""
    """SHA-256 of the file's first ``head_size`` bytes, in hex."""

    def encode(self) -> str:
        """Checkpoint representation."""
        return json.dumps(
            {
                "device": self.device,
                "inode": self.inode,
                "generation": self.generation,
                "offset": self.offset,
                "head_size": self.head_size,
                "head": self.head,
            }
        )

    @classmethod
    def decode(cls, value: str) -> "TailPosition | None":
        """Parse a checkpoint (one without a fingerprint, too); ``None`` if unreadable."""
        try:
            data = json.loads(value)
            return cls(
                int(data["device"]),
                int(data["inode"]),
                int(data["generation"]),
                int(data["offset"]),
                int(data.get("head_size", 0)),
                str(data.get("head", "")),
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            return None


@dataclass(frozen=True, slots=True)
class TailSource:
    """The file the next bytes come from, and where."""

    path: Path
    """The configured path, or the previous file after a rotation."""
    position: TailPosition
    size: int
    final: bool = False
    """A quiet previous file: its last line is complete even without a newline."""


@dataclass(frozen=True, slots=True)
class TailChunk:
    """Complete lines read from one position, each with the offset it started at."""

    position: TailPosition
    lines: list[tuple[int, bytes]]
    end: TailPosition


def locate(
    path: Path, stored: TailPosition | None, *, read_from_start: bool, action: str
) -> TailSource:
    """Where to read ``path`` next (blocking: run it in a thread).

    Args:
        path: The configured file.
        stored: The last position, or ``None`` for a file never read.
        read_from_start: Whether a file never read starts at its beginning or its end.
        action: The ``action`` logged when reading moves to other content.

    Raises:
        FileNotFoundError: ``path`` does not exist.
    """
    status = os.stat(path)
    size = status.st_size
    if stored is None:
        first = TailPosition(status.st_dev, status.st_ino, 0, 0 if read_from_start else size)
        return TailSource(path, _fingerprint(path, first, size), size)
    same_file = (stored.device, stored.inode) == (status.st_dev, status.st_ino)
    if same_file and size == stored.offset:
        return TailSource(path, stored, size)
    if same_file and size > stored.offset and _head_matches(path, stored):
        return TailSource(path, _fingerprint(path, stored, size), size)
    previous = _previous(path, stored, same_file=same_file)
    if previous is not None:
        if (previous.position.device, previous.position.inode) != (stored.device, stored.inode):
            _moved(action, path, previous.path, "copy of the truncated file")
        return previous
    _moved(action, path, path, "new file" if not same_file else "truncated file")
    fresh = TailPosition(status.st_dev, status.st_ino, stored.generation + 1, 0)
    return TailSource(path, _fingerprint(path, fresh, size), size)


def read_lines(
    source: TailSource, *, limit: int, max_line: int, keep_pieces: bool
) -> tuple[list[tuple[int, bytes]], int]:
    """Lines after ``source.position`` (blocking) and the bytes they span.

    A line without a newline waits for it, except at the end of a final previous file. A
    line longer than ``max_line`` is consumed in ``max_line`` pieces, so it cannot stall
    the file; the pieces are returned only with ``keep_pieces``.
    """
    start = source.position.offset
    with source.path.open("rb") as handle:
        handle.seek(start)
        data = handle.read(limit)
    at_end = start + len(data) >= source.size
    lines: list[tuple[int, bytes]] = []
    consumed = 0
    while consumed < len(data):
        newline = data.find(b"\n", consumed, consumed + max_line)
        if newline == -1 and len(data) - consumed >= max_line:
            if keep_pieces:
                lines.append((start + consumed, data[consumed : consumed + max_line]))
            consumed += max_line
            continue
        if newline != -1:
            end = newline + 1
        elif source.final and at_end:
            end = len(data)  # the last line of a previous file: no newline will come
        else:
            break
        lines.append((start + consumed, data[consumed:end]))
        consumed = end
    return lines, consumed


class LineTail:
    """Reads complete new lines of one file from a checkpointed position."""

    def __init__(self, path: Path, *, read_from_start: bool) -> None:
        self.path = Path(path)
        self._read_from_start = read_from_start
        self._missing_reported = False

    async def read(self, stored: TailPosition | None) -> TailChunk | None:
        """New complete lines after ``stored`` (``None`` if the file is missing or unchanged)."""
        try:
            source = await asyncio.to_thread(
                locate,
                self.path,
                stored,
                read_from_start=self._read_from_start,
                action="agent_tail_rotated",
            )
        except FileNotFoundError:
            if not self._missing_reported:
                self._missing_reported = True
                logger.warning(
                    "file not found; waiting for it",
                    extra={"action": "agent_tail_missing", "path": str(self.path)},
                )
            return None
        self._missing_reported = False
        position = source.position
        if source.size <= position.offset:
            return TailChunk(position, [], position) if position != stored else None
        lines, consumed = await asyncio.to_thread(
            read_lines, source, limit=MAX_READ_BYTES, max_line=MAX_LINE_BYTES, keep_pieces=False
        )
        return TailChunk(position, lines, replace(position, offset=position.offset + consumed))


def _fingerprint(path: Path, position: TailPosition, size: int) -> TailPosition:
    """``position`` with a fingerprint covering up to :data:`FINGERPRINT_BYTES` bytes."""
    wanted = min(FINGERPRINT_BYTES, size)
    if position.head_size >= wanted:
        return position
    head = _head(path, wanted)
    if head is None or len(head) < wanted:
        return position
    return replace(position, head_size=wanted, head=hashlib.sha256(head).hexdigest())


def _head_matches(path: Path, position: TailPosition) -> bool:
    """Whether ``path`` still starts with the bytes ``position`` was fingerprinted on."""
    if position.head_size == 0:
        return True  # a checkpoint written before fingerprints: nothing to compare
    head = _head(path, position.head_size)
    return (
        head is not None
        and len(head) == position.head_size
        and hashlib.sha256(head).hexdigest() == position.head
    )


def _head(path: Path, size: int) -> bytes | None:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return None


def _previous(path: Path, stored: TailPosition, *, same_file: bool) -> TailSource | None:
    """The file now holding the content ``stored`` points into, if it has unread bytes.

    After a rename that file keeps its device and inode; a copy made by copytruncate keeps
    its first bytes. Only files next to ``path`` whose name starts like its name are
    searched; the fingerprint also guards against a reused inode.
    """
    by_inode: tuple[Path, os.stat_result] | None = None
    copies: list[tuple[Path, os.stat_result]] = []
    for candidate in _siblings(path):
        try:
            status = os.stat(candidate)  # DirEntry.stat() has no inode on Windows
        except OSError:
            continue
        if status.st_size < stored.offset:
            continue
        if not same_file and (status.st_dev, status.st_ino) == (stored.device, stored.inode):
            by_inode = (candidate, status)
            break
        if stored.head_size:
            copies.append((candidate, status))
    if by_inode is not None and _head_matches(by_inode[0], stored):
        return _unread(by_inode[0], by_inode[1], stored)
    for candidate, status in sorted(copies, key=lambda item: item[1].st_mtime, reverse=True):
        if _head_matches(candidate, stored):
            return _unread(
                candidate,
                status,
                replace(stored, device=status.st_dev, inode=status.st_ino),
            )
    return None


def _unread(path: Path, status: os.stat_result, position: TailPosition) -> TailSource | None:
    if status.st_size <= position.offset:
        return None
    quiet = time.time() - status.st_mtime >= QUIET_SECONDS
    return TailSource(path, position, status.st_size, final=quiet)


def _siblings(path: Path) -> list[Path]:
    prefix = path.name.split(".", 1)[0]
    try:
        with os.scandir(path.parent) as entries:
            names = sorted(
                entry.name
                for entry in entries
                if entry.name != path.name and entry.name.startswith(prefix) and entry.is_file()
            )
    except OSError:
        return []
    return [path.parent / name for name in names[:MAX_ROTATION_CANDIDATES]]


def _moved(action: str, path: Path, source: Path, reason: str) -> None:
    logger.info(
        "file rotated or truncated; reading the new content after any unread lines",
        extra={"action": action, "path": str(path), "source_path": str(source), "reason": reason},
    )
