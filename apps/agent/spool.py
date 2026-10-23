"""Durable local spool: events wait here until the server acknowledges them.

The spool is a SQLite database (WAL journal, ``synchronous=FULL``) in
``AGENT_DATA_DIR``, so buffered events survive crashes, restarts and power loss.
Nothing leaves it silently:

- **Acknowledged** events are deleted only after the server confirmed them.
- **Permanently rejected** events move to the ``quarantine`` table with the reason, for
  inspection (``python -m apps.agent status``).
- **Capacity** is enforced at the door. ``append`` refuses a batch that would exceed
  ``max_events`` (:class:`SpoolFullError`, nothing written), and collectors pause
  until space frees up.
- **Quarantine overflow** evicts the oldest quarantined events, but counts every
  eviction persistently (``quarantine_evicted``); the caller logs it as an error.

Collector checkpoints (e.g. log file offsets) are stored in the same transaction as the
events they cover, so a crash can neither skip nor duplicate collected data.

Payloads are sealed by a :class:`~apps.agent.spool_crypto.PayloadCipher` (AES-256-GCM
by default, see :mod:`apps.agent.spool_crypto`). A key check stored in the spool proves,
at open, that the key opens it; a spool the key cannot open is set aside like a corrupt
one. Checkpoints and counters are not encrypted: they hold positions, not telemetry.
"""

import asyncio
import logging
import sqlite3
import threading
import time
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from apps.agent.spool_crypto import HEADER, NoEncryption, PayloadCipher, SpoolKeyError

logger = logging.getLogger(__name__)

_SQLITE_BATCH: Final = 500
_SCHEMA: Final = (
    """CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        payload BLOB NOT NULL,
        enqueued_at REAL NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS quarantine (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL,
        payload BLOB NOT NULL,
        reason TEXT NOT NULL,
        quarantined_at REAL NOT NULL
    )""",
    "CREATE TABLE IF NOT EXISTS checkpoints (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value BLOB NOT NULL)",
)
QUARANTINE_EVICTED: Final = "quarantine_evicted"
_KEY_CHECK: Final = "key_check"
_KEY_CHECK_VALUE: Final = b"adis-spool"


@dataclass(frozen=True, slots=True)
class SpooledEvent:
    """One buffered event."""

    seq: int
    event_id: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class AppendResult:
    """Outcome of an append."""

    added: int
    duplicates: int


@dataclass(frozen=True, slots=True)
class QuarantineResult:
    """Outcome of quarantining events."""

    moved: int
    evicted: int


@dataclass(frozen=True, slots=True)
class SpoolStats:
    """Current spool state."""

    queued: int
    capacity: int
    quarantined: int
    quarantine_evicted: int


class SpoolFullError(Exception):
    """Appending would exceed the spool capacity; nothing was written."""

    def __init__(self, *, queued: int, requested: int, capacity: int) -> None:
        self.queued = queued
        self.requested = requested
        self.capacity = capacity
        super().__init__(f"spool full: {queued} queued + {requested} new > capacity {capacity}")


class Spool:
    """SQLite-backed FIFO of serialized canonical events.

    Blocking SQLite work runs in a worker thread; a lock serializes access, so one
    ``Spool`` is safe to share between the collectors and the sender.
    """

    def __init__(
        self,
        path: Path,
        *,
        max_events: int,
        max_quarantined: int | None = None,
        cipher: PayloadCipher | None = None,
    ) -> None:
        """Open or create the spool.

        Raises:
            sqlite3.DatabaseError: If the file is not a sound SQLite spool.
            SpoolKeyError: If ``cipher`` cannot open this spool (another key, or
                encryption disabled for an encrypted spool).
        """
        if max_events < 1:
            raise ValueError("max_events must be positive")
        self._capacity = max_events
        self._max_quarantined = max_quarantined or max_events
        self._cipher: PayloadCipher = cipher or NoEncryption()
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        try:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            for statement in _SCHEMA:
                self._connection.execute(statement)
            (verdict,) = self._connection.execute("PRAGMA quick_check").fetchone()
            if verdict != "ok":
                raise sqlite3.DatabaseError("spool integrity check failed")
            self._check_key()
        except (sqlite3.DatabaseError, SpoolKeyError):
            self._connection.close()
            raise

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        max_events: int,
        max_quarantined: int | None = None,
        cipher: PayloadCipher | None = None,
    ) -> Self:
        """Open the spool at ``path``; one that cannot be read is preserved and replaced.

        A corrupt spool, or one the key cannot open, cannot be sent. Rather than keep
        the agent from starting (and collecting), the file is renamed to
        ``<name>.corrupt-<UTC time>`` for forensic recovery, the loss is logged as an
        error, and collection continues with an empty spool.
        """
        try:
            return cls(path, max_events=max_events, max_quarantined=max_quarantined, cipher=cipher)
        except (sqlite3.DatabaseError, SpoolKeyError) as error:
            preserved = _set_aside(path)
            corrupt = isinstance(error, sqlite3.DatabaseError)
            logger.error(
                "local spool is corrupt; it was preserved and replaced by an empty one"
                if corrupt
                else "the spool key does not open the local spool; it was preserved and "
                "replaced by an empty one",
                extra={
                    "action": "agent_spool_corrupt" if corrupt else "agent_spool_key_mismatch",
                    "error_type": type(error).__name__,
                    "preserved_as": str(preserved),
                },
            )
            return cls(path, max_events=max_events, max_quarantined=max_quarantined, cipher=cipher)

    @property
    def encryption(self) -> str:
        """How payloads are protected at rest."""
        return self._cipher.description

    @property
    def capacity(self) -> int:
        """Most events the spool holds."""
        return self._capacity

    # ------------------------------------------------------------------------- async API

    async def append(
        self, records: Sequence[tuple[str, bytes]], checkpoints: Mapping[str, str] | None = None
    ) -> AppendResult:
        """Buffer ``(event_id, payload)`` records and store ``checkpoints``, atomically.

        Records whose ``event_id`` is already queued are skipped (collectors may replay
        after a crash).

        Raises:
            SpoolFullError: If the new records do not fit; nothing is written.
        """
        return await asyncio.to_thread(self._append, records, dict(checkpoints or {}))

    async def peek(self, limit: int) -> list[SpooledEvent]:
        """The oldest ``limit`` events, without removing them."""
        return await asyncio.to_thread(self._peek, limit)

    async def acknowledge(self, seqs: Collection[int]) -> int:
        """Delete events the server accepted; returns how many were deleted."""
        return await asyncio.to_thread(self._acknowledge, list(seqs))

    async def quarantine(self, reasons: Mapping[int, str]) -> QuarantineResult:
        """Move permanently rejected events (``{seq: reason}``) to the quarantine."""
        return await asyncio.to_thread(self._quarantine, dict(reasons))

    async def checkpoint(self, key: str) -> str | None:
        """A stored checkpoint value."""
        return await asyncio.to_thread(self._checkpoint, key)

    async def set_checkpoint(self, key: str, value: str) -> None:
        """Store a checkpoint on its own."""
        await asyncio.to_thread(self._append, (), {key: value})

    async def stats(self) -> SpoolStats:
        """Queue and quarantine sizes."""
        return await asyncio.to_thread(self._stats)

    async def quarantined(self, limit: int) -> list[tuple[str, str]]:
        """The newest quarantined ``(event_id, reason)`` pairs."""
        return await asyncio.to_thread(self._quarantined, limit)

    def close(self) -> None:
        """Close the database. Queued events stay on disk for the next start."""
        with self._lock:
            self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    # -------------------------------------------------------------------------- blocking

    def _append(
        self, records: Sequence[tuple[str, bytes]], checkpoints: dict[str, str]
    ) -> AppendResult:
        unique = dict(records)
        with self._lock, self._transaction() as connection:
            existing = self._existing_ids(connection, list(unique))
            fresh = [
                (event_id, payload)
                for event_id, payload in unique.items()
                if event_id not in existing
            ]
            queued = self._count(connection, "events")
            if queued + len(fresh) > self._capacity:
                raise SpoolFullError(queued=queued, requested=len(fresh), capacity=self._capacity)
            now = time.time()
            connection.executemany(
                "INSERT INTO events (event_id, payload, enqueued_at) VALUES (?, ?, ?)",
                [
                    (event_id, self._cipher.seal(event_id, payload), now)
                    for event_id, payload in fresh
                ],
            )
            connection.executemany(
                "INSERT INTO checkpoints (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                list(checkpoints.items()),
            )
        return AppendResult(added=len(fresh), duplicates=len(records) - len(fresh))

    def _peek(self, limit: int) -> list[SpooledEvent]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT seq, event_id, payload FROM events ORDER BY seq LIMIT ?", (limit,)
            ).fetchall()
        readable: list[SpooledEvent] = []
        unreadable: dict[int, str] = {}
        for seq, event_id, stored in rows:
            try:
                payload = self._cipher.open(event_id, stored)
            except SpoolKeyError:
                # Altered on disk: it can never be sent, so it is kept aside, not dropped.
                unreadable[seq] = "spool record failed its integrity check"
                continue
            readable.append(SpooledEvent(seq=seq, event_id=event_id, payload=payload))
        if unreadable:
            self._quarantine(unreadable)
            logger.error(
                "spool records failed their integrity check and were quarantined",
                extra={"action": "agent_spool_record_unreadable", "records": len(unreadable)},
            )
        return readable

    def _acknowledge(self, seqs: list[int]) -> int:
        deleted = 0
        with self._lock, self._transaction() as connection:
            for chunk in _chunks(seqs):
                placeholders = ",".join("?" * len(chunk))
                deleted += connection.execute(
                    f"DELETE FROM events WHERE seq IN ({placeholders})",  # noqa: S608 - placeholders only
                    chunk,
                ).rowcount
        return deleted

    def _quarantine(self, reasons: dict[int, str]) -> QuarantineResult:
        now = time.time()
        moved = 0
        with self._lock, self._transaction() as connection:
            for seq, reason in reasons.items():
                moved += connection.execute(
                    "INSERT INTO quarantine (event_id, payload, reason, quarantined_at) "
                    "SELECT event_id, payload, ?, ? FROM events WHERE seq = ?",
                    (reason[:2_000], now, seq),
                ).rowcount
                connection.execute("DELETE FROM events WHERE seq = ?", (seq,))
            overflow = self._count(connection, "quarantine") - self._max_quarantined
            evicted = 0
            if overflow > 0:
                evicted = connection.execute(
                    "DELETE FROM quarantine WHERE seq IN "
                    "(SELECT seq FROM quarantine ORDER BY seq LIMIT ?)",
                    (overflow,),
                ).rowcount
                connection.execute(
                    "INSERT INTO counters (name, value) VALUES (?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET value = value + excluded.value",
                    (QUARANTINE_EVICTED, evicted),
                )
        return QuarantineResult(moved=moved, evicted=evicted)

    def _checkpoint(self, key: str) -> str | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT value FROM checkpoints WHERE key = ?", (key,)
            ).fetchone()
        return None if row is None else str(row[0])

    def _stats(self) -> SpoolStats:
        with self._lock:
            evicted = self._connection.execute(
                "SELECT value FROM counters WHERE name = ?", (QUARANTINE_EVICTED,)
            ).fetchone()
            return SpoolStats(
                queued=self._count(self._connection, "events"),
                capacity=self._capacity,
                quarantined=self._count(self._connection, "quarantine"),
                quarantine_evicted=0 if evicted is None else int(evicted[0]),
            )

    def _quarantined(self, limit: int) -> list[tuple[str, str]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT event_id, reason FROM quarantine ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
        return [(str(event_id), str(reason)) for event_id, reason in rows]

    def _check_key(self) -> None:
        """Prove the cipher opens this spool, recording the check on first use.

        A plaintext check is upgraded when encryption is turned on (records written
        before stay readable); an encrypted check refuses a cipher that cannot open it.
        """
        row = self._connection.execute(
            "SELECT value FROM meta WHERE name = ?", (_KEY_CHECK,)
        ).fetchone()
        if row is not None:
            if self._cipher.open(_KEY_CHECK, bytes(row[0])) != _KEY_CHECK_VALUE:
                raise SpoolKeyError("the spool key check does not match")
            if bytes(row[0]).startswith(HEADER) or isinstance(self._cipher, NoEncryption):
                return
        self._connection.execute(
            "INSERT INTO meta (name, value) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            (_KEY_CHECK, self._cipher.seal(_KEY_CHECK, _KEY_CHECK_VALUE)),
        )

    def _transaction(self) -> "_Transaction":
        return _Transaction(self._connection)

    @staticmethod
    def _count(connection: sqlite3.Connection, table: str) -> int:
        row = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # noqa: S608 - fixed names
        return int(row[0])

    @staticmethod
    def _existing_ids(connection: sqlite3.Connection, event_ids: list[str]) -> set[str]:
        existing: set[str] = set()
        for chunk in _chunks(event_ids):
            placeholders = ",".join("?" * len(chunk))
            rows = connection.execute(
                f"SELECT event_id FROM events WHERE event_id IN ({placeholders})",  # noqa: S608
                chunk,
            ).fetchall()
            existing.update(str(row[0]) for row in rows)
        return existing


class _Transaction:
    """``BEGIN IMMEDIATE`` ... ``COMMIT``, rolled back if the block raises."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def __enter__(self) -> sqlite3.Connection:
        self._connection.execute("BEGIN IMMEDIATE")
        return self._connection

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._connection.execute("ROLLBACK" if exc_type else "COMMIT")


def _chunks[T](items: list[T]) -> list[list[T]]:
    return [items[start : start + _SQLITE_BATCH] for start in range(0, len(items), _SQLITE_BATCH)]


def _set_aside(path: Path) -> Path:
    """Rename a spool and its WAL files to ``*.corrupt-<UTC time>``; the new main path."""
    suffix = f".corrupt-{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
    for companion in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        if companion.exists():
            companion.rename(companion.with_name(companion.name + suffix))
    return path.with_name(path.name + suffix)
