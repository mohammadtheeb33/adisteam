"""Services, containers, observers and the API client used by the verification."""

import asyncio
import contextlib
import json
import logging
import os
import socket
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import BinaryIO, Final
from uuid import UUID

import httpx2
from aiokafka import AIOKafkaConsumer, TopicPartition
from sqlalchemy import text

from packages.database import Database
from packages.kafka import DeadLetterHeader, Topic
from tests.e2e.phase1.generator import GeneratedEvent, InvalidEvent, batch_body
from tests.e2e.phase1.ledger import DeadLetterSeen, Observations, Outcome, Submission

logger = logging.getLogger("adis.verification")
ROOT: Final = Path(__file__).resolve().parents[3]

_RETRIABLE_STATUSES: Final = frozenset({429, 500, 502, 503, 504})


# ------------------------------------------------------------------------ containers


class DockerError(RuntimeError):
    """A docker CLI command failed."""


async def docker(*arguments: str) -> str:
    """Run ``docker <arguments>`` and return its output."""
    process = await asyncio.create_subprocess_exec(
        "docker",
        *arguments,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    output, errors = await process.communicate()
    if process.returncode != 0:
        raise DockerError(
            f"docker {arguments[0]} failed: {errors.decode(errors='replace').strip()}"
        )
    return output.decode().strip()


class Container:
    """A running infrastructure container, for fault injection."""

    def __init__(self, name: str) -> None:
        self.name = name

    async def stop(self) -> None:
        """Stop the container (a clean shutdown, like a restart or an outage)."""
        await docker("stop", "--time", "10", self.name)

    async def start(self) -> None:
        """Start the stopped container."""
        await docker("start", self.name)

    async def health(self) -> str:
        """The container's health status (``healthy``, ``starting``...)."""
        return await docker("inspect", "--format", "{{.State.Health.Status}}", self.name)

    async def wait_healthy(self, limit_seconds: float) -> float:
        """Wait until healthy; returns the seconds waited."""
        started = time.monotonic()
        async with asyncio.timeout(limit_seconds):
            while True:
                if await self.health() == "healthy":
                    return time.monotonic() - started
                await asyncio.sleep(1)


# -------------------------------------------------------------------------- services


def free_port() -> int:
    """A free local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


class ServiceProcess:
    """An ADIS service run as ``python -m <module> [args]``, logging JSON lines to a file.

    It can be started again after :meth:`stop` or :meth:`kill`; the log is appended to.
    """

    def __init__(
        self,
        name: str,
        module: str,
        env: Mapping[str, str],
        log_path: Path,
        *,
        args: Sequence[str] = (),
    ) -> None:
        self.name = name
        self.module = module
        self.args = tuple(args)
        self.env = dict(env)
        self.log_path = log_path
        self._process: asyncio.subprocess.Process | None = None
        self._log_file: BinaryIO | None = None

    async def start(self) -> None:
        """Start the process in its log directory, with ``env`` over the inherited environment.

        It runs outside the repository, so a developer's ``.env`` (for example a hosted
        database's ``DB_SSL_MODE=require``) never leaks into the verification.
        """
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = self.log_path.open("ab")
        self._log_file = log_file
        self._process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            self.module,
            *self.args,
            cwd=self.log_path.parent,
            env={**os.environ, **self.env, "PYTHONPATH": str(ROOT)},
            stdout=log_file,
            stderr=asyncio.subprocess.STDOUT,
        )

    @property
    def alive(self) -> bool:
        """Whether the process is still running."""
        return self._process is not None and self._process.returncode is None

    @property
    def exit_code(self) -> int | None:
        """The exit code, once it exited."""
        return None if self._process is None else self._process.returncode

    async def stop(self) -> None:
        """Terminate the process and wait for it."""
        process = self._process
        if process is not None and process.returncode is None:
            process.terminate()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(process.wait(), timeout=15)
        self._close_log()

    async def kill(self) -> None:
        """Kill the process at once, like a crash or a power loss: no clean shutdown."""
        process = self._process
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        self._close_log()

    def _close_log(self) -> None:
        log_file = self._log_file
        if log_file is not None:
            log_file.close()
            self._log_file = None

    def log_records(self) -> list[dict[str, object]]:
        """Every JSON log line written so far."""
        records: list[dict[str, object]] = []
        if not self.log_path.exists():
            return records
        for line in self.log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            with contextlib.suppress(json.JSONDecodeError):
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    records.append(parsed)
        return records

    def count_actions(self, action: str) -> int:
        """Log lines whose ``action`` is ``action``."""
        return sum(1 for record in self.log_records() if record.get("action") == action)

    async def wait_for_log(self, action: str, limit_seconds: float) -> None:
        """Wait until a log line with ``action`` appears."""
        async with asyncio.timeout(limit_seconds):
            while not self.count_actions(action):
                if not self.alive:
                    raise RuntimeError(f"{self.name} exited with code {self.exit_code}")
                await asyncio.sleep(0.2)


# ------------------------------------------------------------------------- observers


class TopicObserver:
    """Reads ``adis.security.events`` and ``adis.deadletter`` from their end at start-up.

    It uses no consumer group (partitions are assigned directly), so broker restarts
    never rebalance it. Only records of this run are kept.
    """

    TOPICS: Final = (Topic.SECURITY_EVENTS, Topic.DEADLETTER)

    def __init__(self, bootstrap_servers: str, run_id: str, observations: Observations) -> None:
        self._bootstrap_servers = bootstrap_servers
        self._run_id = run_id
        self._marker = run_id.encode()
        self._observations = observations
        self._consumer: AIOKafkaConsumer | None = None
        self._task: asyncio.Task[None] | None = None

    async def start(self, partitions: Mapping[Topic, frozenset[int]]) -> None:
        """Position at the current end of both topics, then read in the background.

        Args:
            partitions: Partition ids of each observed topic.
        """
        consumer = AIOKafkaConsumer(
            bootstrap_servers=self._bootstrap_servers,
            enable_auto_commit=False,
            auto_offset_reset="latest",
            client_id="adis-phase1-verifier",
        )
        await consumer.start()
        try:
            assigned = [
                TopicPartition(topic.value, partition)
                for topic in self.TOPICS
                for partition in sorted(partitions[topic])
            ]
            consumer.assign(assigned)
            await consumer.seek_to_end(*assigned)
            for partition in assigned:
                await consumer.position(partition)  # resolve now, before anything is sent
        except BaseException:
            await consumer.stop()
            raise
        self._consumer = consumer
        self._task = asyncio.create_task(self._read(consumer))

    async def stop(self) -> None:
        """Stop reading."""
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        if self._consumer is not None:
            await self._consumer.stop()

    async def _read(self, consumer: AIOKafkaConsumer) -> None:
        while True:
            try:
                batches = await consumer.getmany(timeout_ms=200)
            except Exception:  # broker outages are expected; keep reading
                logger.warning("observer poll failed; retrying", exc_info=True)
                await asyncio.sleep(1)
                continue
            seen_at = time.monotonic()
            for partition, records in batches.items():
                for record in records:
                    if partition.topic == Topic.SECURITY_EVENTS.value:
                        self._published(record.value, seen_at)
                    else:
                        self._dead_letter(record.value, record.headers)

    def _published(self, value: bytes | None, seen_at: float) -> None:
        if value is None or self._marker not in value:
            return
        envelope = json.loads(value)
        verification = envelope["payload"].get("metadata", {}).get("verification", {})
        if verification.get("run") == self._run_id:
            event_id = UUID(envelope["event_id"])
            self._observations.published.setdefault(event_id, []).append(seen_at)

    def _dead_letter(self, value: bytes | None, headers: Sequence[tuple[str, bytes]]) -> None:
        if value is None or self._marker not in value:
            return
        text_value = value.decode(errors="replace")
        start = text_value.find(f"{self._run_id}-poison-")
        marker = text_value[start:].split('"', 1)[0].split(",", 1)[0] if start >= 0 else ""
        found = {name: raw.decode(errors="replace") for name, raw in headers}
        self._observations.dead_letters.append(
            DeadLetterSeen(
                marker=marker,
                original_topic=found.get(DeadLetterHeader.ORIGINAL_TOPIC, ""),
                error_type=found.get(DeadLetterHeader.ERROR_TYPE, ""),
                consumer_group=found.get(DeadLetterHeader.CONSUMER_GROUP, ""),
            )
        )


async def stored_counts(database: Database, run_id: str) -> dict[UUID, int]:
    """Rows per ``event_id`` of this run in ``adis.security_events``."""
    statement = text(
        "SELECT event_id, count(*) FROM adis.security_events "
        "WHERE payload -> 'metadata' -> 'verification' ->> 'run' = :run GROUP BY event_id"
    )
    async with database.session() as session:
        rows = await session.execute(statement, {"run": run_id})
        return {UUID(str(event_id)): int(count) for event_id, count in rows}


async def stored_payload(database: Database, event_id: UUID) -> dict[str, object] | None:
    """The stored canonical payload of ``event_id``."""
    statement = text("SELECT payload FROM adis.security_events WHERE event_id = :id")
    async with database.session() as session:
        value = (await session.execute(statement, {"id": event_id})).scalar_one_or_none()
    return value if isinstance(value, dict) else None


# ---------------------------------------------------------------------------- client


class IngestClient:
    """Submits events to the ingestion API like a resilient agent.

    ``429``, ``5xx`` and transport errors are retried with capped exponential backoff
    until ``deadline_seconds``; any other answer is final.
    """

    def __init__(self, base_url: str, token: str, *, deadline_seconds: float) -> None:
        self._client = httpx2.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=httpx2.Timeout(15.0),
        )
        self._deadline_seconds = deadline_seconds
        self.retried_statuses: dict[str, int] = {}

    async def close(self) -> None:
        """Close the connection pool."""
        await self._client.aclose()

    async def ready(self) -> bool:
        """Whether ``GET /ready`` answers 200."""
        try:
            return (await self._client.get("/ready")).status_code == 200
        except httpx2.TransportError:
            return False

    async def send_one(
        self, event: GeneratedEvent | InvalidEvent, *, scenario: str, duplicate: bool = False
    ) -> Submission:
        """``POST /api/v1/events`` with one event."""
        [submission] = await self._send(
            "/api/v1/events",
            json.dumps(event.document).encode(),
            [event],
            scenario=scenario,
            duplicate=duplicate,
        )
        return submission

    async def send_batch(
        self,
        events: Sequence[GeneratedEvent | InvalidEvent],
        *,
        scenario: str,
        duplicate: bool = False,
    ) -> list[Submission]:
        """``POST /api/v1/events/batch``."""
        return await self._send(
            "/api/v1/events/batch",
            batch_body(events),
            events,
            scenario=scenario,
            duplicate=duplicate,
        )

    async def _send(
        self,
        path: str,
        body: bytes,
        events: Sequence[GeneratedEvent | InvalidEvent],
        *,
        scenario: str,
        duplicate: bool,
    ) -> list[Submission]:
        started = time.monotonic()
        submissions = [
            Submission(
                event_id=event.event_id,
                scenario=scenario,
                category=event.category if isinstance(event, GeneratedEvent) else None,
                duplicate=duplicate,
                first_sent=started,
            )
            for event in events
        ]
        delay = 0.25
        attempts = 0
        while True:
            attempts += 1
            retry_reason: str | None = None
            try:
                response = await self._client.post(path, content=body)
            except httpx2.TransportError as error:
                retry_reason = type(error).__name__
            else:
                if response.status_code not in _RETRIABLE_STATUSES:
                    self._settle(submissions, response, attempts)
                    return submissions
                retry_reason = str(response.status_code)
            self.retried_statuses[retry_reason] = self.retried_statuses.get(retry_reason, 0) + 1
            if time.monotonic() - started + delay > self._deadline_seconds:
                for submission in submissions:
                    submission.attempts = attempts
                    submission.code = f"gave up after {retry_reason}"
                return submissions
            await asyncio.sleep(delay)
            delay = min(delay * 2, 5.0)

    @staticmethod
    def _settle(submissions: list[Submission], response: httpx2.Response, attempts: int) -> None:
        now = time.monotonic()
        body = response.json()
        for submission in submissions:
            submission.attempts = attempts
            submission.status = response.status_code
        if response.status_code == 202 and "accepted" in body:  # batch
            accepted = {item["index"] for item in body["accepted"]}
            rejected = {item["index"]: item for item in body["rejected"]}
            for index, submission in enumerate(submissions):
                if index in accepted:
                    submission.outcome, submission.accepted_at = Outcome.ACCEPTED, now
                else:
                    detail = rejected.get(index, {})
                    submission.outcome = Outcome.REJECTED
                    submission.code = detail.get("code")
                    submission.issues = tuple(detail.get("issues", ()))
            return
        if response.status_code == 202:  # single
            submissions[0].outcome, submissions[0].accepted_at = Outcome.ACCEPTED, now
            return
        error = body.get("error", {})
        details = {item.get("index"): item for item in error.get("details", [])}
        for index, submission in enumerate(submissions):
            detail = details.get(index) or details.get(None) or {}
            submission.outcome = Outcome.REJECTED
            submission.code = detail.get("code") or error.get("code")
            submission.issues = tuple(detail.get("issues", ()))
