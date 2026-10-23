"""Orchestration of the Phase 1 verification: services, scenarios and checks."""

import asyncio
import contextlib
import logging
import os
import platform
import secrets
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import UUID, uuid4

from pydantic import SecretStr
from sqlalchemy import text

from apps.agent.identity import IDENTITY_FILE, prepare_data_directory
from packages.config import DatabaseSettings, KafkaSettings
from packages.database import Database
from packages.kafka import KafkaProducer, ensure_topics
from tests.e2e.phase1.generator import (
    CATEGORIES,
    GeneratedEvent,
    InvalidEvent,
    TelemetryGenerator,
)
from tests.e2e.phase1.infrastructure import (
    Container,
    IngestClient,
    ServiceProcess,
    TopicObserver,
    free_port,
    stored_counts,
    stored_payload,
)
from tests.e2e.phase1.ledger import Observations, Outcome, ScenarioResult

logger = logging.getLogger("adis.verification")

ROOT: Final = Path(__file__).resolve().parents[3]
CLIENT_ID: Final = "phase1-verifier"
NORMALIZER_GROUP: Final = "adis-normalizer"
AGENT_NAME: Final = "phase1-agent"
AGENT_LINES_PER_STEP: Final = 40

SERVICE_SETTINGS: Final[dict[str, str]] = {
    "APP_ENV": "test",
    "LOG_LEVEL": "INFO",
    "API_MAX_BATCH_SIZE": "500",
    "API_RATE_LIMIT_EVENTS": "1000000",
    "API_PUBLISH_TIMEOUT_SECONDS": "5",
    "NORMALIZER_CONSUMER_GROUP": NORMALIZER_GROUP,
    "NORMALIZER_POLL_TIMEOUT_MS": "200",
    "NORMALIZER_RETRY_MAX_BACKOFF_SECONDS": "5",
}
"""Service settings used for the run (everything else keeps its default)."""


@dataclass(frozen=True, slots=True)
class VerificationConfig:
    """What to verify against and how hard.

    Attributes:
        bootstrap_servers: Kafka bootstrap servers (a disposable broker).
        database_url: A disposable PostgreSQL migrated by the run.
        kafka_container: Docker container of the broker, for the Kafka outage.
        database_container: Docker container of the database, for the database outage.
        run_dir: Where service logs and the JSON report go.
        batch_events: Events of the batch scenario.
        outage_events: Events sent during each outage.
        outage_seconds: How long each dependency stays down.
        settle_seconds: Upper bound for the pipeline to catch up after each scenario.
        faults: Whether to run the two outage scenarios.
    """

    bootstrap_servers: str
    database_url: SecretStr
    kafka_container: str
    database_container: str
    run_dir: Path
    batch_events: int = 300
    outage_events: int = 100
    outage_seconds: float = 15.0
    settle_seconds: float = 180.0
    faults: bool = True


@dataclass(slots=True)
class VerificationRun:
    """Everything the report needs."""

    run_id: str
    started_at: datetime
    config: VerificationConfig
    environment: dict[str, str] = field(default_factory=dict)
    scenarios: list[ScenarioResult] = field(default_factory=list)
    global_checks: ScenarioResult = field(
        default_factory=lambda: ScenarioResult("global", "Whole-run invariants")
    )
    observations: Observations = field(default_factory=Observations)
    api_retries: dict[str, int] = field(default_factory=dict)
    normalizer_log: dict[str, int] = field(default_factory=dict)
    duration_seconds: float = 0.0

    @property
    def passed(self) -> bool:
        """Whether every check of every scenario passed."""
        return self.global_checks.passed and all(result.passed for result in self.scenarios)


@dataclass(frozen=True, slots=True)
class AgentRows:
    """Stored events carrying one run's agent log lines."""

    total: int
    distinct_ids: int
    distinct_lines: int
    linked: int


class Verification:
    """Runs the scenarios against real services and collects the evidence."""

    def __init__(self, config: VerificationConfig) -> None:
        self.config = config
        run_id = f"p1-{datetime.now(UTC):%Y%m%dT%H%M%S}-{secrets.token_hex(3)}"
        self.run = VerificationRun(run_id=run_id, started_at=datetime.now(UTC), config=config)
        self.generator = TelemetryGenerator(run_id)
        self._token = secrets.token_urlsafe(32)
        # _env_file=None: the verifier, like its services, never reads the developer's .env.
        self._kafka = KafkaSettings(
            _env_file=None,
            kafka_bootstrap_servers=config.bootstrap_servers,
            kafka_client_id=CLIENT_ID,
        )
        self._database = Database.from_settings(
            DatabaseSettings(_env_file=None, supabase_db_url=config.database_url),
            application_name=CLIENT_ID,
        )
        self._producer = KafkaProducer.from_settings(self._kafka, client_id=CLIENT_ID)
        self._observer = TopicObserver(config.bootstrap_servers, run_id, self.run.observations)
        self._api_port = free_port()
        logs = config.run_dir / run_id
        # A real agent, with an agent-bound token: it may only submit its own events.
        self._agent_id = uuid4()
        self._agent_token = secrets.token_urlsafe(32)
        self._agent_data = logs / "agent-data"
        self._agent_input = logs / "agent-input.log"
        self._api = ServiceProcess("api", "apps.api", self._api_environment(), logs / "api.log")
        self._normalizer = ServiceProcess(
            "normalizer", "apps.normalizer", self._normalizer_environment(), logs / "normalizer.log"
        )
        self._client = IngestClient(
            f"http://127.0.0.1:{self._api_port}", self._token, deadline_seconds=240
        )
        self._agent = ServiceProcess(
            "agent", "apps.agent", self._agent_environment(), logs / "agent.log", args=["run"]
        )
        self._batch_events: list[GeneratedEvent] = []
        self._single_events: list[GeneratedEvent] = []

    # ------------------------------------------------------------------- lifecycle

    async def execute(self) -> VerificationRun:
        """Prepare, run every scenario, check the invariants and clean up."""
        started = time.monotonic()
        try:
            await self._prepare()
            scenarios: list[Callable[[], Awaitable[ScenarioResult]]] = [
                self.single,
                self.batch,
                self.invalid,
                self.duplicate,
                self.agent,
            ]
            if self.config.faults:
                scenarios += [self.database_outage, self.kafka_outage]
            for scenario in scenarios:
                result = await scenario()
                self.run.scenarios.append(result)
                logger.info(
                    "scenario finished: %s (%s)", result.name, "pass" if result.passed else "FAIL"
                )
            await self._global_checks()
        finally:
            self.run.api_retries = dict(self._client.retried_statuses)
            self.run.normalizer_log = self._normalizer_log_summary()
            await self._teardown()
            self.run.duration_seconds = time.monotonic() - started
        return self.run

    async def _prepare(self) -> None:
        await self._migrate()
        await ensure_topics(self._kafka)
        await self._producer.start()
        await self._observer.start(
            {topic: await self._producer.partitions_for(topic) for topic in TopicObserver.TOPICS}
        )
        await self._api.start()
        await self._normalizer.start()
        await self._wait_until_ready()
        await self._normalizer.wait_for_log("kafka_consumer_started", limit_seconds=60)
        await self._drain_backlog()
        self.run.environment = await self._describe_environment()

    async def _migrate(self) -> None:
        # Run outside the repository, so the developer's .env is not read.
        self.config.run_dir.mkdir(parents=True, exist_ok=True)
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(ROOT / "alembic.ini"),
            "upgrade",
            "head",
            cwd=self.config.run_dir,
            env={
                **os.environ,  # Windows sockets need SYSTEMROOT and friends
                **self._environment(
                    {"SUPABASE_DB_URL": self.config.database_url.get_secret_value()}
                ),
            },
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output, _ = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"migrations failed:\n{output.decode(errors='replace')}")

    async def _drain_backlog(self) -> None:
        """Let the normalizer finish records left from earlier runs, so latency is clean."""
        canary = self.generator.event("system", "warm-up")
        await self._client.send_one(canary, scenario="warm-up")
        await self._wait(lambda: canary.event_id in self.run.observations.published, 120)
        quiet_since, processed = time.monotonic(), -1
        async with asyncio.timeout(120):
            while time.monotonic() - quiet_since < 3:
                current = self._normalizer.count_actions("normalizer_batch_processed")
                if current != processed:
                    quiet_since, processed = time.monotonic(), current
                await asyncio.sleep(0.5)

    async def _teardown(self) -> None:
        await self._agent.stop()
        await self._client.close()
        await self._normalizer.stop()
        await self._api.stop()
        await self._observer.stop()
        await self._producer.stop()
        await self._database.dispose()

    # ------------------------------------------------------------------- scenarios

    async def single(self) -> ScenarioResult:
        """One event of each category, each in its own request."""
        result = self._begin("single", "Single events (POST /api/v1/events)")
        for category in CATEGORIES:
            event = self.generator.event(category, result.name)
            self._single_events.append(event)
            result.submissions.append(await self._client.send_one(event, scenario=result.name))
        await self._settle(result, result.unique_accepted())
        await self._check_delivered(result, expected=len(CATEGORIES))
        payload = await stored_payload(self._database, self._single_events[0].event_id)
        metadata = payload.get("metadata") if payload else None
        ingestion = metadata.get("adis_ingestion") if isinstance(metadata, dict) else None
        result.check(
            "ingestion metadata stored",
            isinstance(ingestion, dict) and ingestion.get("ingest_client") == CLIENT_ID,
            f"metadata.adis_ingestion = {ingestion}",
        )
        return self._end(result)

    async def batch(self) -> ScenarioResult:
        """Mixed-category batches (POST /api/v1/events/batch)."""
        result = self._begin("batch", "Batches of 100 mixed events (POST /api/v1/events/batch)")
        events = self.generator.events(self.config.batch_events, result.name)
        self._batch_events = events
        for start in range(0, len(events), 100):
            chunk = events[start : start + 100]
            result.submissions.extend(await self._client.send_batch(chunk, scenario=result.name))
        await self._settle(result, result.unique_accepted())
        await self._check_delivered(result, expected=len(events))
        categories = {item.category for item in result.submissions}
        result.check(
            "every category delivered",
            categories == set(CATEGORIES),
            f"categories: {sorted(c for c in categories if c)}",
        )
        return self._end(result)

    async def invalid(self) -> ScenarioResult:
        """Invalid events at the API, a partial batch, and poison records behind the API."""
        result = self._begin("invalid", "Invalid events and poison records")
        invalid = self.generator.invalid_events(result.name)
        for event in invalid:
            result.submissions.append(await self._client.send_one(event, scenario=result.name))
        rejected = result.submissions[: len(invalid)]
        wrong = [
            f"{event.reason}: {submission.status} {submission.issues}"
            for event, submission in zip(invalid, rejected, strict=True)
            if submission.status != 422
            or not any(event.field_name in issue for issue in submission.issues)
        ]
        result.check(
            "invalid events rejected with 422 naming the field",
            not wrong,
            f"{len(invalid)} rejected" if not wrong else "; ".join(wrong),
        )

        valid = self.generator.events(7, result.name)
        mixed: list[GeneratedEvent | InvalidEvent] = [
            *valid[:3],
            invalid[0],
            *valid[3:5],
            invalid[1],
            invalid[2],
            *valid[5:],
        ]
        partial = await self._client.send_batch(mixed, scenario=result.name)
        result.submissions.extend(partial)
        accepted = [item for item in partial if item.outcome is Outcome.ACCEPTED]
        refused = [index for index, item in enumerate(partial) if item.outcome is Outcome.REJECTED]
        result.check(
            "partial batch: valid events accepted, invalid ones rejected by index",
            len(accepted) == 7 and refused == [3, 6, 7],
            f"accepted {len(accepted)}, rejected indices {refused}",
        )

        poison = self.generator.poison_records(result.name)
        for record in poison:
            await self._producer.send_raw(record.topic, record.value, key=None, headers=[])
            result.poison_markers.append(record.marker)
        await self._settle(result, [item.event_id for item in accepted])
        await self._wait(
            lambda: self._dead_lettered(result) >= len(poison), self.config.settle_seconds
        )
        await self._refresh_stored()
        await self._check_delivered(result, expected=7)
        seen = [
            dead
            for dead in self.run.observations.dead_letters
            if dead.marker in result.poison_markers
        ]
        result.check(
            "poison records dead-lettered by the normalizer",
            {dead.marker for dead in seen} == set(result.poison_markers)
            and all(dead.consumer_group == NORMALIZER_GROUP for dead in seen),
            ", ".join(sorted(f"{dead.error_type} from {dead.original_topic}" for dead in seen)),
        )
        stored_poison = [
            record.reason
            for record in poison
            if record.event_id is not None
            and await stored_payload(self._database, record.event_id) is not None
        ]
        result.check("poison records never stored", not stored_poison, str(stored_poison or "none"))
        return self._end(result)

    async def duplicate(self) -> ScenarioResult:
        """Re-submissions of stored events, and duplicates inside one batch."""
        result = self._begin("duplicate", "Duplicate submissions")
        resent = self._batch_events[:50]
        before = {event.event_id: self._publications(event.event_id) for event in resent}
        result.submissions.extend(
            await self._client.send_batch(resent, scenario=result.name, duplicate=True)
        )
        repeated = self._single_events[-1]
        before[repeated.event_id] = self._publications(repeated.event_id)
        for _ in range(2):
            result.submissions.append(
                await self._client.send_one(repeated, scenario=result.name, duplicate=True)
            )
        fresh = self.generator.events(10, result.name)
        pairs = [event for event in fresh for _ in range(2)]
        submissions = await self._client.send_batch(pairs, scenario=result.name)
        for index, submission in enumerate(submissions):
            submission.duplicate = index % 2 == 1
        result.submissions.extend(submissions)

        await self._settle(result, result.unique_accepted())
        await asyncio.sleep(3)  # let any wrongly re-published duplicate arrive
        await self._refresh_stored()
        stored = self.run.observations.stored
        involved = [*before, *(event.event_id for event in fresh)]
        result.check(
            "API accepted every duplicate (deduplication is the pipeline's job)",
            all(item.outcome is Outcome.ACCEPTED for item in result.submissions),
            f"{sum(item.duplicate for item in result.submissions)} duplicate submissions",
        )
        result.check(
            "duplicates created no database rows",
            all(stored.get(event_id) == 1 for event_id in involved),
            f"rows per event: {sorted({stored.get(event_id, 0) for event_id in involved})}",
        )
        republished = [
            event_id for event_id, count in before.items() if self._publications(event_id) != count
        ]
        result.check(
            "already stored events were not published again",
            not republished,
            f"{len(republished)} re-published of {len(before)}",
        )
        doubled = [event.event_id for event in fresh if self._publications(event.event_id) != 1]
        result.check(
            "duplicates inside one batch were published once",
            not doubled,
            f"{len(fresh) - len(doubled)} of {len(fresh)} published exactly once",
        )
        return self._end(result)

    async def agent(self) -> ScenarioResult:
        """A real agent tails a log file through an API outage and its own crash.

        Without faults, only registration and delivery are checked.
        """
        result = self._begin("agent", "Endpoint agent: registration, API outage, crash")
        marker = f"{self.run.run_id}-agent"
        written = 0
        # The identity is created up front, so the API can bind the agent's token to it.
        identity = prepare_data_directory(self._agent_data) / IDENTITY_FILE
        identity.write_text(f"{self._agent_id}\n", encoding="utf-8")
        self._agent_input.touch()
        await self._agent.start()
        await self._agent.wait_for_log("agent_registered", limit_seconds=60)
        agent_row = await self._wait_for_agent_row()
        written += self._append_lines(marker, "steady", AGENT_LINES_PER_STEP)
        await self._wait_for_agent_lines(result, marker, written)

        if self.config.faults:
            retries_before = self._agent.count_actions("agent_send_retry")
            await self._api.stop()
            result.notes.append("API process stopped")
            written += self._append_lines(marker, "api-outage", AGENT_LINES_PER_STEP)
            await asyncio.sleep(self.config.outage_seconds)
            retries = self._agent.count_actions("agent_send_retry") - retries_before
            alive_during_outage = self._agent.alive
            await self._api.start()
            await self._wait_until_ready()
            result.notes.append(
                f"API restarted after {self.config.outage_seconds:.0f} s; the agent logged "
                f"{retries} send retries meanwhile"
            )
            result.check(
                "agent kept its events and retried while the API was down",
                alive_during_outage and retries > 0,
                f"alive={alive_during_outage}, {retries} retries",
            )
            written += self._append_lines(marker, "agent-crash", AGENT_LINES_PER_STEP)
            await asyncio.sleep(0.3)  # read and spooled, not necessarily sent yet
            await self._agent.kill()
            result.notes.append("agent killed 0.3 s after writing lines, then restarted")
            await self._agent.start()

        rows = await self._wait_for_agent_lines(result, marker, written)
        await self._agent.stop()
        result.notes.append(
            f"{written} log lines written and sent by the agent itself (the columns of the "
            "results table count the verifier's own submissions only)"
        )
        agent_after = await self._agent_row()
        result.check(
            "agent registered in adis.agents",
            agent_row is not None and agent_row[0] == AGENT_NAME and agent_row[1] == "active",
            f"name, status = {agent_row[:2] if agent_row else None}",
        )
        result.check(
            "every log line stored exactly once",
            rows.total == rows.distinct_ids == rows.distinct_lines == written,
            f"{rows.total} rows, {rows.distinct_ids} event ids, {rows.distinct_lines} lines "
            f"of {written} written",
        )
        result.check(
            "events linked to the registered agent",
            rows.linked == written,
            f"{rows.linked} of {written}",
        )
        result.check(
            "last_seen advanced with the agent's telemetry",
            agent_after is not None and agent_after[3] > agent_after[2],
            f"first_seen={agent_after[2] if agent_after else None}, "
            f"last_seen={agent_after[3] if agent_after else None}",
        )
        return self._end(result)

    async def database_outage(self) -> ScenarioResult:
        """The database stops while events keep arriving, then comes back."""
        result = self._begin("database_outage", "Temporary database failure")
        container = Container(self.config.database_container)
        retries_before = self._normalizer.count_actions("normalizer_retry")
        await container.stop()
        down_at = time.monotonic()
        result.notes.append(f"database container '{container.name}' stopped")
        events = self.generator.events(self.config.outage_events, result.name)
        for start in range(0, len(events), 50):
            result.submissions.extend(
                await self._client.send_batch(events[start : start + 50], scenario=result.name)
            )
        await asyncio.sleep(max(0.0, self.config.outage_seconds - (time.monotonic() - down_at)))
        await container.start()
        restarted_at = time.monotonic()
        healthy = await container.wait_healthy(120)
        result.notes.append(
            f"down for {restarted_at - down_at:.1f} s; healthy {healthy:.1f} s after the restart"
        )
        await self._settle(result, result.unique_accepted())
        recovered = self._last_published(result.unique_accepted())
        if recovered is not None:
            result.notes.append(
                f"the {len(events)} queued events were normalized and stored within "
                f"{recovered - restarted_at:.1f} s of the restart"
            )
        retries = self._normalizer.count_actions("normalizer_retry") - retries_before
        result.check(
            "API kept accepting while the database was down",
            all(item.outcome is Outcome.ACCEPTED for item in result.submissions),
            f"{len(result.unique_accepted())} accepted",
        )
        result.check(
            "normalizer retried instead of dead-lettering", retries > 0, f"{retries} retries logged"
        )
        await self._check_delivered(result, expected=len(events))
        result.check("normalizer survived the outage", self._normalizer.alive, "process running")
        return self._end(result)

    async def kafka_outage(self) -> ScenarioResult:
        """The broker stops while clients send, then comes back."""
        result = self._begin("kafka_outage", "Temporary Kafka failure")
        container = Container(self.config.kafka_container)
        retried_before = sum(self._client.retried_statuses.values())
        await container.stop()
        down_at = time.monotonic()
        result.notes.append(f"Kafka container '{container.name}' stopped")
        events = self.generator.events(self.config.outage_events, result.name)
        chunks = [events[start : start + 25] for start in range(0, len(events), 25)]
        sending = [
            asyncio.create_task(self._client.send_batch(chunk, scenario=result.name))
            for chunk in chunks
        ]
        await asyncio.sleep(self.config.outage_seconds)
        ready_during_outage = await self._client.ready()
        await container.start()
        restarted_at = time.monotonic()
        healthy = await container.wait_healthy(180)
        result.notes.append(
            f"down for {restarted_at - down_at:.1f} s; healthy {healthy:.1f} s after the restart"
        )
        for task in sending:
            result.submissions.extend(await task)
        await self._settle(result, result.unique_accepted())
        recovered = self._last_published(result.unique_accepted())
        if recovered is not None:
            result.notes.append(
                f"all {len(events)} events accepted, normalized and stored within "
                f"{recovered - restarted_at:.1f} s of the restart"
            )
        retried = sum(self._client.retried_statuses.values()) - retried_before
        result.check(
            "API reported not ready while Kafka was down",
            not ready_during_outage,
            "GET /ready -> 503" if not ready_during_outage else "GET /ready -> 200",
        )
        result.check(
            "clients were told to retry (503) instead of losing events",
            retried > 0,
            f"{retried} retried requests: {self._client.retried_statuses}",
        )
        result.check(
            "every event accepted after recovery",
            all(item.outcome is Outcome.ACCEPTED for item in result.submissions),
            f"{sum(item.outcome is Outcome.ACCEPTED for item in result.submissions)} of "
            f"{len(result.submissions)}",
        )
        await self._check_delivered(result, expected=len(events))
        result.check(
            "API and normalizer survived the outage",
            self._api.alive and self._normalizer.alive,
            f"api alive={self._api.alive}, normalizer alive={self._normalizer.alive}",
        )
        return self._end(result)

    # ---------------------------------------------------------------------- checks

    async def _global_checks(self) -> None:
        checks = self.run.global_checks
        await self._refresh_stored()
        stored = self.run.observations.stored
        unique = [
            event_id for result in self.run.scenarios for event_id in result.unique_accepted()
        ]
        missing = [event_id for event_id in unique if event_id not in stored]
        unpublished = [
            event_id for event_id in unique if event_id not in self.run.observations.published
        ]
        checks.check(
            "no accepted event lost (stored)",
            not missing,
            f"{len(missing)} missing of {len(unique)}",
        )
        checks.check(
            "no accepted event lost (normalized)",
            not unpublished,
            f"{len(unpublished)} missing of {len(unique)}",
        )
        extra = {event_id: count for event_id, count in stored.items() if count != 1}
        checks.check("exactly one row per event", not extra, f"{len(extra)} events with != 1 row")
        unexpected = [dead for dead in self.run.observations.dead_letters if not dead.marker]
        checks.check(
            "no valid event dead-lettered",
            not unexpected,
            f"{len(unexpected)} unexpected dead letters",
        )
        duplicates_in_db = await self._duplicate_event_ids()
        checks.check(
            "unique event_id enforced by the database",
            duplicates_in_db == 0,
            f"{duplicates_in_db} duplicates",
        )

    async def _check_delivered(self, result: ScenarioResult, *, expected: int) -> None:
        await self._refresh_stored()
        unique = result.unique_accepted()
        observations = self.run.observations
        result.check("accepted", len(unique) == expected, f"{len(unique)} of {expected}")
        normalized = [event_id for event_id in unique if event_id in observations.published]
        result.check(
            "normalized to adis.security.events",
            len(normalized) == len(unique),
            f"{len(normalized)} of {len(unique)}",
        )
        once = [event_id for event_id in unique if observations.stored.get(event_id) == 1]
        result.check(
            "stored exactly once", len(once) == len(unique), f"{len(once)} of {len(unique)}"
        )

    # --------------------------------------------------------------------- helpers

    def _append_lines(self, marker: str, step: str, count: int) -> int:
        with self._agent_input.open("a", encoding="utf-8", newline="\n") as log:
            for number in range(count):
                log.write(f"phase1 {marker} {step} line {number} user=verifier status=ok\n")
        return count

    async def _agent_row(self) -> tuple[str, str, datetime, datetime] | None:
        statement = text(
            "SELECT name, status, first_seen, last_seen FROM adis.agents WHERE id = :id"
        )
        async with self._database.session() as session:
            row = (await session.execute(statement, {"id": self._agent_id})).one_or_none()
        return None if row is None else (str(row[0]), str(row[1]), row[2], row[3])

    async def _wait_for_agent_row(self) -> tuple[str, str, datetime, datetime] | None:
        found: list[tuple[str, str, datetime, datetime]] = []

        async def registered() -> bool:
            row = await self._agent_row()
            if row is not None:
                found.append(row)
            return row is not None

        with contextlib.suppress(TimeoutError):
            await self._wait_async(registered, 60)
        return found[-1] if found else None

    async def _agent_lines(self, marker: str) -> AgentRows:
        statement = text(
            "SELECT count(*), count(DISTINCT event_id), "
            "count(DISTINCT payload -> 'metadata' ->> 'message'), "
            "count(*) FILTER (WHERE agent_id = :agent) "
            "FROM adis.security_events WHERE payload -> 'metadata' ->> 'message' LIKE :pattern"
        )
        parameters = {"agent": self._agent_id, "pattern": f"%{marker}%"}
        async with self._database.session() as session:
            row = (await session.execute(statement, parameters)).one()
        return AgentRows(int(row[0]), int(row[1]), int(row[2]), int(row[3]))

    async def _wait_for_agent_lines(
        self, result: ScenarioResult, marker: str, expected: int
    ) -> AgentRows:
        latest: list[AgentRows] = []

        async def stored() -> bool:
            latest.append(await self._agent_lines(marker))
            return latest[-1].distinct_lines >= expected

        try:
            await self._wait_async(stored, self.config.settle_seconds)
        except TimeoutError:
            result.notes.append(
                f"agent lines not all stored within {self.config.settle_seconds:.0f} s"
            )
        return latest[-1] if latest else await self._agent_lines(marker)

    async def _wait_until_ready(self) -> None:
        async with asyncio.timeout(60):
            while not await self._client.ready():
                if not self._api.alive:
                    raise RuntimeError(f"the API exited with code {self._api.exit_code}")
                await asyncio.sleep(0.5)

    def _begin(self, name: str, title: str) -> ScenarioResult:
        logger.info("scenario started: %s", name)
        return ScenarioResult(name, title, started=time.monotonic())

    @staticmethod
    def _end(result: ScenarioResult) -> ScenarioResult:
        result.finished = time.monotonic()
        return result

    async def _settle(self, result: ScenarioResult, expected: Sequence[UUID]) -> None:
        """Wait until every expected event is published and stored (or the time is up)."""
        pending = set(expected)

        async def settled() -> bool:
            published = self.run.observations.published
            if not pending.issubset(published):
                return False
            await self._refresh_stored()
            return pending.issubset(self.run.observations.stored)

        try:
            await self._wait_async(settled, self.config.settle_seconds)
        except TimeoutError:
            result.notes.append(
                f"pipeline did not settle within {self.config.settle_seconds:.0f} s"
            )

    async def _wait(self, condition: Callable[[], bool], limit_seconds: float) -> None:
        async def check() -> bool:
            return condition()

        await self._wait_async(check, limit_seconds)

    @staticmethod
    async def _wait_async(condition: Callable[[], Awaitable[bool]], limit_seconds: float) -> None:
        async with asyncio.timeout(limit_seconds):
            while True:
                if await condition():
                    return
                await asyncio.sleep(0.25)

    async def _refresh_stored(self) -> None:
        self.run.observations.stored = await stored_counts(self._database, self.run.run_id)

    async def _duplicate_event_ids(self) -> int:
        statement = text(
            "SELECT count(*) FROM (SELECT event_id FROM adis.security_events "
            "GROUP BY event_id HAVING count(*) > 1) AS duplicated"
        )
        async with self._database.session() as session:
            return int((await session.execute(statement)).scalar_one())

    def _publications(self, event_id: UUID) -> int:
        return self.run.observations.publication_count(event_id)

    def _last_published(self, event_ids: Sequence[UUID]) -> float | None:
        times = [
            seen
            for event_id in event_ids
            if (seen := self.run.observations.first_published(event_id)) is not None
        ]
        return max(times) if times else None

    def _dead_lettered(self, result: ScenarioResult) -> int:
        markers = set(result.poison_markers)
        return len(
            {dead.marker for dead in self.run.observations.dead_letters if dead.marker in markers}
        )

    def _normalizer_log_summary(self) -> dict[str, int]:
        actions = (
            "normalizer_batch_processed",
            "normalizer_retry",
            "normalizer_batch_isolated",
            "normalizer_record_dead_lettered",
            "kafka_commit_failed",
            "normalizer_unexpected_error",
        )
        return {action: self._normalizer.count_actions(action) for action in actions}

    async def _describe_environment(self) -> dict[str, str]:
        async with self._database.session() as session:
            postgres = str((await session.execute(text("SHOW server_version"))).scalar_one())
        return {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "postgresql": postgres,
            "kafka_bootstrap": self.config.bootstrap_servers,
            "kafka_container": self.config.kafka_container,
            "database_container": self.config.database_container,
        }

    def _environment(self, extra: dict[str, str]) -> dict[str, str]:
        return {
            **SERVICE_SETTINGS,
            "KAFKA_BOOTSTRAP_SERVERS": self.config.bootstrap_servers,
            **extra,
        }

    def _api_environment(self) -> dict[str, str]:
        return self._environment(
            {
                "APP_NAME": "adis-api",
                "KAFKA_CLIENT_ID": "adis-api",
                "API_HOST": "127.0.0.1",
                "API_PORT": str(self._api_port),
                "API_INGEST_TOKENS": (
                    f"{CLIENT_ID}:{self._token},agent-{self._agent_id}:{self._agent_token}"
                ),
            }
        )

    def _agent_environment(self) -> dict[str, str]:
        return {
            "APP_ENV": "test",
            "LOG_LEVEL": "INFO",
            "APP_NAME": "adis-agent",
            "AGENT_SERVER_URL": f"http://127.0.0.1:{self._api_port}",
            "AGENT_TOKEN": self._agent_token,
            "AGENT_NAME": AGENT_NAME,
            "AGENT_DATA_DIR": str(self._agent_data),
            "AGENT_LOG_FILES": str(self._agent_input),
            "AGENT_LOG_READ_FROM_START": "true",
            "AGENT_LOG_POLL_INTERVAL_SECONDS": "0.2",
            "AGENT_FLUSH_INTERVAL_SECONDS": "0.5",
            "AGENT_RETRY_INITIAL_BACKOFF_SECONDS": "0.2",
            "AGENT_RETRY_MAX_BACKOFF_SECONDS": "2",
        }

    def _normalizer_environment(self) -> dict[str, str]:
        return self._environment(
            {
                "APP_NAME": "adis-normalizer",
                "KAFKA_CLIENT_ID": "adis-normalizer",
                "SUPABASE_DB_URL": self.config.database_url.get_secret_value(),
            }
        )
