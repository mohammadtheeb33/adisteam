"""Phase 1 real-data lab: start it, run the Windows agent against it, and report results.

Commands (run from the repository root with the project's virtual environment):

    python scripts/lab_phase1.py up                 # lab secrets, Kafka, PostgreSQL, schema,
                                                    # topics, pipeline, real telemetry sources
    python scripts/lab_phase1.py windows-agent --duration 240 [--pcap FILE ...]
    python scripts/lab_phase1.py report --out .adis-lab/results.json
    python scripts/lab_phase1.py scenario [--pcap FILE ...]  # the whole verification run
    python scripts/lab_phase1.py down               # remove the lab and its volumes

The lab (infrastructure/lab/compose.yaml) is a separate compose project with its own
database and broker; the developer's .env and any hosted Supabase project are never used.
Secrets are random, live in .adis-lab/lab.env (git-ignored) and are never printed.
"""

import argparse
import asyncio
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

REPO: Final = Path(__file__).resolve().parents[1]
LAB_DIR: Final = REPO / ".adis-lab"
LAB_ENV: Final = LAB_DIR / "lab.env"
COMPOSE: Final = ["docker", "compose", "-f", str(REPO / "infrastructure/lab/compose.yaml")]
KAFKA: Final = "127.0.0.1:19092"
API_URL: Final = "http://127.0.0.1:18000"
TOPICS: Final = (
    "system_logs",
    "auth_events",
    "network_flows",
    "adis.security.events",
    "adis.deadletter",
)


def _lab_secrets() -> dict[str, str]:
    """The lab's secrets, created once with ``secrets.token_urlsafe``."""
    LAB_DIR.mkdir(exist_ok=True)
    if not LAB_ENV.exists():
        values = {
            "LAB_DB_PASSWORD": secrets.token_urlsafe(24),
            "LAB_LINUX_AGENT_TOKEN": secrets.token_urlsafe(32),
            "LAB_WINDOWS_AGENT_TOKEN": secrets.token_urlsafe(32),
            "LAB_DURATION": "180",
        }
        LAB_ENV.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")
        LAB_ENV.chmod(0o600)
    entries = (line.partition("=") for line in LAB_ENV.read_text(encoding="utf-8").splitlines())
    return {key: value for key, _, value in entries if key}


def _database_url(lab: dict[str, str]) -> str:
    return f"postgresql+asyncpg://adis_lab:{lab['LAB_DB_PASSWORD']}@127.0.0.1:15432/adis_lab"


def _host_environment(lab: dict[str, str]) -> dict[str, str]:
    """Environment for host-side tools: lab services only, whatever the developer's .env says."""
    return {
        **os.environ,
        "APP_ENV": "development",
        "SUPABASE_DB_URL": _database_url(lab),
        "DB_SSL_MODE": "disable",
        "DB_TRANSACTION_POOLER": "false",
        "KAFKA_BOOTSTRAP_SERVERS": KAFKA,
        "KAFKA_SECURITY_PROTOCOL": "PLAINTEXT",
        "KAFKA_TOPIC_PARTITIONS": "3",
        "KAFKA_TOPIC_REPLICATION_FACTOR": "1",
    }


def _run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    sys.stdout.write("$ " + " ".join(command[:6]) + (" ..." if len(command) > 6 else "") + "\n")
    subprocess.run(command, check=True, cwd=REPO, env=env)  # noqa: S603 - fixed commands


def _compose(*arguments: str) -> list[str]:
    return [*COMPOSE, "--env-file", str(LAB_ENV), *arguments]


def up() -> None:
    """Start the lab: infrastructure, schema, topics, pipeline, then the real sources."""
    lab = _lab_secrets()
    env = _host_environment(lab)
    _run(_compose("up", "-d", "--wait", "kafka", "postgres"))
    _run([sys.executable, "-m", "alembic", "upgrade", "head"], env=env)
    _run([sys.executable, "scripts/kafka_create_topics.py"], env=env)
    _run(_compose("--profile", "pipeline", "up", "-d", "--build"))
    _run(_compose("--profile", "sources", "up", "-d", "--build"))


def _windows_agent_environment(pcaps: list[str], data_dir: Path) -> dict[str, str]:
    lab = _lab_secrets()
    return {
        **os.environ,
        "APP_ENV": "development",
        "LOG_LEVEL": "INFO",
        "AGENT_SERVER_URL": API_URL,
        "AGENT_TOKEN": lab["LAB_WINDOWS_AGENT_TOKEN"],
        "AGENT_NAME": "lab-windows-agent",
        "AGENT_DATA_DIR": str(data_dir),
        "AGENT_BATCH_SIZE": "500",
        "AGENT_FLUSH_INTERVAL_SECONDS": "2",
        "AGENT_LOG_FILES": "",
        "AGENT_SIMULATE_AUTH_PER_MINUTE": "0",
        "AGENT_SIMULATE_FLOWS_PER_MINUTE": "0",
        "AGENT_WINDOWS_EVENTLOG_CHANNELS": "System,Application",
        "AGENT_WINDOWS_EVENTLOG_BACKFILL_MINUTES": "1440",
        "AGENT_WINDOWS_SECURITY_ENABLED": "true",
        "AGENT_PCAP_FILES": ",".join(pcaps),
        "AGENT_FLOW_MAX_ACTIVE": "200000",
    }


def _agent_command(duration: float) -> list[str]:
    return [sys.executable, "-m", "apps.agent", "run", "--duration", str(duration)]


def windows_agent(duration: float, pcaps: list[str]) -> None:
    """Run this computer's agent (Windows Event Log, Security log, optional PCAP files)."""
    env = _windows_agent_environment(pcaps, LAB_DIR / "windows-agent")
    _run(_agent_command(duration), env=env)


def _start_windows_agent(
    duration: float, pcaps: list[str], data_dir: Path, log: Path
) -> subprocess.Popen[bytes]:
    env = _windows_agent_environment(pcaps, data_dir)
    with log.open("wb") as handle:
        return subprocess.Popen(  # noqa: S603 - fixed command
            _agent_command(duration), cwd=REPO, env=env, stdout=handle, stderr=subprocess.STDOUT
        )


def _docker(*arguments: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed commands
        ["docker", *arguments],  # noqa: S607 - docker from PATH
        check=True,
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _running(container: str) -> bool:
    return _docker("inspect", "-f", "{{.State.Running}}", container) == "true"


def scenario(pcaps: list[str], out_dir: Path) -> None:
    """The full verification run: fresh lab, both agents, an API outage, a restart, replays.

    1. Fresh lab and real sources; the Windows agent starts at the same time.
    2. 35 s in (during the SSH scenarios) the ingestion API is stopped for 30 s.
    3. When the sources and the Windows agent are done, the results are recorded.
    4. The Linux agent is restarted (its registration is re-sent).
    5. The Windows agent runs again with an empty data directory, so it re-sends the same
       Windows events and omran flows (duplicates for the normalizer to absorb).
    6. The final results are recorded.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    timeline: list[dict[str, Any]] = []

    def mark(step: str) -> None:
        timeline.append(
            {
                "seconds": round(time.monotonic() - started, 1),
                "at": datetime.now(UTC).isoformat(),
                "step": step,
            }
        )
        sys.stdout.write(f"[{timeline[-1]['seconds']:>7}s] {step}\n")

    up()
    mark("lab up: pipeline and real sources started")
    windows = _start_windows_agent(
        300, pcaps, LAB_DIR / "windows-agent", out_dir / "windows-agent.log"
    )
    mark("windows agent started (300 s)")
    time.sleep(35)
    _docker("stop", "adis-lab-api-1")
    mark("ingestion API stopped (outage)")
    time.sleep(30)
    _docker("start", "adis-lab-api-1")
    mark("ingestion API started again")
    while any(_running(f"adis-lab-{name}-1") for name in ("web-client", "ebpf", "ssh-client")):
        time.sleep(5)
    mark("real sources finished")
    windows.wait()
    mark(f"windows agent finished (exit {windows.returncode})")
    time.sleep(30)
    report(out_dir / "results-first-pass.json")
    mark("first-pass results recorded")
    _docker("restart", "adis-lab-agent-1")
    mark("linux agent restarted")
    time.sleep(20)
    replay = _start_windows_agent(
        150, pcaps, LAB_DIR / "windows-agent-replay", out_dir / "windows-agent-replay.log"
    )
    mark("windows agent replay started (empty data directory, 150 s)")
    replay.wait()
    mark(f"windows agent replay finished (exit {replay.returncode})")
    time.sleep(20)
    report(out_dir / "results.json")
    mark("final results recorded")
    for service in ("agent", "api", "normalizer", "ssh-server", "goflow2", "capture"):
        logs = subprocess.run(  # noqa: S603 - fixed command
            ["docker", "logs", f"adis-lab-{service}-1"],  # noqa: S607
            check=False,
            cwd=REPO,
            capture_output=True,
        )
        (out_dir / f"{service}.log").write_bytes(logs.stdout + logs.stderr)
    (out_dir / "timeline.json").write_text(json.dumps(timeline, indent=2), encoding="utf-8")


async def _database_report(lab: dict[str, str]) -> dict[str, Any]:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(_database_url(lab))
    report: dict[str, Any] = {}
    try:
        async with engine.connect() as connection:

            async def rows(sql: str) -> list[dict[str, Any]]:
                result = await connection.execute(text(sql))
                return [dict(row) for row in result.mappings()]

            report["by_source"] = await rows(
                "SELECT source_type, payload->>'category' AS category, count(*) AS events, "
                "count(DISTINCT host_id) AS hosts, min(timestamp) AS first_event, "
                "max(timestamp) AS last_event FROM adis.security_events "
                "GROUP BY 1, 2 ORDER BY 1, 2"
            )
            report["by_event_type"] = await rows(
                "SELECT source_type, event_type, count(*) AS events FROM adis.security_events "
                "GROUP BY 1, 2 ORDER BY 1, 3 DESC"
            )
            report["agents"] = await rows(
                "SELECT name, os_type, status, first_seen, last_seen FROM adis.agents ORDER BY name"
            )
            report["totals"] = (
                await rows(
                    "SELECT count(*) AS events, count(DISTINCT event_id) AS distinct_ids, "
                    "count(DISTINCT host_id) AS hosts FROM adis.security_events"
                )
            )[0]
            report["latency_seconds"] = (
                await rows(
                    "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY "
                    "extract(epoch FROM created_at - received_at)) AS p50_receive_to_store, "
                    "percentile_cont(0.95) WITHIN GROUP (ORDER BY "
                    "extract(epoch FROM created_at - received_at)) AS p95_receive_to_store "
                    "FROM adis.security_events"
                )
            )[0]
            report["session_vectors"] = await rows(
                "SELECT source_type, event_type, payload->'metadata'->'session_vector'->'values' "
                "AS vector FROM adis.security_events WHERE event_type = "
                "'authentication.session_ended' ORDER BY timestamp LIMIT 5"
            )
            report["syscall_sequences"] = await rows(
                "SELECT payload->>'process_name' AS process, "
                "(payload->'metadata'->>'count')::int AS calls, "
                "payload->'metadata'->'syscall_counts' AS counts FROM adis.security_events "
                "WHERE event_type = 'process.syscall_sequence' "
                "ORDER BY (payload->'metadata'->>'count')::int DESC LIMIT 8"
            )
            report["authentication"] = await rows(
                "SELECT source_type, event_type, payload->>'success' AS success, "
                "payload->>'failure_reason' AS failure_reason, count(*) AS events "
                "FROM adis.security_events WHERE payload->>'category' = 'authentication' "
                "GROUP BY 1, 2, 3, 4 ORDER BY 1, 2, 3, 4"
            )
            report["withheld_name_leaks"] = (
                await rows(
                    "SELECT count(*) AS events FROM adis.security_events "
                    "WHERE payload::text ILIKE '%nosuchuser%'"
                )
            )[0]["events"]
            report["flow_sources"] = await rows(
                "SELECT source_type, payload->'metadata'->>'flow_source' AS flow_source, "
                "protocol, count(*) AS flows, sum((payload->>'bytes_sent')::bigint) AS bytes_sent, "
                "sum(coalesce((payload->>'bytes_received')::bigint, 0)) AS bytes_received "
                "FROM adis.security_events WHERE payload->>'category' = 'network' "
                "GROUP BY 1, 2, 3 ORDER BY 1, 4 DESC"
            )
    finally:
        await engine.dispose()
    return report


async def _kafka_report() -> dict[str, Any]:
    from aiokafka import AIOKafkaConsumer, TopicPartition

    consumer = AIOKafkaConsumer(bootstrap_servers=KAFKA, enable_auto_commit=False)
    await consumer.start()
    try:
        counts: dict[str, int] = {}
        for topic in TOPICS:
            partitions = consumer.partitions_for_topic(topic) or set()
            if not partitions:
                await consumer._client.force_metadata_update()
                partitions = consumer.partitions_for_topic(topic) or set()
            assigned = [TopicPartition(topic, p) for p in partitions]
            ends = await consumer.end_offsets(assigned) if assigned else {}
            starts = await consumer.beginning_offsets(assigned) if assigned else {}
            counts[topic] = sum(ends[tp] - starts[tp] for tp in assigned)
        return {"records_per_topic": counts}
    finally:
        await consumer.stop()


def report(out: Path) -> None:
    """Collect the lab results from PostgreSQL and Kafka into ``out`` (JSON)."""
    lab = _lab_secrets()
    os.environ.update(_host_environment(lab))
    database = asyncio.run(_database_report(lab))
    kafka = asyncio.run(_kafka_report())
    result = {"generated_at": datetime.now(UTC).isoformat(), **kafka, **database}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    sys.stdout.write(json.dumps({"totals": database["totals"], **kafka}, default=str) + "\n")


def down() -> None:
    """Remove the lab containers and volumes."""
    _lab_secrets()
    _run(_compose("--profile", "pipeline", "--profile", "sources", "down", "-v"))


def main(argv: list[str] | None = None) -> int:
    """Parse ``argv`` and run the command."""
    parser = argparse.ArgumentParser(prog="python scripts/lab_phase1.py")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("up")
    windows = commands.add_parser("windows-agent")
    windows.add_argument("--duration", type=float, default=240.0)
    windows.add_argument("--pcap", action="append", default=[])
    run = commands.add_parser("scenario")
    run.add_argument("--pcap", action="append", default=[])
    run.add_argument("--out-dir", type=Path, default=LAB_DIR / "final")
    out = commands.add_parser("report")
    out.add_argument("--out", type=Path, default=LAB_DIR / "results.json")
    commands.add_parser("down")
    arguments = parser.parse_args(argv)
    started = time.monotonic()
    if arguments.command == "up":
        up()
    elif arguments.command == "windows-agent":
        windows_agent(arguments.duration, arguments.pcap)
    elif arguments.command == "scenario":
        scenario(arguments.pcap, arguments.out_dir)
    elif arguments.command == "report":
        report(arguments.out)
    else:
        down()
    sys.stdout.write(f"done in {time.monotonic() - started:.1f}s\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
