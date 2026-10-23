"""Run the Phase 1 verification: ``python -m tests.e2e.phase1``.

Needs a disposable Kafka broker (``TEST_KAFKA_BOOTSTRAP_SERVERS``) and PostgreSQL
(``TEST_DATABASE_URL``) running as Docker containers, because the outage scenarios stop
and restart them. Exit code 0 means every check passed.
"""

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import SecretStr

from tests.e2e.phase1.report import render_json, render_markdown
from tests.e2e.phase1.verification import Verification, VerificationConfig

EXIT_PASSED = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run the verification and write the reports."""
    arguments = _parser().parse_args(argv)
    bootstrap = os.environ.get("TEST_KAFKA_BOOTSTRAP_SERVERS")
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not bootstrap or not database_url:
        sys.stderr.write(
            "TEST_KAFKA_BOOTSTRAP_SERVERS and TEST_DATABASE_URL must point at disposable "
            "services (see docs/VERIFICATION.md)\n"
        )
        return EXIT_USAGE
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    for noisy in ("aiokafka", "kafka", "sqlalchemy", "httpx2"):
        logging.getLogger(noisy).setLevel(logging.ERROR)
    config = VerificationConfig(
        bootstrap_servers=bootstrap,
        database_url=SecretStr(database_url),
        kafka_container=arguments.kafka_container,
        database_container=arguments.database_container,
        run_dir=arguments.run_dir,
        batch_events=arguments.batch_events,
        outage_events=arguments.outage_events,
        outage_seconds=arguments.outage_seconds,
        faults=not arguments.no_faults,
    )
    run = asyncio.run(Verification(config).execute())
    run_dir = config.run_dir / run.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.json").write_text(render_json(run), encoding="utf-8")
    markdown = render_markdown(run)
    (run_dir / "report.md").write_text(markdown, encoding="utf-8")
    if arguments.report is not None:
        arguments.report.write_text(markdown, encoding="utf-8")
    sys.stdout.write(f"{'PASS' if run.passed else 'FAIL'}: {run_dir / 'report.md'}\n")
    return EXIT_PASSED if run.passed else EXIT_FAILED


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tests.e2e.phase1", description=__doc__)
    parser.add_argument("--report", type=Path, default=None, help="also write the Markdown here")
    parser.add_argument("--run-dir", type=Path, default=Path(".verification"))
    parser.add_argument("--kafka-container", default="adis-phase1-copy-kafka-1")
    parser.add_argument("--database-container", default="adis-phase1-copy-postgres-test-1")
    parser.add_argument("--batch-events", type=int, default=300)
    parser.add_argument("--outage-events", type=int, default=100)
    parser.add_argument("--outage-seconds", type=float, default=15.0)
    parser.add_argument("--no-faults", action="store_true", help="skip the outage scenarios")
    return parser


if __name__ == "__main__":
    sys.exit(main())
