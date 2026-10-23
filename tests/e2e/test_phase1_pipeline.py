"""The Phase 1 verification as a test.

Opt-in with ``TEST_E2E=1``: it needs ``TEST_KAFKA_BOOTSTRAP_SERVERS`` and
``TEST_DATABASE_URL``, and it stops and restarts the Kafka and database containers
(``TEST_KAFKA_CONTAINER``, ``TEST_DATABASE_CONTAINER``).
"""

import os
from pathlib import Path

import pytest
from pydantic import SecretStr

from tests.e2e.phase1.verification import Verification, VerificationConfig
from tests.services import require_variable

pytestmark = pytest.mark.e2e


@pytest.fixture
def config(tmp_path: Path) -> VerificationConfig:
    require_variable("TEST_E2E", "set TEST_E2E=1: it stops and restarts the test containers")
    bootstrap = require_variable("TEST_KAFKA_BOOTSTRAP_SERVERS")
    database_url = require_variable("TEST_DATABASE_URL")
    return VerificationConfig(
        bootstrap_servers=bootstrap,
        database_url=SecretStr(database_url),
        kafka_container=os.environ.get("TEST_KAFKA_CONTAINER", "adis-phase1-copy-kafka-1"),
        database_container=os.environ.get(
            "TEST_DATABASE_CONTAINER", "adis-phase1-copy-postgres-test-1"
        ),
        run_dir=tmp_path,
    )


async def test_phase1_pipeline(config: VerificationConfig) -> None:
    run = await Verification(config).execute()

    failed = [
        f"{result.name}: {check.name} ({check.detail})"
        for result in [*run.scenarios, run.global_checks]
        for check in result.checks
        if not check.passed
    ]
    assert failed == []
    assert [result.name for result in run.scenarios] == [
        "single",
        "batch",
        "invalid",
        "duplicate",
        "agent",
        "database_outage",
        "kafka_outage",
    ]
