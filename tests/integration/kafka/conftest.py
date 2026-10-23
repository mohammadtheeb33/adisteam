"""Integration fixtures backed by a real Kafka broker.

Set ``TEST_KAFKA_BOOTSTRAP_SERVERS`` (for example ``127.0.0.1:9092`` with the compose
broker) to enable these tests. The broker must be disposable: the tests create the ADIS
topics and write test records, including dead letters.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import pytest

from packages.config import KafkaSettings, load_settings
from packages.kafka import KafkaProducer, ensure_topics
from tests.services import require_variable

TEST_KAFKA_VARIABLE = "TEST_KAFKA_BOOTSTRAP_SERVERS"


@pytest.fixture
def kafka_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> KafkaSettings:
    """Settings pointing at the test broker, with fast retries; skips when unset."""
    servers = require_variable(TEST_KAFKA_VARIABLE)
    monkeypatch.chdir(tmp_path)  # ignore the developer's .env
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", servers)
    monkeypatch.setenv("KAFKA_CLIENT_ID", "adis-integration-tests")
    monkeypatch.setenv("KAFKA_RETRY_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("KAFKA_RETRY_INITIAL_BACKOFF_MS", "10")
    monkeypatch.setenv("KAFKA_RETRY_MAX_BACKOFF_MS", "50")
    return load_settings(KafkaSettings)


@pytest.fixture
async def topics(kafka_settings: KafkaSettings) -> None:
    """Ensure every ADIS topic exists on the test broker."""
    await ensure_topics(kafka_settings)


@pytest.fixture
async def producer(kafka_settings: KafkaSettings, topics: None) -> AsyncIterator[KafkaProducer]:
    """A started producer, stopped after the test."""
    async with KafkaProducer.from_settings(kafka_settings) as started:
        yield started


@pytest.fixture
def unique_group() -> str:
    """A fresh consumer group, so each test reads from the beginning of its topics."""
    return f"adis-it-{uuid4().hex[:12]}"
