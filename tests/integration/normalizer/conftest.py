"""Fixtures for normalizer integration tests: a real broker and a real database.

Both ``TEST_KAFKA_BOOTSTRAP_SERVERS`` and ``TEST_DATABASE_URL`` must be set; otherwise the
tests are skipped.
"""

from tests.integration.database.conftest import (
    database,
    database_settings,
    migrated_database,
)
from tests.integration.kafka.conftest import kafka_settings, producer, topics, unique_group

__all__ = [
    "database",
    "database_settings",
    "kafka_settings",
    "migrated_database",
    "producer",
    "topics",
    "unique_group",
]
