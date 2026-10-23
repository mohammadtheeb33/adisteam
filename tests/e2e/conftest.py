"""Real database, Kafka and Redis fixtures for the opt-in end-to-end tests."""

from tests.integration.database.conftest import database, database_settings, migrated_database
from tests.integration.kafka.conftest import kafka_settings, producer, topics, unique_group
from tests.integration.redis.conftest import redis_settings

__all__ = [
    "database",
    "database_settings",
    "kafka_settings",
    "migrated_database",
    "producer",
    "redis_settings",
    "topics",
    "unique_group",
]
