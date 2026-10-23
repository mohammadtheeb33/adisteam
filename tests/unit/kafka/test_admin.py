"""Idempotent topic provisioning over an in-memory admin client."""

from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest
from aiokafka.admin import NewTopic
from aiokafka.errors import InvalidReplicationFactorError, TopicAlreadyExistsError

from packages.config import KafkaSettings
from packages.kafka import Topic, TopicAdministrationError, ensure_topics


@dataclass
class Response:
    """Minimal CreateTopics response."""

    topic_errors: Sequence[tuple[object, int, str | None]]


@dataclass
class FakeAdminClient:
    """Tracks existing topics and creation requests."""

    existing: set[str] = field(default_factory=set)
    error_codes: dict[str, int] = field(default_factory=dict)
    created: list[NewTopic] = field(default_factory=list)
    closed: bool = False

    async def start(self) -> None:
        pass

    async def close(self) -> None:
        self.closed = True

    async def list_topics(self) -> list[str]:
        return sorted(self.existing)

    async def create_topics(
        self, new_topics: list[NewTopic], timeout_ms: int | None = None
    ) -> Response:
        self.created.extend(new_topics)
        errors = [(t.name, self.error_codes.get(t.name, 0), None) for t in new_topics]
        self.existing.update(t.name for t in new_topics if self.error_codes.get(t.name, 0) == 0)
        return Response(errors)


SETTINGS = KafkaSettings.model_validate(
    {"kafka_topic_partitions": 2, "kafka_topic_replication_factor": 1}
)


async def test_creates_missing_topics_only_once() -> None:
    admin = FakeAdminClient(existing={"system_logs", "unrelated.topic"})

    created = await ensure_topics(SETTINGS, client_factory=lambda: admin)
    created_again = await ensure_topics(SETTINGS, client_factory=lambda: admin)

    assert set(created) == {topic.value for topic in Topic} - {"system_logs"}
    assert created_again == ()
    assert all(t.num_partitions == 2 and t.replication_factor == 1 for t in admin.created)
    assert admin.closed


async def test_topic_created_concurrently_is_not_an_error() -> None:
    admin = FakeAdminClient(error_codes={"auth_events": TopicAlreadyExistsError.errno})

    await ensure_topics(SETTINGS, client_factory=lambda: admin)


async def test_broker_rejection_raises() -> None:
    admin = FakeAdminClient(error_codes={"system_logs": InvalidReplicationFactorError.errno})

    with pytest.raises(TopicAdministrationError, match=r"system_logs"):
        await ensure_topics(SETTINGS, client_factory=lambda: admin)

    assert admin.closed
