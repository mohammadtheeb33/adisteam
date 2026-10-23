"""Idempotent topic provisioning."""

import logging
from collections.abc import Callable, Sequence
from typing import Final, Protocol

from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import TopicAlreadyExistsError, for_code

from packages.config import KafkaSettings
from packages.kafka.clients import security_options
from packages.kafka.errors import TopicAdministrationError
from packages.kafka.topics import TopicSpec, topic_specs

logger = logging.getLogger(__name__)

_CREATE_TIMEOUT_MS: Final = 30_000


class CreateTopicsResponse(Protocol):
    """The subset of the broker's CreateTopics response used here."""

    @property
    def topic_errors(self) -> Sequence[Sequence[object]]:
        """Per-topic ``(name, error_code, ...)`` entries."""
        ...


class AdminClient(Protocol):
    """The subset of ``AIOKafkaAdminClient`` used here."""

    async def start(self) -> None:
        """Connect to the cluster."""
        ...

    async def close(self) -> None:
        """Disconnect."""
        ...

    async def list_topics(self) -> list[str]:
        """Names of existing topics."""
        ...

    async def create_topics(
        self, new_topics: list[NewTopic], timeout_ms: int | None = None
    ) -> CreateTopicsResponse:
        """Request topic creation."""
        ...


async def ensure_topics(
    settings: KafkaSettings, *, client_factory: Callable[[], AdminClient] | None = None
) -> tuple[str, ...]:
    """Create every missing ADIS topic. Existing topics are never modified.

    Args:
        settings: Kafka settings (connection and ``KAFKA_TOPIC_*`` values).
        client_factory: Admin client factory, injectable for tests.

    Returns:
        Names of the topics that were created.

    Raises:
        TopicAdministrationError: If the broker rejects a topic.
    """
    specs = topic_specs(settings)
    client = (client_factory or _admin_client_factory(settings))()
    await client.start()
    try:
        existing = set(await client.list_topics())
        missing = [spec for spec in specs if spec.topic.value not in existing]
        if missing:
            response = await client.create_topics(
                [_new_topic(spec) for spec in missing], timeout_ms=_CREATE_TIMEOUT_MS
            )
            _raise_for_topic_errors(response)
    finally:
        await client.close()
    created = tuple(spec.topic.value for spec in missing)
    logger.info(
        "kafka topics ensured",
        extra={"action": "kafka_topics_ensured", "topics_created": list(created)},
    )
    return created


def _admin_client_factory(settings: KafkaSettings) -> Callable[[], AdminClient]:
    def create_client() -> AdminClient:
        client: AdminClient = AIOKafkaAdminClient(
            **security_options(settings), client_id=settings.kafka_client_id
        )
        return client

    return create_client


def _new_topic(spec: TopicSpec) -> NewTopic:
    return NewTopic(
        name=spec.topic.value,
        num_partitions=spec.partitions,
        replication_factor=spec.replication_factor,
        topic_configs=dict(spec.configs),
    )


def _raise_for_topic_errors(response: CreateTopicsResponse) -> None:
    failures = []
    for entry in response.topic_errors:
        name, code = entry[0], entry[1]
        if not isinstance(code, int) or code in {0, TopicAlreadyExistsError.errno}:
            continue
        failures.append(f"{name}: {for_code(code).__name__}")
    if failures:
        raise TopicAdministrationError("topic creation failed: " + ", ".join(failures))
