"""ADIS topic catalogue and per-environment topic configuration."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from packages.config import KafkaSettings
from packages.events.canonical import EventCategory

_MS_PER_HOUR: Final = 3600000


class Topic(StrEnum):
    """Every ADIS Kafka topic. Producers and consumers may only use these."""

    SYSTEM_EVENTS = "system_logs"
    AUTH_EVENTS = "auth_events"
    NETWORK_EVENTS = "network_flows"
    SECURITY_EVENTS = "adis.security.events"
    DEADLETTER = "adis.deadletter"


TOPIC_DESCRIPTIONS: Final[dict[Topic, str]] = {
    Topic.SYSTEM_EVENTS: "Accepted host, process and security-tool telemetry (not normalized).",
    Topic.AUTH_EVENTS: "Accepted authentication and authorization telemetry (not normalized).",
    Topic.NETWORK_EVENTS: "Accepted network telemetry (not normalized).",
    Topic.SECURITY_EVENTS: (
        "Normalized, deduplicated and stored canonical events of every category "
        "(normalizer output)."
    ),
    Topic.DEADLETTER: "Records that could not be processed, with failure context in headers.",
}
TELEMETRY_TOPICS: Final[dict[EventCategory, Topic]] = {
    EventCategory.SYSTEM: Topic.SYSTEM_EVENTS,
    EventCategory.PROCESS: Topic.SYSTEM_EVENTS,
    EventCategory.SECURITY: Topic.SYSTEM_EVENTS,
    EventCategory.AUTHENTICATION: Topic.AUTH_EVENTS,
    EventCategory.NETWORK: Topic.NETWORK_EVENTS,
}
"""Topic accepted telemetry of each canonical category is published to.

Process activity and security-tool findings are host telemetry. The normalizer consumes
these topics and publishes to :data:`NORMALIZED_EVENTS_TOPIC`.
"""
RAW_TELEMETRY_TOPICS: Final = (Topic.SYSTEM_EVENTS, Topic.AUTH_EVENTS, Topic.NETWORK_EVENTS)
"Accepted, not yet normalized telemetry: the normalizer's input."
NORMALIZED_EVENTS_TOPIC: Final = Topic.SECURITY_EVENTS
"Normalized, deduplicated, stored canonical events: the normalizer's output."


def telemetry_topic(category: EventCategory) -> Topic:
    """The topic canonical events of ``category`` are published to."""
    return TELEMETRY_TOPICS[category]


@dataclass(frozen=True, slots=True)
class TopicSpec:
    """Creation parameters for one topic.

    Attributes:
        topic: The topic.
        partitions: Partition count.
        replication_factor: Replicas per partition.
        configs: Broker-side topic configuration entries.
    """

    topic: Topic
    partitions: int
    replication_factor: int
    configs: tuple[tuple[str, str], ...]


def topic_specs(settings: KafkaSettings) -> tuple[TopicSpec, ...]:
    """Build the creation parameters of every topic from settings.

    ``min.insync.replicas`` is 1 for replication factors below 3 and 2 otherwise, so
    producers using ``acks=all`` survive the loss of one replica.
    """
    replication = settings.kafka_topic_replication_factor
    min_insync_replicas = 2 if replication >= 3 else 1
    specs = []
    for topic in Topic:
        retention_hours = (
            settings.kafka_deadletter_retention_hours
            if topic is Topic.DEADLETTER
            else settings.kafka_topic_retention_hours
        )
        specs.append(
            TopicSpec(
                topic=topic,
                partitions=settings.kafka_topic_partitions,
                replication_factor=replication,
                configs=(
                    ("cleanup.policy", "delete"),
                    ("retention.ms", str(retention_hours * _MS_PER_HOUR)),
                    ("min.insync.replicas", str(min_insync_replicas)),
                ),
            )
        )
    return tuple(specs)
