"""Topic catalogue and creation parameters."""

import pytest

from packages.config import KafkaSettings
from packages.events.canonical import EventCategory
from packages.kafka import (
    NORMALIZED_EVENTS_TOPIC,
    RAW_TELEMETRY_TOPICS,
    TELEMETRY_TOPICS,
    TOPIC_DESCRIPTIONS,
    Topic,
    telemetry_topic,
    topic_specs,
)


def _settings(**values: int) -> KafkaSettings:
    return KafkaSettings.model_validate(values)


def test_initial_topics() -> None:
    assert {topic.value for topic in Topic} == {
        "system_logs",
        "auth_events",
        "network_flows",
        "adis.security.events",
        "adis.deadletter",
    }


def test_every_topic_is_described() -> None:
    assert set(TOPIC_DESCRIPTIONS) == set(Topic)


def test_specs_follow_settings() -> None:
    settings = _settings(
        kafka_topic_partitions=6,
        kafka_topic_replication_factor=3,
        kafka_topic_retention_hours=24,
        kafka_deadletter_retention_hours=240,
    )

    specs = {spec.topic: spec for spec in topic_specs(settings)}

    assert set(specs) == set(Topic)
    for topic, spec in specs.items():
        configs = dict(spec.configs)
        expected_hours = 240 if topic is Topic.DEADLETTER else 24
        assert spec.partitions == 6
        assert spec.replication_factor == 3
        assert configs["retention.ms"] == str(expected_hours * 3_600_000)
        assert configs["cleanup.policy"] == "delete"
        assert configs["min.insync.replicas"] == "2"


@pytest.mark.parametrize(("replication", "min_insync"), [(1, "1"), (2, "1"), (3, "2"), (5, "2")])
def test_min_insync_replicas(replication: int, min_insync: str) -> None:
    [spec, *_] = topic_specs(_settings(kafka_topic_replication_factor=replication))

    assert dict(spec.configs)["min.insync.replicas"] == min_insync


def test_every_canonical_category_has_a_raw_telemetry_topic() -> None:
    assert set(TELEMETRY_TOPICS) == set(EventCategory)
    assert {telemetry_topic(category) for category in EventCategory} == set(RAW_TELEMETRY_TOPICS)
    assert telemetry_topic(EventCategory.PROCESS) is Topic.SYSTEM_EVENTS
    assert telemetry_topic(EventCategory.SECURITY) is Topic.SYSTEM_EVENTS
    assert telemetry_topic(EventCategory.AUTHENTICATION) is Topic.AUTH_EVENTS
    assert telemetry_topic(EventCategory.NETWORK) is Topic.NETWORK_EVENTS


def test_accepted_telemetry_never_bypasses_normalization() -> None:
    assert NORMALIZED_EVENTS_TOPIC is Topic.SECURITY_EVENTS
    assert NORMALIZED_EVENTS_TOPIC not in RAW_TELEMETRY_TOPICS
    assert NORMALIZED_EVENTS_TOPIC not in TELEMETRY_TOPICS.values()
