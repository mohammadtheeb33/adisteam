"""ADIS-P2-003 against a real broker: a partition with unread records is not caught up."""

import asyncio
from collections.abc import Sequence

import pytest

from packages.config import KafkaSettings
from packages.events import EventEnvelope
from packages.kafka import ConsumerRecordLike, KafkaBatchConsumer, KafkaProducer, Topic
from tests.integration.kafka.helpers import WAIT_SECONDS, commit_group_offsets, end_offsets

pytestmark = pytest.mark.integration

RECORDS = 5


async def test_a_backlogged_partition_is_caught_up_only_after_its_last_record(
    kafka_settings: KafkaSettings, producer: KafkaProducer, unique_group: str
) -> None:
    await commit_group_offsets(
        kafka_settings, unique_group, await end_offsets(kafka_settings, [Topic.SYSTEM_EVENTS])
    )
    key = f"caught-up-{unique_group}"  # one key: every record lands on one partition
    published = [
        await producer.publish(
            Topic.SYSTEM_EVENTS,
            EventEnvelope(
                event_type="security.integration_probe",
                event_version=1,
                producer="adis-integration-tests",
                payload={"n": n},
            ),
            key=key,
        )
        for n in range(RECORDS)
    ]
    [partition] = {(record.topic, record.partition) for record in published}
    last_offset = published[-1].offset
    consumer = KafkaBatchConsumer.from_settings(
        kafka_settings,
        topics=[Topic.SYSTEM_EVENTS],
        group_id=unique_group,
        poll_timeout_ms=100,
        max_records=1,  # a starved partition: one record per poll
        idle_calls=True,
    )
    observed: list[tuple[int | None, bool]] = []

    async def handler(records: Sequence[ConsumerRecordLike]) -> None:
        mine = [
            record.offset for record in records if (record.topic, record.partition) == partition
        ]
        observed.append((mine[-1] if mine else None, consumer.is_caught_up(partition)))
        if mine and mine[-1] == last_offset:
            consumer.request_stop()

    async with asyncio.timeout(WAIT_SECONDS):
        await consumer.run(handler)

    handled = [(offset, caught_up) for offset, caught_up in observed if offset is not None]
    ours = [(offset, caught_up) for offset, caught_up in handled if offset >= published[0].offset]
    assert [offset for offset, _ in ours] == [record.offset for record in published]
    assert all(not caught_up for offset, caught_up in ours if offset < last_offset)
    assert ours[-1] == (last_offset, True)
