"""Helpers shared by the Kafka integration tests.

The test broker is shared and keeps growing across runs, so tests never read a topic
from its beginning: they capture the current end offsets first (:func:`end_offsets`)
and read, or start consumer groups (:func:`commit_group_offsets`), from there. That keeps
every test's duration independent of what earlier runs left behind.
"""

import asyncio
from collections.abc import Callable, Iterable, Mapping
from typing import Final
from uuid import uuid4

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition

from packages.config import KafkaSettings
from packages.kafka import Topic
from packages.kafka.consumer import ConsumerRecordLike

WAIT_SECONDS: Final = 30.0

Offsets = Mapping[TopicPartition, int]


async def end_offsets(
    settings: KafkaSettings, topics: Iterable[Topic]
) -> dict[TopicPartition, int]:
    """The next offset of every partition of ``topics`` (where new records will land)."""
    producer = AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap_servers)
    await producer.start()
    try:
        partitions = [
            TopicPartition(topic.value, partition)
            for topic in topics
            for partition in sorted(await producer.partitions_for(topic.value))
        ]
    finally:
        await producer.stop()
    consumer = AIOKafkaConsumer(
        bootstrap_servers=settings.kafka_bootstrap_servers, enable_auto_commit=False
    )
    await consumer.start()
    try:
        return dict(await consumer.end_offsets(partitions))
    finally:
        await consumer.stop()


async def commit_group_offsets(settings: KafkaSettings, group_id: str, offsets: Offsets) -> None:
    """Make consumer group ``group_id`` start at ``offsets`` (instead of the earliest)."""
    consumer = AIOKafkaConsumer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=group_id,
        enable_auto_commit=False,
    )
    await consumer.start()
    try:
        consumer.assign(list(offsets))
        await consumer.commit(dict(offsets))
    finally:
        await consumer.stop()


async def committed_offsets(
    settings: KafkaSettings, group_id: str, partitions: Iterable[TopicPartition]
) -> dict[TopicPartition, int | None]:
    """The offsets ``group_id`` has committed for ``partitions`` (``None``: nothing yet)."""
    consumer = AIOKafkaConsumer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=group_id,
        enable_auto_commit=False,
    )
    await consumer.start()
    try:
        return {partition: await consumer.committed(partition) for partition in partitions}
    finally:
        await consumer.stop()


async def read_from(
    settings: KafkaSettings, start: Offsets, matches: Callable[[ConsumerRecordLike], bool]
) -> list[ConsumerRecordLike]:
    """Every matching record from ``start`` to the end of those partitions at call time.

    Raises:
        TimeoutError: If the end is not reached within :data:`WAIT_SECONDS`.
    """
    consumer = AIOKafkaConsumer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=f"adis-it-reader-{uuid4().hex[:12]}",
        enable_auto_commit=False,
    )
    await consumer.start()
    found: list[ConsumerRecordLike] = []
    try:
        partitions = list(start)
        consumer.assign(partitions)
        for partition, offset in start.items():
            consumer.seek(partition, offset)
        # Read up to the end offsets as they are now: an empty poll does not mean the
        # end, since a new consumer's first polls return nothing until fetching starts.
        ends = await consumer.end_offsets(partitions)
        async with asyncio.timeout(WAIT_SECONDS):
            while [p for p in partitions if await consumer.position(p) < ends[p]]:
                batches = await consumer.getmany(timeout_ms=500)
                for records in batches.values():
                    found.extend(record for record in records if matches(record))
    finally:
        await consumer.stop()
    return found


async def read_until(
    settings: KafkaSettings,
    start: Offsets,
    matches: Callable[[ConsumerRecordLike], bool],
) -> ConsumerRecordLike:
    """Read from ``start`` until a record matches.

    Raises:
        TimeoutError: If no record matches within :data:`WAIT_SECONDS`.
    """
    consumer = AIOKafkaConsumer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=f"adis-it-reader-{uuid4().hex[:12]}",
        enable_auto_commit=False,
    )
    await consumer.start()
    try:
        consumer.assign(list(start))
        for partition, offset in start.items():
            consumer.seek(partition, offset)
        async with asyncio.timeout(WAIT_SECONDS):
            while True:
                batches = await consumer.getmany(timeout_ms=500)
                for records in batches.values():
                    for record in records:
                        candidate: ConsumerRecordLike = record
                        if matches(candidate):
                            return candidate
    finally:
        await consumer.stop()
