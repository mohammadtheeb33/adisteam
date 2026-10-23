"""Logging of consumer group rebalances."""

import logging
from collections.abc import Sequence

from aiokafka.abc import ConsumerRebalanceListener

logger = logging.getLogger(__name__)


class RebalanceLogger(ConsumerRebalanceListener):  # type: ignore[misc]
    """Logs partition assignments and revocations of a consumer group member."""

    def __init__(self, group_id: str) -> None:
        self._group_id = group_id

    async def on_partitions_revoked(self, revoked: Sequence[object]) -> None:
        """Log the partitions taken away by a rebalance."""
        self._log("kafka partitions revoked", "kafka_partitions_revoked", revoked)

    async def on_partitions_assigned(self, assigned: Sequence[object]) -> None:
        """Log the partitions received from a rebalance."""
        self._log("kafka partitions assigned", "kafka_partitions_assigned", assigned)

    def _log(self, message: str, action: str, partitions: Sequence[object]) -> None:
        logger.info(
            message,
            extra={
                "action": action,
                "group_id": self._group_id,
                "partitions": sorted(partition_label(partition) for partition in partitions),
            },
        )


def partition_label(partition: object) -> str:
    """``topic:partition`` for a ``TopicPartition`` (or a ``(topic, partition)`` tuple)."""
    topic = getattr(partition, "topic", None)
    number = getattr(partition, "partition", None)
    if topic is None and isinstance(partition, tuple) and len(partition) == 2:
        topic, number = partition
    return f"{topic}:{number}"
