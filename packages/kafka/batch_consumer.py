"""Batch consumer: each poll is processed as one unit and committed after it."""

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Final, Protocol, Self

from aiokafka import AIOKafkaConsumer
from aiokafka.errors import CommitFailedError, IllegalStateError, KafkaError

from packages.config import KafkaSettings
from packages.kafka.clients import OffsetReset, consumer_options, is_transient_transport_error
from packages.kafka.consumer import ConsumerClient, ConsumerRecordLike, validate_subscription
from packages.kafka.errors import BatchAbortedError
from packages.kafka.rebalance import RebalanceLogger, partition_label
from packages.kafka.retry import RetryPolicy, default_jitter
from packages.kafka.topics import Topic

logger = logging.getLogger(__name__)

DEFAULT_START_BACKOFF: Final = RetryPolicy(
    max_attempts=1, initial_backoff_seconds=0.5, max_backoff_seconds=30.0
)
LAG_REFRESH_SECONDS: Final = 5.0

type CommitPositions = Mapping[tuple[str, int], int]
"""The next offset to commit, per ``(topic, partition)``."""


class BatchHandler(Protocol):
    """Processes the records of one poll.

    Records of one partition arrive in offset order; a batch can span partitions and
    topics. Return once the records are handled:

    - ``None``: every record is settled (processed, or dead-lettered), and the consumer
      commits past the whole batch.
    - :data:`CommitPositions`: the consumer commits exactly these next offsets, for the
      partitions still assigned to it. A handler that holds records back across polls
      (until a watermark passes, for instance) commits only up to the first record it
      still holds; after a restart or a rebalance the records beyond are redelivered.

    Raise :class:`~packages.kafka.errors.BatchAbortedError` to leave the batch
    uncommitted and stop; any other exception also leaves it uncommitted and ends
    :meth:`KafkaBatchConsumer.run`. Handlers must be idempotent, because uncommitted
    records are redelivered.
    """

    async def __call__(self, records: Sequence[ConsumerRecordLike]) -> CommitPositions | None:
        """Handle ``records`` (empty on idle polls when the consumer has ``idle_calls``)."""
        ...


class KafkaBatchConsumer:
    """Consumes ADIS topics in batches with at-least-once semantics.

    Each iteration polls up to ``max_records`` records, hands them to the handler in one
    call, and commits the next offset of every polled partition only after the handler
    returned. Compared with :class:`~packages.kafka.consumer.KafkaConsumer`, retries and
    dead-lettering are the handler's responsibility, which lets it process a batch in one
    database transaction.

    - Joining the group is retried with backoff while the broker is unreachable, so a
      service can start before Kafka does.
    - A commit refused because the group rebalanced is logged, not raised: the records
      are redelivered to the partitions' new owner and the idempotent handler skips them.
    - Consumer lag per partition is refreshed every few seconds (:attr:`lag`).
    - A stop requested before :meth:`run` starts makes it return right away.
    - With ``idle_calls``, a poll that returned nothing still calls the handler, with no
      records, so it can do time-based work (such as releasing records it holds).
      :meth:`is_caught_up` then tells, for each assigned partition, whether this member
      has consumed every record known from the last fetch (no unread backlog).
    """

    def __init__(
        self,
        client_factory: Callable[[], ConsumerClient],
        *,
        topics: Sequence[Topic],
        group_id: str,
        poll_timeout_ms: int = 1_000,
        max_records: int = 500,
        start_backoff: RetryPolicy = DEFAULT_START_BACKOFF,
        idle_calls: bool = False,
    ) -> None:
        validate_subscription(topics, group_id)
        if poll_timeout_ms < 0 or max_records < 1:
            raise ValueError("poll_timeout_ms must be >= 0 and max_records >= 1")
        self._client_factory = client_factory
        self._topics = tuple(topics)
        self._group_id = group_id
        self._poll_timeout_ms = poll_timeout_ms
        self._max_records = max_records
        self._start_backoff = start_backoff
        self._idle_calls = idle_calls
        self._stop_requested = asyncio.Event()
        self._stopped = asyncio.Event()
        self._stopped.set()
        self._connected = False
        self._lag: dict[str, int] = {}
        self._lag_checked = float("-inf")
        self._caught_up: dict[tuple[str, int], bool] = {}

    @classmethod
    def from_settings(
        cls,
        settings: KafkaSettings,
        *,
        topics: Sequence[Topic],
        group_id: str,
        client_id: str | None = None,
        auto_offset_reset: OffsetReset = "earliest",
        poll_timeout_ms: int = 1_000,
        max_records: int = 500,
        idle_calls: bool = False,
    ) -> Self:
        """Create a consumer backed by ``AIOKafkaConsumer`` with manual commits.

        Connection attempts back off like ``KAFKA_RETRY_*`` retries, without a limit.
        """
        options = consumer_options(
            settings, group_id=group_id, client_id=client_id, auto_offset_reset=auto_offset_reset
        )
        subscribed = [topic.value for topic in topics]

        def create_client() -> ConsumerClient:
            consumer = AIOKafkaConsumer(**options)
            consumer.subscribe(subscribed, listener=RebalanceLogger(group_id))
            client: ConsumerClient = consumer
            return client

        return cls(
            create_client,
            topics=topics,
            group_id=group_id,
            poll_timeout_ms=poll_timeout_ms,
            max_records=max_records,
            start_backoff=RetryPolicy(
                max_attempts=1,
                initial_backoff_seconds=settings.kafka_retry_initial_backoff_ms / 1000,
                max_backoff_seconds=settings.kafka_retry_max_backoff_ms / 1000,
            ),
            idle_calls=idle_calls,
        )

    @property
    def group_id(self) -> str:
        """The consumer group."""
        return self._group_id

    @property
    def running(self) -> bool:
        """Whether :meth:`run` is active."""
        return not self._stopped.is_set()

    @property
    def connected(self) -> bool:
        """Whether the consumer has joined the cluster and is polling."""
        return self._connected

    @property
    def lag(self) -> Mapping[str, int]:
        """Records not yet consumed per ``topic:partition`` (refreshed every few seconds)."""
        return dict(self._lag)

    def is_caught_up(self, partition: tuple[str, int]) -> bool:
        """Whether ``(topic, partition)`` had no unread records after the last poll.

        Measured before each handler call from the member's local position and the
        partition's high watermark from the latest fetch, without a broker round trip.
        A partition whose state is unknown (not assigned, never fetched) is not caught up.
        Only maintained when the consumer was created with ``idle_calls``.
        """
        return self._caught_up.get(partition, False)

    def request_stop(self) -> None:
        """Ask :meth:`run` to return after the batch in progress. Safe from signal handlers."""
        self._stop_requested.set()

    async def stop(self) -> None:
        """Request a graceful stop and wait until :meth:`run` has returned."""
        self.request_stop()
        await self._stopped.wait()

    async def run(self, handler: BatchHandler) -> None:
        """Consume until a stop is requested or the handler aborts.

        Raises:
            RuntimeError: If already running.
            Exception: Whatever the handler raised, other than ``BatchAbortedError``, or a
                non-transient connection error; the batch is not committed.
        """
        if self.running:
            raise RuntimeError("KafkaBatchConsumer is already running")
        self._stopped.clear()
        client: ConsumerClient | None = None
        try:
            client = await self._connect()
            if client is None:
                return
            logger.info(
                "kafka batch consumer started",
                extra={
                    "action": "kafka_consumer_started",
                    "group_id": self._group_id,
                    "topics": [topic.value for topic in self._topics],
                },
            )
            while not self._stop_requested.is_set():
                batches = await client.getmany(
                    timeout_ms=self._poll_timeout_ms, max_records=self._max_records
                )
                await self._refresh_lag(client)
                if self._idle_calls:
                    await self._refresh_caught_up(client)
                records = [record for polled in batches.values() for record in polled]
                if not records and not self._idle_calls:
                    continue
                try:
                    positions = await handler(records)
                except BatchAbortedError:
                    logger.info(
                        "batch aborted; its records will be redelivered",
                        extra={
                            "action": "kafka_batch_aborted",
                            "group_id": self._group_id,
                            "records": len(records),
                        },
                    )
                    return
                if positions is None:
                    offsets = {
                        partition: polled[-1].offset + 1
                        for partition, polled in batches.items()
                        if polled
                    }
                else:
                    offsets = _assigned(client, positions)
                if offsets:
                    await self._commit(client, offsets)
        finally:
            self._connected = False
            try:
                if client is not None:
                    await client.stop()
            finally:
                self._stop_requested.clear()  # a later run() starts afresh
                self._stopped.set()
                logger.info(
                    "kafka batch consumer stopped",
                    extra={"action": "kafka_consumer_stopped", "group_id": self._group_id},
                )

    async def _connect(self) -> ConsumerClient | None:
        """Start a client, retrying outages; ``None`` if stopping before it connected."""
        attempt = 0
        while not self._stop_requested.is_set():
            client = self._client_factory()
            try:
                await client.start()
            except Exception as error:
                with contextlib.suppress(Exception):
                    await client.stop()
                if not is_transient_transport_error(error):
                    raise
                attempt += 1
                delay = self._start_backoff.backoff_seconds(min(attempt, 32), default_jitter)
                logger.warning(
                    "kafka consumer could not connect; retrying",
                    extra={
                        "action": "kafka_consumer_connect_retry",
                        "group_id": self._group_id,
                        "attempt": attempt,
                        "error_type": type(error).__name__,
                        "retry_in_ms": round(delay * 1000),
                    },
                )
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stop_requested.wait(), timeout=delay)
                continue
            self._connected = True
            return client
        return None

    async def _refresh_caught_up(self, client: ConsumerClient) -> None:
        caught_up: dict[tuple[str, int], bool] = {}
        for partition in client.assignment():
            key = _partition_key(partition)
            if key is None:
                continue
            highwater = client.highwater(partition)
            try:
                position = await client.position(partition)
            except (IllegalStateError, KafkaError):
                continue  # revoked meanwhile
            caught_up[key] = highwater is not None and position >= highwater
        self._caught_up = caught_up

    async def _refresh_lag(self, client: ConsumerClient) -> None:
        now = time.monotonic()
        if now - self._lag_checked < LAG_REFRESH_SECONDS:
            return
        self._lag_checked = now
        lag: dict[str, int] = {}
        for partition in client.assignment():
            highwater = client.highwater(partition)
            if highwater is None:
                continue
            try:
                position = await client.position(partition)
            except (IllegalStateError, KafkaError):
                continue  # revoked meanwhile
            lag[partition_label(partition)] = max(0, highwater - position)
        self._lag = lag

    async def _commit(self, client: ConsumerClient, offsets: Mapping[object, int]) -> None:
        try:
            await client.commit(offsets)
        except (CommitFailedError, IllegalStateError) as error:
            logger.warning(
                "offsets not committed because the group rebalanced; the records will be "
                "redelivered",
                extra={
                    "action": "kafka_commit_failed",
                    "group_id": self._group_id,
                    "error_type": type(error).__name__,
                },
            )


def _assigned(client: ConsumerClient, positions: CommitPositions) -> dict[object, int]:
    """``positions`` keyed by the client's own partition objects, for assigned ones only."""
    assigned = {_partition_key(partition): partition for partition in client.assignment()}
    return {assigned[key]: offset for key, offset in positions.items() if key in assigned}


def _partition_key(partition: object) -> tuple[str, int] | None:
    """``(topic, partition)`` of a ``TopicPartition`` (a named tuple) or a plain tuple."""
    if isinstance(partition, tuple) and len(partition) == 2:
        topic, number = partition
        if isinstance(topic, str) and isinstance(number, int):
            return topic, number
    return None
