"""Dead-letter handling.

A record that cannot be processed (undecodable, rejected as non-retriable, or still
failing after all retries) is re-published to ``adis.deadletter``:

- the **value and key are copied byte for byte**, so even undecodable records can be
  inspected and replayed to their original topic;
- the original headers are kept, and failure context is added as ``adis-dlq-*`` headers.

The consumer commits the original offset only after the dead-letter write succeeds, so a
failing record is never lost.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Protocol, Self

from packages.kafka.producer import KafkaProducer, PublishedRecord
from packages.kafka.topics import Topic

DEFAULT_MAX_ERROR_MESSAGE_LENGTH: Final = 1_024


class DeadLetterHeader(StrEnum):
    """Headers describing why and where a record failed."""

    ORIGINAL_TOPIC = "adis-dlq-original-topic"
    ORIGINAL_PARTITION = "adis-dlq-original-partition"
    ORIGINAL_OFFSET = "adis-dlq-original-offset"
    ORIGINAL_TIMESTAMP_MS = "adis-dlq-original-timestamp-ms"
    CONSUMER_GROUP = "adis-dlq-consumer-group"
    ERROR_TYPE = "adis-dlq-error-type"
    ERROR_MESSAGE = "adis-dlq-error-message"
    ATTEMPTS = "adis-dlq-attempts"
    FAILED_AT = "adis-dlq-failed-at"


_DEAD_LETTER_HEADERS: Final = frozenset(header.value for header in DeadLetterHeader)


class FailedRecord(Protocol):
    """Where the failing record came from."""

    @property
    def topic(self) -> str:
        """Original topic."""
        ...

    @property
    def partition(self) -> int:
        """Original partition."""
        ...

    @property
    def offset(self) -> int:
        """Original offset."""
        ...

    @property
    def timestamp_ms(self) -> int:
        """Original record timestamp, epoch milliseconds."""
        ...

    @property
    def key(self) -> bytes | None:
        """Original key."""
        ...

    @property
    def headers(self) -> tuple[tuple[str, bytes], ...]:
        """Original headers."""
        ...


@dataclass(frozen=True, slots=True)
class DeadLetterRecord:
    """A dead-lettered record and why it failed."""

    original_topic: str
    original_partition: int
    original_offset: int
    original_timestamp_ms: int
    consumer_group: str
    error_type: str
    error_message: str
    attempts: int
    failed_at: datetime
    key: bytes | None
    value: bytes | None
    original_headers: tuple[tuple[str, bytes], ...]

    def headers(self) -> list[tuple[str, bytes]]:
        """Original headers followed by the ``adis-dlq-*`` failure headers."""
        failure = {
            DeadLetterHeader.ORIGINAL_TOPIC: self.original_topic,
            DeadLetterHeader.ORIGINAL_PARTITION: str(self.original_partition),
            DeadLetterHeader.ORIGINAL_OFFSET: str(self.original_offset),
            DeadLetterHeader.ORIGINAL_TIMESTAMP_MS: str(self.original_timestamp_ms),
            DeadLetterHeader.CONSUMER_GROUP: self.consumer_group,
            DeadLetterHeader.ERROR_TYPE: self.error_type,
            DeadLetterHeader.ERROR_MESSAGE: self.error_message,
            DeadLetterHeader.ATTEMPTS: str(self.attempts),
            DeadLetterHeader.FAILED_AT: self.failed_at.isoformat(),
        }
        return [
            *self.original_headers,
            *((header.value, text.encode("utf-8")) for header, text in failure.items()),
        ]

    @classmethod
    def from_message(
        cls, *, key: bytes | None, value: bytes | None, headers: tuple[tuple[str, bytes], ...]
    ) -> Self:
        """Parse a record read from the dead-letter topic.

        Raises:
            ValueError: If a failure header is missing or malformed.
        """
        found = {name: raw.decode("utf-8") for name, raw in headers if name in _DEAD_LETTER_HEADERS}
        missing = _DEAD_LETTER_HEADERS - found.keys()
        if missing:
            raise ValueError(f"not a dead-letter record; missing headers: {sorted(missing)}")
        return cls(
            original_topic=found[DeadLetterHeader.ORIGINAL_TOPIC],
            original_partition=int(found[DeadLetterHeader.ORIGINAL_PARTITION]),
            original_offset=int(found[DeadLetterHeader.ORIGINAL_OFFSET]),
            original_timestamp_ms=int(found[DeadLetterHeader.ORIGINAL_TIMESTAMP_MS]),
            consumer_group=found[DeadLetterHeader.CONSUMER_GROUP],
            error_type=found[DeadLetterHeader.ERROR_TYPE],
            error_message=found[DeadLetterHeader.ERROR_MESSAGE],
            attempts=int(found[DeadLetterHeader.ATTEMPTS]),
            failed_at=datetime.fromisoformat(found[DeadLetterHeader.FAILED_AT]),
            key=key,
            value=value,
            original_headers=_without_dead_letter_headers(headers),
        )


class DeadLetterPublisher:
    """Writes failed records to ``adis.deadletter`` through a shared producer."""

    def __init__(
        self,
        producer: KafkaProducer,
        *,
        max_error_message_length: int = DEFAULT_MAX_ERROR_MESSAGE_LENGTH,
    ) -> None:
        self._producer = producer
        self._max_error_message_length = max_error_message_length

    async def publish(
        self,
        record: FailedRecord,
        value: bytes | None,
        error: BaseException,
        *,
        attempts: int,
        consumer_group: str,
    ) -> PublishedRecord:
        """Dead-letter one record.

        The error message is truncated. Handlers must never put secrets in exception
        messages, because they are persisted here.

        Raises:
            PublishError: If the dead-letter topic is unreachable after all retries.
        """
        dead_letter = DeadLetterRecord(
            original_topic=record.topic,
            original_partition=record.partition,
            original_offset=record.offset,
            original_timestamp_ms=record.timestamp_ms,
            consumer_group=consumer_group,
            error_type=type(error).__name__,
            error_message=str(error)[: self._max_error_message_length],
            attempts=attempts,
            failed_at=datetime.now(UTC),
            key=record.key,
            value=value,
            original_headers=_without_dead_letter_headers(record.headers),
        )
        return await self._producer.send_raw(
            Topic.DEADLETTER, value, key=record.key, headers=dead_letter.headers()
        )


def _without_dead_letter_headers(
    headers: tuple[tuple[str, bytes], ...],
) -> tuple[tuple[str, bytes], ...]:
    """Drop failure headers left over from an earlier dead-lettering (e.g. after a replay)."""
    return tuple((name, raw) for name, raw in headers if name not in _DEAD_LETTER_HEADERS)
