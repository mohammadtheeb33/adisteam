"""Kafka transport for ADIS events (aiokafka).

Kafka is the event transport, never a source of truth. Delivery is at-least-once:
consumers must be idempotent and deduplicate by ``event_id``.
"""

from packages.kafka.admin import ensure_topics
from packages.kafka.batch_consumer import BatchHandler, CommitPositions, KafkaBatchConsumer
from packages.kafka.clients import is_transient_transport_error
from packages.kafka.consumer import (
    ConsumerRecordLike,
    KafkaConsumer,
    MessageContext,
    MessageHandler,
)
from packages.kafka.dead_letter import DeadLetterHeader, DeadLetterPublisher, DeadLetterRecord
from packages.kafka.errors import (
    BatchAbortedError,
    DeserializationError,
    KafkaConfigurationError,
    NonRetriableError,
    PublishError,
    TopicAdministrationError,
)
from packages.kafka.producer import KafkaProducer, PublishedRecord
from packages.kafka.retry import RetryError, RetryPolicy, retry_async
from packages.kafka.serialization import (
    HEADER_INGEST_CLIENT,
    HEADER_INGEST_HOST_SCOPE,
    HEADER_REQUEST_ID,
    HOST_SCOPES,
    HostScope,
    deserialize_envelope,
    encode_key,
    envelope_headers,
    serialize_envelope,
    trace_id_from_headers,
)
from packages.kafka.topics import (
    NORMALIZED_EVENTS_TOPIC,
    RAW_TELEMETRY_TOPICS,
    TELEMETRY_TOPICS,
    TOPIC_DESCRIPTIONS,
    Topic,
    TopicSpec,
    telemetry_topic,
    topic_specs,
)

__all__ = [
    "HEADER_INGEST_CLIENT",
    "HEADER_INGEST_HOST_SCOPE",
    "HEADER_REQUEST_ID",
    "HOST_SCOPES",
    "NORMALIZED_EVENTS_TOPIC",
    "RAW_TELEMETRY_TOPICS",
    "TELEMETRY_TOPICS",
    "TOPIC_DESCRIPTIONS",
    "BatchAbortedError",
    "BatchHandler",
    "CommitPositions",
    "ConsumerRecordLike",
    "DeadLetterHeader",
    "DeadLetterPublisher",
    "DeadLetterRecord",
    "DeserializationError",
    "HostScope",
    "KafkaBatchConsumer",
    "KafkaConfigurationError",
    "KafkaConsumer",
    "KafkaProducer",
    "MessageContext",
    "MessageHandler",
    "NonRetriableError",
    "PublishError",
    "PublishedRecord",
    "RetryError",
    "RetryPolicy",
    "Topic",
    "TopicAdministrationError",
    "TopicSpec",
    "deserialize_envelope",
    "encode_key",
    "ensure_topics",
    "envelope_headers",
    "is_transient_transport_error",
    "retry_async",
    "serialize_envelope",
    "telemetry_topic",
    "topic_specs",
    "trace_id_from_headers",
]
