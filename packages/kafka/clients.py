"""aiokafka client options derived from settings.

aiokafka clients bind to the running event loop when constructed, so the producer and
consumer build them lazily in ``start()``/``run()`` from these options.
"""

from typing import Literal

from aiokafka.errors import KafkaError, KafkaTimeoutError
from aiokafka.helpers import create_ssl_context

from packages.config import KafkaSecurityProtocol, KafkaSettings
from packages.kafka.errors import KafkaConfigurationError, PublishError

OffsetReset = Literal["earliest", "latest"]


def security_options(settings: KafkaSettings) -> dict[str, object]:
    """Connection security options shared by every client.

    - ``SSL`` and ``SASL_SSL`` use the system trust store.
    - ``SASL_*`` authenticate with ``KAFKA_SASL_MECHANISM`` (``PLAIN``,
      ``SCRAM-SHA-256`` or ``SCRAM-SHA-512``), ``KAFKA_SASL_USERNAME`` and
      ``KAFKA_SASL_PASSWORD``; configuration validation guarantees all three are set.

    Raises:
        KafkaConfigurationError: If a SASL protocol lacks its credentials (settings
            built without validation).
    """
    protocol = settings.kafka_security_protocol
    options: dict[str, object] = {
        "bootstrap_servers": settings.kafka_bootstrap_servers,
        "security_protocol": protocol.value,
    }
    if protocol in {KafkaSecurityProtocol.SSL, KafkaSecurityProtocol.SASL_SSL}:
        options["ssl_context"] = create_ssl_context()
    if protocol in {KafkaSecurityProtocol.SASL_PLAINTEXT, KafkaSecurityProtocol.SASL_SSL}:
        mechanism, username, password = (
            settings.kafka_sasl_mechanism,
            settings.kafka_sasl_username,
            settings.kafka_sasl_password,
        )
        if mechanism is None or username is None or password is None:
            raise KafkaConfigurationError(
                f"KAFKA_SECURITY_PROTOCOL={protocol.value} requires KAFKA_SASL_MECHANISM, "
                "KAFKA_SASL_USERNAME and KAFKA_SASL_PASSWORD"
            )
        options |= {
            "sasl_mechanism": mechanism.value,
            "sasl_plain_username": username,
            "sasl_plain_password": password.get_secret_value(),
        }
    return options


def producer_options(settings: KafkaSettings, *, client_id: str | None = None) -> dict[str, object]:
    """Options for ``AIOKafkaProducer``: durable (``acks=all``) and idempotent."""
    return {
        **security_options(settings),
        "client_id": client_id or settings.kafka_client_id,
        "acks": "all",
        "enable_idempotence": True,
    }


def consumer_options(
    settings: KafkaSettings,
    *,
    group_id: str,
    client_id: str | None = None,
    auto_offset_reset: OffsetReset = "earliest",
) -> dict[str, object]:
    """Options for ``AIOKafkaConsumer``: manual commits for at-least-once processing."""
    return {
        **security_options(settings),
        "client_id": client_id or settings.kafka_client_id,
        "group_id": group_id,
        "enable_auto_commit": False,
        "auto_offset_reset": auto_offset_reset,
    }


def is_retriable_kafka_error(error: Exception) -> bool:
    """Whether a Kafka client error is transient.

    aiokafka marks broker-side transient errors as ``retriable``; client-side timeouts
    (``KafkaTimeoutError``) are transient too but are not flagged by aiokafka.
    """
    if isinstance(error, KafkaTimeoutError):
        return True
    return isinstance(error, KafkaError) and bool(error.retriable)


def is_transient_transport_error(error: BaseException) -> bool:
    """Whether ``error`` is a broker or network outage, worth retrying until it recovers.

    Covers exhausted publish retries, timeouts, socket errors and retriable aiokafka
    errors; an exception group counts when every member does.
    """
    if isinstance(error, BaseExceptionGroup):
        return all(is_transient_transport_error(member) for member in error.exceptions)
    if isinstance(error, PublishError | TimeoutError | OSError):
        return True
    return isinstance(error, KafkaError) and is_retriable_kafka_error(error)
