"""aiokafka client options and error classification."""

import ssl

import pytest
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient
from aiokafka.errors import (
    KafkaConnectionError,
    KafkaError,
    KafkaTimeoutError,
    MessageSizeTooLargeError,
    NotLeaderForPartitionError,
)

from packages.config import KafkaSecurityProtocol, KafkaSettings
from packages.kafka import KafkaConfigurationError
from packages.kafka.clients import (
    consumer_options,
    is_retriable_kafka_error,
    producer_options,
    security_options,
)


def _settings(**values: object) -> KafkaSettings:
    return KafkaSettings.model_validate(
        {"kafka_bootstrap_servers": "broker-1:9092,broker-2:9092", **values}
    )


def test_producer_is_durable_and_idempotent() -> None:
    options = producer_options(_settings(), client_id="adis-agent")

    assert options == {
        "bootstrap_servers": "broker-1:9092,broker-2:9092",
        "security_protocol": "PLAINTEXT",
        "client_id": "adis-agent",
        "acks": "all",
        "enable_idempotence": True,
    }


def test_consumer_commits_manually() -> None:
    options = consumer_options(_settings(), group_id="adis-detector")

    assert options["group_id"] == "adis-detector"
    assert options["enable_auto_commit"] is False
    assert options["auto_offset_reset"] == "earliest"
    assert options["client_id"] == "adis"


def test_ssl_uses_a_verifying_context() -> None:
    options = security_options(_settings(kafka_security_protocol="SSL"))

    context = options["ssl_context"]
    assert options["security_protocol"] == "SSL"
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode is ssl.CERT_REQUIRED


@pytest.mark.parametrize(("protocol", "encrypted"), [("SASL_PLAINTEXT", False), ("SASL_SSL", True)])
def test_sasl_options_carry_the_credentials(protocol: str, encrypted: bool) -> None:
    options = security_options(
        _settings(
            kafka_security_protocol=protocol,
            kafka_sasl_mechanism="SCRAM-SHA-256",
            kafka_sasl_username="adis",
            kafka_sasl_password="p" * 24,
        )
    )

    assert options["security_protocol"] == protocol
    assert (options["sasl_mechanism"], options["sasl_plain_username"]) == ("SCRAM-SHA-256", "adis")
    assert options["sasl_plain_password"] == "p" * 24
    assert ("ssl_context" in options) is encrypted


def test_sasl_without_credentials_is_a_configuration_error() -> None:
    settings = KafkaSettings.model_construct(kafka_security_protocol=KafkaSecurityProtocol.SASL_SSL)

    with pytest.raises(KafkaConfigurationError, match="KAFKA_SASL_MECHANISM"):
        security_options(settings)


@pytest.mark.parametrize(
    ("error", "retriable"),
    [
        (KafkaTimeoutError(), True),
        (KafkaConnectionError(), True),
        (NotLeaderForPartitionError(), True),
        (MessageSizeTooLargeError(), False),
        (KafkaError(), False),
        (ValueError(), False),
    ],
)
def test_retriable_classification(error: Exception, retriable: bool) -> None:
    assert is_retriable_kafka_error(error) is retriable


async def test_real_clients_accept_the_generated_options() -> None:
    """Constructing (without connecting) catches misspelled or unsupported options."""
    settings = _settings()

    producer = AIOKafkaProducer(**producer_options(settings))
    consumer = AIOKafkaConsumer("system_logs", **consumer_options(settings, group_id="g"))
    admin = AIOKafkaAdminClient(**security_options(settings), client_id="adis")

    await producer.stop()
    await consumer.stop()
    await admin.close()
