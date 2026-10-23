"""Errors raised by the ADIS Kafka layer."""


class KafkaConfigurationError(ValueError):
    """The Kafka settings request a capability that is not supported yet."""


class DeserializationError(ValueError):
    """A record value is not a valid ADIS event envelope (a poison message)."""


class NonRetriableError(Exception):
    """Raised by message handlers for failures that retrying cannot fix.

    The consumer dead-letters the message immediately instead of retrying. Any other
    exception is treated as transient and retried with backoff first.
    """


class BatchAbortedError(Exception):
    """Raised by a batch handler to leave its batch uncommitted, e.g. when stopping.

    The records are redelivered to the next consumer of their partitions.
    """


class PublishError(Exception):
    """A record could not be published after all retry attempts."""

    def __init__(self, topic: str, attempts: int) -> None:
        self.topic = topic
        self.attempts = attempts
        super().__init__(f"failed to publish to {topic} after {attempts} attempt(s)")


class TopicAdministrationError(Exception):
    """The broker rejected the creation of one or more topics."""
