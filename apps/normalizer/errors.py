"""Errors of the normalization pipeline and how failures are classified.

- **Transient** failures (database or broker unreachable, timeouts, lock conflicts) are
  outages: the pipeline retries them until they recover and never dead-letters an event
  because of one.
- Everything else is treated as a problem with specific records: the batch is split and
  each event is retried a bounded number of times before it is dead-lettered.
"""

from typing import Self

from packages.database.errors import is_transient_database_error, sqlstate_of
from packages.kafka import is_transient_transport_error


class NormalizationError(ValueError):
    """A record cannot be turned into a canonical event.

    Messages name the failing field but never its value, because dead-letter headers and
    logs must not carry attacker-supplied content or personal data.
    """


class PersistenceError(Exception):
    """The database refused an event permanently.

    The message names the error type and SQLSTATE only: database messages can quote the
    offending value.
    """

    @classmethod
    def from_error(cls, error: BaseException) -> Self:
        """Describe ``error`` without its message."""
        sqlstate = sqlstate_of(error)
        details = f" (SQLSTATE {sqlstate})" if sqlstate else ""
        return cls(f"event could not be stored: {type(error).__name__}{details}")


class ConflictingDuplicateError(Exception):
    """An event reuses a stored ``event_id`` with different content.

    The stored event is kept (the first write wins); the conflicting record is
    dead-lettered so that it is never lost silently and can be investigated: it may be
    a producer bug or an attempt to pre-empt an event id.
    """

    def __init__(self) -> None:
        super().__init__("event_id already stored with different content")


def is_transient_error(error: BaseException) -> bool:
    """Whether ``error`` is an outage worth retrying until it recovers."""
    if isinstance(error, BaseExceptionGroup):
        return all(is_transient_error(member) for member in error.exceptions)
    return is_transient_transport_error(error) or is_transient_database_error(error)
