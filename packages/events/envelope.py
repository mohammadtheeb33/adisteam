"""Event envelope: the metadata every ADIS event carries, whatever the transport."""

from datetime import UTC, datetime
from typing import Final
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, field_validator
from pydantic_core import PydanticCustomError

from packages.observability.context import TRACE_ID_PATTERN, current_trace_id, new_trace_id

__all__ = [
    "EVENT_TYPE_PATTERN",
    "PRODUCER_PATTERN",
    "TRACE_ID_PATTERN",
    "EventEnvelope",
    "new_trace_id",
]

EVENT_TYPE_PATTERN: Final = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"
PRODUCER_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
_INVALID_TRACE_ID: Final = "0" * 32


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _inherited_or_new_trace_id() -> str:
    """Continue the trace bound to the current task (request or event), or start one."""
    return current_trace_id() or new_trace_id()


class EventEnvelope(BaseModel):
    """Immutable wrapper around every ADIS event.

    Attributes:
        event_id: Unique id of this event. Consumers use it to deduplicate, because
            delivery is at-least-once.
        event_version: Schema version of ``payload`` for this ``event_type``, starting at 1.
        event_type: Dotted, lower-case type such as ``auth.login_failed``.
        timestamp: When the event occurred, normalized to UTC.
        producer: Name of the producing service (its ``APP_NAME``).
        trace_id: W3C trace id correlating every event in one causal chain. When omitted,
            it is inherited from the current correlation context (the HTTP request or
            the event being consumed), or a new trace is started.
        payload: Event-specific JSON object, validated against the schema for
            ``event_type``/``event_version`` by consumers. Treat it as read-only.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    event_id: UUID = Field(default_factory=uuid4)
    event_version: int = Field(ge=1)
    event_type: str = Field(pattern=EVENT_TYPE_PATTERN, max_length=128)
    timestamp: AwareDatetime = Field(default_factory=_utc_now)
    producer: str = Field(pattern=PRODUCER_PATTERN)
    trace_id: str = Field(default_factory=_inherited_or_new_trace_id, pattern=TRACE_ID_PATTERN)
    payload: dict[str, JsonValue]

    @field_validator("timestamp")
    @classmethod
    def _normalize_to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator("trace_id")
    @classmethod
    def _reject_all_zero_trace_id(cls, value: str) -> str:
        if value == _INVALID_TRACE_ID:
            raise PydanticCustomError("invalid_trace_id", "must not be all zeros")
        return value
