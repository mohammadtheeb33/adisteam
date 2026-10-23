"""Canonical security event schemas and normalization contracts.

Currently provides the transport-independent :class:`EventEnvelope`. Payload schemas per
event type are added as producers are implemented.
"""

from packages.events.envelope import (
    EVENT_TYPE_PATTERN,
    PRODUCER_PATTERN,
    TRACE_ID_PATTERN,
    EventEnvelope,
    new_trace_id,
)

__all__ = [
    "EVENT_TYPE_PATTERN",
    "PRODUCER_PATTERN",
    "TRACE_ID_PATTERN",
    "EventEnvelope",
    "new_trace_id",
]
