"""Canonical ADIS security event schema (versioned).

Import models from here to get the current schema version; import a version module
(``packages.events.canonical.v1``) to pin one. See docs/EVENT_SCHEMA.md.
"""

from packages.events.canonical.codec import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    AnyCanonicalEvent,
    CanonicalEventError,
    UnsupportedSchemaVersionError,
    canonical_event_json_schema,
    from_envelope,
    parse_canonical_event,
    serialize_canonical_event,
    to_envelope,
)
from packages.events.canonical.v1 import (
    AuthenticationEvent,
    AuthFailureReason,
    AuthMethod,
    CanonicalEvent,
    EventCategory,
    NetworkFlowEvent,
    NetworkProtocol,
    ProcessEvent,
    SecurityEvent,
    SeverityHint,
    SystemEvent,
)

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_VERSIONS",
    "AnyCanonicalEvent",
    "AuthFailureReason",
    "AuthMethod",
    "AuthenticationEvent",
    "CanonicalEvent",
    "CanonicalEventError",
    "EventCategory",
    "NetworkFlowEvent",
    "NetworkProtocol",
    "ProcessEvent",
    "SecurityEvent",
    "SeverityHint",
    "SystemEvent",
    "UnsupportedSchemaVersionError",
    "canonical_event_json_schema",
    "from_envelope",
    "parse_canonical_event",
    "serialize_canonical_event",
    "to_envelope",
]
