"""JSON serialization of event envelopes and Kafka headers."""

from collections.abc import Sequence
from typing import Final, Literal

from pydantic import ValidationError

from packages.events import EventEnvelope
from packages.kafka.errors import DeserializationError
from packages.observability import is_valid_trace_id

CONTENT_TYPE: Final = "application/json"

HEADER_CONTENT_TYPE: Final = "content-type"
HEADER_EVENT_ID: Final = "adis-event-id"
HEADER_EVENT_TYPE: Final = "adis-event-type"
HEADER_EVENT_VERSION: Final = "adis-event-version"
HEADER_PRODUCER: Final = "adis-producer"
HEADER_TRACE_ID: Final = "adis-trace-id"
HEADER_INGEST_CLIENT: Final = "adis-ingest-client"
"""Ingestion client (API token owner) that submitted the event; set by the ingestion API."""
HEADER_REQUEST_ID: Final = "adis-request-id"
"""Ingestion API request that carried the event."""
HEADER_INGEST_HOST_SCOPE: Final = "adis-ingest-host-scope"
"""How far the submitting client is trusted for the event's host; set by the ingestion API."""

HostScope = Literal["exclusive", "shared", "unbound"]
"""The submitting client's binding to the event's host (``API_INGEST_CLIENT_HOSTS``).

- ``exclusive``: the client may write this host only (typically the host's own agent);
- ``shared``: the client may write this host and others (for example a network sensor);
- ``unbound``: the client may write any host. Missing provenance counts as ``unbound``.
"""
HOST_SCOPES: Final[tuple[HostScope, ...]] = ("exclusive", "shared", "unbound")

_MAX_REPORTED_ISSUES: Final = 3

Headers = list[tuple[str, bytes]]


def serialize_envelope(envelope: EventEnvelope) -> bytes:
    """Encode an envelope as UTF-8 JSON."""
    return envelope.model_dump_json().encode("utf-8")


def deserialize_envelope(value: bytes | None) -> EventEnvelope:
    """Decode and validate a record value.

    Raises:
        DeserializationError: If the value is missing, not JSON, or not a valid envelope.
            The message names the failing fields but never includes their values.
    """
    if value is None:
        raise DeserializationError("record has no value")
    try:
        return EventEnvelope.model_validate_json(value)
    except ValidationError as error:
        issues = [
            f"{'.'.join(str(part) for part in details['loc']) or '<root>'}: {details['msg']}"
            for details in error.errors(include_url=False, include_input=False)[
                :_MAX_REPORTED_ISSUES
            ]
        ]
        raise DeserializationError(
            f"invalid event envelope ({error.error_count()} issue(s)): {'; '.join(issues)}"
        ) from None


def envelope_headers(envelope: EventEnvelope) -> Headers:
    """Kafka headers mirroring envelope metadata, for routing and triage without parsing.

    The record value remains the source of truth.
    """
    return [
        (HEADER_CONTENT_TYPE, CONTENT_TYPE.encode()),
        (HEADER_EVENT_ID, str(envelope.event_id).encode()),
        (HEADER_EVENT_TYPE, envelope.event_type.encode()),
        (HEADER_EVENT_VERSION, str(envelope.event_version).encode()),
        (HEADER_PRODUCER, envelope.producer.encode()),
        (HEADER_TRACE_ID, envelope.trace_id.encode()),
    ]


def trace_id_from_headers(headers: Sequence[tuple[str, bytes]]) -> str | None:
    """The ``adis-trace-id`` header value, if present and a valid W3C trace id.

    Used to correlate records whose value cannot be decoded (poison messages).
    """
    for name, raw in headers:
        if name == HEADER_TRACE_ID:
            candidate = raw.decode("ascii", errors="replace")
            return candidate if is_valid_trace_id(candidate) else None
    return None


def encode_key(key: str | None) -> bytes | None:
    """Encode a partition key. Records with the same key keep their relative order."""
    return None if key is None else key.encode("utf-8")
