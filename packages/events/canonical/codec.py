"""Parsing, JSON serialization, envelope mapping and JSON Schema of canonical events."""

import re
from collections.abc import Mapping
from typing import Final, Self

from pydantic import TypeAdapter, ValidationError
from pydantic_core import from_json

from packages.events.canonical import v1
from packages.events.envelope import EventEnvelope

CURRENT_SCHEMA_VERSION: Final = v1.SCHEMA_VERSION

_VERSION_PATTERN: Final = re.compile(r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)$")
_MAX_REPORTED_ISSUES: Final = 5

# One entry per supported schema_version; minor versions of one major share a module.
_ADAPTERS: Final[dict[str, TypeAdapter[v1.CanonicalEventV1]]] = {
    v1.SCHEMA_VERSION: TypeAdapter(v1.AnyCanonicalEvent),
}
_MAX_EVENT_BYTES: Final = {v1.SCHEMA_VERSION: v1.MAX_EVENT_BYTES}

SUPPORTED_SCHEMA_VERSIONS: Final = frozenset(_ADAPTERS)

AnyCanonicalEvent = v1.CanonicalEventV1
"""Any canonical event of any supported schema version."""


class CanonicalEventError(ValueError):
    """A document is not a valid canonical event.

    The message and :attr:`issues` name the failing fields but never their values, which
    may contain personal data or attacker-supplied content.
    """

    def __init__(self, message: str, issues: tuple[str, ...] = ()) -> None:
        self.issues = issues
        details = f": {'; '.join(issues)}" if issues else ""
        super().__init__(f"{message}{details}")

    @classmethod
    def from_validation_error(cls, error: ValidationError) -> Self:
        """Summarize a pydantic error without input values."""
        issues = tuple(
            f"{'.'.join(str(part) for part in details['loc']) or '<event>'}: {details['msg']}"
            for details in error.errors(include_url=False, include_input=False)[
                :_MAX_REPORTED_ISSUES
            ]
        )
        return cls(f"invalid canonical event ({error.error_count()} issue(s))", issues)


class UnsupportedSchemaVersionError(CanonicalEventError):
    """The document declares a ``schema_version`` this build does not understand."""


def parse_canonical_event(data: bytes | str | Mapping[str, object]) -> AnyCanonicalEvent:
    """Validate a canonical event from JSON (bytes or text) or an already-decoded mapping.

    The model is selected by ``schema_version`` and then by ``category``.

    Raises:
        UnsupportedSchemaVersionError: If ``schema_version`` is missing or unknown.
        CanonicalEventError: If the document is too large, not a JSON object, or invalid.
    """
    if isinstance(data, bytes | str):
        encoded = data.encode("utf-8") if isinstance(data, str) else data
        limit = max(_MAX_EVENT_BYTES.values())
        if len(encoded) > limit:
            raise CanonicalEventError(f"event exceeds {limit} bytes")
        try:
            document: object = from_json(encoded)
        except ValueError:
            raise CanonicalEventError("event is not valid JSON") from None
    else:
        document = data
    if not isinstance(document, Mapping):
        raise CanonicalEventError("event must be a JSON object")
    adapter = _adapter_for(document.get("schema_version"))
    try:
        return adapter.validate_python(document)
    except ValidationError as error:
        raise CanonicalEventError.from_validation_error(error) from None


def serialize_canonical_event(event: AnyCanonicalEvent) -> bytes:
    """Encode an event as compact UTF-8 JSON (UTC ``Z`` timestamps, IPs as strings)."""
    return event.model_dump_json().encode("utf-8")


def to_envelope(event: AnyCanonicalEvent, *, producer: str) -> EventEnvelope:
    """Wrap an event for transport, keeping the shared fields identical.

    ``event_id``, ``event_type``, ``timestamp`` and ``trace_id`` are copied, and
    ``event_version`` is the schema's major version.
    """
    return EventEnvelope(
        event_id=event.event_id,
        event_version=_major(event.schema_version),
        event_type=event.event_type,
        timestamp=event.timestamp,
        producer=producer,
        trace_id=event.trace_id,
        payload=event.model_dump(mode="json"),
    )


def from_envelope(envelope: EventEnvelope) -> AnyCanonicalEvent:
    """Extract and validate the canonical event carried by ``envelope``.

    Raises:
        CanonicalEventError: If the payload is invalid or disagrees with the envelope.
    """
    event = parse_canonical_event(envelope.payload)
    mismatched = [
        name
        for name, matches in (
            ("event_id", event.event_id == envelope.event_id),
            ("event_type", event.event_type == envelope.event_type),
            ("trace_id", event.trace_id == envelope.trace_id),
            ("event_version", _major(event.schema_version) == envelope.event_version),
        )
        if not matches
    ]
    if mismatched:
        raise CanonicalEventError(
            "envelope and canonical event disagree",
            tuple(f"{name}: mismatch" for name in mismatched),
        )
    return event


def canonical_event_json_schema(schema_version: str = CURRENT_SCHEMA_VERSION) -> dict[str, object]:
    """JSON Schema (draft 2020-12) of every event category for ``schema_version``.

    The committed copies under ``packages/events/canonical/schemas/`` are the published
    contract; ``scripts/generate_event_schemas.py`` regenerates them.
    """
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": f"ADIS canonical event {schema_version}",
        **_adapter_for(schema_version).json_schema(),
    }


def _adapter_for(schema_version: object) -> TypeAdapter[v1.CanonicalEventV1]:
    adapter = _ADAPTERS.get(schema_version) if isinstance(schema_version, str) else None
    if adapter is None:
        supported = ", ".join(sorted(SUPPORTED_SCHEMA_VERSIONS))
        if not isinstance(schema_version, str) or not _VERSION_PATTERN.match(schema_version):
            raise UnsupportedSchemaVersionError(
                f"schema_version must be a 'MAJOR.MINOR' string; supported: {supported}"
            )
        raise UnsupportedSchemaVersionError(
            f"schema_version {schema_version} is not supported; supported: {supported}"
        )
    return adapter


def _major(schema_version: str) -> int:
    return int(schema_version.split(".", 1)[0])
