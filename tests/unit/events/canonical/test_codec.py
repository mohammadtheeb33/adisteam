"""Parsing, JSON serialization, versioning and envelope mapping."""

import json
from typing import Any

import pytest

from packages.events import EventEnvelope
from packages.events.canonical import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    AuthenticationEvent,
    CanonicalEventError,
    NetworkFlowEvent,
    ProcessEvent,
    SecurityEvent,
    SystemEvent,
    UnsupportedSchemaVersionError,
    from_envelope,
    parse_canonical_event,
    serialize_canonical_event,
    to_envelope,
)
from packages.events.canonical.v1 import MAX_EVENT_BYTES
from packages.kafka import deserialize_envelope, serialize_envelope
from tests.unit.events.canonical.samples import BUILDERS, authentication, network, system

EXPECTED_CLASSES = {
    "system": SystemEvent,
    "authentication": AuthenticationEvent,
    "network": NetworkFlowEvent,
    "process": ProcessEvent,
    "security": SecurityEvent,
}


def test_versions() -> None:
    assert CURRENT_SCHEMA_VERSION == "1.0"
    assert sorted(SUPPORTED_SCHEMA_VERSIONS) == ["1.0"]


@pytest.mark.parametrize("category", sorted(BUILDERS))
@pytest.mark.parametrize("form", ["mapping", "text", "bytes"])
def test_parse_selects_the_model_by_category(category: str, form: str) -> None:
    document = BUILDERS[category]()
    data: object = {
        "mapping": document,
        "text": json.dumps(document),
        "bytes": json.dumps(document).encode(),
    }[form]

    event = parse_canonical_event(data)  # type: ignore[arg-type]

    assert type(event) is EXPECTED_CLASSES[category]


@pytest.mark.parametrize("category", sorted(BUILDERS))
def test_json_round_trip_is_lossless(category: str) -> None:
    event = parse_canonical_event(BUILDERS[category]())

    assert parse_canonical_event(serialize_canonical_event(event)) == event


def test_serialized_form() -> None:
    event = parse_canonical_event(
        network(timestamp="2026-09-25T15:00:00+03:00", src_ip="::ffff:10.0.0.5")
    )

    raw = serialize_canonical_event(event)
    document = json.loads(raw)

    assert isinstance(raw, bytes)
    assert b"\n" not in raw
    assert document["schema_version"] == "1.0"
    assert document["category"] == "network"
    assert document["event_id"] == str(event.event_id)
    assert document["timestamp"] == "2026-09-25T12:00:00Z"
    assert document["src_ip"] == "10.0.0.5"
    assert document["protocol"] == "tcp"


def test_non_ascii_text_is_kept_as_utf8() -> None:
    event = parse_canonical_event(authentication(username="José"))

    assert "José".encode() in serialize_canonical_event(event)


@pytest.mark.parametrize("version", ["1.1", "2.0", "0.9"])
def test_unknown_schema_versions_are_rejected_with_the_supported_list(version: str) -> None:
    with pytest.raises(UnsupportedSchemaVersionError, match=r"not supported; supported: 1\.0"):
        parse_canonical_event(system(schema_version=version))


@pytest.mark.parametrize("version", [None, 1, 1.0, "1", "v1.0", "01.0", ""])
def test_malformed_schema_versions_are_rejected(version: object) -> None:
    with pytest.raises(UnsupportedSchemaVersionError, match=r"MAJOR\.MINOR"):
        parse_canonical_event(system(schema_version=version))


def test_missing_schema_version_is_rejected() -> None:
    document = system()
    del document["schema_version"]

    with pytest.raises(UnsupportedSchemaVersionError):
        parse_canonical_event(document)


@pytest.mark.parametrize(
    "document",
    [system(category="dns"), {k: v for k, v in system().items() if k != "category"}],
)
def test_unknown_or_missing_category_is_rejected(document: dict[str, object]) -> None:
    with pytest.raises(CanonicalEventError):
        parse_canonical_event(document)


@pytest.mark.parametrize("data", [b"not json", b"[1, 2]", b'"text"', b"", "{", b"null"])
def test_non_object_json_is_rejected(data: bytes | str) -> None:
    with pytest.raises(CanonicalEventError):
        parse_canonical_event(data)


def test_oversized_events_are_rejected_before_parsing() -> None:
    oversized = b" " * (MAX_EVENT_BYTES + 1)

    with pytest.raises(CanonicalEventError, match="exceeds"):
        parse_canonical_event(oversized)


def test_errors_name_fields_but_never_echo_values() -> None:
    with pytest.raises(CanonicalEventError) as caught:
        parse_canonical_event(
            authentication(username="sentinel-user", src_port=99_999, src_ip="sentinel-ip")
        )

    error = caught.value
    assert "sentinel" not in str(error)
    assert error.__cause__ is None
    assert any("src_port" in issue for issue in error.issues)
    assert any("src_ip" in issue for issue in error.issues)


@pytest.mark.parametrize("category", sorted(BUILDERS))
def test_envelope_round_trip(category: str) -> None:
    event = parse_canonical_event(BUILDERS[category]())

    envelope = to_envelope(event, producer="adis-agent")

    assert envelope.event_id == event.event_id
    assert envelope.event_type == event.event_type
    assert envelope.timestamp == event.timestamp
    assert envelope.trace_id == event.trace_id
    assert envelope.event_version == 1
    assert envelope.producer == "adis-agent"
    assert envelope.payload == event.model_dump(mode="json")
    assert from_envelope(envelope) == event


def test_envelope_survives_the_kafka_wire_format() -> None:
    event = parse_canonical_event(network())

    record = serialize_envelope(to_envelope(event, producer="adis-agent"))

    assert from_envelope(deserialize_envelope(record)) == event


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", "00000000-0000-0000-0000-000000000001"),
        ("event_type", "system.boot"),
        ("trace_id", "b" * 32),
        ("event_version", 2),
    ],
)
def test_envelope_disagreeing_with_its_payload_is_rejected(field: str, value: object) -> None:
    event = parse_canonical_event(system())
    fields: dict[str, Any] = to_envelope(event, producer="adis-agent").model_dump()
    fields[field] = value

    with pytest.raises(CanonicalEventError, match=field):
        from_envelope(EventEnvelope.model_validate(fields))


def test_envelope_with_invalid_payload_is_rejected() -> None:
    envelope = EventEnvelope(
        event_type="system.boot",
        event_version=1,
        producer="adis-agent",
        payload={"schema_version": "1.0", "category": "system"},
    )

    with pytest.raises(CanonicalEventError):
        from_envelope(envelope)
