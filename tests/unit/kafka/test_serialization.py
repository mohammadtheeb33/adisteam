"""Envelope serialization and headers."""

import json

import pytest

from packages.kafka import (
    DeserializationError,
    deserialize_envelope,
    encode_key,
    envelope_headers,
    serialize_envelope,
    trace_id_from_headers,
)
from tests.unit.kafka.fakes import make_envelope

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


def test_round_trip() -> None:
    envelope = make_envelope(payload={"ip": "10.0.0.5", "ports": [22, 443]})

    assert deserialize_envelope(serialize_envelope(envelope)) == envelope


def test_serialized_form_is_utf8_json_with_every_envelope_field() -> None:
    envelope = make_envelope()

    document = json.loads(serialize_envelope(envelope).decode("utf-8"))

    assert set(document) == {
        "event_id",
        "event_version",
        "event_type",
        "timestamp",
        "producer",
        "trace_id",
        "payload",
    }
    assert document["event_id"] == str(envelope.event_id)
    assert document["timestamp"].endswith("Z")


@pytest.mark.parametrize(
    "value",
    [
        None,
        b"",
        b"not json",
        b"\xff\xfe\x00",
        b"[]",
        b'{"event_type": "x"}',
    ],
)
def test_invalid_values_raise_deserialization_error(value: bytes | None) -> None:
    with pytest.raises(DeserializationError):
        deserialize_envelope(value)


def test_deserialization_error_names_fields_but_not_values() -> None:
    document = json.loads(serialize_envelope(make_envelope()))
    document["event_version"] = 0
    document["producer"] = "sentinel value with spaces"

    with pytest.raises(DeserializationError) as caught:
        deserialize_envelope(json.dumps(document).encode())

    message = str(caught.value)
    assert "event_version" in message
    assert "producer" in message
    assert "sentinel" not in message


def test_headers_mirror_envelope_metadata() -> None:
    envelope = make_envelope()

    headers = dict(envelope_headers(envelope))

    assert headers == {
        "content-type": b"application/json",
        "adis-event-id": str(envelope.event_id).encode(),
        "adis-event-type": b"security.alert_raised",
        "adis-event-version": b"1",
        "adis-producer": b"adis-test",
        "adis-trace-id": envelope.trace_id.encode(),
    }


def test_encode_key() -> None:
    assert encode_key(None) is None
    assert encode_key("host-42") == b"host-42"


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([("adis-trace-id", TRACE.encode())], TRACE),
        ([("adis-trace-id", b"not-a-trace")], None),
        ([("adis-trace-id", bytes([0xFF, 0xFE]))], None),
        ([("adis-trace-id", b"0" * 32)], None),
        ([("other", b"x")], None),
        ([], None),
    ],
)
def test_trace_id_from_headers(headers: list[tuple[str, bytes]], expected: str | None) -> None:
    assert trace_id_from_headers(headers) == expected


def test_headers_round_trip_the_trace_id() -> None:
    envelope = make_envelope()

    assert trace_id_from_headers(envelope_headers(envelope)) == envelope.trace_id
