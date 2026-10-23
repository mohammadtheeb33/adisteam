"""Vendor metadata: preserved losslessly when JSON-safe, bounded, credentials redacted."""

import json
from datetime import UTC, datetime, timedelta, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

import pytest
from pydantic import ValidationError

from packages.events.canonical import SystemEvent, parse_canonical_event, serialize_canonical_event
from packages.events.canonical.v1 import (
    MAX_METADATA_BYTES,
    MAX_METADATA_DEPTH,
    MAX_METADATA_KEY_LENGTH,
)
from packages.observability import REDACTED
from tests.unit.events.canonical.samples import system


class Color(Enum):
    """An arbitrary vendor enum."""

    RED = "red"


def _metadata(value: object) -> dict[str, object]:
    return dict(SystemEvent.model_validate(system(metadata=value)).metadata)


def _nested(depth: int) -> dict[str, object]:
    value: dict[str, object] = {"leaf": 1}
    for _ in range(depth - 1):
        value = {"level": value}
    return value


def test_unknown_vendor_data_survives_a_json_round_trip() -> None:
    vendor = {
        "EventID": 4625,
        "LogonType": 3,
        "SubStatus": "0xC000006A",
        "ratio": 0.25,
        "flags": [True, False, None],
        "nested": {"list": [{"a": 1}, {"b": [1, 2, {"c": "d"}]}], "empty": {}},
        "unicode": "José ✓",
    }
    event = SystemEvent.model_validate(system(metadata=vendor))

    restored = parse_canonical_event(serialize_canonical_event(event))

    assert restored.metadata == vendor
    assert restored == event


def test_python_values_are_converted_to_json() -> None:
    metadata = _metadata(
        {
            "at": datetime(2026, 9, 25, 15, tzinfo=timezone(timedelta(hours=3))),
            "id": UUID(int=7),
            "v4": IPv4Address("10.0.0.1"),
            "v6": IPv6Address("2001:db8::1"),
            "color": Color.RED,
            "pair": (1, "two"),
        }
    )

    assert metadata == {
        "at": "2026-09-25T12:00:00Z",
        "id": "00000000-0000-0000-0000-000000000007",
        "v4": "10.0.0.1",
        "v6": "2001:db8::1",
        "color": "red",
        "pair": [1, "two"],
    }


@pytest.mark.parametrize(
    "metadata",
    [
        {"when": datetime(2026, 9, 25, 12)},  # naive on purpose
        {"raw": b"\x00\x01"},
        {"tags": {"a", "b"}},
        {"object": object()},
        {"nan": float("nan")},
        {"inf": float("inf")},
        {1: "integer key"},
        {"": "empty key"},
        {"k" * (MAX_METADATA_KEY_LENGTH + 1): "long key"},
        _nested(MAX_METADATA_DEPTH + 1),
        {"blob": "x" * MAX_METADATA_BYTES},
        ["not", "an", "object"],
        "not an object",
    ],
)
def test_unsafe_metadata_is_rejected(metadata: object) -> None:
    with pytest.raises(ValidationError):
        _metadata(metadata)


def test_limits_are_inclusive() -> None:
    key = "k" * MAX_METADATA_KEY_LENGTH

    assert key in _metadata({key: 1})
    assert _metadata(_nested(MAX_METADATA_DEPTH))


def test_unstorable_characters_are_replaced_in_keys_and_values() -> None:
    metadata = _metadata({"cmd\x00line": "a\x00b", "list": ["\ud800"]})

    assert metadata == {"cmd�line": "a�b", "list": ["�"]}
    json.dumps(metadata).encode("utf-8")


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Password",
        "PASSWD",
        "pwd",
        "api_key",
        "API-KEY",
        "client_secret",
        "access_token",
        "Refresh-Token",
        "Authorization",
        "set-cookie",
        "Cookie",
        "private_key",
        "session_token",
    ],
)
def test_credential_keys_are_redacted_at_any_depth(key: str) -> None:
    metadata = _metadata({key: "sentinel-1", "nested": [{"inner": {key: "sentinel-2"}}]})

    assert metadata[key] == REDACTED
    assert "sentinel" not in json.dumps(metadata)


@pytest.mark.parametrize(
    "key",
    [
        "registry_key",
        "TokenElevationType",
        "public_key",
        "key",
        "password_last_set",
        "token_count",
        "secret_scanning_rule",
        "cookie_count",
    ],
)
def test_security_relevant_lookalikes_are_preserved(key: str) -> None:
    assert _metadata({key: "kept"})[key] == "kept"


def test_metadata_cannot_shadow_canonical_fields() -> None:
    event = SystemEvent.model_validate(
        system(metadata={"event_id": "spoofed", "host_id": "attacker", "category": "network"})
    )

    assert event.host_id == "web-1"
    assert event.metadata["host_id"] == "attacker"
    assert str(event.event_id) != "spoofed"


def test_metadata_is_serialized_last() -> None:
    event = SystemEvent.model_validate(system(metadata={"a": 1}))

    document = json.loads(serialize_canonical_event(event))

    assert list(document)[-1] == "metadata"


def test_aware_datetime_metadata_is_normalized_to_utc_z() -> None:
    assert _metadata({"at": datetime(2026, 1, 1, tzinfo=UTC)}) == {"at": "2026-01-01T00:00:00Z"}
