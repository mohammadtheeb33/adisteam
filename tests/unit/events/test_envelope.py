"""Event envelope defaults, validation and JSON round trip."""

import re
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from packages.events import TRACE_ID_PATTERN, EventEnvelope, new_trace_id
from packages.observability import log_context


def _envelope(**overrides: object) -> EventEnvelope:
    fields: dict[str, object] = {
        "event_type": "auth.login_failed",
        "event_version": 1,
        "producer": "adis-agent",
        "payload": {"user": "alice", "attempts": 3},
    }
    fields.update(overrides)
    return EventEnvelope.model_validate(fields)


def test_defaults_are_generated() -> None:
    envelope = _envelope()

    assert isinstance(envelope.event_id, UUID)
    assert envelope.timestamp.tzinfo is UTC
    assert abs(datetime.now(UTC) - envelope.timestamp) < timedelta(seconds=5)
    assert re.fullmatch(TRACE_ID_PATTERN, envelope.trace_id)


def test_generated_identifiers_are_unique() -> None:
    first, second = _envelope(), _envelope()

    assert first.event_id != second.event_id
    assert first.trace_id != second.trace_id


def test_new_trace_id_format() -> None:
    assert re.fullmatch(TRACE_ID_PATTERN, new_trace_id())


def test_timestamp_is_normalized_to_utc() -> None:
    local = datetime(2026, 9, 25, 12, 0, tzinfo=timezone(timedelta(hours=3)))

    envelope = _envelope(timestamp=local)

    assert envelope.timestamp == datetime(2026, 9, 25, 9, 0, tzinfo=UTC)
    assert envelope.timestamp.tzinfo is UTC


def test_json_round_trip_preserves_every_field() -> None:
    envelope = _envelope(payload={"nested": {"list": [1, 2.5, None, True, "x"]}})

    restored = EventEnvelope.model_validate_json(envelope.model_dump_json())

    assert restored == envelope


def test_trace_id_is_propagated_when_given() -> None:
    parent = _envelope()

    child = _envelope(event_type="detector.anomaly_detected", trace_id=parent.trace_id)

    assert child.trace_id == parent.trace_id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_type", "Auth.LoginFailed"),
        ("event_type", "auth..login"),
        ("event_type", ""),
        ("event_version", 0),
        ("producer", "adis agent"),
        ("trace_id", "ABCDEF0123456789ABCDEF0123456789"),
        ("trace_id", "0" * 32),
        ("trace_id", "abc"),
        ("timestamp", datetime(2026, 9, 25, 12, 0)),  # naive on purpose
        ("payload", ["not", "an", "object"]),
        ("unexpected_field", "x"),
    ],
)
def test_invalid_envelopes_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        _envelope(**{field: value})


@pytest.mark.parametrize("field", ["event_type", "event_version", "producer", "payload"])
def test_required_fields(field: str) -> None:
    fields: dict[str, object] = {
        "event_type": "auth.login_failed",
        "event_version": 1,
        "producer": "adis-agent",
        "payload": {},
    }
    del fields[field]

    with pytest.raises(ValidationError):
        EventEnvelope.model_validate(fields)


def test_envelope_is_immutable() -> None:
    envelope = _envelope()

    with pytest.raises(ValidationError):
        envelope.producer = "someone-else"  # type: ignore[misc]


def test_validation_errors_do_not_echo_payload_values() -> None:
    with pytest.raises(ValidationError) as caught:
        _envelope(event_version=0, payload={"password": "sentinel-secret"})

    assert "sentinel" not in str(caught.value)


def test_trace_id_is_inherited_from_the_log_context() -> None:
    trace = "4bf92f3577b34da6a3ce929d0e0e4736"

    with log_context(trace_id=trace):
        inherited = _envelope()
    fresh = _envelope()

    assert inherited.trace_id == trace
    assert fresh.trace_id != trace


def test_explicit_trace_id_wins_over_the_log_context() -> None:
    explicit = new_trace_id()

    with log_context(trace_id="4bf92f3577b34da6a3ce929d0e0e4736"):
        envelope = _envelope(trace_id=explicit)

    assert envelope.trace_id == explicit
