"""POST /api/v1/events."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest

from apps.api.publisher import PublishUnavailableError
from packages.events.canonical.v1 import MAX_EVENT_BYTES
from tests.unit.api.fakes import AUTH, OTHER_TOKEN, RecordingPublisher, api_client
from tests.unit.events.canonical.samples import authentication, network
from tests.unit.log_capture import JsonLogCapture

URL = "/api/v1/events"
TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


def _event(**overrides: object) -> dict[str, object]:
    """An authentication event without ``trace_id`` unless one is given."""
    return authentication(**overrides)


def test_valid_event_is_enqueued() -> None:
    with api_client() as (client, publisher):
        response = client.post(URL, json=_event(), headers=AUTH)

    assert response.status_code == 202
    [event] = publisher.events
    assert response.json() == {
        "status": "accepted",
        "event_id": str(event.event_id),
        "trace_id": event.trace_id,
    }
    [(_, context)] = publisher.batches
    assert context.client_id == "agent-a"
    assert context.request_id == response.headers["X-Request-ID"]


def test_received_at_is_set_by_the_server() -> None:
    before = datetime.now(UTC)

    with api_client() as (client, publisher):
        client.post(URL, json=_event(received_at="2000-01-01T00:00:00Z"), headers=AUTH)

    received_at = publisher.events[0].received_at
    assert before <= received_at <= datetime.now(UTC) + timedelta(seconds=1)


def test_event_without_trace_joins_the_request_trace() -> None:
    with api_client() as (client, publisher):
        response = client.post(
            URL, json=_event(), headers={**AUTH, "traceparent": f"00-{TRACE}-00f067aa0ba902b7-01"}
        )

    assert publisher.events[0].trace_id == TRACE
    assert response.json()["trace_id"] == TRACE == response.headers["X-Trace-ID"]


def test_event_trace_is_kept_when_provided() -> None:
    with api_client() as (client, publisher):
        client.post(URL, json=_event(trace_id="c" * 32), headers=AUTH)

    assert publisher.events[0].trace_id == "c" * 32


def test_success_reports_rate_limit_headers() -> None:
    with api_client() as (client, _):
        response = client.post(URL, json=_event(), headers=AUTH)

    assert response.headers["RateLimit-Limit"] == "1000"
    assert response.headers["RateLimit-Remaining"] == "999"
    assert "RateLimit-Reset" in response.headers


def test_each_client_is_identified_by_its_own_token() -> None:
    with api_client() as (client, publisher):
        client.post(URL, json=_event(), headers={"Authorization": f"Bearer {OTHER_TOKEN}"})

    assert publisher.batches[0][1].client_id == "agent-b"


@pytest.mark.parametrize(
    ("document", "code", "field"),
    [
        (_event(src_port=70_000), "validation_failed", "src_port"),
        (_event(timestamp="2026-09-25T12:00:00"), "validation_failed", "timestamp"),
        (_event(category="dns"), "validation_failed", ""),
        (_event(schema_version="9.0"), "unsupported_schema_version", ""),
        (["not", "an", "object"], "validation_failed", ""),
    ],
)
def test_invalid_events_are_rejected(document: object, code: str, field: str) -> None:
    with api_client() as (client, publisher):
        response = client.post(URL, json=document, headers=AUTH)

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == code
    assert error["request_id"] == response.headers["X-Request-ID"]
    [detail] = error["details"]
    assert detail["index"] is None
    assert field in " ".join(detail["issues"])
    assert publisher.events == []


def test_rejections_never_echo_submitted_values() -> None:
    with api_client() as (client, _):
        response = client.post(
            URL, json=_event(username="sentinel-user", src_ip="sentinel-ip"), headers=AUTH
        )

    assert response.status_code == 422
    assert "sentinel-ip" not in response.text


def test_invalid_json_is_a_bad_request() -> None:
    with api_client() as (client, _):
        response = client.post(
            URL, content=b"{not json", headers={**AUTH, "Content-Type": "application/json"}
        )

    assert (response.status_code, response.json()["error"]["code"]) == (400, "invalid_json")


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", ""])
def test_non_json_media_types_are_rejected(content_type: str) -> None:
    with api_client() as (client, _):
        response = client.post(
            URL,
            content=json.dumps(_event()).encode(),
            headers={**AUTH, "Content-Type": content_type},
        )

    assert (response.status_code, response.json()["error"]["code"]) == (
        415,
        "unsupported_media_type",
    )


def test_json_media_type_parameters_are_accepted() -> None:
    with api_client() as (client, _):
        response = client.post(
            URL,
            content=json.dumps(_event()).encode(),
            headers={**AUTH, "Content-Type": "Application/JSON; charset=utf-8"},
        )

    assert response.status_code == 202


def test_events_larger_than_the_canonical_limit_are_rejected() -> None:
    padded = _event(metadata={"note": "x" * (MAX_EVENT_BYTES + 1)})

    with api_client() as (client, publisher):
        response = client.post(URL, json=padded, headers=AUTH)

    assert (response.status_code, response.json()["error"]["code"]) == (413, "payload_too_large")
    assert publisher.events == []


def test_declared_oversized_bodies_are_rejected_before_reading() -> None:
    with api_client(api_max_request_bytes=2_048) as (client, _):
        response = client.post(
            URL,
            content=b"{}" * 2_000,
            headers={**AUTH, "Content-Type": "application/json"},
        )

    assert (response.status_code, response.json()["error"]["code"]) == (413, "payload_too_large")


def test_streamed_oversized_bodies_are_cut_off() -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(10):
            yield b" " * 1_024

    with api_client(api_max_request_bytes=2_048) as (client, _):
        response = client.post(
            URL, content=chunks(), headers={**AUTH, "Content-Type": "application/json"}
        )

    assert (response.status_code, response.json()["error"]["code"]) == (413, "payload_too_large")


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic YWdlbnQ6cGFzcw=="},
        {"Authorization": "Bearer not-a-known-token"},
        {"Authorization": "Bearer"},
    ],
)
def test_unauthenticated_requests_are_rejected(
    headers: dict[str, str], json_logs: JsonLogCapture
) -> None:
    with api_client() as (client, publisher):
        response = client.post(URL, json=_event(), headers=headers)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["error"]["code"] == "unauthorized"
    assert publisher.events == []
    assert "not-a-known-token" not in json_logs.text
    assert "YWdlbnQ6cGFzcw" not in json_logs.text


def test_tokens_never_reach_the_logs(json_logs: JsonLogCapture) -> None:
    with api_client() as (client, _):
        client.post(URL, json=_event(), headers=AUTH)

    assert AUTH["Authorization"].split()[1] not in json_logs.text
    [ingested] = json_logs.with_message("events ingested")
    assert (ingested["client_id"], ingested["accepted"], ingested["rejected"]) == ("agent-a", 1, 0)


def test_unavailable_kafka_is_a_retryable_503() -> None:
    publisher = RecordingPublisher(failure=PublishUnavailableError("down"))

    with api_client(publisher) as (client, _):
        response = client.post(URL, json=network(), headers=AUTH)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_unavailable"
    assert response.headers["Retry-After"] == "2"


def test_unexpected_failures_are_opaque_500s() -> None:
    publisher = RecordingPublisher(failure=RuntimeError("sentinel internal detail"))

    with api_client(publisher) as (client, _):
        response = client.post(URL, json=network(), headers={**AUTH, "X-Request-ID": "r-500"})

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "internal_error",
            "message": "The server failed to process the request.",
            "request_id": "r-500",
            "details": [],
        }
    }
    assert response.headers["X-Request-ID"] == "r-500"
