"""POST /api/v1/events/batch."""

from uuid import uuid4

import pytest

from apps.api.rate_limit import TokenBucketRateLimiter
from tests.unit.api.fakes import AUTH, api_client
from tests.unit.events.canonical.samples import authentication, network, process, system

URL = "/api/v1/events/batch"


def test_valid_batch_is_enqueued() -> None:
    events = [system(), network(), process()]

    with api_client() as (client, publisher):
        response = client.post(URL, json={"events": events}, headers=AUTH)

    assert response.status_code == 202
    body = response.json()
    assert (body["status"], body["accepted_count"], body["rejected_count"]) == ("accepted", 3, 0)
    assert [item["index"] for item in body["accepted"]] == [0, 1, 2]
    assert [str(event.event_id) for event in publisher.events] == [
        item["event_id"] for item in body["accepted"]
    ]
    assert len(publisher.batches) == 1


def test_invalid_events_are_reported_by_index_and_the_rest_enqueued() -> None:
    events = [system(), network(src_port=-1), authentication(schema_version="2.0"), process()]

    with api_client() as (client, publisher):
        response = client.post(URL, json={"events": events}, headers=AUTH)

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "partially_accepted"
    assert [item["index"] for item in body["accepted"]] == [0, 3]
    assert [(item["index"], item["code"]) for item in body["rejected"]] == [
        (1, "validation_failed"),
        (2, "unsupported_schema_version"),
    ]
    assert any("src_port" in issue for issue in body["rejected"][0]["issues"])
    assert len(publisher.events) == 2


def test_batch_with_no_valid_event_is_unprocessable() -> None:
    with api_client() as (client, publisher):
        response = client.post(
            URL, json={"events": [network(src_port=-1), "not an object"]}, headers=AUTH
        )

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_failed"
    assert [detail["index"] for detail in error["details"]] == [0, 1]
    assert publisher.events == []


def test_empty_batch_is_rejected() -> None:
    with api_client() as (client, _):
        response = client.post(URL, json={"events": []}, headers=AUTH)

    assert (response.status_code, response.json()["error"]["code"]) == (422, "empty_batch")


def test_batch_size_is_configurable() -> None:
    with api_client(api_max_batch_size=2) as (client, publisher):
        too_many = client.post(URL, json={"events": [system()] * 3}, headers=AUTH)
        at_limit = client.post(URL, json={"events": [system(), network()]}, headers=AUTH)

    assert (too_many.status_code, too_many.json()["error"]["code"]) == (413, "batch_too_large")
    assert at_limit.status_code == 202
    assert len(publisher.events) == 2


@pytest.mark.parametrize(
    "body",
    [
        [system()],
        {"items": [system()]},
        {"events": system()},
        {"events": [system()], "extra": True},
    ],
)
def test_malformed_batch_bodies_are_rejected(body: object) -> None:
    with api_client() as (client, _):
        response = client.post(URL, json=body, headers=AUTH)

    assert (response.status_code, response.json()["error"]["code"]) == (422, "validation_failed")


def test_repeated_events_are_published_once() -> None:
    event = network(event_id=str(uuid4()))

    with api_client() as (client, publisher):
        response = client.post(URL, json={"events": [event, event]}, headers=AUTH)

    assert response.json()["accepted_count"] == 2
    assert len(publisher.events) == 1


def test_rate_limit_is_charged_per_event() -> None:
    limiter = TokenBucketRateLimiter(capacity=6, window_seconds=3_600)

    with api_client(rate_limiter=limiter) as (client, publisher):
        first = client.post(URL, json={"events": [system()] * 5}, headers=AUTH)
        second = client.post(URL, json={"events": [system(), network()]}, headers=AUTH)

    assert first.status_code == 202
    assert first.headers["RateLimit-Remaining"] == "1"
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "rate_limited"
    assert int(second.headers["Retry-After"]) > 0
    assert second.headers["RateLimit-Remaining"] == "1"
    assert len(publisher.events) == 5


def test_rate_limits_are_per_client() -> None:
    limiter = TokenBucketRateLimiter(capacity=5, window_seconds=3_600)
    other = {"Authorization": "Bearer t0k3n-" + "b" * 32}

    with api_client(rate_limiter=limiter) as (client, _):
        client.post(URL, json={"events": [system()] * 5}, headers=AUTH)
        response = client.post(URL, json={"events": [system()]}, headers=other)

    assert response.status_code == 202
