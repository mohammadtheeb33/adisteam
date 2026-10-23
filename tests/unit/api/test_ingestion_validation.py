"""Ingestion input validation: values JSON can smuggle in are refused and never stored."""

import json

import pytest

from tests.unit.api.fakes import AUTH, api_client
from tests.unit.events.canonical.samples import authentication, network

URL = "/api/v1/events"


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_numbers_are_refused(token: str) -> None:
    # Python's json accepts these tokens; the canonical schema must not.
    raw = json.dumps(network()).replace('"bytes_sent": 1200', f'"bytes_sent": {token}')
    assert token in raw
    with api_client() as (client, publisher):
        response = client.post(
            URL, content=raw.encode(), headers={**AUTH, "Content-Type": "application/json"}
        )
    assert response.status_code in (400, 422)
    assert publisher.events == []


@pytest.mark.parametrize(
    "document",
    [
        authentication(event_id="not-a-uuid"),
        authentication(event_id="00000000-0000-0000-0000-00000000000g"),
        network(bytes_sent=-1),
        network(bytes_sent=2**70),
        authentication(success="maybe"),
        authentication(host_id="../../etc/passwd"),
        authentication(metadata={"k" * 300: "v"}),
    ],
    ids=[
        "bad-uuid",
        "bad-uuid-hex",
        "negative-bytes",
        "oversized-integer",
        "invalid-boolean",
        "path-like-host",
        "oversized-metadata-key",
    ],
)
def test_malformed_fields_are_refused_without_echo(document: dict[str, object]) -> None:
    with api_client() as (client, publisher):
        response = client.post(URL, json=document, headers=AUTH)
    assert response.status_code == 422
    assert "etc/passwd" not in response.text
    assert publisher.events == []
