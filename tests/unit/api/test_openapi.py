"""The generated OpenAPI document is complete and self-consistent."""

from collections.abc import Iterator
from typing import Any

import pytest

from tests.unit.api.fakes import api_client


@pytest.fixture(scope="module")
def spec() -> dict[str, Any]:
    with api_client(api_max_batch_size=250, api_rate_limit_events=1_000) as (client, _):
        document: dict[str, Any] = client.get("/openapi.json").json()
    return document


def _refs(node: object) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _refs(item)


def test_every_endpoint_is_documented(spec: dict[str, Any]) -> None:
    assert spec["info"]["title"] == "ADIS Ingestion API"
    assert {path: sorted(item) for path, item in spec["paths"].items()} == {
        "/health": ["get"],
        "/ready": ["get"],
        "/metrics": ["get"],
        "/api/v1/events": ["post"],
        "/api/v1/events/batch": ["post"],
    }


def test_every_reference_resolves(spec: dict[str, Any]) -> None:
    schemas = spec["components"]["schemas"]
    prefix = "#/components/schemas/"

    unresolved = {ref for ref in _refs(spec) if ref.removeprefix(prefix) not in schemas}

    assert unresolved == set()


def test_request_bodies_use_the_canonical_schema(spec: dict[str, Any]) -> None:
    single = spec["paths"]["/api/v1/events"]["post"]["requestBody"]
    batch = spec["paths"]["/api/v1/events/batch"]["post"]["requestBody"]
    schemas = spec["components"]["schemas"]

    assert single["content"]["application/json"]["schema"]["$ref"].endswith("/CanonicalEvent")
    assert batch["content"]["application/json"]["schema"]["$ref"].endswith("/EventBatch")
    assert set(schemas["CanonicalEvent"]["discriminator"]["mapping"]) == {
        "system",
        "authentication",
        "network",
        "process",
        "security",
    }
    assert schemas["EventBatch"]["properties"]["events"]["maxItems"] == 250


def test_ingestion_requires_bearer_authentication(spec: dict[str, Any]) -> None:
    assert spec["components"]["securitySchemes"]["IngestToken"] == {
        "type": "http",
        "scheme": "bearer",
        "description": "Per-client ingestion token from API_INGEST_TOKENS.",
    }
    for path in ("/api/v1/events", "/api/v1/events/batch"):
        assert spec["paths"][path]["post"]["security"] == [{"IngestToken": []}]
    for path in ("/health", "/ready", "/metrics"):
        assert "security" not in spec["paths"][path]["get"]


def test_error_responses_are_documented(spec: dict[str, Any]) -> None:
    for path in ("/api/v1/events", "/api/v1/events/batch"):
        responses = spec["paths"][path]["post"]["responses"]
        assert set(responses) >= {"202", "400", "401", "413", "415", "422", "429", "503"}
        assert responses["413"]["content"]["application/json"]["schema"]["$ref"].endswith(
            "/ErrorResponse"
        )
    assert "503" in spec["paths"]["/ready"]["get"]["responses"]
