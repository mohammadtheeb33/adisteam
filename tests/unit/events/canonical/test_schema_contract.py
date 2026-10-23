"""The committed JSON Schema is the published contract and must match the models."""

import json
from pathlib import Path

import pytest

from packages.events.canonical import SUPPORTED_SCHEMA_VERSIONS, canonical_event_json_schema

SCHEMA_DIRECTORY = Path(__file__).resolve().parents[4] / "packages/events/canonical/schemas"


def _committed(version: str) -> dict[str, object]:
    path = SCHEMA_DIRECTORY / f"canonical-event-{version}.schema.json"
    loaded: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


@pytest.mark.parametrize("version", sorted(SUPPORTED_SCHEMA_VERSIONS))
def test_committed_schema_matches_the_models(version: str) -> None:
    assert canonical_event_json_schema(version) == _committed(version), (
        f"The canonical event schema {version} changed. If the change is backward "
        "compatible, run `python scripts/generate_event_schemas.py` and commit the result; "
        "otherwise introduce a new schema version (docs/EVENT_SCHEMA.md)."
    )


def test_every_category_is_in_the_discriminator() -> None:
    schema = canonical_event_json_schema()

    discriminator = schema["discriminator"]
    assert isinstance(discriminator, dict)
    assert discriminator["propertyName"] == "category"
    assert set(discriminator["mapping"]) == {
        "system",
        "authentication",
        "network",
        "process",
        "security",
    }


@pytest.mark.parametrize(
    ("model", "required"),
    [
        ("SystemEvent", {"event_type", "timestamp", "source_type", "source_name"}),
        ("AuthenticationEvent", {"success"}),
        ("NetworkFlowEvent", {"src_ip", "dst_ip", "protocol"}),
        ("ProcessEvent", {"process_name", "process_id"}),
        ("SecurityEvent", {"event_type", "timestamp"}),
    ],
)
def test_required_fields_are_published(model: str, required: set[str]) -> None:
    definitions = canonical_event_json_schema()["$defs"]
    assert isinstance(definitions, dict)

    published = definitions[model]

    assert required <= set(published["required"])
    assert published["additionalProperties"] is False
