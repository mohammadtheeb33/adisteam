"""Regenerate the committed JSON Schemas of the canonical event contract.

    python scripts/generate_event_schemas.py

Run it after an intentional schema change. A change to a released version must be
backward compatible (see docs/EVENT_SCHEMA.md); otherwise add a new schema version.
"""

import json
import sys
from pathlib import Path

from packages.events.canonical import SUPPORTED_SCHEMA_VERSIONS, canonical_event_json_schema

SCHEMA_DIRECTORY = Path(__file__).resolve().parents[1] / "packages/events/canonical/schemas"


def schema_path(schema_version: str) -> Path:
    """Where the committed schema of ``schema_version`` lives."""
    return SCHEMA_DIRECTORY / f"canonical-event-{schema_version}.schema.json"


def render(schema_version: str) -> str:
    """Deterministic text of the schema of ``schema_version``."""
    schema = canonical_event_json_schema(schema_version)
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    """Write every supported schema version; return the process exit code."""
    SCHEMA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    for schema_version in sorted(SUPPORTED_SCHEMA_VERSIONS):
        path = schema_path(schema_version)
        path.write_text(render(schema_version), encoding="utf-8", newline="\n")
        sys.stdout.write(f"wrote {path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
