"""Synthetic telemetry for the verification: system, authentication and network events.

Every document is tagged ``metadata.verification = {run, scenario, seq}`` so the run's
events can be told apart in Kafka and PostgreSQL. Addresses come from private
(``10.20.0.0/24``) and documentation (RFC 5737) ranges only.
"""

import json
import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final
from uuid import UUID, uuid4

from packages.events import EventEnvelope
from packages.events.canonical import parse_canonical_event
from packages.kafka import Topic

CATEGORIES: Final = ("system", "authentication", "network")
SOURCE_TYPE: Final = "verifier"
SOURCE_NAME: Final = "phase1-verifier@lab"

_INTERNAL: Final = "10.20.0."
_EXTERNAL: Final = ("198.51.100.", "203.0.113.")
_USERS: Final = ("alice", "bob", "carol", "deploy", "svc-backup")
_SERVICES: Final = ("sshd", "nginx", "postgres", "cron")


@dataclass(frozen=True, slots=True)
class GeneratedEvent:
    """A valid canonical event document."""

    event_id: UUID
    category: str
    scenario: str
    document: dict[str, object] = field(repr=False)


@dataclass(frozen=True, slots=True)
class InvalidEvent:
    """A document the ingestion API must reject; ``field_name`` must appear in its issues."""

    event_id: UUID
    reason: str
    field_name: str
    document: dict[str, object] = field(repr=False)


@dataclass(frozen=True, slots=True)
class PoisonRecord:
    """A record written straight to an accepted-telemetry topic, bypassing the API.

    The normalizer must dead-letter it. ``marker`` occurs in the record value.
    """

    marker: str
    reason: str
    topic: Topic
    value: bytes = field(repr=False)
    event_id: UUID | None = None


def utc_now() -> str:
    """The current time as ISO 8601 UTC."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class TelemetryGenerator:
    """Builds tagged canonical documents; every valid one is checked against the schema."""

    def __init__(self, run_id: str, *, seed: int = 1) -> None:
        self.run_id = run_id
        self._rng = random.Random(seed)  # synthetic data, not security
        self._sequence = 0

    def events(self, count: int, scenario: str) -> list[GeneratedEvent]:
        """``count`` events cycling through system, authentication and network."""
        return [self.event(CATEGORIES[index % 3], scenario) for index in range(count)]

    def event(self, category: str, scenario: str) -> GeneratedEvent:
        """One valid event of ``category``."""
        builders = {
            "system": self._system,
            "authentication": self._authentication,
            "network": self._network,
        }
        document = builders[category](scenario)
        event = parse_canonical_event(document)  # a generator bug must fail loudly
        return GeneratedEvent(event.event_id, category, scenario, document)

    def invalid_events(self, scenario: str) -> list[InvalidEvent]:
        """Documents violating the canonical schema in different ways."""
        cases: list[tuple[str, str, dict[str, object]]] = [
            ("malformed source address", "src_ip", self._network(scenario, src_ip="999.1.1.1")),
            (
                "unknown protocol",
                "protocol",
                self._network(scenario, protocol="carrier-pigeon"),
            ),
            (
                "missing authentication outcome",
                "success",
                self._without(self._authentication(scenario), "success", "failure_reason"),
            ),
            (
                "timestamp without a zone",
                "timestamp",
                self._system(scenario, timestamp="2026-09-25T12:00:00"),
            ),
            (
                "event type outside its category",
                "event_type",
                self._system(scenario, event_type="network.flow"),
            ),
        ]
        return [
            InvalidEvent(UUID(str(document["event_id"])), reason, name, document)
            for reason, name, document in cases
        ]

    def poison_records(self, scenario: str) -> list[PoisonRecord]:
        """Records that are not valid canonical envelopes, for direct injection."""
        records: list[PoisonRecord] = []
        marker = self._marker_text("json")
        records.append(
            PoisonRecord(
                marker,
                "not JSON",
                Topic.NETWORK_EVENTS,
                f'{{"verification": "{marker}", truncated'.encode(),
            )
        )
        marker = self._marker_text("payload")
        invalid = self._network(scenario, src_ip="999.1.1.1")
        invalid["metadata"] = {"verification_marker": marker}
        records.append(
            PoisonRecord(
                marker,
                "invalid canonical payload",
                Topic.NETWORK_EVENTS,
                self._envelope(invalid),
                UUID(str(invalid["event_id"])),
            )
        )
        marker = self._marker_text("mismatch")
        mismatched = self._authentication(scenario)
        mismatched["metadata"] = {"verification_marker": marker}
        records.append(
            PoisonRecord(
                marker,
                "envelope and payload disagree",
                Topic.AUTH_EVENTS,
                self._envelope(mismatched, event_id=uuid4()),
                UUID(str(mismatched["event_id"])),
            )
        )
        return records

    # ------------------------------------------------------------------ builders

    def _base(self, scenario: str, category: str, event_type: str) -> dict[str, object]:
        self._sequence += 1
        return {
            "schema_version": "1.0",
            "category": category,
            "event_id": str(uuid4()),
            "event_type": event_type,
            "timestamp": utc_now(),
            "source_type": SOURCE_TYPE,
            "source_name": SOURCE_NAME,
            "host_id": f"verify-host-{self._sequence % 5}",
            "metadata": {
                "verification": {"run": self.run_id, "scenario": scenario, "seq": self._sequence}
            },
        }

    def _system(self, scenario: str, **overrides: object) -> dict[str, object]:
        rng = self._rng
        event_type = rng.choice(("system.service_started", "system.service_stopped"))
        document = self._base(scenario, "system", event_type)
        document["severity_hint"] = "info"
        metadata = document["metadata"]
        assert isinstance(metadata, dict)
        metadata["service"] = rng.choice(_SERVICES)
        return {**document, **overrides}

    def _authentication(self, scenario: str, **overrides: object) -> dict[str, object]:
        rng = self._rng
        success = rng.random() < 0.7
        document = self._base(scenario, "authentication", "authentication.login")
        document |= {
            "username": rng.choice(_USERS),
            "auth_method": rng.choice(("password", "public_key")),
            "success": success,
            "src_ip": self._address(external=not success),
            "src_port": rng.randrange(49_152, 65_536),
            "dst_ip": self._address(external=False),
            "dst_port": 22,
            "protocol": "tcp",
        }
        if not success:
            document["failure_reason"] = "invalid_credentials"
        return {**document, **overrides}

    def _network(self, scenario: str, **overrides: object) -> dict[str, object]:
        rng = self._rng
        dst_port = rng.choice((443, 53, 22, 8080))
        document = self._base(scenario, "network", "network.flow")
        document |= {
            "src_ip": self._address(external=False),
            "src_port": rng.randrange(49_152, 65_536),
            "dst_ip": self._address(external=rng.random() < 0.5),
            "dst_port": dst_port,
            "protocol": "udp" if dst_port == 53 else "tcp",
            "bytes_sent": rng.randrange(40, 200_000),
            "bytes_received": rng.randrange(40, 2_000_000),
        }
        return {**document, **overrides}

    def _address(self, *, external: bool) -> str:
        prefix = self._rng.choice(_EXTERNAL) if external else _INTERNAL
        return f"{prefix}{self._rng.randrange(1, 255)}"

    def _envelope(self, document: dict[str, object], *, event_id: UUID | None = None) -> bytes:
        envelope = EventEnvelope.model_validate(
            {
                "event_id": event_id or document["event_id"],
                "event_type": document["event_type"],
                "event_version": 1,
                "producer": "phase1-verifier",
                "payload": document,
            }
        )
        return envelope.model_dump_json().encode()

    def _marker_text(self, kind: str) -> str:
        self._sequence += 1
        return f"{self.run_id}-poison-{kind}-{self._sequence}"

    @staticmethod
    def _without(document: dict[str, object], *names: str) -> dict[str, object]:
        return {key: value for key, value in document.items() if key not in names}


def batch_body(events: Sequence[GeneratedEvent | InvalidEvent]) -> bytes:
    """A ``POST /api/v1/events/batch`` body."""
    return json.dumps({"events": [event.document for event in events]}).encode()
