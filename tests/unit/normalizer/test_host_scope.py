"""The API's host scope travels with every event and cannot be supplied by a producer."""

from collections.abc import Mapping

import pytest

from apps.normalizer.normalization import INGESTION_METADATA_KEY, Provenance, normalize_record
from packages.kafka import MessageContext
from tests.unit.events.canonical.samples import system
from tests.unit.normalizer.fakes import API_HEADERS, NOW, envelope_of


def _block(headers: tuple[tuple[str, bytes], ...], **overrides: object) -> Mapping[str, object]:
    envelope = envelope_of(system(**overrides))
    context = MessageContext(
        topic="system_logs", partition=0, offset=7, timestamp_ms=0, key=None, headers=headers
    )
    normalized = normalize_record(
        envelope, Provenance.of(envelope, context), normalizer="adis-normalizer", now=NOW
    )
    block = normalized.event.metadata[INGESTION_METADATA_KEY]
    assert isinstance(block, dict)
    return block


@pytest.mark.parametrize("scope", ["exclusive", "shared", "unbound"])
def test_the_api_host_scope_is_recorded(scope: str) -> None:
    block = _block((*API_HEADERS, ("adis-ingest-host-scope", scope.encode())))

    assert block["host_scope"] == scope


@pytest.mark.parametrize("raw", [b"trusted", b"", b"EXCLUSIVE", b"\xff"])
def test_an_unknown_scope_is_left_out(raw: bytes) -> None:
    """Without a known scope the event counts as unbound evidence (never trusted)."""
    block = _block((*API_HEADERS, ("adis-ingest-host-scope", raw)))

    assert "host_scope" not in block


def test_a_producer_cannot_claim_a_scope_in_the_event() -> None:
    forged = {"host_scope": "exclusive", "ingest_client": "agent-victim"}

    block = _block(API_HEADERS, metadata={INGESTION_METADATA_KEY: forged})

    assert "host_scope" not in block
    assert block["ingest_client"] == "agent-a"


def test_the_scope_is_forwarded_with_the_normalized_record() -> None:
    envelope = envelope_of(system())
    context = MessageContext(
        topic="system_logs",
        partition=0,
        offset=7,
        timestamp_ms=0,
        key=None,
        headers=(*API_HEADERS, ("adis-ingest-host-scope", b"exclusive")),
    )

    provenance = Provenance.of(envelope, context)

    assert ("adis-ingest-host-scope", b"exclusive") in provenance.forwarded_headers()
