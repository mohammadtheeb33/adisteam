"""Normalization rules: timestamps, addresses, ports, protocols, envelope fields, enrichment."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from apps.normalizer.errors import NormalizationError
from apps.normalizer.normalization import (
    INGESTION_METADATA_KEY,
    NormalizedEvent,
    Provenance,
    normalize_record,
)
from packages.events import EventEnvelope
from packages.events.canonical import CanonicalEventError, parse_canonical_event, to_envelope
from packages.kafka import MessageContext
from tests.unit.events.canonical.samples import authentication, network, system
from tests.unit.normalizer.fakes import API_HEADERS, NOW, envelope_of, raw_envelope


def _context(headers: tuple[tuple[str, bytes], ...] = API_HEADERS) -> MessageContext:
    return MessageContext(
        topic="network_flows",
        partition=2,
        offset=41,
        timestamp_ms=0,
        key=None,
        headers=headers,
    )


def _normalize(
    envelope: EventEnvelope, headers: tuple[tuple[str, bytes], ...] = API_HEADERS
) -> NormalizedEvent:
    provenance = Provenance.of(envelope, _context(headers))
    return normalize_record(envelope, provenance, normalizer="adis-normalizer", now=NOW)


def _flow(**overrides: object) -> NormalizedEvent:
    return _normalize(raw_envelope(network(**overrides)))


# ------------------------------------------------------------------- canonical input


def test_canonical_events_pass_through_unchanged_apart_from_enrichment() -> None:
    original = parse_canonical_event(authentication(metadata={"pam_service": "sshd"}))

    normalized = _normalize(to_envelope(original, producer="adis-api"))
    event = normalized.event

    assert normalized.normalized_fields == ()
    assert normalized.enriched
    assert event.model_dump(exclude={"metadata"}) == original.model_dump(exclude={"metadata"})
    assert event.metadata["pam_service"] == "sshd"


def test_ingestion_metadata_describes_the_record() -> None:
    event = _normalize(envelope_of(system())).event

    assert event.metadata[INGESTION_METADATA_KEY] == {
        "normalizer": "adis-normalizer",
        "normalized_at": "2026-09-25T12:30:00Z",
        "producer": "adis-api",
        "source_topic": "network_flows",
        "source_partition": 2,
        "source_offset": 41,
        "ingest_client": "agent-a",
        "request_id": "0123456789abcdef0123456789abcdef",
    }


def test_producer_supplied_ingestion_metadata_is_replaced() -> None:
    forged = {"ingest_client": "someone-else", "source_topic": "made-up"}
    event = _normalize(envelope_of(system(metadata={INGESTION_METADATA_KEY: forged}))).event

    block = event.metadata[INGESTION_METADATA_KEY]
    assert isinstance(block, dict)
    assert (block["ingest_client"], block["source_topic"]) == ("agent-a", "network_flows")


def test_enrichment_is_left_out_rather_than_losing_a_full_event() -> None:
    forged = {"ingest_client": "someone-else"}
    filler = "x" * (65_536 - 200)
    document = system(metadata={"blob": filler, INGESTION_METADATA_KEY: forged})

    normalized = _normalize(raw_envelope(document, producer="adis-api"))

    assert not normalized.enriched
    assert INGESTION_METADATA_KEY not in normalized.event.metadata  # forgery removed too
    assert normalized.event.metadata["blob"] == filler


def test_invalid_provenance_headers_are_ignored() -> None:
    headers = (
        ("adis-ingest-client", b"has space"),
        ("adis-request-id", b"<script>alert(1)</script>"),
    )

    normalized = _normalize(envelope_of(system()), headers)

    assert (normalized.provenance.ingest_client, normalized.provenance.request_id) == (None, None)
    assert normalized.provenance.forwarded_headers() == []
    block = normalized.event.metadata[INGESTION_METADATA_KEY]
    assert isinstance(block, dict)
    assert "ingest_client" not in block


# -------------------------------------------------------------------- timestamps

EPOCH_SECONDS = 1_790_000_000  # 2026-09-21T14:13:20Z
EXPECTED = datetime(2026, 9, 21, 14, 13, 20, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    [
        EPOCH_SECONDS,
        float(EPOCH_SECONDS),
        EPOCH_SECONDS * 1_000,
        EPOCH_SECONDS * 1_000_000,
        EPOCH_SECONDS * 1_000_000_000,
        str(EPOCH_SECONDS),
        f" {EPOCH_SECONDS * 1_000} ",
        "Mon, 21 Sep 2026 16:13:20 +0200",
    ],
)
def test_epoch_and_rfc2822_timestamps_become_utc(value: object) -> None:
    normalized = _flow(timestamp=value)

    assert normalized.event.timestamp == EXPECTED
    assert normalized.normalized_fields == ("timestamp",)


def test_fractional_epoch_keeps_microseconds() -> None:
    normalized = _flow(timestamp=f"{EPOCH_SECONDS}.123456")

    assert normalized.event.timestamp == EXPECTED.replace(microsecond=123_456)


def test_nanosecond_epoch_is_truncated_to_microseconds() -> None:
    normalized = _flow(timestamp=EPOCH_SECONDS * 1_000_000_000 + 123_456_789)

    assert normalized.event.timestamp == EXPECTED.replace(microsecond=123_456)


def test_received_at_is_normalized_too() -> None:
    normalized = _flow(received_at=EPOCH_SECONDS * 1_000)

    assert normalized.event.received_at == EXPECTED
    assert normalized.normalized_fields == ("received_at",)


def test_iso_offsets_are_converted_by_the_schema() -> None:
    normalized = _flow(timestamp="2026-09-21T16:13:20.5+02:00")

    assert normalized.event.timestamp == EXPECTED.replace(microsecond=500_000)
    assert normalized.normalized_fields == ()


@pytest.mark.parametrize("value", [0, 12_345, 99_999_999_999, 5_000_000_000_000_000_000])
def test_implausible_epochs_are_rejected(value: int) -> None:
    with pytest.raises(NormalizationError, match="timestamp: epoch number"):
        _flow(timestamp=value)


@pytest.mark.parametrize("value", ["2026-09-21T14:13:20", "Mon, 21 Sep 2026 14:13:20 -0000"])
def test_timestamps_without_a_zone_are_rejected(value: str) -> None:
    with pytest.raises(CanonicalEventError, match="timestamp"):
        _flow(timestamp=value)


def test_rejections_never_echo_the_value() -> None:
    with pytest.raises(CanonicalEventError) as caught:
        _flow(timestamp="secret-looking-garbage")

    assert "secret-looking-garbage" not in str(caught.value)


# --------------------------------------------------------------------- addresses


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" 10.0.0.5 ", "10.0.0.5"),
        ("[2001:DB8::1]", "2001:db8::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ],
)
def test_addresses_take_their_canonical_form(raw: str, expected: str) -> None:
    normalized = _flow(src_ip=raw, dst_ip=expected)

    assert str(normalized.event.src_ip) == expected  # type: ignore[union-attr]
    assert normalized.normalized_fields == ("src_ip",)


def test_ipv4_mapped_addresses_become_ipv4() -> None:
    normalized = _flow(src_ip="::FFFF:10.0.0.5")

    assert str(normalized.event.src_ip) == "10.0.0.5"  # type: ignore[union-attr]


@pytest.mark.parametrize("marker", ["", "-", "  "])
def test_unset_markers_clear_optional_addresses(marker: str) -> None:
    normalized = _normalize(raw_envelope(authentication(src_ip=marker)))

    assert normalized.event.src_ip is None  # type: ignore[union-attr]


@pytest.mark.parametrize("value", ["999.1.1.1", "010.0.0.1", "10.0.0.0/24", 167_772_161])
def test_invalid_addresses_are_rejected(value: object) -> None:
    with pytest.raises(CanonicalEventError, match="src_ip"):
        _flow(src_ip=value)


def test_a_flow_needs_both_addresses() -> None:
    with pytest.raises(CanonicalEventError, match="dst_ip"):
        _flow(dst_ip="-")


# ------------------------------------------------------------------ ports, protocols


@pytest.mark.parametrize(("raw", "expected"), [("443", 443), (" 443 ", 443), (443.0, 443)])
def test_numeric_ports_become_integers(raw: object, expected: int) -> None:
    normalized = _flow(dst_port=raw)

    assert normalized.event.dst_port == expected  # type: ignore[union-attr]
    assert normalized.normalized_fields == ("dst_port",)


@pytest.mark.parametrize("value", ["https", "44 3", 443.5, "-1"])
def test_invalid_ports_are_rejected(value: object) -> None:
    with pytest.raises(CanonicalEventError, match="dst_port"):
        _flow(dst_port=value)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("TCP", "tcp"),
        (" Udp ", "udp"),
        ("6", "tcp"),
        ("17", "udp"),
        ("tcp6", "tcp"),
        ("UDP4", "udp"),
    ],
)
def test_protocol_names_are_normalized(raw: str, expected: str) -> None:
    normalized = _flow(protocol=raw)

    assert normalized.event.protocol == expected  # type: ignore[union-attr]
    assert normalized.normalized_fields == ("protocol",)


@pytest.mark.parametrize(
    ("raw", "expected"), [("ipv6-icmp", "icmpv6"), ("ICMP6", "icmpv6"), ("1", "icmp")]
)
def test_icmp_aliases(raw: str, expected: str) -> None:
    address = "2001:db8::1" if expected == "icmpv6" else "10.0.0.5"
    peer = "2001:db8::2" if expected == "icmpv6" else "10.0.0.9"
    normalized = _flow(protocol=raw, src_ip=address, dst_ip=peer, src_port=None, dst_port=None)

    assert normalized.event.protocol == expected  # type: ignore[union-attr]


@pytest.mark.parametrize("value", ["http", "tcp/ip", "300"])
def test_unknown_protocols_are_rejected_not_guessed(value: str) -> None:
    with pytest.raises(CanonicalEventError, match="protocol"):
        _flow(protocol=value)


def test_every_rewritten_field_is_reported() -> None:
    normalized = _flow(
        timestamp=EPOCH_SECONDS, src_ip="[10.0.0.5]", src_port="51514", protocol="TCP"
    )

    assert normalized.normalized_fields == ("timestamp", "src_ip", "src_port", "protocol")
    block = normalized.event.metadata[INGESTION_METADATA_KEY]
    assert isinstance(block, dict)
    assert block["normalized_fields"] == ["timestamp", "src_ip", "src_port", "protocol"]


# --------------------------------------------------------------- envelope fields


def test_missing_fields_are_taken_from_the_envelope() -> None:
    payload = network()
    for name in ("schema_version", "category", "timestamp"):
        del payload[name]
    envelope = raw_envelope(payload, timestamp="2026-09-25T09:00:00+02:00")

    event = _normalize(envelope).event

    assert event.event_id == envelope.event_id
    assert event.trace_id == envelope.trace_id
    assert (event.schema_version, event.category) == ("1.0", "network")
    assert event.timestamp == datetime(2026, 9, 25, 7, tzinfo=UTC)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", str(uuid4())),
        ("event_type", "network.connection_opened"),
        ("trace_id", "a" * 32),
    ],
)
def test_payload_and_envelope_must_agree(field: str, value: str) -> None:
    envelope = raw_envelope(network(**{field: value}), event_type="network.flow")

    with pytest.raises(CanonicalEventError, match=f"{field}: mismatch"):
        _normalize(envelope)


def test_unknown_schema_versions_are_rejected() -> None:
    envelope = raw_envelope(network(schema_version=None), event_version=7)

    with pytest.raises(CanonicalEventError, match="schema_version"):
        _normalize(envelope)
