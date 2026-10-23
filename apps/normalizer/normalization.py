"""Normalization of accepted telemetry into canonical events.

Records on the raw telemetry topics carry an ``EventEnvelope`` whose payload is a
canonical event, or close to one: the ingestion API only publishes canonical events,
but internal connectors may publish source-shaped values. Normalization rewrites the
values it recognizes, then the canonical schema validates the result strictly:

- **Envelope fields.** A missing ``event_id``, ``event_type``, ``trace_id``,
  ``timestamp`` or ``schema_version`` is taken from the envelope, and a missing
  ``category`` from the ``event_type`` prefix.
- **Timestamps.** Epoch numbers (and numeric strings) in seconds, milliseconds,
  microseconds or nanoseconds become UTC. The unit is inferred from the magnitude, and
  only times between 2000 and 2100 are accepted, where the four ranges cannot overlap.
  RFC 2822 dates (``Thu, 25 Sep 2026 12:00:00 +0000``) are converted. ISO 8601 values are
  left to the schema, which converts offsets to UTC and rejects values without one.
- **IP addresses.** Surrounding whitespace and brackets (``[2001:db8::1]``) are removed,
  and the canonical text form is used: lower-case compressed IPv6, with IPv4-mapped IPv6
  becoming IPv4. ``""`` and ``"-"`` mean "not set".
- **Ports.** Decimal strings and integral floats become integers.
- **Protocols.** Names are lower-cased, numeric strings become IANA numbers, and common
  aliases are mapped (``tcp6`` → ``tcp``, ``ipv6-icmp`` → ``icmpv6``).

Anything else is left unchanged. The canonical schema then rejects it with a precise,
value-free message.

The event is enriched with ingestion metadata under
``metadata["adis_ingestion"]``. That key is reserved: a producer-supplied value is
always replaced.
"""

import contextlib
import email.utils
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_FLOOR, Decimal
from functools import partial
from ipaddress import IPv6Address, ip_address
from typing import Final, Self

from pydantic import JsonValue

from apps.normalizer.errors import NormalizationError
from packages.events import EventEnvelope
from packages.events.canonical import (
    SUPPORTED_SCHEMA_VERSIONS,
    AnyCanonicalEvent,
    CanonicalEventError,
    EventCategory,
    from_envelope,
)
from packages.kafka import (
    HEADER_INGEST_CLIENT,
    HEADER_INGEST_HOST_SCOPE,
    HEADER_REQUEST_ID,
    HOST_SCOPES,
    HostScope,
    MessageContext,
)
from packages.observability import is_valid_request_id

INGESTION_METADATA_KEY: Final = "adis_ingestion"

TIMESTAMP_FIELDS: Final = ("timestamp", "received_at")
ADDRESS_FIELDS: Final = ("src_ip", "dst_ip")
PORT_FIELDS: Final = ("src_port", "dst_port")
PROTOCOL_FIELD: Final = "protocol"

PROTOCOL_ALIASES: Final[dict[str, str]] = {
    "tcp4": "tcp",
    "tcp6": "tcp",
    "udp4": "udp",
    "udp6": "udp",
    "sctp4": "sctp",
    "sctp6": "sctp",
    "icmp4": "icmp",
    "icmpv4": "icmp",
    "icmp6": "icmpv6",
    "icmp-v6": "icmpv6",
    "ipv6-icmp": "icmpv6",
    "ipsec-esp": "esp",
    "ipsec-ah": "ah",
}
"""Source spellings of canonical protocol names (keys lower-case)."""

EPOCH_EARLIEST: Final = datetime(2000, 1, 1, tzinfo=UTC)
EPOCH_LATEST: Final = datetime(2100, 1, 1, tzinfo=UTC)

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
_EARLIEST_SECONDS: Final = Decimal(int((EPOCH_EARLIEST - _EPOCH).total_seconds()))
_LATEST_SECONDS: Final = Decimal(int((EPOCH_LATEST - _EPOCH).total_seconds()))
_EPOCH_DIVISORS: Final = (Decimal(1), Decimal(10**3), Decimal(10**6), Decimal(10**9))
_EPOCH_TEXT: Final = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
_UNSET: Final = frozenset({"", "-"})
_CLIENT_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CATEGORIES: Final = frozenset(category.value for category in EventCategory)


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where an accepted record came from."""

    topic: str
    partition: int
    offset: int
    producer: str
    ingest_client: str | None
    request_id: str | None
    host_scope: HostScope | None = None

    @classmethod
    def of(cls, envelope: EventEnvelope, context: MessageContext) -> Self:
        """Provenance of ``envelope``, read from its record; invalid headers are ignored."""
        return cls(
            topic=context.topic,
            partition=context.partition,
            offset=context.offset,
            producer=envelope.producer,
            ingest_client=_header(context.headers, HEADER_INGEST_CLIENT, _is_client_id),
            request_id=_header(context.headers, HEADER_REQUEST_ID, is_valid_request_id),
            host_scope=_host_scope(context.headers),
        )

    def forwarded_headers(self) -> list[tuple[str, bytes]]:
        """Ingestion provenance headers to carry onto the normalized record."""
        headers = []
        if self.ingest_client is not None:
            headers.append((HEADER_INGEST_CLIENT, self.ingest_client.encode()))
        if self.request_id is not None:
            headers.append((HEADER_REQUEST_ID, self.request_id.encode()))
        if self.host_scope is not None:
            headers.append((HEADER_INGEST_HOST_SCOPE, self.host_scope.encode()))
        return headers


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """A canonical event ready to be stored and published.

    Attributes:
        event: The validated canonical event.
        provenance: Where its record came from.
        normalized_fields: Fields whose values normalization rewrote.
        enriched: Whether ingestion metadata was added. It is left out only when the
            event's metadata is too large to take it.
        timestamp_skew_seconds: How far ``timestamp`` lies ahead of ``received_at``, when
            that exceeds the allowed skew; ``None`` otherwise.
    """

    event: AnyCanonicalEvent
    provenance: Provenance
    normalized_fields: tuple[str, ...]
    enriched: bool
    timestamp_skew_seconds: float | None = None


def normalize_record(
    envelope: EventEnvelope,
    provenance: Provenance,
    *,
    normalizer: str,
    now: datetime,
    max_future_skew_seconds: float | None = None,
) -> NormalizedEvent:
    """Normalize, enrich and validate the event carried by ``envelope``.

    An event timestamped more than ``max_future_skew_seconds`` after it was received is
    kept (observed values are never rejected) but flagged with
    ``metadata.adis_ingestion.timestamp_skew_seconds``.

    Raises:
        NormalizationError: If a value is recognized but unusable.
        CanonicalEventError: If the result is not a valid canonical event, or disagrees
            with its envelope.
    """
    document, normalized_fields = normalize_document(envelope)
    enrichment = ingestion_metadata(
        provenance, normalizer=normalizer, normalized_at=now, normalized_fields=normalized_fields
    )
    try:
        event = _validate(envelope, with_ingestion_metadata(document, enrichment))
    except CanonicalEventError:
        # Enrichment must never cost the event: retry without it. If the event itself is
        # invalid, this raises the event's own error.
        event = _validate(envelope, without_ingestion_metadata(document))
        return NormalizedEvent(
            event,
            provenance,
            normalized_fields,
            enriched=False,
            timestamp_skew_seconds=_future_skew(event, max_future_skew_seconds),
        )
    skew = _future_skew(event, max_future_skew_seconds)
    if skew is not None:
        flagged = {**enrichment, "timestamp_skew_seconds": skew}
        # If the flag does not fit, the event itself stays valid and is kept unflagged.
        with contextlib.suppress(CanonicalEventError):
            event = _validate(envelope, with_ingestion_metadata(document, flagged))
    return NormalizedEvent(
        event, provenance, normalized_fields, enriched=True, timestamp_skew_seconds=skew
    )


def _future_skew(event: AnyCanonicalEvent, allowed: float | None) -> float | None:
    if allowed is None:
        return None
    skew = (event.timestamp - event.received_at).total_seconds()
    return round(skew, 3) if skew > allowed else None


def normalize_document(envelope: EventEnvelope) -> tuple[dict[str, JsonValue], tuple[str, ...]]:
    """The envelope's payload with recognized values rewritten, and the fields rewritten.

    Raises:
        NormalizationError: If a value is recognized but unusable (an implausible epoch).
    """
    document: dict[str, JsonValue] = dict(envelope.payload)
    _fill_from_envelope(document, envelope)
    changed: list[str] = []
    for name in TIMESTAMP_FIELDS:
        _rewrite(document, name, partial(normalize_timestamp, field=name), changed)
    for name in ADDRESS_FIELDS:
        _rewrite(document, name, normalize_address, changed)
    for name in PORT_FIELDS:
        _rewrite(document, name, normalize_port, changed)
    _rewrite(document, PROTOCOL_FIELD, normalize_protocol, changed)
    return document, tuple(changed)


def normalize_timestamp(value: JsonValue, field: str) -> JsonValue:
    """Rewrite epoch numbers and RFC 2822 dates as ISO 8601 UTC; keep anything else.

    Raises:
        NormalizationError: If an epoch number is not a time between 2000 and 2100.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return _iso(_from_epoch(Decimal(str(value)), field))
    if not isinstance(value, str):
        return value
    text = value.strip()
    if _EPOCH_TEXT.fullmatch(text):
        return _iso(_from_epoch(Decimal(text), field))
    try:
        datetime.fromisoformat(text)
    except ValueError:
        parsed = _rfc2822(text)
        return value if parsed is None else _iso(parsed)
    return text


def normalize_address(value: JsonValue) -> JsonValue:
    """The canonical text form of an IP address, ``None`` for "not set"; keep anything else."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text in _UNSET:
        return None
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        address = ip_address(text)
    except ValueError:
        return value
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def normalize_port(value: JsonValue) -> JsonValue:
    """Decimal strings and integral floats as integers, ``None`` for "not set"."""
    if isinstance(value, str):
        text = value.strip()
        if text in _UNSET:
            return None
        return int(text) if text.isascii() and text.isdigit() else value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def normalize_protocol(value: JsonValue) -> JsonValue:
    """Lower-case name, IANA number for numeric strings, aliases mapped."""
    if not isinstance(value, str):
        return value
    text = value.strip().lower()
    if text in _UNSET:
        return None
    if text.isascii() and text.isdigit():
        return int(text)
    return PROTOCOL_ALIASES.get(text, text)


def ingestion_metadata(
    provenance: Provenance,
    *,
    normalizer: str,
    normalized_at: datetime,
    normalized_fields: Sequence[str],
) -> dict[str, JsonValue]:
    """The ``metadata["adis_ingestion"]`` block describing how the event arrived."""
    block: dict[str, JsonValue] = {
        "normalizer": normalizer,
        "normalized_at": _iso(normalized_at),
        "producer": provenance.producer,
        "source_topic": provenance.topic,
        "source_partition": provenance.partition,
        "source_offset": provenance.offset,
    }
    if provenance.ingest_client is not None:
        block["ingest_client"] = provenance.ingest_client
    if provenance.request_id is not None:
        block["request_id"] = provenance.request_id
    if provenance.host_scope is not None:
        block["host_scope"] = provenance.host_scope
    if normalized_fields:
        fields: list[JsonValue] = [*normalized_fields]
        block["normalized_fields"] = fields
    return block


def with_ingestion_metadata(
    document: dict[str, JsonValue], block: dict[str, JsonValue]
) -> dict[str, JsonValue]:
    """``document`` with the ingestion block set, replacing any producer-supplied one."""
    metadata = document.get("metadata")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        return document  # invalid; the schema rejects it
    return {**document, "metadata": {**metadata, INGESTION_METADATA_KEY: block}}


def without_ingestion_metadata(document: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """``document`` without any ingestion block, so a producer cannot supply one."""
    metadata = document.get("metadata")
    if isinstance(metadata, dict) and INGESTION_METADATA_KEY in metadata:
        kept = {key: value for key, value in metadata.items() if key != INGESTION_METADATA_KEY}
        return {**document, "metadata": kept}
    return document


def _validate(envelope: EventEnvelope, document: dict[str, JsonValue]) -> AnyCanonicalEvent:
    return from_envelope(envelope.model_copy(update={"payload": document}))


def _fill_from_envelope(document: dict[str, JsonValue], envelope: EventEnvelope) -> None:
    carried: dict[str, JsonValue] = {
        "event_id": str(envelope.event_id),
        "event_type": envelope.event_type,
        "trace_id": envelope.trace_id,
        "timestamp": _iso(envelope.timestamp),
    }
    for name, value in carried.items():
        if document.get(name) is None:
            document[name] = value
    if document.get("schema_version") is None:
        version = _latest_schema_version(envelope.event_version)
        if version is not None:
            document["schema_version"] = version
    event_type = document.get("event_type")
    if document.get("category") is None and isinstance(event_type, str):
        prefix = event_type.split(".", 1)[0]
        if prefix in _CATEGORIES:
            document["category"] = prefix


def _rewrite(
    document: dict[str, JsonValue],
    name: str,
    normalize: Callable[[JsonValue], JsonValue],
    changed: list[str],
) -> None:
    if name not in document:
        return
    original = document[name]
    value = normalize(original)
    if value != original or type(value) is not type(original):
        document[name] = value
        changed.append(name)


def _from_epoch(number: Decimal, field: str) -> datetime:
    if number.is_finite():
        for divisor in _EPOCH_DIVISORS:
            if _EARLIEST_SECONDS <= number / divisor < _LATEST_SECONDS:
                micros = (number * 1_000_000 / divisor).to_integral_value(rounding=ROUND_FLOOR)
                return _EPOCH + timedelta(microseconds=int(micros))
    raise NormalizationError(
        f"{field}: epoch number is not a time between 2000 and 2100 in seconds, "
        "milliseconds, microseconds or nanoseconds"
    )


def _rfc2822(text: str) -> datetime | None:
    try:
        parsed = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    return parsed if parsed.tzinfo is not None else None  # "-0000" means unknown zone


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _latest_schema_version(major: int) -> str | None:
    versions = [
        version for version in SUPPORTED_SCHEMA_VERSIONS if version.split(".")[0] == str(major)
    ]
    if not versions:
        return None
    return max(versions, key=lambda version: tuple(int(part) for part in version.split(".")))


def _header(
    headers: Sequence[tuple[str, bytes]], name: str, is_valid: Callable[[str], bool]
) -> str | None:
    values = [raw for key, raw in headers if key == name]
    if not values:
        return None
    try:
        text = values[-1].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if is_valid(text) else None


def _host_scope(headers: Sequence[tuple[str, bytes]]) -> HostScope | None:
    """The API's host scope header, or ``None`` when absent or not a known scope."""
    value = _header(headers, HEADER_INGEST_HOST_SCOPE, lambda text: text in HOST_SCOPES)
    return next((scope for scope in HOST_SCOPES if scope == value), None)


def _is_client_id(value: str) -> bool:
    return _CLIENT_ID.fullmatch(value) is not None
