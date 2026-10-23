"""Validation and normalization helpers shared by ADIS event schemas.

Two kinds of string input are treated differently:

- **Controlled** values (identifiers, types, enums) are produced by ADIS components and
  are validated strictly: malformed input is a bug and is rejected.
- **Observed** values (usernames, process names, paths) come from monitored systems and
  can be attacker-controlled. They are never rejected for their content, because
  rejecting would let an attacker hide activity behind a crafted value. They are only
  made storable: NUL characters and lone surrogates become U+FFFD, and overlong values
  are truncated.
"""

import json
import math
import re
from collections.abc import Callable, Collection, Mapping
from datetime import UTC, datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Final
from uuid import UUID

from pydantic import JsonValue
from pydantic_core import PydanticCustomError

REPLACEMENT_CHARACTER: Final = "�"
_UNSTORABLE: Final = re.compile("[\x00\ud800-\udfff]")
_KEY_NORMALIZATION: Final = re.compile(r"[\s_\-]")


def reject_numeric_timestamp(value: object) -> object:
    """Refuse epoch numbers: seconds versus milliseconds cannot be told apart reliably.

    Numeric strings (``"1790000000"``, ``"2026"``) are refused too; pydantic would
    otherwise read them as Unix time.
    """
    if isinstance(value, bool | int | float) or (isinstance(value, str) and _is_number(value)):
        raise PydanticCustomError(
            "timestamp_type",
            "must be an ISO 8601 string or datetime with a UTC offset, not an epoch number",
        )
    return value


def _is_number(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


def to_utc(value: datetime) -> datetime:
    """Convert an aware datetime to UTC."""
    return value.astimezone(UTC)


def parse_ip_address(value: object) -> IPv4Address | IPv6Address:
    """Parse an IP address string strictly and normalize it.

    Rejects anything that is not a textual IPv4/IPv6 address (integers, networks,
    whitespace, IPv4 octets with leading zeros...). IPv4-mapped IPv6 addresses
    (``::ffff:10.0.0.1``) are normalized to IPv4 so the same host always has one form.
    """
    if isinstance(value, IPv4Address | IPv6Address):
        address = value
    elif isinstance(value, str):
        try:
            address = ip_address(value)
        except ValueError:
            raise PydanticCustomError(
                "ip_address", "must be a valid IPv4 or IPv6 address"
            ) from None
    else:
        raise PydanticCustomError("ip_address_type", "must be an IP address string")
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def make_storable(value: str) -> str:
    """Replace characters that PostgreSQL and UTF-8 JSON cannot store with U+FFFD."""
    return _UNSTORABLE.sub(REPLACEMENT_CHARACTER, value)


def observed_text(max_length: int) -> Callable[[str], str]:
    """Build a normalizer for an observed (possibly attacker-controlled) string field."""

    def normalize(value: str) -> str:
        return make_storable(value)[:max_length]

    return normalize


def lower_if_str(value: object) -> object:
    """Case-insensitive enum input: ``"TCP"`` and ``" tcp "`` both become ``"tcp"``."""
    return value.strip().lower() if isinstance(value, str) else value


def normalize_key(key: str) -> str:
    """Lower-case a key and drop spaces, ``_`` and ``-`` for comparisons."""
    return _KEY_NORMALIZATION.sub("", key).lower()


def json_metadata(
    *,
    max_depth: int,
    max_bytes: int,
    max_key_length: int,
    redacted_keys: Collection[str],
    redaction: str,
) -> Callable[[object], dict[str, JsonValue]]:
    """Build a validator that makes vendor metadata safe to keep.

    The result is a plain JSON object:

    - values are JSON types; ``datetime`` (aware only), ``UUID``, IP addresses and enums
      are converted to strings; anything else (bytes, sets, arbitrary objects, NaN or
      infinite floats) is rejected;
    - keys are strings of 1 to ``max_key_length`` characters;
    - strings and keys are made storable (NUL and lone surrogates become U+FFFD);
    - nesting depth and serialized size are bounded;
    - values under keys that exactly name a credential (compared after
      :func:`normalize_key`) are replaced by ``redaction``.
    """
    normalized_redacted = frozenset(normalize_key(key) for key in redacted_keys)

    def convert(value: object, parent_depth: int) -> JsonValue:
        """Convert ``value``, held by a container nested ``parent_depth`` levels deep."""
        if value is None or isinstance(value, bool | int):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise PydanticCustomError("metadata_float", "metadata numbers must be finite")
            return value
        if isinstance(value, str):
            return make_storable(value)
        if isinstance(value, Mapping | list | tuple):
            depth = parent_depth + 1
            if depth > max_depth:
                raise PydanticCustomError(
                    "metadata_depth",
                    "metadata objects and arrays are nested more than {max_depth} levels deep",
                    {"max_depth": max_depth},
                )
            if isinstance(value, Mapping):
                return convert_mapping(value, depth)
            return [convert(item, depth) for item in value]
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise PydanticCustomError(
                    "metadata_datetime", "metadata datetimes must have a UTC offset"
                )
            return to_utc(value).isoformat().replace("+00:00", "Z")
        if isinstance(value, UUID | IPv4Address | IPv6Address):
            return str(value)
        if isinstance(value, Enum):
            return convert(value.value, parent_depth)
        raise PydanticCustomError(
            "metadata_value",
            "metadata values must be JSON-compatible; got {type_name}",
            {"type_name": type(value).__name__},
        )

    def convert_mapping(value: Mapping[object, object], depth: int) -> dict[str, JsonValue]:
        converted: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not 1 <= len(key) <= max_key_length:
                raise PydanticCustomError(
                    "metadata_key",
                    "metadata keys must be strings of 1 to {max_key_length} characters",
                    {"max_key_length": max_key_length},
                )
            safe_key = make_storable(key)
            converted[safe_key] = (
                redaction
                if normalize_key(safe_key) in normalized_redacted
                else convert(item, depth)
            )
        return converted

    def validate(value: object) -> dict[str, JsonValue]:
        if not isinstance(value, Mapping):
            raise PydanticCustomError("metadata_type", "metadata must be a JSON object")
        converted = convert_mapping(value, 1)
        size = len(json.dumps(converted, ensure_ascii=False).encode("utf-8"))
        if size > max_bytes:
            raise PydanticCustomError(
                "metadata_size",
                "metadata serializes to more than {max_bytes} bytes",
                {"max_bytes": max_bytes},
            )
        return converted

    return validate
