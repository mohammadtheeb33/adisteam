"""Identifier generation for database rows."""

import secrets
import time
from typing import Final
from uuid import UUID

_TIMESTAMP_MASK: Final = (1 << 48) - 1
_VERSION_7: Final = 0x7
_RFC_9562_VARIANT: Final = 0b10


def uuid7() -> UUID:
    """Return an RFC 9562 version 7 UUID: 48-bit Unix milliseconds, then 74 random bits.

    Time-ordered primary keys keep b-tree inserts at the right edge of the index, and
    make pages of deleted old rows reusable, which suits append-heavy, retention-pruned
    tables such as ``security_events``.
    """
    unix_ms = time.time_ns() // 1_000_000
    value = (
        (unix_ms & _TIMESTAMP_MASK) << 80
        | _VERSION_7 << 76
        | secrets.randbits(12) << 64
        | _RFC_9562_VARIANT << 62
        | secrets.randbits(62)
    )
    return UUID(int=value)
