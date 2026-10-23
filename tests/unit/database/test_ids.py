"""Time-ordered UUIDv7 row identifiers."""

import time

from packages.database import uuid7


def test_version_and_variant() -> None:
    value = uuid7()

    assert value.version == 7
    assert value.variant == "specified in RFC 4122"


def test_embeds_the_current_unix_milliseconds() -> None:
    before = time.time_ns() // 1_000_000
    value = uuid7()
    after = time.time_ns() // 1_000_000

    assert before <= value.int >> 80 <= after


def test_later_ids_sort_after_earlier_ones() -> None:
    first = uuid7()
    time.sleep(0.002)
    second = uuid7()

    assert first < second
    assert str(first) < str(second)


def test_ids_are_unique() -> None:
    assert len({uuid7() for _ in range(10_000)}) == 10_000
