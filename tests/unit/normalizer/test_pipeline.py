"""Pipeline: idempotent storage and publication, retries, isolation and dead-lettering."""

import asyncio
from uuid import UUID

import pytest

from apps.normalizer.errors import NormalizationError, PersistenceError
from packages.events.canonical import parse_canonical_event, to_envelope
from packages.kafka import BatchAbortedError, PublishError, deserialize_envelope
from tests.unit.events.canonical.samples import authentication, network, system
from tests.unit.kafka.fakes import ConsumerRecord
from tests.unit.normalizer.fakes import (
    GROUP,
    Harness,
    MemoryEventStore,
    RecordingDeadLetter,
    RecordingPublisher,
    envelope_of,
    raw_envelope,
    record_of,
    transient_error,
)


def record_of_id(record: ConsumerRecord) -> UUID:
    return deserialize_envelope(record.value).event_id


def _records(count: int, *, first_offset: int = 0) -> list[ConsumerRecord]:
    return [
        record_of(envelope_of(network()), offset=first_offset + index) for index in range(count)
    ]


# ------------------------------------------------------------------------ happy path


async def test_valid_records_are_stored_and_published_once() -> None:
    harness = Harness()
    records = [
        record_of(envelope_of(system()), topic="system_logs", offset=0),
        record_of(envelope_of(authentication()), topic="auth_events", offset=0),
        record_of(envelope_of(network()), topic="network_flows", offset=0),
    ]

    await harness.pipeline(records)

    assert len(harness.store.rows) == 3
    assert {event.category for event in harness.store.rows.values()} == {
        "system",
        "authentication",
        "network",
    }
    assert set(harness.publisher.event_ids()) == set(harness.store.rows)
    assert harness.dead_letter.records == []
    assert (harness.pipeline.stats.published, harness.pipeline.stats.records) == (3, 3)


async def test_one_transaction_per_batch() -> None:
    harness = Harness()

    await harness.pipeline(_records(5))

    assert (harness.store.store_calls, harness.store.commits) == (1, 1)
    assert len(harness.publisher.batches) == 1


async def test_stored_and_published_events_are_identical() -> None:
    harness = Harness()

    await harness.pipeline(_records(1))

    [published] = harness.publisher.events
    assert harness.store.rows[published.event.event_id] == published.event


# ------------------------------------------------------------------------ duplicates


async def test_duplicates_within_a_batch_produce_one_row_and_one_publication() -> None:
    harness = Harness()
    envelope = envelope_of(network())
    records = [record_of(envelope, offset=0), record_of(envelope, offset=1)]

    await harness.pipeline(records)

    assert len(harness.store.rows) == 1
    assert harness.publisher.event_ids() == [envelope.event_id]
    assert harness.pipeline.stats.duplicates == 1


async def test_redelivered_batches_are_neither_stored_nor_published_again() -> None:
    harness = Harness()
    records = _records(3)

    await harness.pipeline(records)
    await harness.pipeline(records)  # e.g. a crash before the offsets were committed

    assert len(harness.store.rows) == 3
    assert len(harness.publisher.events) == 3
    assert harness.pipeline.stats.duplicates == 3


async def test_resubmitted_events_keep_the_first_stored_version() -> None:
    harness = Harness()
    event = parse_canonical_event(network())
    first = to_envelope(event, producer="adis-api")
    retried = to_envelope(
        event.model_copy(update={"received_at": event.received_at.replace(year=2030)}),
        producer="adis-api",
    )

    await harness.pipeline([record_of(first, offset=0)])
    await harness.pipeline([record_of(retried, offset=7)])

    assert harness.store.rows[event.event_id].received_at == event.received_at
    assert len(harness.publisher.events) == 1


async def test_duplicates_mixed_with_new_events_only_publish_the_new_ones() -> None:
    harness = Harness()
    known = _records(2)
    await harness.pipeline(known)
    fresh = _records(2, first_offset=2)

    await harness.pipeline([*known, *fresh])

    fresh_ids = [record_of_id(record) for record in fresh]
    assert len(harness.store.rows) == 4
    assert [event.event.event_id for event in harness.publisher.batches[-1]] == fresh_ids
    assert harness.pipeline.stats.duplicates == 2


# ---------------------------------------------------------------------- dead letters


async def test_malformed_records_are_dead_lettered_and_the_rest_processed() -> None:
    harness = Harness()
    good = envelope_of(network())
    records = [
        record_of(b"{not json", offset=0),
        record_of(None, offset=1),
        record_of(b'{"event_type": "x"}', offset=2),
        record_of(raw_envelope(network(src_ip="999.0.0.1")), offset=3),
        record_of(raw_envelope(network(timestamp=12)), offset=4),
        record_of(good, offset=5),
    ]

    await harness.pipeline(records)

    assert [record.offset for record in harness.dead_letter.records] == [0, 1, 2, 3, 4]
    assert harness.dead_letter.error_types() == [
        "DeserializationError",
        "DeserializationError",
        "DeserializationError",
        "CanonicalEventError",
        "NormalizationError",
    ]
    assert harness.dead_letter.records[0].value == b"{not json"  # original bytes kept
    assert {record.consumer_group for record in harness.dead_letter.records} == {GROUP}
    assert list(harness.store.rows) == [good.event_id]
    assert harness.pipeline.stats.dead_lettered == 5


async def test_unexpected_normalization_errors_are_dead_lettered_without_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(*args: object, **kwargs: object) -> object:
        raise KeyError("attacker-controlled-value")

    monkeypatch.setattr("apps.normalizer.pipeline.normalize_record", broken)
    harness = Harness()

    await harness.pipeline(_records(1))

    [dead] = harness.dead_letter.records
    assert isinstance(dead.error, NormalizationError)
    assert "attacker-controlled-value" not in str(dead.error)


async def test_dead_letter_outages_are_retried() -> None:
    dead_letter = RecordingDeadLetter(failures=[PublishError("adis.deadletter", 5)] * 2)
    harness = Harness(dead_letter=dead_letter)

    await harness.pipeline([record_of(b"garbage")])

    assert len(dead_letter.records) == 1
    assert harness.pipeline.stats.retries == 2


# --------------------------------------------------------------------------- retries


async def test_database_outages_are_retried_without_dead_lettering() -> None:
    store = MemoryEventStore(store_failures=[transient_error(), transient_error()])
    harness = Harness(store=store)

    await harness.pipeline(_records(3))

    assert len(store.rows) == 3
    assert len(harness.publisher.events) == 3
    assert harness.dead_letter.records == []
    assert harness.pipeline.stats.retries == 2


async def test_a_failed_publish_rolls_the_rows_back_and_the_retry_publishes() -> None:
    publisher = RecordingPublisher(failures=[PublishError("adis.security.events", 5)])
    harness = Harness(publisher=publisher)

    await harness.pipeline(_records(2))

    assert (harness.store.rollbacks, harness.store.commits) == (1, 1)
    assert publisher.attempts == 2
    assert len(publisher.events) == 2  # not skipped as "already stored"
    assert len(harness.store.rows) == 2


async def test_publish_timeouts_are_retried() -> None:
    publisher = RecordingPublisher(failures=[TimeoutError()])
    harness = Harness(publisher=publisher)

    await harness.pipeline(_records(1))

    assert len(publisher.events) == 1


async def test_a_lost_commit_republishes_but_stores_once() -> None:
    store = MemoryEventStore(commit_failures=[(transient_error(), False)])
    harness = Harness(store=store)

    await harness.pipeline(_records(1))

    assert len(store.rows) == 1
    assert len(harness.publisher.events) == 2  # at-least-once: published before the commit


async def test_an_ambiguous_commit_that_succeeded_is_not_published_twice() -> None:
    store = MemoryEventStore(commit_failures=[(transient_error(), True)])
    harness = Harness(store=store)

    await harness.pipeline(_records(1))

    assert len(store.rows) == 1
    assert len(harness.publisher.events) == 1


async def test_a_poison_event_is_isolated_and_dead_lettered() -> None:
    records = _records(3)
    store = MemoryEventStore()
    harness = Harness(store=store)
    poison = envelope_of(network())
    store.poison.add(poison.event_id)
    records.insert(1, record_of(poison, offset=99))

    await harness.pipeline(records)

    assert len(store.rows) == 3
    assert len(harness.publisher.events) == 3
    [dead] = harness.dead_letter.records
    assert dead.offset == 99
    assert isinstance(dead.error, PersistenceError)
    assert "SQLSTATE 22P02" in str(dead.error)
    assert "secret-value" not in str(dead.error)  # database messages quote values
    assert dead.attempts == harness.retry_policy.max_attempts


async def test_unknown_failures_are_retried_a_bounded_number_of_times() -> None:
    store = MemoryEventStore(store_failures=[RuntimeError("bug")] * 10)
    harness = Harness(store=store)

    await harness.pipeline(_records(1))

    assert store.store_calls == 1 + harness.retry_policy.max_attempts  # batch, then alone
    assert harness.dead_letter.error_types() == ["PersistenceError"]
    assert store.rows == {}


async def test_outages_during_isolation_are_still_retried() -> None:
    store = MemoryEventStore(store_failures=[RuntimeError("bug"), transient_error(), None])
    harness = Harness(store=store)

    await harness.pipeline(_records(1))

    assert len(store.rows) == 1
    assert harness.dead_letter.records == []


async def test_stopping_during_an_outage_leaves_the_batch_unsettled() -> None:
    store = MemoryEventStore(store_failures=[transient_error()] * 10_000)
    harness = Harness(store=store)

    async def stop_soon() -> None:
        await asyncio.sleep(0.05)
        harness.stopping.set()

    stopper = asyncio.create_task(stop_soon())
    with pytest.raises(BatchAbortedError):
        await harness.pipeline(_records(2))
    await stopper

    assert store.rows == {}
    assert harness.publisher.events == []
    assert harness.dead_letter.records == []  # an outage never dead-letters valid events


async def test_backoff_grows_and_is_capped() -> None:
    delays: list[float] = []
    harness = Harness(store=MemoryEventStore(store_failures=[transient_error()] * 6))
    real_pause = harness.pipeline._pause

    async def recording_pause(seconds: float) -> None:
        delays.append(seconds)
        await real_pause(0)

    harness.pipeline._pause = recording_pause  # type: ignore[method-assign]

    await harness.pipeline(_records(1))

    assert delays == [0.001, 0.002, 0.002, 0.002, 0.002, 0.002]
