"""Log file collector and synthetic telemetry simulators."""

import asyncio
import os
import random
import shutil
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from apps.agent.collectors import (
    AuthEventSimulator,
    LogFileCollector,
    NetworkFlowSimulator,
)
from apps.agent.collectors.logfile import MAX_LINE_BYTES
from apps.agent.collectors.simulation import SIMULATION_NETWORKS
from packages.events.canonical import (
    AuthenticationEvent,
    NetworkFlowEvent,
    SeverityHint,
    SystemEvent,
    parse_canonical_event,
    serialize_canonical_event,
)
from tests.unit.agent.fakes import AGENT_ID, MemorySink, make_context


def _collector(path: Path, *, read_from_start: bool = True) -> LogFileCollector:
    return LogFileCollector(
        [path], make_context(), poll_interval_seconds=0.01, read_from_start=read_from_start
    )


def _messages(sink: MemorySink) -> list[str]:
    messages = []
    for event in sink.events:
        assert isinstance(event, SystemEvent)
        messages.append(str(event.metadata["message"]))
    return messages


def _append(path: Path, text: str) -> None:
    with path.open("ab") as handle:
        handle.write(text.encode())


# ---------------------------------------------------------------------------------- logfile


async def test_each_complete_line_becomes_an_event(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_bytes(b"first line\r\nsecond line\n\npartial")
    sink = MemorySink()

    emitted = await _collector(log).poll(sink)

    assert emitted == 2
    assert _messages(sink) == ["first line", "second line"]
    event = sink.events[0]
    assert event.event_type == "system.log_entry"
    assert (event.source_type, event.source_name) == ("logfile", "logfile@agent-test")
    assert (event.host_id, event.agent_id) == ("web-1.example.test", str(AGENT_ID))
    assert event.metadata["path"] == str(log)
    assert event.metadata["offset"] == 0


async def test_partial_lines_wait_for_their_newline(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_bytes(b"partial")
    sink = MemorySink()
    collector = _collector(log)

    await collector.poll(sink)
    _append(log, " line\n")
    await collector.poll(sink)

    assert _messages(sink) == ["partial line"]


async def test_new_files_start_at_the_end_unless_configured(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("old history\n")
    sink = MemorySink()
    collector = _collector(log, read_from_start=False)

    await collector.poll(sink)
    _append(log, "new line\n")
    await collector.poll(sink)

    assert _messages(sink) == ["new line"]


async def test_restart_resumes_from_the_checkpoint(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("one\ntwo\n")
    sink = MemorySink()
    await _collector(log).poll(sink)
    _append(log, "three\n")

    await _collector(log).poll(sink)  # a new process, same spool checkpoints

    assert _messages(sink) == ["one", "two", "three"]


async def test_event_ids_are_deterministic_for_replays(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("same line\n")
    first, second = MemorySink(), MemorySink()

    await _collector(log).poll(first)
    await _collector(log).poll(second)  # no shared checkpoint: a replay

    assert first.events[0].event_id == second.events[0].event_id


async def test_rotation_restarts_from_the_beginning_with_new_ids(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("before rotation\n")
    sink = MemorySink()
    collector = _collector(log)
    await collector.poll(sink)

    os.replace(log, tmp_path / "app.log.1")
    log.write_text("after rotation\n")
    await collector.poll(sink)

    assert _messages(sink) == ["before rotation", "after rotation"]
    assert sink.events[0].event_id != sink.events[1].event_id


async def test_truncation_restarts_with_a_new_generation(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("a longer original line\n")
    sink = MemorySink()
    collector = _collector(log)
    await collector.poll(sink)

    log.write_text("short\n")  # copytruncate-style rotation
    await collector.poll(sink)

    assert _messages(sink) == ["a longer original line", "short"]
    assert sink.events[0].event_id != sink.events[1].event_id


async def test_lines_written_before_a_rotation_are_not_lost(tmp_path: Path) -> None:
    # They used to be skipped: reading jumped to the new file (deep audit C-2).
    log = tmp_path / "app.log"
    log.write_text("one\ntwo\n")
    sink = MemorySink()
    collector = _collector(log)
    await collector.poll(sink)
    _append(log, "three\nfour\n")
    os.replace(log, tmp_path / "app.log.1")
    log.write_text("five\n")

    await collector.poll(sink)
    await collector.poll(sink)

    assert _messages(sink) == ["one", "two", "three", "four", "five"]
    assert len({event.event_id for event in sink.events}) == 5


async def test_a_restart_after_rotation_still_reads_the_previous_file(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("one\n")
    sink = MemorySink()
    await _collector(log).poll(sink)
    _append(log, "two\n")
    os.replace(log, tmp_path / "app.log.1")
    log.write_text("three\n")

    restarted = _collector(log)  # only the checkpoint stored with the events survives
    await restarted.poll(sink)
    await restarted.poll(sink)

    assert _messages(sink) == ["one", "two", "three"]


async def test_copytruncate_refilled_past_the_old_offset_is_not_misread(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("2026-10-20T00:00:01 first\n2026-10-20T00:00:02 second\n")
    sink = MemorySink()
    collector = _collector(log)
    await collector.poll(sink)
    _append(log, "2026-10-20T00:00:03 third\n")
    shutil.copyfile(log, tmp_path / "app.log.1")
    with log.open("r+b") as handle:  # logrotate copytruncate, then the writer goes on
        handle.truncate(0)
        handle.write(b"2026-10-20T00:01:00 new content, longer than the old one\n")
        handle.write(b"2026-10-20T00:01:01 more\n")

    await collector.poll(sink)
    await collector.poll(sink)

    assert _messages(sink) == [
        "2026-10-20T00:00:01 first",
        "2026-10-20T00:00:02 second",
        "2026-10-20T00:00:03 third",
        "2026-10-20T00:01:00 new content, longer than the old one",
        "2026-10-20T00:01:01 more",
    ]


async def test_secrets_are_scrubbed_before_leaving_the_host(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text(
        "login failed password=hunter2 user=bob\n"
        "GET /x Authorization: Bearer abcdefghijklmnop\n"
        "db postgresql://adis:s3cret@db:5432/adis\n"
    )
    sink = MemorySink()

    await _collector(log).poll(sink)

    text = " ".join(_messages(sink))
    for secret in ("hunter2", "abcdefghijklmnop", "s3cret"):
        assert secret not in text
    assert "user=bob" in text


@pytest.mark.parametrize(
    ("line", "severity"),
    [
        ("kernel: panic - not syncing", SeverityHint.HIGH),
        ("CRITICAL disk failure", SeverityHint.HIGH),
        ("ERROR could not connect", SeverityHint.MEDIUM),
        ("request failed with 500", SeverityHint.MEDIUM),
        ("WARNING disk 90% full", SeverityHint.LOW),
        ("service started", SeverityHint.INFO),
    ],
)
async def test_severity_hint_is_derived_from_keywords(
    tmp_path: Path, line: str, severity: SeverityHint
) -> None:
    log = tmp_path / "app.log"
    log.write_text(f"{line}\n")
    sink = MemorySink()

    await _collector(log).poll(sink)

    assert sink.events[0].severity_hint is severity


async def test_huge_lines_are_split_not_stalled(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_bytes(b"x" * (MAX_LINE_BYTES * 2 + 10) + b"\n")
    sink = MemorySink()

    await _collector(log).poll(sink)

    assert [len(message) for message in _messages(sink)] == [MAX_LINE_BYTES, MAX_LINE_BYTES, 10]


async def test_undecodable_bytes_are_replaced(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_bytes(b"bad \xff\xfe bytes\n")
    sink = MemorySink()

    await _collector(log).poll(sink)

    assert _messages(sink) == ["bad �� bytes"]


async def test_missing_files_are_waited_for(tmp_path: Path) -> None:
    log = tmp_path / "later.log"
    sink = MemorySink()
    collector = _collector(log)

    assert await collector.poll(sink) == 0
    log.write_text("now it exists\n")
    await collector.poll(sink)

    assert _messages(sink) == ["now it exists"]


async def test_emitted_events_are_valid_canonical_json(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("hello\n")
    sink = MemorySink()

    await _collector(log).poll(sink)

    event = sink.events[0]
    assert parse_canonical_event(serialize_canonical_event(event)) == event


# ------------------------------------------------------------------------------- simulators


def _within_simulation_networks(address: object) -> bool:
    return isinstance(address, IPv4Address) and any(address in net for net in SIMULATION_NETWORKS)


def test_auth_simulator_generates_marked_valid_events() -> None:
    simulator = AuthEventSimulator(make_context(), per_minute=60, rng=random.Random(7))

    events = simulator.generate(300)

    scenarios = set()
    for event in events:
        assert isinstance(event, AuthenticationEvent)
        assert event.source_type == "simulator"
        assert event.metadata["simulated"] is True
        assert _within_simulation_networks(event.src_ip)
        assert _within_simulation_networks(event.dst_ip)
        assert parse_canonical_event(serialize_canonical_event(event)) == event
        scenarios.add(event.metadata["scenario"])
    assert scenarios == {"normal_login", "mistyped_password", "password_bruteforce"}
    assert any(not event.success for event in events if isinstance(event, AuthenticationEvent))


def test_flow_simulator_generates_marked_valid_events() -> None:
    simulator = NetworkFlowSimulator(make_context(), per_minute=60, rng=random.Random(3))

    events = simulator.generate(500)

    scenarios = set()
    for event in events:
        assert isinstance(event, NetworkFlowEvent)
        assert event.metadata["simulated"] is True
        assert _within_simulation_networks(event.src_ip)
        assert _within_simulation_networks(event.dst_ip)
        scenarios.add(event.metadata["scenario"])
    assert scenarios == {
        "web_browsing",
        "dns_lookup",
        "internal_ssh",
        "port_scan",
        "large_outbound_transfer",
    }


def test_seeded_simulators_are_reproducible() -> None:
    def scenarios(seed: int) -> list[object]:
        simulator = NetworkFlowSimulator(make_context(), per_minute=60, rng=random.Random(seed))
        return [event.metadata["scenario"] for event in simulator.generate(50)]

    assert scenarios(11) == scenarios(11)


async def test_simulator_rate_is_spread_over_ticks() -> None:
    ticks = 0

    async def fake_sleep(seconds: float) -> None:
        nonlocal ticks
        ticks += 1
        if ticks > 10:
            raise asyncio.CancelledError

    sink = MemorySink()
    simulator = AuthEventSimulator(make_context(), per_minute=90, sleep=fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        await simulator.run(sink)

    assert len(sink.events) == 15  # 1.5 events per second over 10 ticks


def test_simulator_rate_must_be_positive() -> None:
    with pytest.raises(ValueError, match="per_minute"):
        AuthEventSimulator(make_context(), per_minute=0)
