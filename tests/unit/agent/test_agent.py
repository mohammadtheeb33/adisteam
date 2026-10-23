"""Registration and the agent runtime (collectors, spool, batcher) with a scripted server."""

import asyncio
import json
import logging
from collections.abc import Sequence
from pathlib import Path

import pytest

from apps.agent.agent import Agent, SpoolSink, build_collectors
from apps.agent.backoff import Backoff
from apps.agent.batcher import Batcher
from apps.agent.client import Outcome, SendResult
from apps.agent.collectors import (
    AuthEventSimulator,
    CollectorContext,
    EventSink,
    LogFileCollector,
    NetworkFlowSimulator,
)
from apps.agent.registration import (
    CHECKPOINT,
    EVENT_TYPE,
    RegistrationError,
    register,
    registration_event,
)
from packages.events.canonical import AnyCanonicalEvent, parse_canonical_event
from packages.observability import current_log_context
from tests.unit.agent.fakes import (
    ScriptedSender,
    agent_settings,
    make_identity,
    open_spool,
    run_agent_until,
)
from tests.unit.events.canonical.samples import network


def _backoff() -> Backoff:
    return Backoff(initial_seconds=0.001, max_seconds=0.005)


# ------------------------------------------------------------------------------ registration


def test_registration_event_describes_the_agent() -> None:
    identity = make_identity()

    event = registration_event(identity)

    assert event.event_type == EVENT_TYPE
    assert event.agent_id == str(identity.agent_id)
    assert event.host_id == identity.host_id
    assert event.metadata["os_type"] == "linux"
    assert event.metadata["agent_version"] == "0.1.0"


def test_registration_event_id_is_stable_until_the_identity_changes() -> None:
    same = registration_event(make_identity()).event_id
    again = registration_event(make_identity()).event_id
    upgraded = registration_event(make_identity(agent_version="0.2.0")).event_id

    assert same == again
    assert upgraded != same


async def test_registration_retries_until_acknowledged(tmp_path: Path) -> None:
    unavailable = SendResult(Outcome.UNAVAILABLE, status=503)
    sender = ScriptedSender([unavailable, unavailable])

    with open_spool(tmp_path) as spool:
        registered = await register(
            sender, make_identity(), spool, backoff=_backoff(), stop=asyncio.Event()
        )
        checkpoint = await spool.checkpoint(CHECKPOINT)

    assert registered is True
    assert len(sender.events) == 3
    assert checkpoint is not None
    assert json.loads(checkpoint)["event_id"] == str(registration_event(make_identity()).event_id)


async def test_restart_resends_the_identical_registration(tmp_path: Path) -> None:
    # Found by the real-data lab: a new timestamp under the same id was dead-lettered by
    # the normalizer as a conflicting duplicate after every agent restart.
    sender = ScriptedSender()

    with open_spool(tmp_path) as spool:
        for _ in range(2):
            await register(sender, make_identity(), spool, backoff=_backoff(), stop=asyncio.Event())

    first, second = (json.loads(payload) for payload in sender.events)
    assert (first["event_id"], first["timestamp"]) == (second["event_id"], second["timestamp"])


async def test_registration_stops_when_asked(tmp_path: Path) -> None:
    stop = asyncio.Event()
    sender = ScriptedSender([SendResult(Outcome.UNAVAILABLE, status=503)] * 1_000)

    with open_spool(tmp_path) as spool:
        task = asyncio.create_task(
            register(sender, make_identity(), spool, backoff=_backoff(), stop=stop)
        )
        await asyncio.sleep(0.02)
        stop.set()

        assert await asyncio.wait_for(task, timeout=2) is False


@pytest.mark.parametrize("outcome", [Outcome.REJECTED, Outcome.MALFORMED, Outcome.TOO_LARGE])
async def test_permanent_registration_rejection_is_an_error(
    tmp_path: Path, outcome: Outcome
) -> None:
    sender = ScriptedSender([SendResult(outcome, status=422, code="validation_failed")])

    with open_spool(tmp_path) as spool, pytest.raises(RegistrationError, match="validation_failed"):
        await register(sender, make_identity(), spool, backoff=_backoff(), stop=asyncio.Event())


# ---------------------------------------------------------------------------------- runtime


class OneShotCollector:
    """Submits a fixed list of events once."""

    name = "one-shot"

    def __init__(self, events: Sequence[AnyCanonicalEvent]) -> None:
        self.events = list(events)

    async def run(self, sink: EventSink) -> None:
        await sink.submit(self.events)
        await asyncio.Event().wait()


class CrashingCollector:
    """Fails on its first run, then submits one event."""

    name = "crashing"

    def __init__(self, event: AnyCanonicalEvent) -> None:
        self.event = event
        self.runs = 0

    async def run(self, sink: EventSink) -> None:
        self.runs += 1
        if self.runs == 1:
            raise RuntimeError("collector bug")
        await sink.submit([self.event])
        await asyncio.Event().wait()


def _agent(
    tmp_path: Path, sender: ScriptedSender, collectors: Sequence[object], *, max_events: int = 1_000
) -> Agent:
    spool = open_spool(tmp_path, max_events=max_events)
    batcher = Batcher(spool, sender, batch_size=10, flush_interval_seconds=0.01, backoff=_backoff())
    return Agent(
        identity=make_identity(),
        spool=spool,
        client=sender,  # type: ignore[arg-type]
        collectors=collectors,  # type: ignore[arg-type]
        batcher=batcher,
        sink=SpoolSink(spool, batch_size=10, retry_seconds=0.01, wake=batcher.wake),
        registration_backoff=_backoff(),
        shutdown_flush_seconds=1,
    )


async def test_agent_registers_then_delivers_collected_events(tmp_path: Path) -> None:
    events = [parse_canonical_event(network()) for _ in range(3)]
    sender = ScriptedSender()
    agent = _agent(tmp_path, sender, [OneShotCollector(events)])

    await run_agent_until(agent, lambda: len(sender.sent_ids()) == 3)
    stats = await agent.spool.stats()
    agent.spool.close()

    assert json.loads(sender.events[0])["event_type"] == EVENT_TYPE
    assert sender.sent_ids() == [str(event.event_id) for event in events]
    assert stats.queued == 0


class _HostIdRecorder(logging.Handler):
    """Records the correlation ``host_id`` in effect when each record is emitted."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.host_ids: list[str | None] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.host_ids.append(current_log_context().host_id)


async def test_agent_logs_carry_the_host_id(tmp_path: Path) -> None:
    sender = ScriptedSender()
    agent = _agent(tmp_path, sender, [])
    recorder = _HostIdRecorder()
    agent_logger = logging.getLogger("apps.agent")
    agent_logger.addHandler(recorder)
    previous_level = agent_logger.level
    agent_logger.setLevel(logging.DEBUG)
    try:
        await run_agent_until(agent, lambda: bool(sender.events))
    finally:
        agent_logger.removeHandler(recorder)
        agent_logger.setLevel(previous_level)
        agent.spool.close()

    assert len(recorder.host_ids) >= 3  # started, registered, stopped
    assert set(recorder.host_ids) == {make_identity().host_id}
    assert current_log_context().host_id is None


async def test_events_are_buffered_while_the_server_is_unreachable(tmp_path: Path) -> None:
    events = [parse_canonical_event(network()) for _ in range(4)]
    sender = ScriptedSender([SendResult(Outcome.UNAVAILABLE, status=503)] * 1_000)
    agent = _agent(tmp_path, sender, [OneShotCollector(events)])

    async def all_spooled() -> bool:
        return (await agent.spool.stats()).queued == 4

    await run_agent_until(agent, all_spooled)
    agent.spool.close()

    with open_spool(tmp_path) as reopened:  # nothing lost across the restart
        assert [event.event_id for event in await reopened.peek(10)] == [
            str(event.event_id) for event in events
        ]


async def test_failed_collectors_are_restarted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("apps.agent.agent._COLLECTOR_RESTART_SECONDS", 0.01)
    event = parse_canonical_event(network())
    collector = CrashingCollector(event)
    sender = ScriptedSender()
    agent = _agent(tmp_path, sender, [collector])

    await run_agent_until(agent, lambda: str(event.event_id) in sender.sent_ids())
    agent.spool.close()

    assert collector.runs == 2


async def test_sink_applies_backpressure_instead_of_dropping(tmp_path: Path) -> None:
    wake = asyncio.Event()
    events = [parse_canonical_event(network()) for _ in range(3)]

    with open_spool(tmp_path, max_events=2) as spool:
        sink = SpoolSink(spool, batch_size=10, retry_seconds=0.01, wake=wake)
        submission = asyncio.create_task(sink.submit(events, checkpoints={"k": "v"}))
        await asyncio.sleep(0.05)
        blocked = not submission.done()
        await spool.acknowledge([record.seq for record in await spool.peek(2)])
        await asyncio.wait_for(submission, timeout=2)
        remaining = [record.event_id for record in await spool.peek(10)]
        checkpoint = await spool.checkpoint("k")

    assert blocked
    assert wake.is_set()
    assert remaining == [str(events[2].event_id)]
    assert checkpoint == "v"


async def test_full_batch_wakes_the_sender(tmp_path: Path) -> None:
    wake = asyncio.Event()

    with open_spool(tmp_path) as spool:
        sink = SpoolSink(spool, batch_size=2, retry_seconds=0.01, wake=wake)
        await sink.submit([parse_canonical_event(network())])
        early = wake.is_set()
        await sink.submit([parse_canonical_event(network())])

    assert (early, wake.is_set()) == (False, True)


def test_collectors_follow_configuration(tmp_path: Path) -> None:
    context = CollectorContext(make_identity())
    none = build_collectors(agent_settings(tmp_path), context)
    everything = build_collectors(
        agent_settings(
            tmp_path,
            agent_log_files=f"{tmp_path / 'a.log'}, {tmp_path / 'b.log'}",
            agent_simulate_auth_per_minute=10,
            agent_simulate_flows_per_minute=10,
        ),
        context,
    )

    assert none == []
    assert [type(c) for c in everything] == [
        LogFileCollector,
        AuthEventSimulator,
        NetworkFlowSimulator,
    ]
