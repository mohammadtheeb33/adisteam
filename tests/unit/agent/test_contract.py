"""The agent against the real ingestion API application (in-process, no network).

This pins the contract between ``apps/agent`` and ``apps/api``: request format,
authentication, per-event rejection and acknowledgement.
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx2

from apps.agent.agent import Agent
from apps.agent.registration import EVENT_TYPE
from apps.api.app import create_app
from packages.events.canonical import SystemEvent
from tests.unit.agent.fakes import agent_settings, run_agent_until
from tests.unit.api.fakes import TOKEN, RecordingPublisher, api_settings


@asynccontextmanager
async def _agent_with_api(
    tmp_path: Path, publisher: RecordingPublisher, **settings: object
) -> AsyncIterator[Agent]:
    app = create_app(api_settings(api_max_batch_size=20), publisher=publisher)
    async with app.router.lifespan_context(app):
        options: dict[str, object] = {"agent_token": TOKEN, **settings}
        agent = Agent.from_settings(
            agent_settings(tmp_path / "agent", **options),
            transport=httpx2.ASGITransport(app=app),
        )
        async with agent:
            yield agent


async def test_agent_registers_and_delivers_simulated_telemetry(tmp_path: Path) -> None:
    publisher = RecordingPublisher()

    async with _agent_with_api(
        tmp_path,
        publisher,
        agent_simulate_auth_per_minute=1_200,
        agent_simulate_flows_per_minute=1_200,
    ) as agent:
        await run_agent_until(agent, lambda: len(publisher.events) >= 40)
        stats = await agent.spool.stats()
        agent_id = str(agent.identity.agent_id)

    registration = publisher.events[0]
    assert isinstance(registration, SystemEvent)
    assert registration.event_type == EVENT_TYPE
    assert {event.agent_id for event in publisher.events} == {agent_id}
    assert {event.category for event in publisher.events[1:]} == {"authentication", "network"}
    assert all(context.client_id == "agent-a" for _, context in publisher.batches)
    assert stats.queued == 0


async def test_log_lines_reach_the_api(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("ERROR payment failed token=abc123secret\nINFO ok\n")
    publisher = RecordingPublisher()

    async with _agent_with_api(
        tmp_path, publisher, agent_log_files=str(log), agent_log_read_from_start=True
    ) as agent:
        await run_agent_until(agent, lambda: len(publisher.events) >= 3)

    messages = [event.metadata.get("message") for event in publisher.events[1:]]
    assert messages == ["ERROR payment failed token=[REDACTED]", "INFO ok"]


async def test_wrong_token_keeps_events_buffered(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("one\ntwo\n")
    publisher = RecordingPublisher()

    async with _agent_with_api(
        tmp_path,
        publisher,
        agent_token="wrong-token-" + "z" * 32,
        agent_log_files=str(log),
        agent_log_read_from_start=True,
    ) as agent:

        async def both_lines_buffered() -> bool:
            return (await agent.spool.stats()).queued == 2

        await run_agent_until(agent, both_lines_buffered)

    assert publisher.events == []


async def test_server_side_rejections_are_quarantined(tmp_path: Path) -> None:
    publisher = RecordingPublisher()

    async with _agent_with_api(tmp_path, publisher) as agent:
        # An event the server's schema refuses (the agent validates what it builds, so a
        # corrupted spool entry stands in for a schema mismatch between agent and server).
        await agent.spool.append([("bad-event", b'{"schema_version": "9.9"}')])
        await run_agent_until(agent, lambda: bool(publisher.events))
        await asyncio.sleep(0.2)
        stats = await agent.spool.stats()
        quarantined = await agent.spool.quarantined(5)

    assert (stats.queued, stats.quarantined) == (0, 1)
    assert quarantined[0][0] == "bad-event"
    assert "unsupported_schema_version" in quarantined[0][1]
