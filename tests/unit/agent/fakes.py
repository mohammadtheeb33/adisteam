"""Test doubles for the endpoint agent."""

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

from apps.agent.agent import Agent
from apps.agent.client import Outcome, SendResult
from apps.agent.collectors import CollectorContext
from apps.agent.identity import AgentIdentity
from apps.agent.settings import AgentServiceSettings
from apps.agent.spool import Spool
from packages.events.canonical import (
    AnyCanonicalEvent,
    parse_canonical_event,
    serialize_canonical_event,
)
from tests.unit.events.canonical.samples import network

AGENT_ID = UUID("7d1f0e4c-5c1b-4b0c-9a61-2d3b3c1e9f00")
TOKEN = "agent-token-" + "x" * 32


def make_identity(**overrides: object) -> AgentIdentity:
    """A fixed identity."""
    values: dict[str, object] = {
        "agent_id": AGENT_ID,
        "name": "agent-test",
        "hostname": "web-1.example.test",
        "host_id": "web-1.example.test",
        "os_type": "linux",
        "agent_version": "0.1.0",
    }
    values.update(overrides)
    return AgentIdentity(**values)  # type: ignore[arg-type]


def make_context() -> CollectorContext:
    """Collector context of :func:`make_identity`."""
    return CollectorContext(make_identity())


def agent_settings(data_dir: Path, **overrides: object) -> AgentServiceSettings:
    """Agent settings without reading the environment."""
    values: dict[str, object] = {
        "agent_token": TOKEN,
        "agent_name": "agent-test",
        "agent_data_dir": data_dir,
        "agent_flush_interval_seconds": 0.05,
        "agent_retry_initial_backoff_seconds": 0.01,
        "agent_retry_max_backoff_seconds": 0.05,
        "agent_batch_size": 10,
    }
    values.update(overrides)
    return AgentServiceSettings.model_validate(values)


def spooled_payload(**overrides: object) -> tuple[str, bytes]:
    """A ``(event_id, payload)`` record of a valid network flow."""
    event = parse_canonical_event(network(**overrides))
    return str(event.event_id), serialize_canonical_event(event)


def delivered(count: int, *, rejected: Mapping[int, str] | None = None) -> SendResult:
    """A 202 accepting every index except ``rejected``."""
    refused = dict(rejected or {})
    return SendResult(
        Outcome.DELIVERED,
        status=202,
        accepted=frozenset(i for i in range(count) if i not in refused),
        rejected=refused,
    )


Script = SendResult | Callable[[Sequence[bytes]], SendResult]


@dataclass
class ScriptedSender:
    """Replies with scripted results, then accepts everything."""

    script: list[Script] = field(default_factory=list)
    batches: list[list[bytes]] = field(default_factory=list)
    events: list[bytes] = field(default_factory=list)

    async def send_batch(self, payloads: Sequence[bytes]) -> SendResult:
        self.batches.append(list(payloads))
        return self._reply(payloads)

    async def send_event(self, payload: bytes) -> SendResult:
        self.events.append(payload)
        return self._reply([payload])

    def _reply(self, payloads: Sequence[bytes]) -> SendResult:
        if not self.script:
            return delivered(len(payloads))
        step = self.script.pop(0)
        return step(payloads) if callable(step) else step

    def sent_ids(self) -> list[str]:
        """``event_id`` of every event sent in batches, in order."""
        return [json.loads(payload)["event_id"] for batch in self.batches for payload in batch]


@dataclass
class MemorySink:
    """Collects submitted events and checkpoints in memory."""

    events: list[AnyCanonicalEvent] = field(default_factory=list)
    checkpoints: dict[str, str] = field(default_factory=dict)
    submissions: int = 0

    async def submit(
        self, events: Sequence[AnyCanonicalEvent], *, checkpoints: Mapping[str, str] | None = None
    ) -> None:
        self.submissions += 1
        self.events.extend(events)
        self.checkpoints.update(checkpoints or {})

    async def checkpoint(self, key: str) -> str | None:
        return self.checkpoints.get(key)


def open_spool(
    tmp_path: Path, *, max_events: int = 1_000, max_quarantined: int | None = None
) -> Spool:
    """A spool in ``tmp_path``."""
    return Spool(tmp_path / "spool.sqlite3", max_events=max_events, max_quarantined=max_quarantined)


Condition = Callable[[], bool | Awaitable[bool]]


async def wait_until(condition: Condition, *, interval: float = 0.01) -> None:
    """Poll ``condition`` until it holds; callers bound the wait with ``asyncio.timeout``."""
    while True:
        result = condition()
        if not isinstance(result, bool):
            result = await result
        if result:
            return
        await asyncio.sleep(interval)


async def run_agent_until(agent: Agent, condition: Condition, *, limit_seconds: float = 5) -> None:
    """Run ``agent`` until ``condition`` holds, then stop it and wait for a clean shutdown."""
    stop = asyncio.Event()
    task = asyncio.create_task(agent.run(stop))
    try:
        async with asyncio.timeout(limit_seconds):
            await wait_until(condition)
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=limit_seconds)
