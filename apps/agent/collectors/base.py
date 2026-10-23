"""Collector interface.

A collector turns one source of telemetry into canonical events and submits them to an
:class:`EventSink`. It runs until cancelled. ``submit`` returns once the events are
durably spooled; while the spool is full it waits (backpressure), so a collector must
not drop events itself.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from apps.agent.identity import AgentIdentity
from packages.events.canonical import AnyCanonicalEvent

SIMULATOR_SOURCE_TYPE: Final = "simulator"


class EventSink(Protocol):
    """Where collectors deliver events."""

    async def submit(
        self, events: Sequence[AnyCanonicalEvent], *, checkpoints: Mapping[str, str] | None = None
    ) -> None:
        """Spool ``events`` durably, together with the collector's ``checkpoints``."""
        ...

    async def checkpoint(self, key: str) -> str | None:
        """A checkpoint stored by an earlier ``submit``."""
        ...


class Collector(Protocol):
    """A source of telemetry."""

    @property
    def name(self) -> str:
        """Stable collector name, used in ``source_name``."""
        ...

    async def run(self, sink: EventSink) -> None:
        """Collect until cancelled."""
        ...


@dataclass(frozen=True, slots=True)
class CollectorContext:
    """What collectors need to know about the agent."""

    identity: AgentIdentity

    @property
    def agent_id(self) -> str:
        """The agent UUID as carried in canonical events."""
        return str(self.identity.agent_id)

    def source_name(self, collector: str) -> str:
        """``<collector>@<agent name>``."""
        return f"{collector}@{self.identity.name}"
