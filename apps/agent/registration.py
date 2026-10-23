"""Agent registration.

At every start the agent announces itself with a canonical ``system.agent_registered``
event: agent id, name, host name, OS type and version. The event id is derived from the
agent id and those attributes, so repeating the announcement is idempotent downstream,
and an upgrade or rename produces a new one. The announcement is sent directly (not
spooled) and retried with backoff until the server acknowledges it; collectors keep
buffering meanwhile. Server-side, the normalizer keeps ``adis.agents`` up to date from
these events.
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Final
from uuid import uuid5

from apps.agent.backoff import Backoff
from apps.agent.client import IngestSender, Outcome
from apps.agent.identity import AgentIdentity
from apps.agent.spool import Spool
from packages.events.agents import AGENT_REGISTERED_EVENT_TYPE
from packages.events.canonical import SeverityHint, SystemEvent, serialize_canonical_event

logger = logging.getLogger(__name__)

EVENT_TYPE: Final = AGENT_REGISTERED_EVENT_TYPE
CHECKPOINT: Final = "registration"
_PERMANENT: Final = frozenset({Outcome.REJECTED, Outcome.MALFORMED, Outcome.TOO_LARGE})


class RegistrationError(RuntimeError):
    """The server rejected the registration event permanently."""


def registration_event(
    identity: AgentIdentity, *, timestamp: datetime | None = None
) -> SystemEvent:
    """The canonical announcement of ``identity``, dated ``timestamp`` (default: now)."""
    attributes = {key: str(value) for key, value in asdict(identity).items()}
    fingerprint = hashlib.sha256(json.dumps(attributes, sort_keys=True).encode()).hexdigest()
    return SystemEvent(
        event_id=uuid5(identity.agent_id, f"registration:{fingerprint}"),
        event_type=EVENT_TYPE,
        timestamp=timestamp or datetime.now(UTC),
        source_type="agent",
        source_name=f"adis-agent@{identity.name}",
        host_id=identity.host_id,
        agent_id=str(identity.agent_id),
        severity_hint=SeverityHint.INFO,
        metadata={**attributes, "fingerprint": fingerprint},
    )


async def _first_registered(spool: Spool, identity: AgentIdentity) -> datetime | None:
    """The time this identity was first registered, if the spool remembers it."""
    stored = await spool.checkpoint(CHECKPOINT)
    if stored is None:
        return None
    try:
        data = json.loads(stored)
        if data.get("event_id") != str(registration_event(identity).event_id):
            return None
        moment = datetime.fromisoformat(str(data["timestamp"]))
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    return moment if moment.tzinfo is not None else None


async def register(
    client: IngestSender,
    identity: AgentIdentity,
    spool: Spool,
    *,
    backoff: Backoff,
    stop: asyncio.Event,
) -> bool:
    """Announce the agent until acknowledged.

    Returns:
        ``True`` once registered, ``False`` if ``stop`` was set first.

    Raises:
        RegistrationError: If the server rejects the announcement permanently.
    """
    # A restart re-sends the first registration of this identity unchanged (same id, same
    # time), which the normalizer deduplicates; a new timestamp under the same id would be
    # a conflicting duplicate and be dead-lettered (found by the Phase 1 real-data lab).
    event = registration_event(identity, timestamp=await _first_registered(spool, identity))
    payload = serialize_canonical_event(event)
    while not stop.is_set():
        result = await client.send_event(payload)
        if result.outcome is Outcome.DELIVERED:
            backoff.reset()
            await spool.set_checkpoint(
                CHECKPOINT,
                json.dumps(
                    {
                        "event_id": str(event.event_id),
                        "timestamp": event.timestamp.isoformat(),
                        "registered_at": datetime.now(UTC).isoformat(),
                    }
                ),
            )
            logger.info(
                "agent registered",
                extra={"action": "agent_registered", "agent_id": str(identity.agent_id)},
            )
            return True
        if result.outcome in _PERMANENT:
            raise RegistrationError(f"registration rejected: {result.code or result.detail}")
        delay = result.retry_after if result.retry_after is not None else backoff.next_delay()
        logger.warning(
            "registration failed; retrying",
            extra={
                "action": "agent_registration_retry",
                "outcome": result.outcome.value,
                "status_code": result.status,
                "retry_in_ms": round(delay * 1000),
            },
        )
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except TimeoutError:
            continue
    return False
