"""Contract of agent registration events.

Agents announce themselves with a canonical ``SystemEvent`` of this type; the
normalizer keeps ``adis.agents`` up to date from it. The metadata keys below carry the
agent's identity.
"""

from typing import Final

AGENT_REGISTERED_EVENT_TYPE: Final = "system.agent_registered"
"""``event_type`` of a registration; the event's ``agent_id`` is the agent's UUID."""

REGISTRATION_NAME: Final = "name"
REGISTRATION_HOSTNAME: Final = "hostname"
REGISTRATION_OS_TYPE: Final = "os_type"
REGISTRATION_VERSION: Final = "agent_version"
