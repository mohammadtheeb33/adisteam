"""Ingestion client authentication: bearer tokens from ``API_INGEST_TOKENS``.

This is deliberately minimal and replaceable (see ARCHITECTURE.md OD-16): each client
holds a random token, and the server keeps only SHA-256 digests in memory. Tokens are
never logged.
"""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from fastapi.security import HTTPBearer

from packages.config import AGENT_CLIENT_PREFIX, bound_agent_id
from packages.kafka import HostScope

__all__ = ["AGENT_CLIENT_PREFIX", "IngestClient", "TokenAuthenticator", "bearer_scheme"]

bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="IngestToken",
    description="Per-client ingestion token from API_INGEST_TOKENS.",
)


@dataclass(frozen=True, slots=True)
class IngestClient:
    """An authenticated ingestion client.

    A client id of the form ``agent-<uuid>`` is **bound** to that agent: every event it
    submits must carry ``agent_id`` equal to the UUID, so one agent's token cannot write
    (or pre-empt the event ids of) another agent's telemetry.

    A client with ``allowed_hosts`` (``API_INGEST_CLIENT_HOSTS``) may also only submit
    events whose ``host_id`` is one of them. The agent binding does not constrain the host
    an event names, and detection, threats and recommendations are all keyed by host, so
    without this a stolen token could drive responses against another host (OD-34).
    """

    client_id: str
    allowed_hosts: frozenset[str] | None = None

    @property
    def bound_agent_id(self) -> UUID | None:
        """The agent this client may speak for, or ``None`` for unbound clients."""
        return bound_agent_id(self.client_id)

    @property
    def host_scope(self) -> HostScope:
        """How far this client is trusted for the host of an event it may submit.

        Recorded with every event it submits, so later stages can tell evidence from the
        host's own bound source (``exclusive``) from evidence a multi-host or unrestricted
        client could have written for any host.
        """
        if self.allowed_hosts is None:
            return "unbound"
        return "exclusive" if len(self.allowed_hosts) == 1 else "shared"


class TokenAuthenticator:
    """Resolves bearer tokens to clients."""

    def __init__(
        self,
        credentials: Mapping[str, str],
        hosts: Mapping[str, frozenset[str]] | None = None,
    ) -> None:
        """Index ``{client_id: token}`` by token digest; the tokens are not retained.

        Args:
            credentials: ``{client_id: token}``.
            hosts: ``{client_id: allowed hosts}``; clients not listed may name any host.
        """
        self._clients = {_digest(token): client for client, token in credentials.items()}
        self._hosts = dict(hosts or {})

    def authenticate(self, token: str) -> IngestClient | None:
        """The client owning ``token``, or ``None``."""
        client_id = self._clients.get(_digest(token))
        if client_id is None:
            return None
        return IngestClient(client_id, self._hosts.get(client_id))


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()
