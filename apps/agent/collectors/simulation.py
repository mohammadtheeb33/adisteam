"""Synthetic telemetry for development: authentication events and network flows.

Safety properties:

- Only for ``APP_ENV`` development or test; configuration refuses non-zero rates
  elsewhere.
- Every address is from private (RFC 1918) or documentation (RFC 5737) ranges, never a
  real Internet host. Nothing is sent on the network; the records are invented.
- Every event says what it is: ``source_type="simulator"``, and
  ``metadata.simulated=true`` with the ``scenario`` name.

The scenarios mix normal activity with a few attack-like patterns (password
brute-forcing, port scans, large outbound transfers), so downstream detection has
something to find.
"""

import asyncio
import random
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Final

from pydantic import JsonValue

from apps.agent.collectors.base import SIMULATOR_SOURCE_TYPE, CollectorContext, EventSink
from packages.events.canonical import (
    AnyCanonicalEvent,
    AuthenticationEvent,
    AuthFailureReason,
    AuthMethod,
    NetworkFlowEvent,
    NetworkProtocol,
)

INTERNAL_NETWORK: Final = IPv4Network("10.0.0.0/16")
DOCUMENTATION_NETWORKS: Final = (
    IPv4Network("192.0.2.0/24"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
)
SIMULATION_NETWORKS: Final = (INTERNAL_NETWORK, *DOCUMENTATION_NETWORKS)
"""Every address a simulator may produce."""

MONITORED_HOST: Final = IPv4Address("10.0.0.10")
_DNS_SERVER: Final = IPv4Address("10.0.0.2")
_ATTACKERS: Final = (
    IPv4Address("203.0.113.66"),
    IPv4Address("203.0.113.99"),
    IPv4Address("198.51.100.200"),
)
_USERS: Final = ("alice", "bob", "carol", "dave", "deploy", "backup")
_SPRAYED_USERS: Final = ("root", "admin", "test", "oracle", "ubuntu", "postgres", "guest")

Sleep = Callable[[float], Awaitable[None]]


def _address(rng: random.Random, network: IPv4Network) -> IPv4Address:
    return network[rng.randrange(1, network.num_addresses - 1)]


def _ephemeral_port(rng: random.Random) -> int:
    return rng.randrange(49_152, 65_536)


def _metadata(scenario: str, **extra: JsonValue) -> dict[str, JsonValue]:
    return {"simulated": True, "scenario": scenario, **extra}


class _RateLimitedSimulator:
    """Emits ``per_minute`` events on average, in ticks of ``tick_seconds``."""

    name = "simulator"

    def __init__(
        self,
        context: CollectorContext,
        *,
        per_minute: int,
        rng: random.Random | None = None,
        sleep: Sleep = asyncio.sleep,
        tick_seconds: float = 1.0,
    ) -> None:
        if per_minute < 1:
            raise ValueError("per_minute must be positive")
        self._context = context
        self._per_second = per_minute / 60
        self._rng = rng or random.Random()  # noqa: S311 - synthetic data, not security
        self._sleep = sleep
        self._tick = tick_seconds

    async def run(self, sink: EventSink) -> None:
        """Generate until cancelled."""
        budget = 0.0
        while True:
            await self._sleep(self._tick)
            budget += self._per_second * self._tick
            count = int(budget)
            budget -= count
            if count:
                await sink.submit(self.generate(count))

    def generate(self, count: int) -> list[AnyCanonicalEvent]:
        """``count`` synthetic events."""
        raise NotImplementedError


class AuthEventSimulator(_RateLimitedSimulator):
    """Logins: mostly legitimate, some typos, and password brute-forcing from a few hosts."""

    name = "auth-simulator"

    def generate(self, count: int) -> list[AnyCanonicalEvent]:
        """``count`` synthetic authentication events."""
        return [self._one() for _ in range(count)]

    def _one(self) -> AuthenticationEvent:
        rng = self._rng
        roll = rng.random()
        if roll < 0.70:
            scenario, success, reason = "normal_login", True, None
            user, source = rng.choice(_USERS), _address(rng, INTERNAL_NETWORK)
            method = rng.choice((AuthMethod.PUBLIC_KEY, AuthMethod.PASSWORD))
        elif roll < 0.85:
            scenario, success, reason = (
                "mistyped_password",
                False,
                AuthFailureReason.INVALID_CREDENTIALS,
            )
            user, source, method = (
                rng.choice(_USERS),
                _address(rng, INTERNAL_NETWORK),
                AuthMethod.PASSWORD,
            )
        else:
            scenario, success, method = "password_bruteforce", False, AuthMethod.PASSWORD
            user, source = rng.choice(_SPRAYED_USERS), rng.choice(_ATTACKERS)
            reason = rng.choice(
                (AuthFailureReason.INVALID_CREDENTIALS, AuthFailureReason.UNKNOWN_USER)
            )
        identity = self._context.identity
        return AuthenticationEvent(
            event_type="authentication.login",
            timestamp=datetime.now(UTC),
            source_type=SIMULATOR_SOURCE_TYPE,
            source_name=self._context.source_name(self.name),
            host_id=identity.host_id,
            agent_id=self._context.agent_id,
            username=user,
            auth_method=method,
            success=success,
            failure_reason=reason,
            src_ip=source,
            src_port=_ephemeral_port(rng),
            dst_ip=MONITORED_HOST,
            dst_port=22,
            protocol=NetworkProtocol.TCP,
            metadata=_metadata(scenario, service="sshd"),
        )


class NetworkFlowSimulator(_RateLimitedSimulator):
    """Flows: web and DNS traffic, internal SSH, port scans and large outbound transfers."""

    name = "flow-simulator"

    def generate(self, count: int) -> list[AnyCanonicalEvent]:
        """``count`` synthetic network flows."""
        return [self._one() for _ in range(count)]

    def _one(self) -> NetworkFlowEvent:
        rng = self._rng
        roll = rng.random()
        if roll < 0.55:
            flow = (
                "web_browsing",
                _address(rng, INTERNAL_NETWORK),
                _address(rng, DOCUMENTATION_NETWORKS[1]),
                _ephemeral_port(rng),
                443,
                NetworkProtocol.TCP,
                rng.randrange(400, 6_000),
                rng.randrange(2_000, 250_000),
            )
        elif roll < 0.80:
            flow = (
                "dns_lookup",
                _address(rng, INTERNAL_NETWORK),
                _DNS_SERVER,
                _ephemeral_port(rng),
                53,
                NetworkProtocol.UDP,
                rng.randrange(40, 120),
                rng.randrange(60, 512),
            )
        elif roll < 0.88:
            flow = (
                "internal_ssh",
                _address(rng, INTERNAL_NETWORK),
                _address(rng, INTERNAL_NETWORK),
                _ephemeral_port(rng),
                22,
                NetworkProtocol.TCP,
                rng.randrange(2_000, 80_000),
                rng.randrange(2_000, 80_000),
            )
        elif roll < 0.95:
            flow = (
                "port_scan",
                rng.choice(_ATTACKERS),
                MONITORED_HOST,
                _ephemeral_port(rng),
                rng.randrange(1, 1_025),
                NetworkProtocol.TCP,
                60,
                0,
            )
        else:
            flow = (
                "large_outbound_transfer",
                _address(rng, INTERNAL_NETWORK),
                _address(rng, DOCUMENTATION_NETWORKS[0]),
                _ephemeral_port(rng),
                443,
                NetworkProtocol.TCP,
                rng.randrange(50_000_000, 500_000_000),
                rng.randrange(1_000, 20_000),
            )
        scenario, source, destination, src_port, dst_port, protocol, sent, received = flow
        identity = self._context.identity
        return NetworkFlowEvent(
            event_type="network.flow",
            timestamp=datetime.now(UTC),
            source_type=SIMULATOR_SOURCE_TYPE,
            source_name=self._context.source_name(self.name),
            host_id=identity.host_id,
            agent_id=self._context.agent_id,
            src_ip=source,
            dst_ip=destination,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            bytes_sent=sent,
            bytes_received=received,
            metadata=_metadata(scenario, duration_ms=rng.randrange(1, 120_000)),
        )
