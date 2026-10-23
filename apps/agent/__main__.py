"""Command-line interface of the endpoint agent: ``python -m apps.agent <command>``.

Commands:

- ``run``: collect per configuration and send to the ingestion API.
- ``simulate``: like ``run`` with the synthetic collectors enabled (development only).
- ``status``: identity, queue, quarantine and registration state, as JSON.
- ``interfaces``: the network interfaces live capture can use, as JSON.
- ``generate``: print synthetic canonical events without a server (development only).
"""

import argparse
import asyncio
import contextlib
import json
import logging
import random
import signal
import sys
from collections.abc import Sequence
from uuid import uuid4

from apps.agent.agent import SPOOL_FILE, Agent
from apps.agent.collectors import AuthEventSimulator, CollectorContext, NetworkFlowSimulator
from apps.agent.identity import (
    AgentIdentity,
    IdentityError,
    build_identity,
    load_or_create_agent_id,
)
from apps.agent.registration import CHECKPOINT, RegistrationError
from apps.agent.settings import AgentServiceSettings
from apps.agent.spool import Spool
from apps.agent.spool_crypto import spool_cipher
from packages.config import AppSettings, ConfigurationError, load_settings
from packages.events.canonical import serialize_canonical_event
from packages.observability import configure_logging

logger = logging.getLogger("adis.agent")

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_CONFIGURATION = 2


def main(argv: Sequence[str] | None = None) -> int:
    """Parse ``argv`` and run the command; returns the process exit code."""
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "generate":
            return _generate(arguments)
        if arguments.command == "interfaces":
            return _interfaces()
        settings = load_settings(AgentServiceSettings)
        if arguments.command == "status":
            return _status(settings)
        if arguments.command == "simulate":
            if not settings.app_env.allows_development_defaults:
                raise SystemExit("simulate is only available when APP_ENV is development or test")
            settings = settings.model_copy(
                update={
                    "agent_simulate_auth_per_minute": arguments.auth_per_minute,
                    "agent_simulate_flows_per_minute": arguments.flows_per_minute,
                }
            )
        configure_logging(settings)
        asyncio.run(_serve(settings, duration=getattr(arguments, "duration", None)))
    except (ConfigurationError, IdentityError) as error:
        logging.basicConfig(level=logging.ERROR, format="%(message)s")
        logger.error("%s", error)
        return EXIT_CONFIGURATION
    except RegistrationError as error:
        logger.error("%s", error)
        return EXIT_FAILURE
    return EXIT_OK


async def _serve(settings: AgentServiceSettings, *, duration: float | None) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # Not supported on Windows; Ctrl+C then cancels the run, which still cleans up.
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)
    if duration is not None:
        loop.call_later(duration, stop.set)
    async with Agent.from_settings(settings) as agent:
        await agent.run(stop)


def _status(settings: AgentServiceSettings) -> int:
    identity = build_identity(settings, load_or_create_agent_id(settings.agent_data_dir))

    async def collect() -> dict[str, object]:
        with Spool.open(
            settings.agent_data_dir / SPOOL_FILE,
            max_events=settings.agent_max_queue_events,
            cipher=spool_cipher(
                settings.agent_data_dir,
                enabled=settings.agent_spool_encryption,
                supplied_key=settings.agent_spool_key,
            ),
        ) as spool:
            stats = await spool.stats()
            registration = await spool.checkpoint(CHECKPOINT)
            recent = await spool.quarantined(5)
        return {
            "agent_id": str(identity.agent_id),
            "name": identity.name,
            "host_id": identity.host_id,
            "os_type": identity.os_type,
            "agent_version": identity.agent_version,
            "server_url": str(settings.agent_server_url),
            "queued": stats.queued,
            "capacity": stats.capacity,
            "quarantined": stats.quarantined,
            "quarantine_evicted": stats.quarantine_evicted,
            "spool_encryption": spool.encryption,
            "recent_quarantine": [{"event_id": e, "reason": r} for e, r in recent],
            "registration": json.loads(registration) if registration else None,
        }

    sys.stdout.write(json.dumps(asyncio.run(collect()), indent=2) + "\n")
    return EXIT_OK


def _interfaces() -> int:
    from apps.agent.collectors.live_capture import capture_available, list_interfaces

    report = {
        "capture_available": capture_available(),
        "interfaces": [
            {
                "index": info.index,
                "name": info.name,
                "description": info.description,
                "addresses": list(info.addresses),
            }
            for info in list_interfaces()
        ],
    }
    sys.stdout.write(json.dumps(report, indent=2) + "\n")
    return EXIT_OK


def _generate(arguments: argparse.Namespace) -> int:
    app = load_settings(AppSettings)
    if not app.app_env.allows_development_defaults:
        raise SystemExit("generate is only available when APP_ENV is development or test")
    identity = AgentIdentity(
        agent_id=uuid4(),
        name="adis-agent-dev",
        hostname="dev-host",
        host_id="dev-host",
        os_type="other",
        agent_version="dev",
    )
    context = CollectorContext(identity)
    rng = random.Random(arguments.seed)  # noqa: S311 - synthetic data, not security
    simulator_type = AuthEventSimulator if arguments.kind == "auth" else NetworkFlowSimulator
    events = simulator_type(context, per_minute=1, rng=rng).generate(arguments.count)
    payloads = [serialize_canonical_event(event).decode() for event in events]
    if arguments.batch:
        sys.stdout.write('{"events":[' + ",".join(payloads) + "]}\n")
    else:
        sys.stdout.write("".join(f"{payload}\n" for payload in payloads))
    return EXIT_OK


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m apps.agent", description=__doc__.split("\n")[0]
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="collect per configuration and send events")
    run.add_argument("--duration", type=float, default=None, help="stop after N seconds")
    simulate = commands.add_parser("simulate", help="run with synthetic collectors (dev only)")
    simulate.add_argument("--auth-per-minute", type=_non_negative, default=120)
    simulate.add_argument("--flows-per-minute", type=_non_negative, default=300)
    simulate.add_argument("--duration", type=float, default=None, help="stop after N seconds")
    commands.add_parser("status", help="print identity, queue and registration state")
    commands.add_parser("interfaces", help="list interfaces live capture can use")
    generate = commands.add_parser("generate", help="print synthetic events (dev only)")
    generate.add_argument("kind", choices=("auth", "flows"))
    generate.add_argument("--count", type=_positive, default=10)
    generate.add_argument("--seed", type=int, default=None)
    generate.add_argument("--batch", action="store_true", help='emit one {"events": [...]} body')
    return parser


def _non_negative(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return number


def _positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


if __name__ == "__main__":
    sys.exit(main())
