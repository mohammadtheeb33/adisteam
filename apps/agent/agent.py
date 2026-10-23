"""Agent runtime: collectors feed the spool, the batcher drains it to the server."""

import asyncio
import logging
from collections.abc import Mapping, Sequence
from datetime import timedelta
from importlib.metadata import version
from pathlib import Path
from types import TracebackType
from typing import Final, Self

import httpx2

from apps.agent.backoff import Backoff
from apps.agent.batcher import Batcher
from apps.agent.client import IngestApiClient
from apps.agent.collectors import (
    AuthenticationMapper,
    AuthEventSimulator,
    Collector,
    CollectorContext,
    EventLogCollector,
    GoFlow2ProcessCollector,
    LiveCaptureCollector,
    LogFileCollector,
    NetflowRecordsFileCollector,
    NetworkFlowSimulator,
    PcapFileCollector,
    SyscallFileCollector,
    SyslogMapper,
    SyslogReceiver,
    SystemEventMapper,
    SystemLogRules,
    WindowsEventLogReader,
    parse_audit_line,
    parse_ebpf_line,
)
from apps.agent.identity import AgentIdentity, build_identity, load_or_create_agent_id
from apps.agent.registration import register
from apps.agent.settings import AgentServiceSettings
from apps.agent.spool import Spool, SpoolFullError
from apps.agent.spool_crypto import spool_cipher
from packages.config import comma_list, parse_exporters, parse_listen_address, parse_networks
from packages.events.canonical import AnyCanonicalEvent, serialize_canonical_event
from packages.observability import log_context

logger = logging.getLogger(__name__)

SPOOL_FILE: Final = "spool.sqlite3"
_COLLECTOR_RESTART_SECONDS: Final = 5.0


class SpoolSink:
    """The collectors' :class:`~apps.agent.collectors.EventSink`, with backpressure.

    While the spool is full, ``submit`` waits and retries; nothing is dropped. The
    batcher is woken when a full batch is waiting.
    """

    def __init__(
        self, spool: Spool, *, batch_size: int, retry_seconds: float, wake: asyncio.Event
    ) -> None:
        self._spool = spool
        self._batch_size = batch_size
        self._retry_seconds = retry_seconds
        self._wake = wake

    async def submit(
        self, events: Sequence[AnyCanonicalEvent], *, checkpoints: Mapping[str, str] | None = None
    ) -> None:
        """Spool ``events``; ``checkpoints`` are committed with the last chunk."""
        records = [(str(event.event_id), serialize_canonical_event(event)) for event in events]
        size = max(1, min(len(records), self._spool.capacity))
        chunks = [records[start : start + size] for start in range(0, len(records), size)] or [[]]
        for position, chunk in enumerate(chunks):
            last = position == len(chunks) - 1
            await self._append(chunk, checkpoints if last else None)
        if (await self._spool.stats()).queued >= self._batch_size:
            self._wake.set()

    async def checkpoint(self, key: str) -> str | None:
        """A stored checkpoint."""
        return await self._spool.checkpoint(key)

    async def _append(
        self, records: Sequence[tuple[str, bytes]], checkpoints: Mapping[str, str] | None
    ) -> None:
        paused = False
        while True:
            try:
                await self._spool.append(records, checkpoints)
            except SpoolFullError as full:
                if not paused:
                    paused = True
                    logger.warning(
                        "local spool full; collection paused until events are delivered",
                        extra={"action": "agent_spool_full", "queued": full.queued},
                    )
                self._wake.set()
                await asyncio.sleep(self._retry_seconds)
            else:
                if paused:
                    logger.info("collection resumed", extra={"action": "agent_spool_resumed"})
                return


class Agent:
    """Registers, runs collectors under supervision and sends their events."""

    def __init__(
        self,
        *,
        identity: AgentIdentity,
        spool: Spool,
        client: IngestApiClient,
        collectors: Sequence[Collector],
        batcher: Batcher,
        sink: SpoolSink,
        registration_backoff: Backoff,
        shutdown_flush_seconds: float,
    ) -> None:
        self.identity = identity
        self.spool = spool
        self._client = client
        self._collectors = list(collectors)
        self._batcher = batcher
        self._sink = sink
        self._registration_backoff = registration_backoff
        self._shutdown_flush_seconds = shutdown_flush_seconds

    @classmethod
    def from_settings(
        cls,
        settings: AgentServiceSettings,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> Self:
        """Assemble the agent: identity, spool, client, collectors and batcher."""
        identity = build_identity(settings, load_or_create_agent_id(settings.agent_data_dir))
        spool = Spool.open(
            settings.agent_data_dir / SPOOL_FILE,
            max_events=settings.agent_max_queue_events,
            cipher=spool_cipher(
                settings.agent_data_dir,
                enabled=settings.agent_spool_encryption,
                supplied_key=settings.agent_spool_key,
            ),
        )
        client = IngestApiClient(
            str(settings.agent_server_url),
            settings.agent_token,
            timeout_seconds=settings.agent_http_timeout_seconds,
            user_agent=f"adis-agent/{version('adis')}",
            transport=transport,
        )

        def backoff() -> Backoff:
            return Backoff(
                initial_seconds=settings.agent_retry_initial_backoff_seconds,
                max_seconds=settings.agent_retry_max_backoff_seconds,
            )

        batcher = Batcher(
            spool,
            client,
            batch_size=settings.agent_batch_size,
            flush_interval_seconds=settings.agent_flush_interval_seconds,
            backoff=backoff(),
        )
        sink = SpoolSink(
            spool,
            batch_size=settings.agent_batch_size,
            retry_seconds=settings.agent_flush_interval_seconds,
            wake=batcher.wake,
        )
        return cls(
            identity=identity,
            spool=spool,
            client=client,
            collectors=build_collectors(settings, CollectorContext(identity)),
            batcher=batcher,
            sink=sink,
            registration_backoff=backoff(),
            shutdown_flush_seconds=settings.agent_http_timeout_seconds,
        )

    async def run(self, stop: asyncio.Event) -> None:
        """Run until ``stop`` is set. Unsent events stay spooled for the next start."""
        # Tasks copy the context when created, so every log line of the run carries host_id.
        with log_context(host_id=self.identity.host_id):
            await self._run(stop)

    async def _run(self, stop: asyncio.Event) -> None:
        collectors = [asyncio.create_task(self._supervise(c)) for c in self._collectors]
        logger.info(
            "agent started",
            extra={
                "action": "agent_started",
                "agent_id": str(self.identity.agent_id),
                "collectors": [collector.name for collector in self._collectors],
            },
        )
        registered = False
        try:
            registered = await register(
                self._client,
                self.identity,
                self.spool,
                backoff=self._registration_backoff,
                stop=stop,
            )
            if registered:
                await self._batcher.run(stop)
        finally:
            for task in collectors:
                task.cancel()
            await asyncio.gather(*collectors, return_exceptions=True)
            if registered:
                await self._final_flush()
            stats = await self.spool.stats()
            logger.info(
                "agent stopped",
                extra={
                    "action": "agent_stopped",
                    "queued": stats.queued,
                    "quarantined": stats.quarantined,
                },
            )

    async def close(self) -> None:
        """Release the HTTP client and the spool."""
        await self._client.close()
        self.spool.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()

    async def _supervise(self, collector: Collector) -> None:
        """Run a collector, restarting it after unexpected errors."""
        while True:
            try:
                await collector.run(self._sink)
                return
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "collector failed; restarting",
                    extra={"action": "agent_collector_failed", "collector": collector.name},
                )
                await asyncio.sleep(_COLLECTOR_RESTART_SECONDS)

    async def _final_flush(self) -> None:
        try:
            async with asyncio.timeout(self._shutdown_flush_seconds):
                await self._batcher.flush()
        except TimeoutError:
            logger.warning(
                "final flush timed out; remaining events stay spooled",
                extra={"action": "agent_final_flush_timeout"},
            )


def build_collectors(settings: AgentServiceSettings, context: CollectorContext) -> list[Collector]:
    """The collectors enabled by ``settings``."""
    collectors: list[Collector] = []
    paths = settings.log_file_paths()
    if paths:
        collectors.append(
            LogFileCollector(
                paths,
                context,
                poll_interval_seconds=settings.agent_log_poll_interval_seconds,
                read_from_start=settings.agent_log_read_from_start,
            )
        )
    if settings.agent_simulate_auth_per_minute:
        collectors.append(
            AuthEventSimulator(context, per_minute=settings.agent_simulate_auth_per_minute)
        )
    if settings.agent_simulate_flows_per_minute:
        collectors.append(
            NetworkFlowSimulator(context, per_minute=settings.agent_simulate_flows_per_minute)
        )
    collectors.extend(_windows_collectors(settings, context))
    collectors.extend(_network_collectors(settings, context))
    collectors.extend(_syslog_and_syscall_collectors(settings, context))
    return collectors


def _windows_collectors(
    settings: AgentServiceSettings, context: CollectorContext
) -> list[Collector]:
    collectors: list[Collector] = []
    channels = settings.windows_eventlog_channels()
    if channels:
        rules = SystemLogRules(
            channels=channels,
            levels=frozenset(
                level.lower() for level in comma_list(settings.agent_windows_eventlog_levels)
            ),
            extra_event_ids=settings.int_set(settings.agent_windows_eventlog_extra_event_ids),
            exclude_event_ids=settings.int_set(settings.agent_windows_eventlog_exclude_event_ids),
            include_message=settings.agent_windows_eventlog_include_message,
        )
        collectors.append(
            EventLogCollector(
                "windows_eventlog",
                WindowsEventLogReader(
                    include_message=settings.agent_windows_eventlog_include_message
                ),
                SystemEventMapper(rules, context),
                poll_interval_seconds=settings.agent_windows_eventlog_poll_interval_seconds,
                backfill_minutes=settings.agent_windows_eventlog_backfill_minutes,
            )
        )
    if settings.agent_windows_security_enabled:
        mapper = AuthenticationMapper(
            context,
            exclude_logon_types=settings.int_set(
                settings.agent_windows_security_exclude_logon_types
            ),
            session_logon_types=settings.int_set(settings.agent_session_logon_types),
            failure_window=timedelta(seconds=settings.agent_session_failure_window_seconds),
            max_open_sessions=settings.agent_session_max_open,
        )
        collectors.append(
            EventLogCollector(
                "windows_security",
                WindowsEventLogReader(),
                mapper,
                poll_interval_seconds=settings.agent_windows_eventlog_poll_interval_seconds,
                backfill_minutes=settings.agent_windows_eventlog_backfill_minutes,
            )
        )
    return collectors


def _network_collectors(
    settings: AgentServiceSettings, context: CollectorContext
) -> list[Collector]:
    collectors: list[Collector] = []
    networks = parse_networks(settings.agent_flow_allowed_networks)
    paths = settings.pcap_file_paths()
    if paths:
        collectors.append(
            PcapFileCollector(
                paths,
                context,
                idle_timeout=settings.agent_flow_idle_timeout_seconds,
                active_timeout=settings.agent_flow_active_timeout_seconds,
                max_flows=settings.agent_flow_max_active,
                networks=networks,
            )
        )
    if settings.agent_live_capture_interface.strip():
        collectors.append(
            LiveCaptureCollector(
                context,
                interface=settings.agent_live_capture_interface,
                promiscuous=settings.agent_live_capture_promiscuous,
                snaplen=settings.agent_live_capture_snaplen,
                extra_filter=settings.agent_live_capture_filter,
                networks=networks,
                server_url=str(settings.agent_server_url),
                idle_timeout=settings.agent_flow_idle_timeout_seconds,
                active_timeout=settings.agent_flow_active_timeout_seconds,
                max_flows=settings.agent_flow_max_active,
            )
        )
    exporters = parse_exporters(settings.agent_netflow_exporters)
    if settings.agent_netflow_goflow2_path:
        collectors.append(
            GoFlow2ProcessCollector(
                Path(settings.agent_netflow_goflow2_path),
                Path(settings.agent_netflow_mapping_file),
                parse_listen_address(settings.agent_netflow_listen),
                exporters,
                context,
            )
        )
    if settings.agent_netflow_records_file:
        collectors.append(
            NetflowRecordsFileCollector(
                Path(settings.agent_netflow_records_file), exporters, context
            )
        )
    return collectors


def _syslog_and_syscall_collectors(
    settings: AgentServiceSettings, context: CollectorContext
) -> list[Collector]:
    collectors: list[Collector] = []
    udp, tcp = settings.agent_syslog_udp_listen, settings.agent_syslog_tcp_listen
    if udp.strip() or tcp.strip():
        mapper = SyslogMapper(
            context,
            max_message_bytes=settings.agent_syslog_max_message_bytes,
            failure_window=timedelta(seconds=settings.agent_session_failure_window_seconds),
            max_open_sessions=settings.agent_session_max_open,
        )
        collectors.append(
            SyslogReceiver(
                mapper,
                udp_listen=parse_listen_address(udp) if udp.strip() else None,
                tcp_listen=parse_listen_address(tcp) if tcp.strip() else None,
                allowed_senders=parse_networks(settings.agent_syslog_allowed_senders),
                max_message_bytes=settings.agent_syslog_max_message_bytes,
                max_pending_events=settings.agent_syslog_max_pending_events,
            )
        )
    for name, path, parse in (
        ("auditd", settings.agent_audit_log_file, parse_audit_line),
        ("ebpf", settings.agent_ebpf_events_file, parse_ebpf_line),
    ):
        if path.strip():
            collectors.append(
                SyscallFileCollector(
                    name,
                    Path(path),
                    parse,
                    context,
                    source_type=name,
                    window_seconds=settings.agent_syscall_window_seconds,
                    max_length=settings.agent_syscall_max_sequence,
                    read_from_start=settings.agent_syscall_read_from_start,
                )
            )
    return collectors
