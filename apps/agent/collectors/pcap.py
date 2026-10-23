"""Offline PCAP/PCAPNG files → bidirectional flows → ``network.flow`` events.

Each configured file is read once (packet headers only), its flows are spooled as they end
(bounded memory), and a checkpoint records the file's size and modification time. A file
that changes later is read again; a file read again yields the same event ids, so the
normalizer deduplicates the flows already delivered. Only process captures you own or are
authorized to analyze; nothing is captured or sent on the network.
"""

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Final

from apps.agent.collectors.base import CollectorContext, EventSink
from apps.agent.collectors.flows import Flow, FlowAggregator, Network, flow_event, flow_in_networks
from apps.agent.collectors.packets import CaptureFileError, ReadStats, read_packets
from packages.events.canonical import AnyCanonicalEvent

logger = logging.getLogger(__name__)

SOURCE_TYPE: Final = "pcap"
CHUNK_EVENTS: Final = 500
RECHECK_SECONDS: Final = 30.0

Sleep = Callable[[float], Awaitable[None]]


class PcapFileCollector:
    """Reads capture files and spools their flows."""

    name = "pcap"

    def __init__(
        self,
        paths: Sequence[Path],
        context: CollectorContext,
        *,
        idle_timeout: float,
        active_timeout: float,
        max_flows: int,
        networks: Sequence[Network] = (),
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._paths = [Path(path) for path in paths]
        self._keys = {path: f"pcap:{path.resolve()}" for path in self._paths}
        self._context = context
        self._idle_timeout = idle_timeout
        self._active_timeout = active_timeout
        self._max_flows = max_flows
        self._networks = list(networks)
        self._sleep = sleep

    async def run(self, sink: EventSink) -> None:
        """Process new or changed files, then re-check them periodically."""
        while True:
            await self.process_all(sink)
            await self._sleep(RECHECK_SECONDS)

    async def process_all(self, sink: EventSink) -> int:
        """Process every new or changed file once; returns the flows spooled."""
        spooled = 0
        for path in self._paths:
            spooled += await self._process_if_changed(path, sink)
        return spooled

    async def _process_if_changed(self, path: Path, sink: EventSink) -> int:
        try:
            status = await asyncio.to_thread(os.stat, path)
        except FileNotFoundError:
            return 0
        key = self._keys[path]
        marker = f"{status.st_size}:{status.st_mtime_ns}"
        if await sink.checkpoint(key) == marker:
            return 0
        loop = asyncio.get_running_loop()
        stats = ReadStats()
        try:
            spooled = await asyncio.to_thread(self._read_file, path, stats, sink, loop)
        except CaptureFileError as error:
            logger.warning(
                "not a readable capture file",
                extra={"action": "agent_pcap_unreadable", "file": path.name, "reason": str(error)},
            )
            await sink.submit([], checkpoints={key: marker})
            return 0
        await sink.submit([], checkpoints={key: marker})
        logger.info(
            "capture file processed",
            extra={
                "action": "agent_pcap_processed",
                "file": path.name,
                "capture_format": stats.capture_format,
                "packets": stats.packets,
                "ip_packets": stats.ip_packets,
                "non_ip": stats.non_ip,
                "malformed": stats.malformed,
                "flows": spooled,
                "damaged": stats.damaged,
            },
        )
        return spooled

    def _read_file(
        self, path: Path, stats: ReadStats, sink: EventSink, loop: asyncio.AbstractEventLoop
    ) -> int:
        """Runs in a worker thread; submissions wait on the loop (backpressure)."""
        aggregator = FlowAggregator(
            idle_timeout=self._idle_timeout,
            active_timeout=self._active_timeout,
            max_flows=self._max_flows,
        )
        pending: list[AnyCanonicalEvent] = []
        spooled = 0

        def emit(flows: list[Flow]) -> None:
            nonlocal spooled
            for flow in flows:
                if self._networks and not flow_in_networks(flow, self._networks):
                    continue
                pending.append(
                    flow_event(
                        flow,
                        self._context,
                        collector=self.name,
                        source_type=SOURCE_TYPE,
                        capture={
                            "capture_mode": "offline_file",
                            "capture_file": path.name,
                            "capture_format": stats.capture_format,
                        },
                        idle_timeout=self._idle_timeout,
                        active_timeout=self._active_timeout,
                    )
                )
            if len(pending) >= CHUNK_EVENTS:
                flush()

        def flush() -> None:
            nonlocal spooled
            if pending:
                asyncio.run_coroutine_threadsafe(sink.submit(list(pending)), loop).result()
                spooled += len(pending)
                pending.clear()

        for packet in read_packets(path, stats):
            emit(aggregator.add(packet))
        emit(aggregator.flush())
        flush()
        return spooled
