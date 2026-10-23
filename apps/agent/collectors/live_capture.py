"""Live packet capture on one interface → bidirectional flows → ``network.flow`` events.

Capture needs a libpcap provider (Npcap on Windows, libpcap on Linux), installed by the
operator; the agent never installs drivers or asks for elevation. Safeguards:

- **Explicit authorization.** Only the interface named in ``AGENT_LIVE_CAPTURE_INTERFACE``
  (name, ``#index`` or description, matched exactly) is used, and only with
  ``AGENT_LIVE_CAPTURE_AUTHORIZED=true``.
- **Own traffic by default.** Promiscuous mode is off and a capture filter inside the
  driver keeps only packets to or from the interface's own addresses (checked again in
  Python). Promiscuous mode requires ``AGENT_FLOW_ALLOWED_NETWORKS``, which then limits the
  capture to those lab networks.
- **Headers only.** Only ``snaplen`` bytes per packet are captured, Scapy decodes only
  link/IP/TCP/UDP headers, payloads are never parsed or stored, MAC addresses are not kept.
- **Passive.** Nothing is sent on the captured network. The agent's own traffic to the
  ingestion API and Kafka is excluded.
"""

import asyncio
import functools
import ipaddress
import logging
import queue
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlsplit

from pydantic import JsonValue

from apps.agent.collectors.base import CollectorContext, EventSink
from apps.agent.collectors.flows import Flow, FlowAggregator, Network, flow_event, flow_in_networks
from apps.agent.collectors.packets import (
    NON_IP,
    PacketMeta,
    header_only_dissection,
    packet_metadata,
    scapy_namespace,
)
from packages.events.canonical import AnyCanonicalEvent

if TYPE_CHECKING:
    from scapy.interfaces import NetworkInterface

logger = logging.getLogger(__name__)

SOURCE_TYPE: Final = "live_capture"
LOOPBACK_ADDRESSES: Final = frozenset({"127.0.0.1", "::1"})
KAFKA_PORT: Final = 9092
TICK_SECONDS: Final = 1.0
QUEUE_SIZE: Final = 10_000
BATCH_EVENTS: Final = 200
CAPTURE_UNAVAILABLE: Final = (
    "live capture needs a libpcap provider (Npcap on Windows from https://npcap.com, libpcap "
    "on Linux), installed by an administrator; the agent never installs capture drivers"
)


class CaptureUnavailableError(Exception):
    """Capture cannot start: no libpcap provider, no permission, bad filter or interface."""


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    """A network interface of this computer."""

    index: int
    name: str
    description: str
    addresses: tuple[str, ...]


@dataclass(slots=True)
class CaptureStats:
    """Live capture counters."""

    captured: int = 0
    ip_packets: int = 0
    non_ip: int = 0
    malformed: int = 0
    not_local: int = 0
    queue_drops: int = 0


def _plain_address(address: str) -> str | None:
    try:
        return str(ipaddress.ip_address(address.split("%", 1)[0]))
    except ValueError:
        return None


def list_interfaces() -> list[InterfaceInfo]:
    """This computer's interfaces as Scapy sees them."""
    scapy_namespace()
    import scapy.arch  # noqa: F401 - loads the platform's interface provider
    from scapy.config import conf

    interfaces = []
    for iface in conf.ifaces.values():
        ips = getattr(iface, "ips", {}) or {}
        addresses = [_plain_address(a) for a in [*ips.get(4, []), *ips.get(6, [])]]
        interfaces.append(
            InterfaceInfo(
                index=int(iface.index),
                name=str(iface.name),
                description=str(iface.description),
                addresses=tuple(dict.fromkeys(a for a in addresses if a)),
            )
        )
    return sorted(interfaces, key=lambda info: info.index)


def resolve_interface(selector: str, interfaces: Sequence[InterfaceInfo]) -> InterfaceInfo:
    """The interface named exactly (case-insensitive) by name, ``#index`` or description.

    Raises:
        CaptureUnavailableError: If nothing or several interfaces match.
    """
    wanted = selector.strip().lstrip("#").lower()
    for attribute in ("name", "index", "description"):
        matches = [i for i in interfaces if str(getattr(i, attribute)).lower() == wanted]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise CaptureUnavailableError(f"'{selector}' matches several interfaces")
    raise CaptureUnavailableError(f"no interface is called '{selector}'")


def capture_available() -> bool:
    """Whether a libpcap provider is usable.

    On Windows Scapy uses Npcap whenever it is installed. On Linux it defaults to its own
    raw sockets, so it is switched to libpcap here when the library is present.
    """
    scapy_namespace()
    import scapy.arch  # noqa: F401
    from scapy.config import conf

    if not conf.use_pcap:
        try:
            conf.use_pcap = True
        except Exception:  # a missing provider may raise as well as refuse
            return False
    if not conf.use_pcap:
        return False
    try:
        from scapy.arch.libpcap import L2pcapListenSocket  # noqa: F401
    except ImportError:
        return False
    return True


def build_capture_filter(
    *,
    local_addresses: Iterable[str] = (),
    networks: Sequence[Network] = (),
    exclude_endpoints: Iterable[tuple[str, int]] = (),
    exclude_tcp_ports: Iterable[int] = (),
    extra: str = "",
) -> str:
    """The BPF capture filter applied inside the driver."""
    parts = ["(ip or ip6)"]
    hosts = sorted(set(local_addresses))
    if hosts:
        parts.append("(" + " or ".join(f"host {address}" for address in hosts) + ")")
    if networks:
        parts.append("(" + " or ".join(f"net {network}" for network in networks) + ")")
    for host, port in sorted(set(exclude_endpoints)):
        parts.append(f"not (tcp port {port} and host {host})")
    for port in sorted(set(exclude_tcp_ports)):
        parts.append(f"not tcp port {port}")
    if extra.strip():
        parts.append(f"({extra.strip()})")
    return " and ".join(parts)


def server_endpoint(server_url: str) -> tuple[str, int] | None:
    """The ingestion API's address and port, to keep the agent's own traffic out."""
    parts = urlsplit(server_url)
    host = parts.hostname
    if host is None:
        return None
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        return str(ipaddress.ip_address(host)), port
    except ValueError:
        return None


class ScapyLiveSource:
    """Captures on one interface in a background thread and queues packet metadata."""

    def __init__(
        self,
        interface: InterfaceInfo,
        *,
        promiscuous: bool,
        snaplen: int,
        capture_filter: str,
        local_addresses: frozenset[str] | None,
    ) -> None:
        self.interface = interface
        self.promiscuous = promiscuous
        self.snaplen = snaplen
        self.capture_filter = capture_filter
        self.stats = CaptureStats()
        self._local = local_addresses
        self._queue: queue.Queue[PacketMeta] = queue.Queue(maxsize=QUEUE_SIZE)
        self._sniffer: Any = None
        self._dissection: Any = None

    def start(self) -> None:
        """Open the interface and start the capture thread.

        Raises:
            CaptureUnavailableError: If the interface cannot be opened.
        """
        if not capture_available():
            raise CaptureUnavailableError(CAPTURE_UNAVAILABLE)
        from scapy.config import conf
        from scapy.sendrecv import AsyncSniffer

        self._dissection = header_only_dissection()
        self._dissection.__enter__()
        try:
            iface = conf.ifaces.dev_from_index(self.interface.index)
            socket = _open_socket(iface, self.promiscuous, self.snaplen, self.capture_filter)
        except Exception as error:
            self._dissection.__exit__(None, None, None)
            self._dissection = None
            raise CaptureUnavailableError(
                f"cannot open '{self.interface.name}': {error}"
            ) from error
        self._sniffer = AsyncSniffer(opened_socket=socket, prn=self.handle_packet, store=False)
        self._sniffer.start()

    def handle_packet(self, packet: object) -> None:
        """Called by the capture thread for every frame: keep header metadata only."""
        self.stats.captured += 1
        meta = packet_metadata(packet)
        if meta == NON_IP:
            self.stats.non_ip += 1
            return
        if not isinstance(meta, PacketMeta):
            self.stats.malformed += 1
            return
        if self._local is not None and not (
            _normalize(meta.src_ip) in self._local or _normalize(meta.dst_ip) in self._local
        ):
            self.stats.not_local += 1
            return
        try:
            self._queue.put_nowait(meta)
        except queue.Full:
            self.stats.queue_drops += 1
            return
        self.stats.ip_packets += 1

    def drain(self) -> list[PacketMeta]:
        """Every queued packet."""
        drained: list[PacketMeta] = []
        while True:
            try:
                drained.append(self._queue.get_nowait())
            except queue.Empty:
                return drained

    def stop(self) -> None:
        """Stop the capture thread and close the interface."""
        if self._sniffer is not None and getattr(self._sniffer, "running", False):
            try:
                self._sniffer.stop()
            except Exception:
                logger.debug("ignoring an error while stopping the sniffer", exc_info=True)
        if self._dissection is not None:
            self._dissection.__exit__(None, None, None)
            self._dissection = None


def _normalize(address: str) -> str:
    return _plain_address(address) or address


def _open_socket(
    iface: "NetworkInterface | str", promiscuous: bool, snaplen: int, bpf: str
) -> object:
    """A capture socket limited to ``snaplen`` bytes; Scapy's own one if that fails."""
    from scapy.arch.libpcap import L2pcapListenSocket

    try:
        return _header_only_socket_class()(iface, promiscuous, bpf, snaplen)
    except (TypeError, AttributeError, ImportError) as error:
        logger.warning(
            "could not limit the capture size; whole packets are captured, payloads are "
            "still never parsed or stored",
            extra={"action": "agent_live_capture_snaplen_fallback", "reason": str(error)},
        )
        return L2pcapListenSocket(iface=iface, promisc=promiscuous, filter=bpf)


@functools.cache
def _header_only_socket_class() -> Any:  # noqa: ANN401 - a Scapy socket class
    """Scapy's libpcap listen socket opened with ``snaplen``, keeping the wire length.

    Scapy's own socket captures 65535 bytes and drops the original length; this subclass
    opens the adapter with ``snaplen`` and records the length from the pcap header, so flow
    byte counts stay correct.
    """
    from scapy.arch.libpcap import L2pcapListenSocket, _L2libpcapSocket, open_pcap
    from scapy.data import MTU

    class HeaderOnlyListenSocket(L2pcapListenSocket):
        def __init__(
            self, iface: "NetworkInterface | str", promisc: bool, bpf: str, snaplen: int
        ) -> None:
            self.type = 0x0003
            self.outs = None
            self.iface = iface
            self.promisc = promisc
            self.monitor = None
            self.last_wire_length: int | None = None
            fd = open_pcap(device=iface, snaplen=snaplen, promisc=promisc, to_ms=100, monitor=None)
            _L2libpcapSocket.__init__(self, fd)
            if bpf:
                self.pcap_fd.setfilter(bpf)

        def recv_raw(self, x: int = MTU) -> Any:  # noqa: ANN401 - Scapy's signature
            cls, data, ts = super().recv_raw(x)
            self.last_wire_length = int(self.pcap_fd.header.contents.len) if data else None
            return cls, data, ts

        def recv(self, x: int = MTU, **kwargs: object) -> Any:  # noqa: ANN401
            packet = super().recv(x, **kwargs)
            if packet is not None and self.last_wire_length:
                packet.wirelen = self.last_wire_length
            return packet

    return HeaderOnlyListenSocket


class LiveCaptureCollector:
    """Captures on the configured interface and spools flows as they end."""

    name = "live_capture"

    def __init__(
        self,
        context: CollectorContext,
        *,
        interface: str,
        promiscuous: bool,
        snaplen: int,
        extra_filter: str,
        networks: Sequence[Network],
        server_url: str,
        idle_timeout: float,
        active_timeout: float,
        max_flows: int,
    ) -> None:
        self._context = context
        self._selector = interface
        self._promiscuous = promiscuous
        self._snaplen = snaplen
        self._extra_filter = extra_filter
        self._networks = list(networks)
        self._server = server_endpoint(server_url)
        self._idle_timeout = idle_timeout
        self._active_timeout = active_timeout
        self._max_flows = max_flows

    def source(self) -> ScapyLiveSource:
        """The capture source for the configured interface (not yet started)."""
        info = resolve_interface(self._selector, list_interfaces())
        local = frozenset(_normalize(a) for a in info.addresses) | LOOPBACK_ADDRESSES
        capture_filter = build_capture_filter(
            local_addresses=() if self._promiscuous else local,
            networks=self._networks if self._promiscuous else (),
            exclude_endpoints=[self._server] if self._server else [],
            exclude_tcp_ports=[KAFKA_PORT],
            extra=self._extra_filter,
        )
        return ScapyLiveSource(
            info,
            promiscuous=self._promiscuous,
            snaplen=self._snaplen,
            capture_filter=capture_filter,
            local_addresses=None if self._promiscuous else local,
        )

    async def run(self, sink: EventSink) -> None:
        """Capture until cancelled; on stop, the open flows are ended and spooled."""
        try:
            source = await asyncio.to_thread(self.source)
            await asyncio.to_thread(source.start)
        except CaptureUnavailableError as unavailable:
            logger.error(
                "live capture not possible; the collector stays off",
                extra={"action": "agent_live_capture_unavailable", "reason": str(unavailable)},
            )
            return
        logger.info(
            "live capture started",
            extra={
                "action": "agent_live_capture_started",
                "interface": source.interface.name,
                "promiscuous": source.promiscuous,
                "snaplen": source.snaplen,
                "filter": source.capture_filter,
            },
        )
        await self.capture(source, sink)

    async def capture(self, source: ScapyLiveSource, sink: EventSink) -> None:
        """Aggregate ``source``'s packets until cancelled."""
        aggregator = FlowAggregator(
            idle_timeout=self._idle_timeout,
            active_timeout=self._active_timeout,
            max_flows=self._max_flows,
        )
        capture: dict[str, JsonValue] = {
            "capture_mode": "live_interface",
            "capture_interface": source.interface.name,
            "promiscuous": source.promiscuous,
            "snaplen": source.snaplen,
        }
        try:
            while True:
                ended: list[Flow] = []
                for packet in source.drain():
                    ended.extend(aggregator.add(packet))
                ended.extend(aggregator.advance(time.time_ns()))
                await self._submit(ended, capture, sink)
                await asyncio.sleep(TICK_SECONDS)
        finally:
            source.stop()
            remaining = [*self._ended(source, aggregator), *aggregator.flush("capture_stopped")]
            try:
                await self._submit(remaining, capture, sink)
            except asyncio.CancelledError:
                logger.warning(
                    "open flows were not spooled at shutdown",
                    extra={"action": "agent_live_capture_lost_flows", "flows": len(remaining)},
                )
            logger.info(
                "live capture stopped",
                extra={
                    "action": "agent_live_capture_stopped",
                    "captured": source.stats.captured,
                    "ip_packets": source.stats.ip_packets,
                    "not_local": source.stats.not_local,
                    "queue_drops": source.stats.queue_drops,
                },
            )

    @staticmethod
    def _ended(source: ScapyLiveSource, aggregator: FlowAggregator) -> list[Flow]:
        ended: list[Flow] = []
        for packet in source.drain():
            ended.extend(aggregator.add(packet))
        return ended

    async def _submit(
        self, flows: list[Flow], capture: dict[str, JsonValue], sink: EventSink
    ) -> None:
        events: list[AnyCanonicalEvent] = [
            flow_event(
                flow,
                self._context,
                collector=self.name,
                source_type=SOURCE_TYPE,
                capture=capture,
                idle_timeout=self._idle_timeout,
                active_timeout=self._active_timeout,
            )
            for flow in flows
            if not self._networks or flow_in_networks(flow, self._networks)
        ]
        for start in range(0, len(events), BATCH_EVENTS):
            await sink.submit(events[start : start + BATCH_EVENTS])
