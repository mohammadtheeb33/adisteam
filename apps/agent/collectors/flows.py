"""Aggregate packets into bidirectional 5-tuple flows and map them to ``network.flow`` events.

A flow is every packet between the same two endpoints with the same protocol and ports,
in both directions. The endpoint that sent the first packet is the initiator (``src_*``);
``bytes_sent`` counts initiator → responder and ``bytes_received`` the reverse, which is
what the canonical ``NetworkFlowEvent`` carries. A flow ends when no packet arrived for
``idle_timeout`` (``idle_timeout``), when it has lasted ``active_timeout`` (later packets
start a new flow, ``active_timeout``), when the flow table is full (``flow_table_full``),
at the end of a capture file (``end_of_capture``) or when a live capture stops
(``capture_stopped``). Time is the packets' capture time.

The extracted features (duration, packets and bytes per direction, TCP flags and their
counts, fragments, end reason) travel in ``metadata`` — the "extracted features" format the
specification gives network flows.
"""

import ipaddress
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final
from uuid import UUID, uuid5

from pydantic import JsonValue

from apps.agent.collectors.base import CollectorContext
from apps.agent.collectors.packets import SCTP_PROTOCOL, TCP_PROTOCOL, UDP_PROTOCOL, PacketMeta
from packages.events.canonical import NetworkFlowEvent

FLOW_EVENT_TYPE: Final = "network.flow"
FLOW_ID_NAMESPACE: Final = UUID("4b6f2d9e-1c3a-4e8b-9f70-5d2a6c8e1b34")
TCP_FLAG_NAMES: Final = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")
TRANSPORT_NAMES: Final = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmpv6",
    132: "sctp",
}
PORT_PROTOCOLS: Final = frozenset({TCP_PROTOCOL, UDP_PROTOCOL, SCTP_PROTOCOL})

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Endpoints of a flow, initiator first."""

    ip_version: int
    src_ip: str
    dst_ip: str
    protocol: int
    src_port: int | None
    dst_port: int | None

    def reverse(self) -> "FlowKey":
        """The same flow seen from the responder."""
        return FlowKey(
            self.ip_version, self.dst_ip, self.src_ip, self.protocol, self.dst_port, self.src_port
        )


@dataclass(slots=True)
class Direction:
    """Counters of one direction of a flow."""

    packets: int = 0
    bytes: int = 0
    frame_bytes: int = 0
    tcp_flags: int = 0
    tcp_flag_counts: list[int] = field(default_factory=lambda: [0] * 8)

    def add(self, packet: PacketMeta) -> None:
        """Count one packet."""
        self.packets += 1
        self.bytes += packet.ip_length
        self.frame_bytes += packet.wire_length
        if packet.tcp_flags is not None:
            self.tcp_flags |= packet.tcp_flags
            for bit in range(8):
                if packet.tcp_flags & (1 << bit):
                    self.tcp_flag_counts[bit] += 1


@dataclass(slots=True)
class Flow:
    """One bidirectional flow."""

    key: FlowKey
    first_seen_ns: int
    last_seen_ns: int
    forward: Direction = field(default_factory=Direction)
    reverse: Direction = field(default_factory=Direction)
    fragments: int = 0
    end_reason: str | None = None

    @property
    def duration_ns(self) -> int:
        """Last packet time minus first packet time."""
        return self.last_seen_ns - self.first_seen_ns

    def add(self, packet: PacketMeta, *, forward: bool) -> None:
        """Count ``packet`` in its direction."""
        self.first_seen_ns = min(self.first_seen_ns, packet.timestamp_ns)
        self.last_seen_ns = max(self.last_seen_ns, packet.timestamp_ns)
        (self.forward if forward else self.reverse).add(packet)
        if packet.fragment:
            self.fragments += 1


def flow_key(packet: PacketMeta) -> FlowKey:
    """The key of ``packet`` seen as an initiator."""
    return FlowKey(
        packet.ip_version,
        packet.src_ip,
        packet.dst_ip,
        packet.protocol,
        packet.src_port,
        packet.dst_port,
    )


class FlowAggregator:
    """Keeps active flows (bounded) and returns each one when it ends."""

    def __init__(self, *, idle_timeout: float, active_timeout: float, max_flows: int) -> None:
        self._idle_ns = int(idle_timeout * 1_000_000_000)
        self._active_ns = int(active_timeout * 1_000_000_000)
        self._max_flows = max_flows
        self._flows: OrderedDict[FlowKey, Flow] = OrderedDict()
        self._now_ns = 0

    @property
    def active_flows(self) -> int:
        """Flows not yet ended."""
        return len(self._flows)

    def add(self, packet: PacketMeta) -> list[Flow]:
        """Account for ``packet``; returns the flows that ended because of it."""
        self._now_ns = max(self._now_ns, packet.timestamp_ns)
        ended = self._end_idle_flows()
        key = flow_key(packet)
        forward = True
        flow = self._flows.get(key)
        if flow is None:
            flow = self._flows.get(key.reverse())
            if flow is not None:
                key, forward = key.reverse(), False
        if flow is not None and packet.timestamp_ns - flow.first_seen_ns >= self._active_ns:
            flow.end_reason = "active_timeout"
            ended.append(self._flows.pop(key))
            flow = None
        if flow is None:
            if len(self._flows) >= self._max_flows:
                _, oldest = self._flows.popitem(last=False)
                oldest.end_reason = "flow_table_full"
                ended.append(oldest)
            flow = Flow(key, packet.timestamp_ns, packet.timestamp_ns)
            self._flows[key] = flow
        else:
            self._flows.move_to_end(key)
        flow.add(packet, forward=forward)
        return ended

    def advance(self, now_ns: int) -> list[Flow]:
        """Move the clock without a packet; returns flows that went idle."""
        self._now_ns = max(self._now_ns, now_ns)
        return self._end_idle_flows()

    def flush(self, reason: str = "end_of_capture") -> list[Flow]:
        """End every remaining flow, oldest first."""
        remaining = sorted(self._flows.values(), key=lambda flow: flow.first_seen_ns)
        for flow in remaining:
            flow.end_reason = reason
        self._flows.clear()
        return remaining

    def _end_idle_flows(self) -> list[Flow]:
        ended = []
        while self._flows:
            oldest = next(iter(self._flows.values()))
            if self._now_ns - oldest.last_seen_ns <= self._idle_ns:
                break
            oldest.end_reason = "idle_timeout"
            ended.append(self._flows.pop(oldest.key))
        return ended


def iso_utc(timestamp_ns: int) -> str:
    """Nanoseconds since the epoch as an ISO 8601 UTC string."""
    return utc_datetime(timestamp_ns).isoformat()


def utc_datetime(timestamp_ns: int) -> datetime:
    """Nanoseconds since the epoch as an aware UTC datetime (microsecond precision)."""
    seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, UTC).replace(microsecond=nanoseconds // 1_000)


def flow_in_networks(flow: Flow, networks: Sequence[Network]) -> bool:
    """Whether either endpoint of ``flow`` is in one of ``networks``."""
    addresses = (ipaddress.ip_address(flow.key.src_ip), ipaddress.ip_address(flow.key.dst_ip))
    return any(
        address.version == network.version and address in network
        for address in addresses
        for network in networks
    )


def _flags(direction: Direction) -> list[JsonValue]:
    return [name for bit, name in enumerate(TCP_FLAG_NAMES) if direction.tcp_flags & (1 << bit)]


def _flag_counts(direction: Direction) -> dict[str, JsonValue]:
    return {
        name: count
        for name, count in zip(TCP_FLAG_NAMES, direction.tcp_flag_counts, strict=True)
        if count
    }


def flow_event(
    flow: Flow,
    context: CollectorContext,
    *,
    collector: str,
    source_type: str,
    capture: dict[str, JsonValue],
    idle_timeout: float,
    active_timeout: float,
) -> NetworkFlowEvent:
    """The canonical ``network.flow`` event of ``flow``, with its features in metadata."""
    key = flow.key
    has_ports = (
        key.protocol in PORT_PROTOCOLS and key.src_port is not None and key.dst_port is not None
    )
    metadata: dict[str, JsonValue] = {
        "flow_source": "packet_capture",
        "flow_note": "Bidirectional flow built by the ADIS agent from captured packet headers; "
        "not a NetFlow/IPFIX exporter record.",
        **capture,
        "ip_version": key.ip_version,
        "protocol_number": key.protocol,
        "transport": TRANSPORT_NAMES.get(key.protocol, "other"),
        "first_seen": iso_utc(flow.first_seen_ns),
        "last_seen": iso_utc(flow.last_seen_ns),
        "duration_seconds": round(flow.duration_ns / 1_000_000_000, 6),
        "packets_sent": flow.forward.packets,
        "packets_received": flow.reverse.packets,
        "frame_bytes_sent": flow.forward.frame_bytes,
        "frame_bytes_received": flow.reverse.frame_bytes,
        "end_reason": flow.end_reason,
        "idle_timeout_seconds": idle_timeout,
        "active_timeout_seconds": active_timeout,
    }
    if flow.fragments:
        metadata["fragments"] = flow.fragments
    if not has_ports and key.protocol in PORT_PROTOCOLS:
        metadata["ports_unknown"] = True  # only later fragments were seen
    if key.protocol == TCP_PROTOCOL:
        metadata["tcp_flags_sent"] = _flags(flow.forward)
        metadata["tcp_flags_received"] = _flags(flow.reverse)
        metadata["tcp_flag_counts_sent"] = _flag_counts(flow.forward)
        metadata["tcp_flag_counts_received"] = _flag_counts(flow.reverse)
    identity = (
        f"flow|{context.identity.host_id}|{key.ip_version}|{key.protocol}|{key.src_ip}|"
        f"{key.src_port}|{key.dst_ip}|{key.dst_port}|{flow.first_seen_ns}"
    )
    return NetworkFlowEvent.model_validate(
        {
            "event_id": uuid5(FLOW_ID_NAMESPACE, identity),
            "event_type": FLOW_EVENT_TYPE,
            "timestamp": utc_datetime(flow.first_seen_ns),
            "source_type": source_type,
            "source_name": context.source_name(collector),
            "host_id": context.identity.host_id,
            "agent_id": context.agent_id,
            "src_ip": key.src_ip,
            "dst_ip": key.dst_ip,
            "src_port": key.src_port if has_ports else None,
            "dst_port": key.dst_port if has_ports else None,
            # A port protocol seen only as later fragments has no ports; keep its number.
            "protocol": key.protocol if has_ports or key.protocol not in PORT_PROTOCOLS else 255,
            "bytes_sent": flow.forward.bytes,
            "bytes_received": flow.reverse.bytes,
            "metadata": metadata,
        }
    )
