"""Network collectors: packet headers, bidirectional flows, PCAP files, live capture, NetFlow."""

import asyncio
import json
import os
from ipaddress import IPv4Network, ip_address
from pathlib import Path

import pytest

from apps.agent.collectors.base import CollectorContext
from apps.agent.collectors.flows import FlowAggregator, flow_event
from apps.agent.collectors.live_capture import (
    InterfaceInfo,
    LiveCaptureCollector,
    ScapyLiveSource,
    build_capture_filter,
    resolve_interface,
    server_endpoint,
)
from apps.agent.collectors.netflow import (
    FlowRecordConverter,
    GoFlow2ProcessCollector,
    InvalidFlowRecordError,
    NetflowRecordsFileCollector,
    parse_line,
)
from apps.agent.collectors.packets import (
    CaptureFileError,
    PacketMeta,
    ReadStats,
    read_packets,
)
from apps.agent.collectors.pcap import PcapFileCollector
from packages.events.canonical import (
    NetworkFlowEvent,
    NetworkProtocol,
    parse_canonical_event,
    serialize_canonical_event,
)
from tests.unit.agent.fakes import MemorySink, make_context

FIXTURES = Path(__file__).parent / "fixtures"
PCAP = FIXTURES / "pcap" / "lab_sample.pcap"
PCAPNG = FIXTURES / "pcap" / "lab_sample.pcapng"
GOFLOW2 = FIXTURES / "goflow2" / "goflow2_synthetic_lab.jsonl"
LAB_EXPORTERS = {
    "127.0.0.11": "lab-edge-router",
    "127.0.0.12": "lab-core-switch",
    "127.0.0.13": "lab-firewall",
}


def _packet(
    t: float,
    src: str,
    dst: str,
    sport: int | None = 40000,
    dport: int | None = 443,
    *,
    size: int = 100,
    flags: int | None = 0x10,
    protocol: int = 6,
) -> PacketMeta:
    return PacketMeta(
        timestamp_ns=int(t * 1e9),
        ip_version=4,
        src_ip=src,
        dst_ip=dst,
        protocol=protocol,
        src_port=sport,
        dst_port=dport,
        ip_length=size,
        wire_length=size + 14,
        tcp_flags=flags,
    )


def _flows(path: Path) -> tuple[ReadStats, list[NetworkFlowEvent]]:
    stats = ReadStats()
    aggregator = FlowAggregator(idle_timeout=30, active_timeout=120, max_flows=1000)
    flows = []
    for packet in read_packets(path, stats):
        flows.extend(aggregator.add(packet))
    flows.extend(aggregator.flush())
    events = [
        flow_event(
            flow,
            make_context(),
            collector="pcap",
            source_type="pcap",
            capture={"capture_file": path.name},
            idle_timeout=30,
            active_timeout=120,
        )
        for flow in flows
    ]
    return stats, events


# ------------------------------------------------------------------------- packets + flows


@pytest.mark.parametrize("path", [PCAP, PCAPNG])
def test_capture_files_are_read_header_only(path: Path) -> None:
    stats, events = _flows(path)

    assert (stats.packets, stats.ip_packets, stats.non_ip, stats.malformed) == (24, 21, 1, 2)
    assert stats.capture_format == path.suffix.lstrip(".")
    assert len(events) == 9
    for event in events:
        assert parse_canonical_event(serialize_canonical_event(event)) == event


def test_both_directions_form_one_flow() -> None:
    _, events = _flows(PCAP)
    https = next(e for e in events if e.dst_port == 443)

    assert (str(https.src_ip), https.src_port, str(https.dst_ip)) == (
        "192.0.2.10",
        51000,
        "198.51.100.20",
    )
    assert (https.bytes_sent, https.bytes_received) == (340, 620)
    assert https.metadata["packets_sent"] == 6
    assert https.metadata["packets_received"] == 3
    assert "SYN" in https.metadata["tcp_flags_sent"]  # type: ignore[operator]


def test_ipv6_icmp_and_portless_protocols_are_kept() -> None:
    _, events = _flows(PCAP)
    protocols = {event.protocol for event in events}

    assert {NetworkProtocol.TCP, NetworkProtocol.UDP, NetworkProtocol.ICMP} <= protocols
    assert NetworkProtocol.GRE in protocols
    assert any(event.src_ip.version == 6 for event in events)
    portless = [e for e in events if e.protocol not in {NetworkProtocol.TCP, NetworkProtocol.UDP}]
    assert all(e.src_port is None and e.dst_port is None for e in portless)


def test_flow_ids_are_deterministic() -> None:
    first = {event.event_id for event in _flows(PCAP)[1]}
    again = {event.event_id for event in _flows(PCAPNG)[1]}

    assert first == again


def test_idle_and_active_timeouts_end_flows() -> None:
    aggregator = FlowAggregator(idle_timeout=5, active_timeout=20, max_flows=10)

    assert aggregator.add(_packet(0, "10.0.0.1", "10.0.0.2")) == []
    assert aggregator.add(_packet(1, "10.0.0.2", "10.0.0.1", 443, 40000)) == []
    [idle] = aggregator.advance(int(7e9))
    assert (idle.end_reason, idle.forward.packets, idle.reverse.packets) == ("idle_timeout", 1, 1)

    for second in range(0, 24, 3):
        ended = aggregator.add(_packet(10 + second, "10.0.0.3", "10.0.0.4"))
    assert [flow.end_reason for flow in ended] == ["active_timeout"]


def test_flow_table_is_bounded() -> None:
    aggregator = FlowAggregator(idle_timeout=60, active_timeout=60, max_flows=2)
    aggregator.add(_packet(0, "10.0.0.1", "10.0.0.2", 1, 2))
    aggregator.add(_packet(0, "10.0.0.1", "10.0.0.2", 3, 4))

    [evicted] = aggregator.add(_packet(0, "10.0.0.1", "10.0.0.2", 5, 6))

    assert evicted.end_reason == "flow_table_full"
    assert aggregator.active_flows == 2


def test_capture_files_can_be_read_while_a_live_capture_holds_the_filter() -> None:
    # Found by the real-data lab: live capture keeps Scapy's process-wide layer filter for
    # its whole run, and reading a capture file alongside it must share, not reset, it.
    from apps.agent.collectors.packets import LAYER_FILTER, header_only_dissection

    with header_only_dissection():
        _, events = _flows(PCAP)
        assert LAYER_FILTER.users == 1
    assert LAYER_FILTER.users == 0
    assert len(events) == 9


def test_missing_or_damaged_file_is_reported(tmp_path: Path) -> None:
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"not a capture at all")

    with pytest.raises(CaptureFileError):
        list(read_packets(tmp_path / "missing.pcap", ReadStats()))
    with pytest.raises(CaptureFileError):
        list(read_packets(junk, ReadStats()))


# ---------------------------------------------------------------------------- pcap collector


async def test_pcap_collector_processes_each_file_once(tmp_path: Path) -> None:
    capture = tmp_path / "day1.pcap"
    capture.write_bytes(PCAP.read_bytes())
    collector = PcapFileCollector(
        [capture], make_context(), idle_timeout=30, active_timeout=120, max_flows=100
    )
    sink = MemorySink()

    assert await collector.process_all(sink) == 9
    assert await collector.process_all(sink) == 0

    os.utime(capture, ns=(1, 1))  # a changed file is read again; ids stay the same
    assert await collector.process_all(sink) == 9
    assert len({event.event_id for event in sink.events}) == 9


async def test_pcap_collector_limits_to_allowed_networks(tmp_path: Path) -> None:
    collector = PcapFileCollector(
        [PCAP],
        make_context(),
        idle_timeout=30,
        active_timeout=120,
        max_flows=100,
        networks=[IPv4Network("203.0.113.0/24")],
    )
    sink = MemorySink()

    await collector.process_all(sink)

    assert sink.events
    assert all(isinstance(e, NetworkFlowEvent) for e in sink.events)
    assert all(str(e.dst_ip).startswith("203.0.113.") for e in sink.events)  # type: ignore[union-attr]


async def test_pcap_collector_skips_unreadable_files(tmp_path: Path) -> None:
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"\x00" * 64)
    collector = PcapFileCollector(
        [junk, tmp_path / "missing.pcap"],
        make_context(),
        idle_timeout=30,
        active_timeout=120,
        max_flows=100,
    )
    sink = MemorySink()

    assert await collector.process_all(sink) == 0
    assert any(key.startswith("pcap:") for key in sink.checkpoints)


# ------------------------------------------------------------------------------ live capture


INTERFACES = [
    InterfaceInfo(1, "Loopback", "Software Loopback Interface", ("127.0.0.1", "::1")),
    InterfaceInfo(5, "Ethernet", "Realtek PCIe GbE", ("192.0.2.5", "fe80::5")),
    InterfaceInfo(7, "Wi-Fi", "Intel Wireless", ("198.51.100.7",)),
]


def test_interfaces_are_matched_exactly() -> None:
    assert resolve_interface("ethernet", INTERFACES).index == 5
    assert resolve_interface("#7", INTERFACES).name == "Wi-Fi"
    assert resolve_interface("Intel Wireless", INTERFACES).index == 7


def test_unknown_interface_is_refused() -> None:
    from apps.agent.collectors.live_capture import CaptureUnavailableError

    with pytest.raises(CaptureUnavailableError):
        resolve_interface("Eth", INTERFACES)


def test_capture_filter_keeps_own_traffic_and_excludes_the_pipeline() -> None:
    bpf = build_capture_filter(
        local_addresses=["192.0.2.5", "127.0.0.1"],
        exclude_endpoints=[("192.0.2.9", 8000)],
        exclude_tcp_ports=[9092],
    )

    assert bpf == (
        "(ip or ip6) and (host 127.0.0.1 or host 192.0.2.5) and "
        "not (tcp port 8000 and host 192.0.2.9) and not tcp port 9092"
    )


def test_server_endpoint_is_resolved_for_exclusion() -> None:
    assert server_endpoint("http://127.0.0.1:8000") == ("127.0.0.1", 8000)
    assert server_endpoint("https://192.0.2.1") == ("192.0.2.1", 443)
    assert server_endpoint("https://api.example.test") is None


def _frame(src: str, dst: str, *, arp: bool = False) -> object:
    """A frame as a capture delivers it: dissected from its bytes."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import ARP, Ether

    built = Ether() / ARP() if arp else Ether() / IP(src=src, dst=dst) / TCP(dport=443)
    return Ether(bytes(built))


def test_live_source_keeps_only_local_header_metadata() -> None:
    source = ScapyLiveSource(
        INTERFACES[1],
        promiscuous=False,
        snaplen=160,
        capture_filter="",
        local_addresses=frozenset({"192.0.2.5"}),
    )
    source.handle_packet(_frame("192.0.2.5", "198.51.100.1"))
    source.handle_packet(_frame("198.51.100.2", "198.51.100.1"))
    source.handle_packet(_frame("", "", arp=True))

    [packet] = source.drain()
    assert (packet.src_ip, packet.dst_port) == ("192.0.2.5", 443)
    assert (source.stats.not_local, source.stats.non_ip) == (1, 1)


async def test_live_capture_spools_flows_and_flushes_on_stop() -> None:
    collector = LiveCaptureCollector(
        make_context(),
        interface="Ethernet",
        promiscuous=False,
        snaplen=160,
        extra_filter="",
        networks=[],
        server_url="http://127.0.0.1:8000",
        idle_timeout=30,
        active_timeout=120,
        max_flows=100,
    )
    source = ScapyLiveSource(
        INTERFACES[1], promiscuous=False, snaplen=160, capture_filter="", local_addresses=None
    )
    for _ in range(3):
        source.handle_packet(_frame("192.0.2.5", "198.51.100.1"))
    sink = MemorySink()
    task = asyncio.create_task(collector.capture(source, sink))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    [flow] = sink.events
    assert isinstance(flow, NetworkFlowEvent)
    assert flow.metadata["end_reason"] == "capture_stopped"
    assert flow.metadata["capture_mode"] == "live_interface"
    assert flow.source_type == "live_capture"


# ---------------------------------------------------------------------------------- netflow


def _context() -> CollectorContext:
    return make_context()


def test_goflow2_lines_become_exporter_flows() -> None:
    converter = FlowRecordConverter(LAB_EXPORTERS, _context())

    events = [converter.convert(line) for line in GOFLOW2.read_text().splitlines()]
    flows = [event for event in events if event is not None]

    assert flows
    for flow in flows:
        assert flow.metadata["flow_source"] == "exporter"
        assert flow.host_id in set(LAB_EXPORTERS.values())
        assert parse_canonical_event(serialize_canonical_event(flow)) == flow
    first = flows[0]
    assert (str(first.src_ip), first.src_port, first.dst_port) == ("10.10.0.21", 51514, 443)
    assert first.bytes_sent == 38000
    assert first.metadata["duration_seconds"] == 60.0


def test_unlisted_exporters_are_refused_and_counted() -> None:
    converter = FlowRecordConverter({"127.0.0.11": "lab-edge-router"}, _context())

    accepted = [converter.convert(line) for line in GOFLOW2.read_text().splitlines()]

    assert any(event is not None for event in accepted)
    assert sum(converter.refused.values()) > 0


def test_bidirectional_records_fill_bytes_received() -> None:
    record = {
        "type": "IPFIX",
        "time_received_ns": 1_791_643_053_000_000_000,
        "sampler_address": "127.0.0.13",
        "src_addr": "10.10.0.5",
        "dst_addr": "203.0.113.9",
        "proto": 6,
        "src_port": 50000,
        "dst_port": 443,
        "bytes": 1200,
        "packets": 10,
        "reverse_bytes": 5400,
        "reverse_packets": 8,
    }
    flow = FlowRecordConverter(LAB_EXPORTERS, _context()).convert(json.dumps(record))

    assert flow is not None
    assert (flow.bytes_sent, flow.bytes_received) == (1200, 5400)
    assert flow.metadata["direction_model"] == "bidirectional"


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("not json", "unparseable"),
        ('{"type": "UNKNOWN"}', "unsupported_type"),
        ('{"type": "IPFIX", "sampler_address": "x"}', "missing_exporter_address"),
        ('{"type": "IPFIX", "sampler_address": "127.0.0.11"}', "missing_receive_time"),
    ],
)
def test_invalid_records_are_classified(line: str, reason: str) -> None:
    with pytest.raises(InvalidFlowRecordError) as caught:
        parse_line(line)

    assert caught.value.reason == reason


async def test_records_file_is_tailed_with_a_checkpoint(tmp_path: Path) -> None:
    records = tmp_path / "goflow2.jsonl"
    lines = GOFLOW2.read_text().splitlines()
    records.write_text("\n".join(lines[:5]) + "\n")
    collector = NetflowRecordsFileCollector(records, LAB_EXPORTERS, _context())
    sink = MemorySink()

    first = await collector.poll(sink)
    with records.open("a") as handle:
        handle.write("\n".join(lines[5:]) + "\n")
    second = await collector.poll(sink)
    restarted = NetflowRecordsFileCollector(records, LAB_EXPORTERS, _context())

    assert first + second == len(sink.events)
    assert await restarted.poll(sink) == 0  # resumes after the stored checkpoint


def test_goflow2_command_line_is_explicit() -> None:
    collector = GoFlow2ProcessCollector(
        Path("goflow2"), Path("mapping.yaml"), ("127.0.0.1", 2055), LAB_EXPORTERS, _context()
    )

    command = collector.command()

    assert command[command.index("-listen") + 1] == "netflow://127.0.0.1:2055"
    assert command[command.index("-format") + 1] == "json"
    assert ip_address("127.0.0.1").is_loopback
