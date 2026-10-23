"""Packet header metadata from PCAP/PCAPNG files and live captures, via Scapy.

Scapy's dissection is limited to link, network and transport headers while packets are
read, so application payloads are never parsed: their bytes are only counted. Each packet
is dropped as soon as its metadata is taken, so memory does not grow with the capture.
Ethernet, VLAN, Linux cooked, loopback and raw-IP captures, IPv4 and IPv6 (with extension
headers) are supported; non-IP frames and malformed packets are counted and skipped.
"""

import functools
import logging
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Final

logger = logging.getLogger(__name__)

IPV4_ETHERTYPE: Final = 0x0800
IPV6_ETHERTYPE: Final = 0x86DD
LOOPBACK_IP_FAMILIES: Final = frozenset({2, 10, 23, 24, 28, 30})
TCP_PROTOCOL: Final = 6
UDP_PROTOCOL: Final = 17
SCTP_PROTOCOL: Final = 132
CAPTURE_MAGICS: Final = frozenset(
    {
        bytes.fromhex("a1b2c3d4"),  # pcap, microseconds, big-endian
        bytes.fromhex("d4c3b2a1"),  # pcap, microseconds, little-endian
        bytes.fromhex("a1b23c4d"),  # pcap, nanoseconds, big-endian
        bytes.fromhex("4d3cb2a1"),  # pcap, nanoseconds, little-endian
        bytes.fromhex("0a0d0d0a"),  # pcapng section header block
    }
)
NON_IP: Final = "non_ip"
MALFORMED: Final = "malformed"


class CaptureFileError(Exception):
    """The file does not exist or is not a PCAP/PCAPNG capture."""


@dataclass(frozen=True, slots=True)
class PacketMeta:
    """Header facts about one IP packet. No payload bytes are kept."""

    timestamp_ns: int
    ip_version: int
    src_ip: str
    dst_ip: str
    protocol: int
    src_port: int | None
    dst_port: int | None
    ip_length: int
    """Bytes of the IP packet as its header states (like NetFlow octets)."""
    wire_length: int
    """Bytes of the whole frame on the wire, from the capture record."""
    tcp_flags: int | None = None
    fragment: bool = False
    """A later IP fragment: no transport header, so no ports."""


@dataclass(slots=True)
class ReadStats:
    """What reading a capture saw."""

    capture_format: str = ""
    packets: int = 0
    ip_packets: int = 0
    non_ip: int = 0
    malformed: int = 0
    damaged: str | None = None
    """Why reading stopped before the end of the file, if it did."""


@functools.cache
def scapy_namespace() -> SimpleNamespace:
    """Import Scapy on first use (it is slow to import), without its start-up warnings."""
    for name in ("scapy.runtime", "scapy.loading"):
        logging.getLogger(name).setLevel(logging.ERROR)
    from scapy.config import conf
    from scapy.error import Scapy_Exception
    from scapy.layers import inet6
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import CookedLinux, CookedLinuxV2, Dot1Q, Ether, Loopback
    from scapy.packet import NoPayload, Raw
    from scapy.utils import PcapNgReader, PcapReader

    ipv6_extensions = tuple(
        getattr(inet6, name)
        for name in (
            "IPv6ExtHdrHopByHop",
            "IPv6ExtHdrRouting",
            "IPv6ExtHdrFragment",
            "IPv6ExtHdrDestOpt",
            "IPv6ExtHdrSegmentRouting",
        )
    )
    link_layers = (Ether, Dot1Q, CookedLinux, CookedLinuxV2, Loopback)
    return SimpleNamespace(
        conf=conf,
        Scapy_Exception=Scapy_Exception,
        IP=IP,
        IPv6=inet6.IPv6,
        IPv6ExtHdrFragment=inet6.IPv6ExtHdrFragment,
        ipv6_extensions=ipv6_extensions,
        TCP=TCP,
        UDP=UDP,
        Ether=Ether,
        Dot1Q=Dot1Q,
        CookedLinux=CookedLinux,
        CookedLinuxV2=CookedLinuxV2,
        Loopback=Loopback,
        NoPayload=NoPayload,
        Raw=Raw,
        PcapReader=PcapReader,
        PcapNgReader=PcapNgReader,
        header_layers=[*link_layers, IP, inet6.IPv6, *ipv6_extensions, TCP, UDP],
    )


class _SharedLayerFilter:
    """Scapy's layer filter is process-wide, so concurrent readers share one.

    A live capture keeps it for its whole run while capture files are read alongside it;
    the filter is set by the first user and removed by the last.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._users = 0

    @property
    def users(self) -> int:
        """Readers currently holding the filter."""
        return self._users

    def acquire(self, s: SimpleNamespace) -> None:
        """Hold the filter, setting it if nobody else does."""
        with self._lock:
            if self._users == 0:
                s.conf.layers.filter(s.header_layers)
            self._users += 1

    def release(self, s: SimpleNamespace) -> None:
        """Let go of the filter, removing it after the last user."""
        with self._lock:
            self._users -= 1
            if self._users == 0:
                s.conf.layers.unfilter()


LAYER_FILTER: Final = _SharedLayerFilter()


@contextmanager
def header_only_dissection() -> Iterator[None]:
    """Make Scapy decode only header layers; everything above them stays raw bytes."""
    s = scapy_namespace()
    LAYER_FILTER.acquire(s)
    try:
        yield
    finally:
        LAYER_FILTER.release(s)


def read_packets(
    path: Path, stats: ReadStats, *, max_packets: int | None = None
) -> Iterator[PacketMeta]:
    """Metadata of every IP packet in ``path``, updating ``stats`` as it goes.

    Raises:
        CaptureFileError: If ``path`` is missing or not a PCAP/PCAPNG file.
    """
    s = scapy_namespace()
    if not path.is_file():
        raise CaptureFileError(f"{path} does not exist or is not a file")
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic not in CAPTURE_MAGICS:  # checked first: Scapy leaks the file it rejects
        raise CaptureFileError(f"{path.name} is not a PCAP or PCAPNG file")
    try:
        reader = s.PcapReader(str(path))
    except (s.Scapy_Exception, OSError, ValueError, EOFError) as error:
        raise CaptureFileError(f"{path.name} is not a PCAP or PCAPNG file ({error})") from None
    stats.capture_format = "pcapng" if isinstance(reader, s.PcapNgReader) else "pcap"
    with reader, header_only_dissection():
        while max_packets is None or stats.packets < max_packets:
            try:
                packet = reader.read_packet()
            except EOFError:
                break
            except Exception as error:  # a damaged record ends the file
                stats.damaged = f"reading stopped after packet {stats.packets}: {error}"
                logger.warning(
                    "capture file damaged; keeping what was read",
                    extra={"action": "agent_pcap_damaged", "file": path.name},
                )
                break
            if packet is None:
                break
            stats.packets += 1
            meta = packet_metadata(packet)
            if meta == NON_IP:
                stats.non_ip += 1
            elif meta == MALFORMED:
                stats.malformed += 1
            elif isinstance(meta, PacketMeta):
                stats.ip_packets += 1
                yield meta


def packet_metadata(packet: object) -> PacketMeta | str:
    """Header metadata of a dissected Scapy packet, or :data:`NON_IP` / :data:`MALFORMED`."""
    s = scapy_namespace()
    if isinstance(packet, s.Raw):
        return MALFORMED
    frame = packet
    timestamp_ns = int(float(getattr(frame, "time", 0)) * 1_000_000_000)
    wire_length = int(getattr(frame, "wirelen", None) or len(frame))  # type: ignore[arg-type]
    if s.IP in frame:  # type: ignore[operator]
        return _ipv4(frame[s.IP], timestamp_ns, wire_length, s)  # type: ignore[index]
    if s.IPv6 in frame:  # type: ignore[operator]
        return _ipv6(frame[s.IPv6], timestamp_ns, wire_length, s)  # type: ignore[index]
    return MALFORMED if _link_announces_ip(frame, s) else NON_IP


def _ipv4(ip: object, timestamp_ns: int, wire_length: int, s: SimpleNamespace) -> PacketMeta | str:
    header = SimpleNamespace(
        version=getattr(ip, "version", None),
        ihl=getattr(ip, "ihl", None),
        length=getattr(ip, "len", None),
        frag=int(getattr(ip, "frag", 0) or 0),
        flags=int(getattr(ip, "flags", 0) or 0),
        proto=int(getattr(ip, "proto", 0) or 0),
    )
    if header.version != 4 or header.ihl is None or header.ihl < 5:
        return MALFORMED
    if header.length and header.length < header.ihl * 4:
        return MALFORMED
    fragmented = bool(header.frag) or bool(header.flags & 0x1)
    later_fragment = header.frag > 0
    transport: tuple[int | None, int | None, int | None] | str = (
        (None, None, None)
        if later_fragment
        else _transport(getattr(ip, "payload", None), header.proto, s)
    )
    if transport == MALFORMED:
        if not fragmented:
            return MALFORMED
        transport = (None, None, None)
    if isinstance(transport, str):
        return MALFORMED
    src_port, dst_port, flags = transport
    return PacketMeta(
        timestamp_ns=timestamp_ns,
        ip_version=4,
        src_ip=str(getattr(ip, "src", "")),
        dst_ip=str(getattr(ip, "dst", "")),
        protocol=header.proto,
        src_port=src_port,
        dst_port=dst_port,
        ip_length=int(header.length or len(ip)),  # type: ignore[arg-type]
        wire_length=wire_length,
        tcp_flags=flags,
        fragment=later_fragment,
    )


def _ipv6(ip6: object, timestamp_ns: int, wire_length: int, s: SimpleNamespace) -> PacketMeta | str:
    if getattr(ip6, "version", None) != 6:
        return MALFORMED
    protocol = int(getattr(ip6, "nh", 0) or 0)
    layer = getattr(ip6, "payload", None)
    later_fragment = False
    while isinstance(layer, s.ipv6_extensions):
        if isinstance(layer, s.IPv6ExtHdrFragment) and int(getattr(layer, "offset", 0) or 0):
            later_fragment = True
        protocol = int(getattr(layer, "nh", 0) or 0)
        layer = getattr(layer, "payload", None)
    transport = (None, None, None) if later_fragment else _transport(layer, protocol, s)
    if isinstance(transport, str):
        return MALFORMED
    src_port, dst_port, flags = transport
    return PacketMeta(
        timestamp_ns=timestamp_ns,
        ip_version=6,
        src_ip=str(getattr(ip6, "src", "")),
        dst_ip=str(getattr(ip6, "dst", "")),
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        ip_length=40 + int(getattr(ip6, "plen", 0) or 0),
        wire_length=wire_length,
        tcp_flags=flags,
        fragment=later_fragment,
    )


def _transport(
    layer: object, protocol: int, s: SimpleNamespace
) -> tuple[int | None, int | None, int | None] | str:
    """(source port, destination port, TCP flags) from the transport header, if any."""
    if protocol == TCP_PROTOCOL:
        offset = getattr(layer, "dataofs", None)
        if not isinstance(layer, s.TCP) or (offset is not None and offset < 5):
            return MALFORMED
        return int(layer.sport), int(layer.dport), int(layer.flags)
    if protocol == UDP_PROTOCOL:
        if not isinstance(layer, s.UDP):
            return MALFORMED
        return int(layer.sport), int(layer.dport), None
    return None, None, None


def _link_announces_ip(packet: object, s: SimpleNamespace) -> bool:
    """Whether the link header says IP follows (so a missing IP header means damage)."""
    ether_type: int | None = None
    layer = packet
    while layer is not None and not isinstance(layer, s.NoPayload):
        if isinstance(layer, s.Loopback):
            return int(getattr(layer, "type", -1)) in LOOPBACK_IP_FAMILIES
        if isinstance(layer, s.Ether | s.Dot1Q):
            ether_type = int(getattr(layer, "type", -1))
        elif isinstance(layer, s.CookedLinux | s.CookedLinuxV2):
            ether_type = int(getattr(layer, "proto", -1))
        layer = getattr(layer, "payload", None)
    return ether_type in (IPV4_ETHERTYPE, IPV6_ETHERTYPE)
