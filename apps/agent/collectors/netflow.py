"""NetFlow v5/v9 and IPFIX from authorized exporters, decoded by GoFlow2 → ``network.flow``.

GoFlow2 receives the exports, handles templates and sampling, and writes one JSON line
per flow record (with ``infrastructure/goflow2/adis-mapping.yaml``). The agent reads those
lines either from GoFlow2's standard output (``AGENT_NETFLOW_GOFLOW2_PATH``: the agent runs
GoFlow2 as a child process listening on ``AGENT_NETFLOW_LISTEN``) or from the file a
separately run GoFlow2 writes (``AGENT_NETFLOW_RECORDS_FILE``, checkpointed).

Rules (from the original ADIS flow collector):

- Only exporters listed in ``AGENT_NETFLOW_EXPORTERS`` are accepted; records from other
  addresses are counted and refused.
- Nothing is invented: zeros GoFlow2 prints for fields the exporter did not send are not
  copied; flow times are kept only where the exporter reported them.
- Counts are as exported. Sampled counts stay sampled (``sampling_interval``,
  ``counts_are_sampled``); bidirectional records keep their reverse counters, which become
  ``bytes_received``.
- ``host_id`` is the exporter's configured name: the device that observed the flow.
"""

import asyncio
import ipaddress
import json
import logging
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from uuid import UUID, uuid5

from pydantic import JsonValue, ValidationError

from apps.agent.collectors.base import CollectorContext, EventSink
from apps.agent.collectors.flows import (
    FLOW_EVENT_TYPE,
    PORT_PROTOCOLS,
    TCP_FLAG_NAMES,
    TRANSPORT_NAMES,
    iso_utc,
    utc_datetime,
)
from apps.agent.collectors.tail import LineTail, TailPosition
from packages.events.canonical import AnyCanonicalEvent, NetworkFlowEvent

logger = logging.getLogger(__name__)

SOURCE_TYPE: Final = "netflow"
FLOW_ID_NAMESPACE: Final = UUID("8d3f5a1c-6b2e-4f7a-9c41-2e7b5d9a0c63")
EXPORT_PROTOCOLS: Final = {
    "NETFLOW_V5": "netflow_v5",
    "NETFLOW_V9": "netflow_v9",
    "IPFIX": "ipfix",
    "SFLOW_5": "sflow_v5",
}
ICMP_PROTOCOLS: Final = frozenset({1, 58})
FLOW_DIRECTIONS: Final = {0: "ingress", 1: "egress"}
FLOW_END_REASONS: Final = {
    1: "idle_timeout",
    2: "active_timeout",
    3: "end_of_flow",
    4: "forced_end",
    5: "lack_of_resources",
}
MAX_FUTURE_SKEW_SECONDS: Final = 300.0
BATCH_EVENTS: Final = 500
POLL_SECONDS: Final = 1.0
_PROTOCOL_NAMES: Final = {"TCP": 6, "UDP": 17, "ICMP": 1, "IPV6-ICMP": 58, "SCTP": 132, "GRE": 47}


class InvalidFlowRecordError(ValueError):
    """A record that cannot become an event; ``reason`` is a short counter name."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class FlowRecord:
    """One GoFlow2 output record and its export-level facts."""

    raw: Mapping[str, object]
    export_protocol: str
    exporter_address: str
    observation_domain_id: int
    sequence: int
    received_ns: int


def _uint(raw: Mapping[str, object], key: str) -> int | None:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = int(value)
    return number if number >= 0 else None


def parse_line(line: str | bytes) -> FlowRecord:
    """Parse one GoFlow2 JSON line.

    Raises:
        InvalidFlowRecordError: If the line is not a usable flow record.
    """
    try:
        raw = json.loads(line)
    except (ValueError, UnicodeDecodeError):
        raise InvalidFlowRecordError("unparseable", "not a JSON object") from None
    if not isinstance(raw, dict):
        raise InvalidFlowRecordError("unparseable", "not a JSON object")
    protocol = EXPORT_PROTOCOLS.get(str(raw.get("type", "")))
    if protocol is None:
        raise InvalidFlowRecordError("unsupported_type", "unsupported record type")
    try:
        exporter = str(ipaddress.ip_address(str(raw.get("sampler_address", ""))))
    except ValueError:
        raise InvalidFlowRecordError("missing_exporter_address", "no sampler_address") from None
    received = _uint(raw, "time_received_ns")
    if not received:
        raise InvalidFlowRecordError("missing_receive_time", "no time_received_ns")
    return FlowRecord(
        raw=raw,
        export_protocol=protocol,
        exporter_address=exporter,
        observation_domain_id=_uint(raw, "observation_domain_id") or 0,
        sequence=_uint(raw, "sequence_num") or 0,
        received_ns=received,
    )


def _address(raw: Mapping[str, object], key: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(str(raw.get(key, "")))
    except ValueError:
        raise InvalidFlowRecordError("missing_addresses", "no valid address") from None


def _protocol(raw: Mapping[str, object]) -> int:
    value = raw.get("proto")
    if isinstance(value, str):
        value = _PROTOCOL_NAMES.get(value.upper())
    number = _uint({"p": value}, "p")
    if number is None or number > 255:
        raise InvalidFlowRecordError("invalid_protocol", "no valid IP protocol number")
    return number


def flow_times(record: FlowRecord) -> tuple[int | None, int | None]:
    """Flow start/end (ns since the epoch), only where the exporter reported them."""
    raw = record.raw
    start = _uint(raw, "time_flow_start_ns")
    end = _uint(raw, "time_flow_end_ns")
    protocol = record.export_protocol
    if protocol == "netflow_v5":
        return start, end
    if protocol == "sflow_v5":
        return None, None

    def side(uptime_key: str, absolute_key: str, decoded: int | None) -> int | None:
        if protocol == "netflow_v9":
            if uptime_key in raw:
                return decoded
            absolute = _uint(raw, absolute_key)
            return absolute * 1_000_000 if absolute else None
        if absolute_key in raw:
            return decoded
        uptime = _uint(raw, uptime_key)
        init = _uint(raw, "system_init_time_ms")
        if uptime is not None and init:
            return (init + uptime) * 1_000_000
        return None

    return (
        side("start_sysuptime_ms", "flow_start_abs", start),
        side("end_sysuptime_ms", "flow_end_abs", end),
    )


def _sampling(raw: Mapping[str, object]) -> tuple[int | None, str]:
    announced = _uint(raw, "sampling_rate")
    if announced:
        return announced, "exporter"
    per_record = _uint(raw, "record_sampling_interval")
    if per_record:
        return per_record, "exporter_record"
    return None, "not_reported"


def flow_record_event(
    record: FlowRecord, exporter_id: str, context: CollectorContext
) -> NetworkFlowEvent:
    """The canonical ``network.flow`` event of one exported record.

    Raises:
        InvalidFlowRecordError: If the record cannot become an event.
    """
    raw = record.raw
    src, dst = _address(raw, "src_addr"), _address(raw, "dst_addr")
    if src.version != dst.version:
        raise InvalidFlowRecordError("mixed_ip_versions", "source and destination differ")
    protocol = _protocol(raw)
    start_ns, end_ns = flow_times(record)
    sampling_interval, sampling_source = _sampling(raw)
    metadata: dict[str, JsonValue] = {
        "flow_source": "exporter",
        "exporter_id": exporter_id,
        "exporter_address": record.exporter_address,
        "export_protocol": record.export_protocol,
        "export_sequence": record.sequence,
        "observation_time": iso_utc(record.received_ns),
        "ip_version": src.version,
        "protocol_number": protocol,
        "transport": TRANSPORT_NAMES.get(protocol, "other"),
        "packets_sent": _uint(raw, "packets") or 0,
        "sampling_source": sampling_source,
        "counts_are_sampled": None if sampling_interval is None else sampling_interval > 1,
        "flow_times_reported": start_ns is not None or end_ns is not None,
    }
    if record.export_protocol != "netflow_v5":
        metadata["observation_domain_id"] = record.observation_domain_id
    if sampling_interval is not None:
        metadata["sampling_interval"] = sampling_interval
    if start_ns is not None:
        metadata["flow_start"] = iso_utc(start_ns)
    if end_ns is not None:
        metadata["flow_end"] = iso_utc(end_ns)
    if start_ns is not None and end_ns is not None and start_ns <= end_ns:
        metadata["duration_seconds"] = round((end_ns - start_ns) / 1e9, 3)
    if protocol in ICMP_PROTOCOLS:
        icmp_type, icmp_code = _uint(raw, "icmp_type") or 0, _uint(raw, "icmp_code") or 0
        if icmp_type or icmp_code:
            metadata["icmp_type"], metadata["icmp_code"] = icmp_type, icmp_code
    if protocol == 6 and (flags := _uint(raw, "tcp_flags")):
        metadata["tcp_flags"] = [n for bit, n in enumerate(TCP_FLAG_NAMES) if flags >> bit & 1]
    for key, name in (("in_if", "ingress_interface"), ("out_if", "egress_interface")):
        if value := _uint(raw, key):
            metadata[name] = value
    if vlan := (_uint(raw, "src_vlan") or _uint(raw, "vlan_id")):
        metadata["vlan_id"] = vlan
    if (direction := _uint(raw, "flow_direction")) in FLOW_DIRECTIONS:
        metadata["flow_direction"] = FLOW_DIRECTIONS[direction or 0]
    if (reason := _uint(raw, "flow_end_reason")) in FLOW_END_REASONS:
        metadata["flow_end_reason"] = FLOW_END_REASONS[reason or 0]
    received_bytes = _uint(raw, "reverse_bytes")
    if received_bytes is None:
        received_bytes = _uint(raw, "responder_bytes")
    reverse_packets = _uint(raw, "reverse_packets") or _uint(raw, "responder_packets")
    if reverse_packets is not None:
        metadata["packets_received"] = reverse_packets
    metadata["direction_model"] = (
        "bidirectional" if received_bytes is not None else "unidirectional"
    )
    timestamp_ns = end_ns or start_ns or record.received_ns
    if (timestamp_ns - record.received_ns) / 1e9 > MAX_FUTURE_SKEW_SECONDS:
        metadata["exporter_clock_ahead_seconds"] = round(
            (timestamp_ns - record.received_ns) / 1e9, 3
        )
        timestamp_ns = record.received_ns
    has_ports = protocol in PORT_PROTOCOLS
    identity = "|".join(
        str(part)
        for part in (
            "exporter-flow",
            exporter_id,
            record.export_protocol,
            record.observation_domain_id,
            record.sequence,
            raw.get("src_addr"),
            raw.get("src_port"),
            raw.get("dst_addr"),
            raw.get("dst_port"),
            protocol,
            raw.get("time_flow_start_ns"),
            raw.get("time_flow_end_ns"),
            raw.get("packets"),
            raw.get("bytes"),
        )
    )
    return NetworkFlowEvent.model_validate(
        {
            "event_id": uuid5(FLOW_ID_NAMESPACE, identity),
            "event_type": FLOW_EVENT_TYPE,
            "timestamp": utc_datetime(timestamp_ns),
            "source_type": SOURCE_TYPE,
            "source_name": context.source_name("netflow"),
            "host_id": exporter_id,
            "agent_id": context.agent_id,
            "src_ip": str(src),
            "dst_ip": str(dst),
            "src_port": (_uint(raw, "src_port") or 0) if has_ports else None,
            "dst_port": (_uint(raw, "dst_port") or 0) if has_ports else None,
            "protocol": protocol,
            "bytes_sent": _uint(raw, "bytes") or 0,
            "bytes_received": received_bytes,
            "metadata": metadata,
        }
    )


class FlowRecordConverter:
    """Allowlist check and conversion, with counters of what was refused."""

    def __init__(self, exporters: Mapping[str, str], context: CollectorContext) -> None:
        self._exporters = dict(exporters)
        self._context = context
        self.refused: Counter[str] = Counter()
        self.invalid: Counter[str] = Counter()

    def convert(self, line: str | bytes) -> NetworkFlowEvent | None:
        """The event of one GoFlow2 line, or ``None`` (counted) if it is refused."""
        if not line.strip():
            return None
        try:
            record = parse_line(line)
        except InvalidFlowRecordError as error:
            self.invalid[error.reason] += 1
            return None
        exporter_id = self._exporters.get(record.exporter_address)
        if exporter_id is None:
            if record.exporter_address not in self.refused:
                logger.warning(
                    "flow records from an unlisted exporter refused",
                    extra={"action": "agent_netflow_unauthorized_exporter"},
                )
            self.refused[record.exporter_address] += 1
            return None
        try:
            return flow_record_event(record, exporter_id, self._context)
        except InvalidFlowRecordError as error:
            self.invalid[error.reason] += 1
        except ValidationError:
            self.invalid["schema"] += 1
        return None


class NetflowRecordsFileCollector:
    """Reads GoFlow2's JSON output file (checkpointed) written by a separate GoFlow2."""

    name = "netflow"

    def __init__(
        self,
        path: Path,
        exporters: Mapping[str, str],
        context: CollectorContext,
        *,
        read_from_start: bool = True,
    ) -> None:
        self._tail = LineTail(path, read_from_start=read_from_start)
        self._converter = FlowRecordConverter(exporters, context)
        self._key = f"netflow:{Path(path).resolve()}"
        self._position: TailPosition | None = None
        self._loaded = False

    async def run(self, sink: EventSink) -> None:
        """Read new records until cancelled."""
        while True:
            if not await self.poll(sink):
                await asyncio.sleep(POLL_SECONDS)

    async def poll(self, sink: EventSink) -> int:
        """Spool the records written since the last poll; returns how many."""
        if not self._loaded:
            stored = await sink.checkpoint(self._key)
            self._position = TailPosition.decode(stored) if stored else None
            self._loaded = True
        chunk = await self._tail.read(self._position)
        if chunk is None:
            return 0
        events: list[AnyCanonicalEvent] = []
        for _, line in chunk.lines:
            event = self._converter.convert(line)
            if event is not None:
                events.append(event)
        await sink.submit(events, checkpoints={self._key: chunk.end.encode()})
        self._position = chunk.end
        return len(events)


class GoFlow2ProcessCollector:
    """Runs GoFlow2 as a child process and reads its records from standard output."""

    name = "netflow"

    def __init__(
        self,
        executable: Path,
        mapping_file: Path,
        listen: tuple[str, int],
        exporters: Mapping[str, str],
        context: CollectorContext,
    ) -> None:
        self._executable = executable
        self._mapping_file = mapping_file
        self._listen = listen
        self._converter = FlowRecordConverter(exporters, context)

    def command(self) -> list[str]:
        """The GoFlow2 command line: explicit listen address, JSON on standard output."""
        host, port = self._listen
        host_text = f"[{host}]" if ":" in host else host
        return [
            str(self._executable),
            "-listen", f"netflow://{host_text}:{port}",
            "-addr", "127.0.0.1:18080",
            "-format", "json",
            "-transport", "file",
            "-mapping", str(self._mapping_file),
            "-produce", "sample",
        ]  # fmt: skip

    async def run(self, sink: EventSink) -> None:
        """Start GoFlow2 and spool its records until cancelled."""
        process = await asyncio.create_subprocess_exec(
            *self.command(),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        logger.info(
            "GoFlow2 started",
            extra={
                "action": "agent_goflow2_started",
                "listen": f"{self._listen[0]}:{self._listen[1]}",
            },
        )
        assert process.stdout is not None  # noqa: S101 - set by stdout=PIPE above
        batch: list[AnyCanonicalEvent] = []
        try:
            while True:
                try:
                    line = await asyncio.wait_for(process.stdout.readline(), POLL_SECONDS)
                except TimeoutError:
                    line = None
                if line == b"":
                    raise RuntimeError("GoFlow2 exited")
                if line:
                    event = self._converter.convert(line)
                    if event is not None:
                        batch.append(event)
                if batch and (line is None or len(batch) >= BATCH_EVENTS):
                    await sink.submit(batch)
                    batch = []
        finally:
            if process.returncode is None:
                process.terminate()
                await process.wait()
