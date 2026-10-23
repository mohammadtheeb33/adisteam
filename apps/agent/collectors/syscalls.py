"""System calls from auditd and eBPF, aggregated into per-process call sequences.

The specification (pentra.pdf, section 2, step 3) lists system calls from Auditd and eBPF,
in the form of *call sequences*. Two sources feed the same aggregator:

- **auditd**: the kernel audit log (``/var/log/audit/audit.log``) with ``SYSCALL`` records,
  produced by audit rules the operator installs (``infrastructure/auditd/adis.rules``).
- **eBPF**: JSON lines written by the bpftrace program ``infrastructure/ebpf/adis-syscalls.bt``
  (``bpftrace -f json``), run by the operator with the privileges tracing needs.

The agent only reads those files, so it never needs kernel privileges itself. Calls of one
process are grouped into a ``process.syscall_sequence`` event when ``window_seconds`` has
passed since the sequence's first call, when it reaches ``max_length`` calls, or when the
process is idle for the window. A successful ``execve``/``execveat`` also produces a
``process.started`` event at once. Command-line arguments are never collected (they may
hold secrets); only the process name, executable path and ids are. Lines that should be
records but cannot be read are counted and logged (``agent_syscall_unreadable``), since a
record broken on purpose would otherwise hide a call.
"""

import asyncio
import json
import logging
import re
import time
from collections import Counter, OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import UUID, uuid5

from pydantic import JsonValue, ValidationError

from apps.agent.collectors.base import CollectorContext, EventSink
from apps.agent.collectors.tail import LineTail, TailPosition
from packages.events.canonical import AnyCanonicalEvent, ProcessEvent

logger = logging.getLogger(__name__)

SEQUENCE_EVENT_TYPE: Final = "process.syscall_sequence"
PROCESS_STARTED_EVENT_TYPE: Final = "process.started"
SEQUENCE_ID_NAMESPACE: Final = UUID("2f8e6b1d-7c4a-4e93-a5d0-6b3c9e1f7a42")
EXEC_SYSCALLS: Final = frozenset({"execve", "execveat"})
POLL_SECONDS: Final = 1.0
MAX_OPEN_SEQUENCES: Final = 10_000

AUDIT_ARCH_X86_64: Final = "c000003e"
AUDIT_ARCH_AARCH64: Final = "c00000b7"
SYSCALLS_X86_64: Final = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat", 6: "lstat", 7: "poll",
    8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk", 13: "rt_sigaction",
    14: "rt_sigprocmask", 16: "ioctl", 17: "pread64", 18: "pwrite64", 19: "readv",
    20: "writev", 21: "access", 22: "pipe", 23: "select", 32: "dup", 33: "dup2",
    35: "nanosleep", 39: "getpid", 40: "sendfile", 41: "socket", 42: "connect", 43: "accept",
    44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 48: "shutdown", 49: "bind",
    50: "listen", 51: "getsockname", 52: "getpeername", 53: "socketpair", 54: "setsockopt",
    55: "getsockopt", 56: "clone", 57: "fork", 58: "vfork", 59: "execve", 60: "exit",
    61: "wait4", 62: "kill", 63: "uname", 72: "fcntl", 76: "truncate", 77: "ftruncate",
    78: "getdents", 79: "getcwd", 80: "chdir", 81: "fchdir", 82: "rename", 83: "mkdir",
    84: "rmdir", 85: "creat", 86: "link", 87: "unlink", 88: "symlink", 89: "readlink",
    90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown", 95: "umask",
    101: "ptrace", 102: "getuid", 104: "getgid", 105: "setuid", 106: "setgid", 107: "geteuid",
    108: "getegid", 109: "setpgid", 110: "getppid", 112: "setsid", 113: "setreuid",
    114: "setregid", 117: "setresuid", 119: "setresgid", 122: "setfsuid", 123: "setfsgid",
    126: "capset", 155: "pivot_root", 157: "prctl", 158: "arch_prctl", 161: "chroot",
    165: "mount", 166: "umount2", 169: "reboot", 170: "sethostname", 175: "init_module",
    176: "delete_module", 186: "gettid", 200: "tkill", 202: "futex", 217: "getdents64",
    218: "set_tid_address", 228: "clock_gettime", 231: "exit_group", 232: "epoll_wait",
    234: "tgkill", 257: "openat", 258: "mkdirat", 260: "fchownat", 263: "unlinkat",
    264: "renameat", 265: "linkat", 266: "symlinkat", 268: "fchmodat", 269: "faccessat",
    272: "unshare", 288: "accept4", 302: "prlimit64", 308: "setns", 313: "finit_module",
    316: "renameat2", 317: "seccomp", 318: "getrandom", 319: "memfd_create", 321: "bpf",
    322: "execveat", 425: "io_uring_setup", 434: "pidfd_open", 435: "clone3", 437: "openat2",
}  # fmt: skip
SYSCALLS_AARCH64: Final = {
    34: "mkdirat", 35: "unlinkat", 38: "renameat", 39: "umount2", 40: "mount", 53: "fchmodat",
    54: "fchownat", 56: "openat", 57: "close", 63: "read", 64: "write", 93: "exit",
    94: "exit_group", 97: "unshare", 98: "futex", 101: "nanosleep", 105: "init_module",
    106: "delete_module", 117: "ptrace", 129: "kill", 144: "setgid", 146: "setuid",
    147: "setresuid", 167: "prctl", 172: "getpid", 174: "getuid", 198: "socket", 200: "bind",
    201: "listen", 202: "accept", 203: "connect", 206: "sendto", 207: "recvfrom", 220: "clone",
    221: "execve", 222: "mmap", 226: "mprotect", 242: "accept4", 261: "prlimit64",
    268: "setns", 273: "finit_module", 276: "renameat2", 279: "memfd_create", 280: "bpf",
    281: "execveat", 435: "clone3", 437: "openat2",
}  # fmt: skip
ARCH_TABLES: Final = {AUDIT_ARCH_X86_64: SYSCALLS_X86_64, AUDIT_ARCH_AARCH64: SYSCALLS_AARCH64}

_AUDIT_LINE: Final = re.compile(
    r"^type=(?P<type>\w+) msg=audit\((?P<s>\d+)\.(?P<ms>\d+):(?P<serial>\d+)\): ?(?P<body>.*)$"
)
_FIELD: Final = re.compile(r'(\w+)=("[^"]*"|\S+)')
_HEX: Final = re.compile(r"^(?:[0-9A-F]{2})+$")


@dataclass(frozen=True, slots=True)
class SyscallRecord:
    """One system call of one process."""

    timestamp_ns: int
    pid: int
    syscall: str
    comm: str
    marker: str
    """Source-specific identity: the audit serial or the eBPF timestamp."""
    ppid: int | None = None
    uid: int | None = None
    auid: int | None = None
    exe: str | None = None
    success: bool | None = None
    key: str | None = None


class UnreadableRecordError(ValueError):
    """A line that should be a system-call record but cannot be read.

    Not noise: a tracer misconfiguration, or a record broken on purpose to hide a call.
    The collector counts and reports these lines.
    """


def _value(raw: str) -> str:
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if _HEX.match(raw):  # auditd hex-encodes values with special characters
        try:
            return bytes.fromhex(raw).decode("utf-8", errors="replace").rstrip("\x00")
        except ValueError:
            return raw
    return raw


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        number = int(value)
    except ValueError:
        return None
    return None if number in (4294967295, -1) else number  # auditd's "unset" id


def parse_audit_line(line: str) -> SyscallRecord | None:
    """A ``SYSCALL`` record of the audit log, or ``None`` for any other record."""
    text, _, enriched = line.rstrip("\r\n").partition("\x1d")
    match = _AUDIT_LINE.match(text)
    if match is None or match.group("type") != "SYSCALL":
        return None
    fields = dict(_FIELD.findall(match.group("body")))
    extra = dict(_FIELD.findall(enriched))
    pid = _int(fields.get("pid"))
    if pid is None:
        return None
    name = extra.get("SYSCALL")
    if not name:
        table = ARCH_TABLES.get(fields.get("arch", ""), {})
        number = _int(fields.get("syscall"))
        if number is None:
            return None
        name = table.get(number, f"syscall_{number}")
    success = fields.get("success")
    milliseconds = match.group("ms").ljust(3, "0")[:3]
    return SyscallRecord(
        timestamp_ns=int(match.group("s")) * 1_000_000_000 + int(milliseconds) * 1_000_000,
        pid=pid,
        syscall=name,
        comm=_value(fields.get("comm", '"?"')),
        marker=match.group("serial"),
        ppid=_int(fields.get("ppid")),
        uid=_int(fields.get("uid")),
        auid=_int(fields.get("auid")),
        exe=_value(fields["exe"]) if "exe" in fields else None,
        success=None if success is None else success == "yes",
        key=_value(fields["key"]) if fields.get("key", "(null)") != "(null)" else None,
    )


def parse_ebpf_line(line: str) -> SyscallRecord | None:
    """One record of ``adis-syscalls.bt`` run with ``bpftrace -f json``.

    A call is a tuple whose strings bpftrace escapes, so a process name or path cannot
    break or forge it: ``{"type": "value", "data": [ts, ns, pid, ppid, uid, comm, probe,
    filename?]}``.

    Returns:
        The call, or ``None`` for bpftrace's own messages and blank lines.

    Raises:
        UnreadableRecordError: Anything else: a damaged line, text output (``-f text``)
            or the tracer's earlier ``printf`` format, which a crafted path could break
            or forge and which is therefore not trusted.
    """
    if not line.strip():
        return None
    try:
        # strict=False: control characters in a name must not make the record unreadable.
        message = json.loads(line, strict=False)
    except ValueError:
        raise UnreadableRecordError("not JSON (is bpftrace run with -f json?)") from None
    if not isinstance(message, dict) or not isinstance(message.get("type"), str):
        raise UnreadableRecordError("not a bpftrace -f json message")
    if message["type"] != "value":
        return None  # attached_probes, printf, lost_events...: not a call
    values = message.get("data")
    if not isinstance(values, list) or len(values) not in (7, 8):
        raise UnreadableRecordError("not a call tuple")
    ts, ns, pid, ppid, uid, comm, probe, *rest = values
    filename = rest[0] if rest else None
    if not isinstance(pid, int) or not isinstance(comm, str) or not isinstance(probe, str):
        raise UnreadableRecordError("invalid pid, comm or probe")
    try:
        seconds = float(str(ts))
    except ValueError:
        raise UnreadableRecordError("invalid ts") from None
    return SyscallRecord(
        timestamp_ns=int(seconds * 1_000_000_000),
        pid=pid,
        syscall=probe.removeprefix("tracepoint:syscalls:sys_enter_"),
        comm=comm,
        marker=str(ns),
        ppid=_int(str(ppid)),
        uid=_int(str(uid)),
        exe=filename if isinstance(filename, str) and filename else None,
    )


@dataclass(slots=True)
class OpenSequence:
    """Calls of one process not yet emitted."""

    first: SyscallRecord
    first_offset: int
    last_ns: int
    calls: list[str] = field(default_factory=list)
    failed: int = 0
    uids: set[int] = field(default_factory=set)
    exe: str | None = None


class SequenceAggregator:
    """Groups calls per process into windows of at most ``max_length`` calls."""

    def __init__(self, *, window_seconds: float, max_length: int) -> None:
        self._window_ns = int(window_seconds * 1_000_000_000)
        self._max_length = max_length
        self._open: OrderedDict[int, OpenSequence] = OrderedDict()

    @property
    def oldest_offset(self) -> int | None:
        """File offset of the first call still waiting in an open sequence."""
        return min((sequence.first_offset for sequence in self._open.values()), default=None)

    def add(self, record: SyscallRecord, offset: int) -> list[OpenSequence]:
        """Account for one call; returns the sequences that closed."""
        closed: list[OpenSequence] = []
        sequence = self._open.get(record.pid)
        if (
            sequence is not None
            and record.timestamp_ns - sequence.first.timestamp_ns > self._window_ns
        ):
            closed.append(self._open.pop(record.pid))
            sequence = None
        if sequence is None:
            if len(self._open) >= MAX_OPEN_SEQUENCES:
                closed.append(self._open.popitem(last=False)[1])
            sequence = OpenSequence(record, offset, record.timestamp_ns)
            self._open[record.pid] = sequence
        else:
            self._open.move_to_end(record.pid)
        sequence.calls.append(record.syscall)
        sequence.last_ns = max(sequence.last_ns, record.timestamp_ns)
        if record.success is False:
            sequence.failed += 1
        if record.uid is not None:
            sequence.uids.add(record.uid)
        if record.exe:
            sequence.exe = record.exe
        if len(sequence.calls) >= self._max_length:
            closed.append(self._open.pop(record.pid))
        return closed

    def expire(self, now_ns: int) -> list[OpenSequence]:
        """Sequences whose window has passed by ``now_ns``."""
        due = [
            pid
            for pid, sequence in self._open.items()
            if now_ns - sequence.first.timestamp_ns > self._window_ns
        ]
        return [self._open.pop(pid) for pid in due]

    def flush(self) -> list[OpenSequence]:
        """Every open sequence."""
        sequences = list(self._open.values())
        self._open.clear()
        return sequences


def _utc(timestamp_ns: int) -> datetime:
    seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, UTC).replace(microsecond=nanoseconds // 1_000)


def _process_name(record: SyscallRecord, exe: str | None) -> str:
    if record.comm and record.comm != "?":
        return record.comm
    return (exe or "unknown").replace("\\", "/").rsplit("/", 1)[-1] or "unknown"


class SyscallMapper:
    """Records and closed sequences → canonical ``ProcessEvent``s."""

    def __init__(
        self, context: CollectorContext, *, collector: str, source_type: str, window_seconds: float
    ) -> None:
        self._context = context
        self._collector = collector
        self._source_type = source_type
        self._window_seconds = window_seconds

    def started(self, record: SyscallRecord) -> ProcessEvent | None:
        """A ``process.started`` event for a successful (or not failed) exec call."""
        if record.syscall not in EXEC_SYSCALLS or record.success is False:
            return None
        metadata: dict[str, JsonValue] = {
            "syscall": record.syscall,
            "outcome_known": record.success is not None,
            "uid": record.uid,
            "auid": record.auid,
            "audit_key": record.key,
            "marker": record.marker,
        }
        return self._event(
            PROCESS_STARTED_EVENT_TYPE,
            record,
            record.exe,
            f"exec|{record.marker}",
            {key: value for key, value in metadata.items() if value is not None},
        )

    def sequence(self, sequence: OpenSequence) -> ProcessEvent:
        """A ``process.syscall_sequence`` event."""
        first = sequence.first
        counts = Counter(sequence.calls)
        calls: list[JsonValue] = [*sequence.calls]
        uids: list[JsonValue] = [*sorted(sequence.uids)]
        metadata: dict[str, JsonValue] = {
            "sequence_schema": "adis.syscall_sequence.v1",
            "syscalls": calls,
            "count": len(sequence.calls),
            "distinct": len(counts),
            "syscall_counts": dict(counts.most_common()),
            "first_seen": _utc(first.timestamp_ns).isoformat(),
            "last_seen": _utc(sequence.last_ns).isoformat(),
            "duration_seconds": round((sequence.last_ns - first.timestamp_ns) / 1e9, 6),
            "window_seconds": self._window_seconds,
            "uids": uids,
        }
        if sequence.failed:
            metadata["failed_calls"] = sequence.failed
        return self._event(
            SEQUENCE_EVENT_TYPE,
            first,
            sequence.exe or first.exe,
            f"sequence|{first.timestamp_ns}|{first.marker}",
            metadata,
        )

    def _event(
        self,
        event_type: str,
        record: SyscallRecord,
        exe: str | None,
        identity: str,
        metadata: dict[str, JsonValue],
    ) -> ProcessEvent:
        host_id = self._context.identity.host_id
        return ProcessEvent.model_validate(
            {
                "event_id": uuid5(
                    SEQUENCE_ID_NAMESPACE, f"{self._source_type}|{host_id}|{record.pid}|{identity}"
                ),
                "event_type": event_type,
                "timestamp": _utc(record.timestamp_ns),
                "source_type": self._source_type,
                "source_name": self._context.source_name(self._collector),
                "host_id": host_id,
                "agent_id": self._context.agent_id,
                "process_name": _process_name(record, exe),
                "process_id": record.pid,
                "parent_process_id": record.ppid,
                "executable_path": exe,
                "metadata": metadata,
            }
        )


class SyscallFileCollector:
    """Tails an auditd log or eBPF output file and spools call sequences."""

    def __init__(
        self,
        name: str,
        path: Path,
        parse: Callable[[str], SyscallRecord | None],
        context: CollectorContext,
        *,
        source_type: str,
        window_seconds: float,
        max_length: int,
        read_from_start: bool,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        self._name = name
        self._tail = LineTail(path, read_from_start=read_from_start)
        self._parse = parse
        self._aggregator = SequenceAggregator(window_seconds=window_seconds, max_length=max_length)
        self._mapper = SyscallMapper(
            context, collector=name, source_type=source_type, window_seconds=window_seconds
        )
        self._key = f"{name}:{Path(path).resolve()}"
        self._position: TailPosition | None = None
        self._loaded = False
        self._clock_ns = clock_ns
        self.counters: Counter[str] = Counter()

    @property
    def name(self) -> str:
        """Collector name."""
        return self._name

    async def run(self, sink: EventSink) -> None:
        """Read new records until cancelled."""
        while True:
            await self.poll(sink)
            await asyncio.sleep(POLL_SECONDS)

    async def poll(self, sink: EventSink) -> int:
        """Process new lines and expired windows once; returns the events spooled."""
        if not self._loaded:
            stored = await sink.checkpoint(self._key)
            self._position = TailPosition.decode(stored) if stored else None
            self._loaded = True
        chunk = await self._tail.read(self._position)
        events: list[AnyCanonicalEvent] = []
        end = self._position
        if chunk is not None:
            unreadable: list[int] = []
            for offset, raw in chunk.lines:
                try:
                    record = self._parse(raw.decode("utf-8", errors="replace"))
                except UnreadableRecordError:
                    self.counters["unreadable"] += 1
                    unreadable.append(offset)
                    continue
                if record is None:
                    self.counters["skipped"] += 1
                    continue
                self.counters["calls"] += 1
                events.extend(self._started(record))
                events.extend(self._sequences(self._aggregator.add(record, offset)))
            end = chunk.end
            if unreadable:
                self._report_unreadable(unreadable)
        events.extend(self._sequences(self._aggregator.expire(self._clock_ns())))
        if end is None or (not events and end == self._position):
            return 0
        oldest = self._aggregator.oldest_offset
        resume = replace(end, offset=min(end.offset, oldest)) if oldest is not None else end
        await sink.submit(events, checkpoints={self._key: resume.encode()})
        self._position = end
        return len(events)

    def _started(self, record: SyscallRecord) -> list[AnyCanonicalEvent]:
        try:
            started = self._mapper.started(record)
        except ValidationError:
            self.counters["unmappable"] += 1
            return []
        return [started] if started is not None else []

    def _report_unreadable(self, offsets: list[int]) -> None:
        """Log lines that should be records but cannot be read (one line per poll)."""
        logger.warning(
            "unreadable lines in the system-call file; they may hide calls",
            extra={
                "action": "agent_syscall_unreadable",
                "collector": self._name,
                "path": str(self._tail.path),
                "lines": len(offsets),
                "first_offset": offsets[0],
                "total": self.counters["unreadable"],
            },
        )

    def _sequences(self, sequences: list[OpenSequence]) -> list[AnyCanonicalEvent]:
        events: list[AnyCanonicalEvent] = []
        for sequence in sequences:
            try:
                events.append(self._mapper.sequence(sequence))
            except ValidationError:
                self.counters["unmappable"] += 1
        return events
