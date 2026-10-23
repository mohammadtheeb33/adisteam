"""System-call collectors: audit log and eBPF parsing, call sequences, file collection."""

import json
import logging
from pathlib import Path

import pytest

from apps.agent.collectors.syscalls import (
    SequenceAggregator,
    SyscallFileCollector,
    SyscallMapper,
    UnreadableRecordError,
    parse_audit_line,
    parse_ebpf_line,
)
from packages.events.canonical import ProcessEvent, parse_canonical_event, serialize_canonical_event
from tests.unit.agent.fakes import MemorySink, make_context

# Records in the format the Linux audit daemon writes (RAW and ENRICHED log formats).
AUDIT_EXEC = (
    "type=SYSCALL msg=audit(1792427911.512:2201): arch=c000003e syscall=59 success=yes exit=0 "
    "a0=55d6a2b3c4d0 a1=55d6a2b3c510 a2=55d6a2b3c528 a3=8 items=2 ppid=4120 pid=4185 auid=1000 "
    "uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 "
    'ses=3 comm="curl" exe="/usr/bin/curl" subj=unconfined key="adis_exec"'
)
AUDIT_EXECVE_ARGS = (
    'type=EXECVE msg=audit(1792427911.512:2201): argc=3 a0="curl" a1="-u" a2="lab:hunter2"'
)
AUDIT_CONNECT = (
    "type=SYSCALL msg=audit(1792427911.640:2202): arch=c000003e syscall=42 success=no "
    "exit=-115 a0=5 a1=7ffd2b6e8a10 a2=10 a3=0 items=0 ppid=4120 pid=4185 auid=1000 uid=1000 "
    "gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 "
    'comm="curl" exe="/usr/bin/curl" subj=unconfined key="adis_net"'
)
AUDIT_ENRICHED_HEX_COMM = (
    "type=SYSCALL msg=audit(1792427912.001:2203): arch=c000003e syscall=101 success=yes exit=0 "
    "a0=10 a1=4186 a2=0 a3=0 items=0 ppid=1 pid=4190 auid=4294967295 uid=0 gid=0 euid=0 "
    "suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=2F746D702F78 "
    'exe="/tmp/x" subj=unconfined key="adis_isolation"\x1dARCH=x86_64 SYSCALL=ptrace '
    'AUID="unset" UID="root"'
)


# Lines written by infrastructure/ebpf/adis-syscalls.bt under bpftrace 0.20.4 (-f json) in
# the lab, for executables named to break or forge a record (deep audit C-3), and for a
# process named "bpftrace" (C-4).
EBPF_ATTACHED = '{"type": "attached_probes", "data": {"probes": 30}}'
EBPF_QUOTE_AND_BACKSLASH = (
    '{"type": "value", "data": [1792445069.910953,18602508994032,54658,54645,0,"sh",'
    r'"tracepoint:syscalls:sys_enter_execve","/tmp/x\"y\\z"]}'
)
EBPF_NEWLINE = (
    '{"type": "value", "data": [1792445069.913919,18602511959751,54660,54645,0,"sh",'
    r'"tracepoint:syscalls:sys_enter_execve","/tmp/a\nb"]}'
)
EBPF_FORGED_FIELD = (
    '{"type": "value", "data": [1792445069.918480,18602516521188,54645,54629,0,"sh",'
    r'"tracepoint:syscalls:sys_enter_execve","/tmp/q\",\"syscall\":\"forged"]}'
)
EBPF_RENAMED_TRACER = (
    '{"type": "value", "data": [1792445097.695045,18630295698302,54748,54730,0,"bpftrace",'
    '"tracepoint:syscalls:sys_enter_kill"]}'
)
# The same exec in the tracer's earlier printf format: the quote breaks the line.
EBPF_PRINTF_BROKEN = (
    '{"ts":"1792445132.779728","ns":18665384218389,"pid":54840,"ppid":54825,"uid":0,'
    '"comm":"sh","syscall":"tracepoint:syscalls:sys_enter_execve","filename":"/tmp/x"y"}'
)
TRACER = Path(__file__).resolve().parents[3] / "infrastructure" / "ebpf" / "adis-syscalls.bt"


def _ebpf(ts: float, pid: int, syscall: str, *, filename: str | None = None) -> str:
    values: list[object] = [
        float(f"{ts:.6f}"),
        int(ts * 1e9),
        pid,
        1,
        0,
        "sh",
        f"tracepoint:syscalls:sys_enter_{syscall}",
    ]
    if filename is not None:
        values.append(filename)
    return json.dumps({"type": "value", "data": values})


# ---------------------------------------------------------------------------------- parsing


def test_audit_syscall_records_are_parsed() -> None:
    record = parse_audit_line(AUDIT_EXEC)

    assert record is not None
    assert (record.syscall, record.pid, record.ppid, record.comm) == ("execve", 4185, 4120, "curl")
    assert (record.exe, record.success, record.uid, record.key) == (
        "/usr/bin/curl",
        True,
        1000,
        "adis_exec",
    )
    assert record.timestamp_ns == 1_792_427_911_512_000_000
    assert record.marker == "2201"


def test_audit_numbers_hex_names_and_enriched_names_are_understood() -> None:
    connect = parse_audit_line(AUDIT_CONNECT)
    enriched = parse_audit_line(AUDIT_ENRICHED_HEX_COMM)

    assert connect is not None
    assert (connect.syscall, connect.success) == ("connect", False)
    assert enriched is not None
    assert (enriched.syscall, enriched.comm, enriched.auid) == ("ptrace", "/tmp/x", None)  # noqa: S108 - an audit record value


def test_other_audit_records_and_arguments_are_ignored() -> None:
    assert parse_audit_line(AUDIT_EXECVE_ARGS) is None
    assert parse_audit_line("garbage") is None


def test_ebpf_lines_are_parsed() -> None:
    record = parse_ebpf_line(_ebpf(1792427911.5, 77, "execve", filename="/bin/ls"))

    assert record is not None
    assert (record.syscall, record.pid, record.exe) == ("execve", 77, "/bin/ls")
    assert record.timestamp_ns == 1_792_427_911_500_000_000
    assert parse_ebpf_line(EBPF_ATTACHED) is None
    assert parse_ebpf_line('{"type": "lost_events", "data": {"events": 3}}') is None
    assert parse_ebpf_line("\n") is None  # bpftrace ends its output with blank lines


def test_ebpf_names_and_paths_cannot_break_or_forge_a_record() -> None:
    quoted = parse_ebpf_line(EBPF_QUOTE_AND_BACKSLASH)
    newline = parse_ebpf_line(EBPF_NEWLINE)
    forged = parse_ebpf_line(EBPF_FORGED_FIELD)

    assert quoted is not None
    assert (quoted.syscall, quoted.pid, quoted.ppid, quoted.comm) == ("execve", 54658, 54645, "sh")
    assert quoted.exe == '/tmp/x"y\\z'  # noqa: S108 - a traced path
    assert newline is not None
    assert newline.exe == "/tmp/a\nb"  # noqa: S108 - a traced path
    assert forged is not None
    assert (forged.syscall, forged.exe) == ("execve", '/tmp/q","syscall":"forged')  # noqa: S108


def test_a_process_named_bpftrace_is_traced() -> None:
    record = parse_ebpf_line(EBPF_RENAMED_TRACER)

    assert record is not None
    assert (record.comm, record.syscall) == ("bpftrace", "kill")


@pytest.mark.parametrize(
    "line",
    [
        EBPF_PRINTF_BROKEN,
        '{"ts":"1.0","pid":1,"syscall":"execve","syscall":"forged"}',  # the old flat format
        "Attaching 30 probes...",  # -f text
        '{"type": "value", "data": [1, 2, 3]}',
        '{"type": "value", "data": [1.0, 2, "1", 1, 0, "sh", "p"]}',
    ],
)
def test_lines_that_are_not_tracer_records_are_unreadable(line: str) -> None:
    with pytest.raises(UnreadableRecordError):
        parse_ebpf_line(line)


def test_tracer_excludes_itself_by_pid_and_escapes_its_output() -> None:
    script = TRACER.read_text(encoding="utf-8")
    probes = [block for block in script.split("\n\n") if block.startswith("tracepoint:")]

    assert 'comm != "bpftrace"' not in script  # any process can take that name
    assert "@tracer = pid;" in script.split("BEGIN", 1)[1].split("}", 1)[0]
    assert len(probes) == 2
    for block in probes:
        assert "/ pid != @tracer /" in block
        assert "print((" in block  # a tuple, escaped by -f json
        assert "printf" not in block


# ------------------------------------------------------------------------------- sequences


def test_sequences_close_on_window_length_and_expiry() -> None:
    aggregator = SequenceAggregator(window_seconds=10, max_length=3)

    for second in range(3):
        closed = aggregator.add(parse_ebpf_line(_ebpf(100 + second, 1, "connect")), second)  # type: ignore[arg-type]
    assert [len(s.calls) for s in closed] == [3]

    aggregator.add(parse_ebpf_line(_ebpf(200, 2, "bind")), 10)  # type: ignore[arg-type]
    [by_window] = aggregator.add(parse_ebpf_line(_ebpf(215, 2, "listen")), 11)  # type: ignore[arg-type]
    assert by_window.calls == ["bind"]

    [expired] = aggregator.expire(int(230e9))
    assert expired.calls == ["listen"]
    assert aggregator.oldest_offset is None


def test_sequence_and_exec_events_are_canonical_process_events() -> None:
    mapper = SyscallMapper(
        make_context(), collector="auditd", source_type="auditd", window_seconds=10
    )
    exec_record = parse_audit_line(AUDIT_EXEC)
    connect_record = parse_audit_line(AUDIT_CONNECT)
    assert exec_record is not None
    assert connect_record is not None
    aggregator = SequenceAggregator(window_seconds=10, max_length=8)
    aggregator.add(exec_record, 0)
    aggregator.add(connect_record, 100)

    started = mapper.started(exec_record)
    [sequence] = [mapper.sequence(s) for s in aggregator.flush()]

    assert isinstance(started, ProcessEvent)
    assert (started.event_type, started.process_name, started.process_id) == (
        "process.started",
        "curl",
        4185,
    )
    assert sequence.event_type == "process.syscall_sequence"
    assert sequence.metadata["syscalls"] == ["execve", "connect"]
    assert sequence.metadata["failed_calls"] == 1
    assert "hunter2" not in serialize_canonical_event(sequence).decode()
    for event in (started, sequence):
        assert parse_canonical_event(serialize_canonical_event(event)) == event


def test_failed_exec_is_not_a_process_start() -> None:
    mapper = SyscallMapper(
        make_context(), collector="auditd", source_type="auditd", window_seconds=10
    )
    failed = parse_audit_line(AUDIT_EXEC.replace("success=yes exit=0", "success=no exit=-2"))

    assert failed is not None
    assert mapper.started(failed) is None


# -------------------------------------------------------------------------------- collector


def _collector(path: Path, clock: list[int]) -> SyscallFileCollector:
    return SyscallFileCollector(
        "ebpf",
        path,
        parse_ebpf_line,
        make_context(),
        source_type="ebpf",
        window_seconds=10,
        max_length=64,
        read_from_start=True,
        clock_ns=lambda: clock[0],
    )


async def test_file_collector_emits_and_checkpoints_before_open_sequences(tmp_path: Path) -> None:
    trace = tmp_path / "ebpf.jsonl"
    trace.write_text(
        EBPF_ATTACHED
        + "\n"
        + _ebpf(100.0, 5, "execve", filename="/usr/bin/curl")
        + "\n"
        + _ebpf(100.5, 5, "connect")
        + "\n",
        newline="\n",
    )
    clock = [int(101e9)]
    sink = MemorySink()
    collector = _collector(trace, clock)

    assert await collector.poll(sink) == 1  # the exec; the sequence is still open
    [checkpoint] = sink.checkpoints.values()
    assert json.loads(checkpoint)["offset"] == len(EBPF_ATTACHED) + 1

    clock[0] = int(120e9)
    assert await collector.poll(sink) == 1  # the window passed: the sequence closes
    sequence = sink.events[-1]
    assert isinstance(sequence, ProcessEvent)
    assert sequence.metadata["syscalls"] == ["execve", "connect"]
    assert json.loads(next(iter(sink.checkpoints.values())))["offset"] == trace.stat().st_size


async def test_restart_rebuilds_open_sequences_with_the_same_ids(tmp_path: Path) -> None:
    trace = tmp_path / "ebpf.jsonl"
    trace.write_text(
        _ebpf(100.0, 5, "bind") + "\n" + _ebpf(101.0, 5, "listen") + "\n", newline="\n"
    )
    sink = MemorySink()
    await _collector(trace, [int(102e9)]).poll(sink)  # sequence open, nothing emitted

    restarted = _collector(trace, [int(200e9)])
    await restarted.poll(sink)
    again = _collector(trace, [int(200e9)])
    again_sink = MemorySink()
    await again.poll(again_sink)

    [sequence] = sink.events
    assert isinstance(sequence, ProcessEvent)
    assert sequence.metadata["syscalls"] == ["bind", "listen"]
    assert again_sink.events[0].event_id == sequence.event_id


async def test_unreadable_lines_are_counted_and_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    trace = tmp_path / "ebpf.jsonl"
    invalid_exec = EBPF_QUOTE_AND_BACKSLASH.replace("54658,", "-1,", 1)  # fails validation
    trace.write_text(
        "\n".join([EBPF_PRINTF_BROKEN, invalid_exec, EBPF_NEWLINE, ""]) + "\n", newline="\n"
    )
    collector = _collector(trace, [int(1792445070e9)])

    with caplog.at_level(logging.WARNING):
        assert await collector.poll(MemorySink()) == 1  # the exec of "/tmp/a<newline>b"

    assert collector.counters["unreadable"] == 1
    assert collector.counters["unmappable"] == 1  # and the collector did not crash
    [warning] = [
        r for r in caplog.records if getattr(r, "action", "") == "agent_syscall_unreadable"
    ]
    assert (getattr(warning, "lines", None), getattr(warning, "first_offset", None)) == (1, 0)


async def test_missing_file_is_waited_for(tmp_path: Path) -> None:
    collector = _collector(tmp_path / "later.jsonl", [0])

    assert await collector.poll(MemorySink()) == 0


GARBAGE = ("{", "type=SYSCALL msg=audit(x): pid=a", '{"ts": "x", "pid": 1, "syscall": 1}')


def test_audit_parser_never_raises_on_garbage() -> None:
    for line in ("", *GARBAGE):
        assert parse_audit_line(line) is None


def test_ebpf_parser_reports_garbage_as_unreadable() -> None:
    for line in GARBAGE:
        with pytest.raises(UnreadableRecordError):
            parse_ebpf_line(line)
