"""Checkpointed line tailing across rotation, copytruncate and restarts (deep audit C-2)."""

import os
import shutil
import time
from pathlib import Path

from apps.agent.collectors.tail import LineTail, TailPosition


def _append(path: Path, data: bytes) -> None:
    with path.open("ab") as handle:
        handle.write(data)


async def _lines(tail: LineTail, position: TailPosition | None) -> tuple[list[bytes], TailPosition]:
    chunk = await tail.read(position)
    assert chunk is not None
    return [line for _, line in chunk.lines], chunk.end


async def test_lines_written_before_a_rename_are_read_before_the_new_file(tmp_path: Path) -> None:
    trace = tmp_path / "audit.log"
    trace.write_bytes(b"one\ntwo\n")
    tail = LineTail(trace, read_from_start=True)
    read, position = await _lines(tail, None)
    _append(trace, b"three\nfour\n")  # written, then the file is rotated before a poll
    os.replace(trace, tmp_path / "audit.log.1")
    trace.write_bytes(b"five\n")

    drained, position = await _lines(tail, position)
    fresh, end = await _lines(tail, position)

    assert (read, drained, fresh) == ([b"one\n", b"two\n"], [b"three\n", b"four\n"], [b"five\n"])
    assert end.generation == 1


async def test_copytruncate_refilled_past_the_old_offset_is_detected(tmp_path: Path) -> None:
    trace = tmp_path / "ebpf.jsonl"
    trace.write_bytes(b'{"n": 1, "t": "2026-10-20T00:00:01"}\n')
    tail = LineTail(trace, read_from_start=True)
    _, position = await _lines(tail, None)
    _append(trace, b'{"n": 2, "t": "2026-10-20T00:00:02"}\n')  # not read yet
    shutil.copyfile(trace, tmp_path / "ebpf.jsonl.1")
    with trace.open("r+b") as handle:  # truncated in place, then refilled past the offset
        handle.truncate(0)
        handle.write(b'{"n": 3, "t": "2026-10-20T00:01:00", "pad": "....."}\n{"n": 4}\n')

    from_copy, position = await _lines(tail, position)
    fresh, _ = await _lines(tail, position)

    assert from_copy == [b'{"n": 2, "t": "2026-10-20T00:00:02"}\n']
    # Before, reading went on at the old offset in the middle of the new first line.
    assert fresh == [b'{"n": 3, "t": "2026-10-20T00:01:00", "pad": "....."}\n', b'{"n": 4}\n']


async def test_truncation_without_a_copy_restarts_from_the_beginning(tmp_path: Path) -> None:
    trace = tmp_path / "goflow2.jsonl"
    trace.write_bytes(b"first record with some length\n")
    tail = LineTail(trace, read_from_start=True)
    _, position = await _lines(tail, None)
    with trace.open("r+b") as handle:
        handle.truncate(0)
        handle.write(b"a new, different and longer first record\n")

    lines, end = await _lines(tail, position)

    assert lines == [b"a new, different and longer first record\n"]
    assert (end.generation, end.inode) == (1, position.inode)


async def test_the_last_line_of_a_previous_file_is_read_once_it_is_quiet(tmp_path: Path) -> None:
    trace = tmp_path / "audit.log"
    trace.write_bytes(b"one\n")
    tail = LineTail(trace, read_from_start=True)
    _, position = await _lines(tail, None)
    _append(trace, b"cut off")
    rotated = tmp_path / "audit.log.1"
    os.replace(trace, rotated)
    trace.write_bytes(b"two\n")

    waiting, still = await _lines(tail, position)  # the writer may still finish the line
    past = time.time() - 60
    os.utime(rotated, (past, past))
    last, after = await _lines(tail, still)
    fresh, _ = await _lines(tail, after)

    assert (waiting, still) == ([], position)  # reading stays on the previous file
    assert (last, fresh) == ([b"cut off"], [b"two\n"])


async def test_checkpoints_carry_the_fingerprint_and_older_ones_still_load(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "audit.log"
    trace.write_bytes(b"one\n")
    _, position = await _lines(LineTail(trace, read_from_start=True), None)

    assert TailPosition.decode(position.encode()) == position
    assert (position.head_size, len(position.head)) == (4, 64)
    legacy = TailPosition.decode('{"device": 1, "inode": 2, "generation": 3, "offset": 4}')
    assert legacy == TailPosition(1, 2, 3, 4)
