"""Syslog receiver: RFC 5424 and 3164 parsing, sshd/PAM authentication, sessions, transport."""

import asyncio
import socket
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network, ip_network

import pytest

from apps.agent.collectors.syslog import (
    SyslogMapper,
    SyslogReceiver,
    parse_syslog,
)
from packages.events.canonical import (
    AnyCanonicalEvent,
    AuthenticationEvent,
    AuthFailureReason,
    AuthMethod,
    SeverityHint,
    SystemEvent,
    parse_canonical_event,
    serialize_canonical_event,
)
from tests.unit.agent.fakes import MemorySink, make_context, wait_until

NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=UTC)


def _mapper(clock: list[datetime] | None = None) -> SyslogMapper:
    moments = clock if clock is not None else [NOW]
    return SyslogMapper(
        make_context(),
        max_message_bytes=8192,
        failure_window=timedelta(hours=1),
        max_open_sessions=100,
        clock=lambda: moments[0],
    )


def _events(lines: list[bytes], mapper: SyslogMapper | None = None) -> list[object]:
    mapper = mapper or _mapper()
    events: list[object] = []
    for line in lines:
        message = parse_syslog(line)
        assert message is not None
        events.extend(mapper.to_events(message, "192.0.2.50"))
    return events


# ---------------------------------------------------------------------------------- parsing


def test_rfc5424_is_parsed() -> None:
    message = parse_syslog(
        b'<38>1 2026-10-19T11:59:58.123+00:00 web-1 sshd 2201 - [meta seq="1"] Server listening'
    )

    assert message is not None
    assert (message.facility, message.severity, message.syslog_format) == (4, 6, "rfc5424")
    assert message.timestamp == datetime(2026, 10, 19, 11, 59, 58, 123000, tzinfo=UTC)
    assert (message.hostname, message.app_name, message.procid) == ("web-1", "sshd", "2201")
    assert message.structured_data == '[meta seq="1"]'
    assert message.message == "Server listening"


def test_rfc3164_classic_header_has_no_reliable_time() -> None:
    message = parse_syslog(b"<86>Oct 19 11:59:58 web-1 sudo[311]: pam_unix(sudo:session): x")

    assert message is not None
    assert message.timestamp is None
    assert message.reported_timestamp == "Oct 19 11:59:58"
    assert (message.hostname, message.app_name, message.procid) == ("web-1", "sudo", "311")


def test_rfc3164_with_iso_date_keeps_its_time() -> None:
    message = parse_syslog(b"<13>2026-10-19T11:59:00.5+02:00 web-1 cron[9]: job done")

    assert message is not None
    assert message.timestamp == datetime(2026, 10, 19, 9, 59, 0, 500000, tzinfo=UTC)


@pytest.mark.parametrize("data", [b"no header", b"<999>1 - - - - - -", b""])
def test_messages_without_a_valid_priority_are_refused(data: bytes) -> None:
    assert parse_syslog(data) is None


# ---------------------------------------------------------------------------------- mapping


def test_plain_messages_are_system_events() -> None:
    [event] = _events([b"<11>1 2026-10-19T11:59:00Z web-1 app - - - disk failure password=s3cret"])

    assert isinstance(event, SystemEvent)
    assert event.event_type == "system.syslog"
    assert event.host_id == "web-1"
    assert event.severity_hint is SeverityHint.MEDIUM
    assert "s3cret" not in str(event.metadata["message"])
    assert parse_canonical_event(serialize_canonical_event(event)) == event


def test_sender_address_names_hosts_without_a_usable_hostname() -> None:
    [event] = _events([b"<14>Oct 19 11:59:58 - app: hello"])

    assert isinstance(event, SystemEvent)
    assert event.host_id == "192.0.2.50"


def test_future_timestamps_are_dated_on_receipt() -> None:
    [event] = _events([b"<14>1 2026-10-19T13:00:00Z web-1 app - - - early clock"])

    assert isinstance(event, SystemEvent)
    assert event.timestamp == NOW
    assert event.metadata["sender_clock_ahead_seconds"] == 3600.0


def test_sshd_logins_become_authentication_events() -> None:
    accepted, failed, invalid = _events(
        [
            b"<38>Oct 19 11:59:58 web-1 sshd[700]: Accepted publickey for lab from 192.0.2.9 "
            b"port 50122 ssh2: ED25519 SHA256:abc",
            b"<38>Oct 19 11:59:59 web-1 sshd[701]: Failed password for lab from 192.0.2.9 "
            b"port 50123 ssh2",
            b"<38>Oct 19 12:00:00 web-1 sshd[702]: Invalid user typo-password from 192.0.2.9 "
            b"port 50124",
        ]
    )

    assert isinstance(accepted, AuthenticationEvent)
    assert (accepted.event_type, accepted.success, accepted.username) == (
        "authentication.login.ssh",
        True,
        "lab",
    )
    assert accepted.auth_method is AuthMethod.PUBLIC_KEY
    assert str(accepted.src_ip) == "192.0.2.9"
    assert isinstance(failed, AuthenticationEvent)
    assert failed.failure_reason is AuthFailureReason.INVALID_CREDENTIALS
    assert isinstance(invalid, AuthenticationEvent)
    assert (invalid.username, invalid.failure_reason) == (None, AuthFailureReason.UNKNOWN_USER)
    assert "typo-password" not in str(invalid.metadata.get("message"))  # name withheld


def test_rsyslog_rfc5424_messages_with_a_leading_space_are_recognized() -> None:
    # Found by the real-data lab: RSYSLOG_SyslogProtocol23Format keeps the space after
    # "sshd[22]:", so the message part starts with a space.
    [accepted] = _events(
        [
            b"<38>1 2026-10-19T11:59:00.123456+00:00 lab-ssh sshd 22 - -  Accepted publickey "
            b"for lab from 172.31.250.41 port 57030 ssh2: ED25519 SHA256:abc"
        ]
    )

    assert isinstance(accepted, AuthenticationEvent)
    assert accepted.event_type == "authentication.login.ssh"
    assert str(accepted.metadata["message"]).startswith("Accepted publickey")


def test_typed_names_of_nonexistent_accounts_never_leave_the_host() -> None:
    # Found by the real-data lab: the name also appears in sshd's follow-up lines.
    events = _events(
        [
            b"<38>1 2026-10-19T11:59:00Z lab-ssh sshd 40 - -  Invalid user hunter2 from "
            b"172.31.250.41 port 50000",
            b"<38>1 2026-10-19T11:59:00Z lab-ssh sshd 40 - -  Connection closed by invalid user "
            b"hunter2 172.31.250.41 port 50000 [preauth]",
            b"<38>1 2026-10-19T11:59:01Z lab-ssh sshd 41 - - Failed publickey for invalid user "
            b"hunter2 from 172.31.250.41 port 50001 ssh2",
        ]
    )

    assert len(events) == 3
    for event in events:
        assert "hunter2" not in serialize_canonical_event(event).decode()  # type: ignore[arg-type]
    assert sum(isinstance(e, AuthenticationEvent) and not e.success for e in events) == 2


def test_a_rejected_key_is_one_failure_not_two() -> None:
    # Found by the real-data lab: with LogLevel VERBOSE, sshd logs a rejected key as
    # "Failed publickey" and again as "Connection closed by authenticating user".
    events = _events(
        [
            b"<38>1 2026-10-19T11:59:00Z lab-ssh sshd 31 - - Failed publickey for lab from "
            b"172.31.250.41 port 50000 ssh2: ED25519 SHA256:abc",
            b"<38>1 2026-10-19T11:59:00Z lab-ssh sshd 31 - - Connection closed by authenticating "
            b"user lab 172.31.250.41 port 50000 [preauth]",
            b"<38>1 2026-10-19T11:59:05Z lab-ssh sshd 32 - - Connection closed by authenticating "
            b"user lab 172.31.250.41 port 50001 [preauth]",
        ]
    )

    failures = [e for e in events if isinstance(e, AuthenticationEvent)]
    assert [e.metadata.get("outcome") for e in failures] == [None, "closed_during_authentication"]
    assert sum(isinstance(e, SystemEvent) for e in events) == 1  # the duplicate line, kept raw


def test_pam_sessions_become_session_vectors() -> None:
    clock = [NOW]
    mapper = _mapper(clock)
    _events(
        [
            b"<38>1 2026-10-19T11:58:00Z web-1 sshd 900 - - Failed password for lab from "
            b"192.0.2.9 port 1 ssh2",
            b"<38>1 2026-10-19T11:59:00Z web-1 sshd 901 - - Accepted password for lab from "
            b"192.0.2.9 port 2 ssh2",
        ],
        mapper,
    )
    [started] = _events(
        [
            b"<86>1 2026-10-19T11:59:01Z web-1 sshd 901 - - pam_unix(sshd:session): session "
            b"opened for user lab(uid=1000) by (uid=0)"
        ],
        mapper,
    )
    [ended] = _events(
        [
            b"<86>1 2026-10-19T11:59:41Z web-1 sshd 901 - - pam_unix(sshd:session): session "
            b"closed for user lab"
        ],
        mapper,
    )

    assert isinstance(started, AuthenticationEvent)
    assert started.event_type == "authentication.session_started"
    assert isinstance(ended, AuthenticationEvent)
    assert ended.event_type == "authentication.session_ended"
    vector = ended.metadata["session_vector"]
    assert isinstance(vector, dict)
    values = vector["values"]
    assert isinstance(values, dict)
    assert values["duration_seconds"] == 40.0
    assert values["failed_attempts_before"] == 1
    assert values["remote"] == 1


def test_pam_authentication_failures_are_failed_logins() -> None:
    [failure] = _events(
        [
            b"<85>Oct 19 11:59:58 web-1 su[33]: pam_unix(su:auth): authentication failure; "
            b"logname=lab uid=1000 euid=0 tty=pts/0 ruser=lab rhost=  user=root"
        ]
    )

    assert isinstance(failure, AuthenticationEvent)
    assert (failure.event_type, failure.success, failure.username) == (
        "authentication.login.pam",
        False,
        "root",
    )


# -------------------------------------------------------------------------------- transport


def _receiver(allowed: list[IPv4Network]) -> SyslogReceiver:
    return SyslogReceiver(
        _mapper(),
        udp_listen=None,
        tcp_listen=None,
        allowed_senders=allowed,
        max_message_bytes=8192,
    )


def test_unlisted_senders_are_dropped() -> None:
    receiver = _receiver([IPv4Network("127.0.0.0/8")])

    receiver.received(b"<14>1 - web-1 app - - - hi", "198.51.100.7")
    receiver.received(b"<14>1 - web-1 app - - - hi", "127.0.0.1")

    assert receiver.counters["refused_sender"] == 1
    assert receiver.counters["received"] == 1


class BlockedSink(MemorySink):
    """A sink whose spool is full until ``release`` is set."""

    def __init__(self) -> None:
        super().__init__()
        self.release = asyncio.Event()

    async def submit(
        self, events: Sequence[AnyCanonicalEvent], *, checkpoints: Mapping[str, str] | None = None
    ) -> None:
        await self.release.wait()
        await super().submit(events, checkpoints=checkpoints)


async def test_udp_beyond_the_backlog_bound_is_dropped_and_counted() -> None:
    # The pending list used to grow without bound while the spool was full (deep audit C-6).
    receiver = SyslogReceiver(
        _mapper(),
        udp_listen=None,
        tcp_listen=None,
        allowed_senders=[IPv4Network("127.0.0.0/8")],
        max_message_bytes=8192,
        max_pending_events=5,
    )
    message = b"<14>1 2026-10-19T11:59:58Z web-1 app - - - flood"
    sink = BlockedSink()
    for _ in range(3):
        receiver.received(message, "127.0.0.1")
    flush = asyncio.create_task(receiver.flush(sink))
    await asyncio.sleep(0)  # the three events are being submitted; the spool is full

    for _ in range(1_000):
        receiver.received(message, "127.0.0.1")

    assert receiver.backlog == 5
    assert receiver.counters["dropped_queue_full"] == 998
    sink.release.set()
    await flush
    assert await receiver.flush(sink) == 2
    receiver.received(message, "127.0.0.1")  # room again: accepted
    assert (receiver.backlog, len(sink.events)) == (1, 5)


async def test_tcp_senders_are_paused_not_dropped_while_the_backlog_is_full() -> None:
    port = _free_port(socket.SOCK_STREAM)
    receiver = SyslogReceiver(
        _mapper(),
        udp_listen=None,
        tcp_listen=("127.0.0.1", port),
        allowed_senders=[ip_network("127.0.0.0/8")],
        max_message_bytes=8192,
        max_pending_events=2,
    )
    sink = BlockedSink()
    task = asyncio.create_task(receiver.run(sink))
    try:
        async with asyncio.timeout(5):
            await asyncio.sleep(0.2)
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            for number in range(10):
                writer.write(b"<14>1 2026-10-19T11:59:58Z web-1 app - - - tcp %d\n" % number)
            await writer.drain()
            await wait_until(lambda: receiver.counters["received"] == 2)
            await asyncio.sleep(0.3)
            assert receiver.counters["received"] == 2  # the connection is no longer read

            sink.release.set()
            await wait_until(lambda: len(sink.events) == 10)
            writer.close()
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert receiver.counters["dropped_queue_full"] == 0
    assert [event.metadata["message"] for event in sink.events] == [f"tcp {n}" for n in range(10)]


def _free_port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def test_udp_and_tcp_messages_are_received_and_spooled() -> None:
    udp_port, tcp_port = _free_port(socket.SOCK_DGRAM), _free_port(socket.SOCK_STREAM)
    receiver = SyslogReceiver(
        _mapper(),
        udp_listen=("127.0.0.1", udp_port),
        tcp_listen=("127.0.0.1", tcp_port),
        allowed_senders=[ip_network("127.0.0.0/8")],
        max_message_bytes=8192,
    )
    sink = MemorySink()
    task = asyncio.create_task(receiver.run(sink))
    try:
        async with asyncio.timeout(5):
            await wait_until(lambda: receiver.counters is not None)
            await asyncio.sleep(0.2)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.sendto(b"<14>Oct 19 11:59:58 web-1 app[1]: over udp", ("127.0.0.1", udp_port))
            reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
            framed = b"<14>1 2026-10-19T11:59:58Z web-1 app - - - octet counted"
            writer.write(str(len(framed)).encode() + b" " + framed)
            writer.write(b"<14>1 2026-10-19T11:59:59Z web-1 app - - - newline framed\n")
            await writer.drain()
            writer.close()
            await wait_until(lambda: len(sink.events) == 3)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    messages = sorted(str(event.metadata["message"]) for event in sink.events)
    assert messages == ["newline framed", "octet counted", "over udp"]
    del reader
