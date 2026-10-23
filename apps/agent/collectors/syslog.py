"""Syslog receiver: RFC 5424 and RFC 3164 messages over UDP and TCP.

Messages from allowed senders become canonical events:

- sshd and PAM authentication messages become ``AuthenticationEvent``s
  (``authentication.login.ssh``, ``authentication.login.pam``) and PAM session messages
  ``authentication.session_started`` / ``authentication.session_ended`` with a session
  vector (:mod:`apps.agent.collectors.sessions`);
- every other message is a ``system.syslog`` ``SystemEvent``.

Safeguards: the receiver listens on one configured address (loopback unless explicitly
allowed, never 0.0.0.0), accepts only senders in ``AGENT_SYSLOG_ALLOWED_SENDERS`` (others are
counted and dropped), caps every message at ``AGENT_SYSLOG_MAX_MESSAGE_BYTES``, redacts
secret-looking text, and withholds the name of a login attempt for an account that does not
exist (it may be a password typed into the user name prompt).

Memory is bounded: at most ``AGENT_SYSLOG_MAX_PENDING_EVENTS`` received events wait for the
spool. While the spool is full and that bound is reached, UDP messages are dropped and
counted (UDP has no flow control), and TCP connections are not read, so the backpressure
reaches the senders, which queue the messages themselves.

Timestamps: RFC 5424 and ISO-dated messages keep their own time; classic RFC 3164 headers
have no year or time zone, so the event is dated on receipt and the header is kept in
``metadata.reported_timestamp``. Syslog has no message identifier, so redelivered messages
cannot be deduplicated.
"""

import asyncio
import contextlib
import ipaddress
import logging
import re
from collections import Counter, OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from uuid import uuid4

from pydantic import JsonValue, ValidationError

from apps.agent.collectors.base import CollectorContext, EventSink
from apps.agent.collectors.sessions import SessionTracker
from packages.events.canonical import (
    AnyCanonicalEvent,
    AuthenticationEvent,
    AuthFailureReason,
    AuthMethod,
    SeverityHint,
    SystemEvent,
)
from packages.events.canonical.v1 import IDENTIFIER_PATTERN
from packages.observability import redact_text

logger = logging.getLogger(__name__)

SOURCE_TYPE: Final = "syslog"
SYSTEM_EVENT_TYPE: Final = "system.syslog"
MAX_FUTURE_SKEW: Final = timedelta(minutes=5)
BATCH_EVENTS: Final = 500
FLUSH_SECONDS: Final = 1.0
MAX_TCP_CONNECTIONS: Final = 64
MAX_PENDING_EVENTS: Final = 10_000

FACILITIES: Final = (
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
    "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2",
    "local3", "local4", "local5", "local6", "local7",
)  # fmt: skip
SEVERITIES: Final = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
SEVERITY_HINTS: Final = (
    SeverityHint.CRITICAL,
    SeverityHint.CRITICAL,
    SeverityHint.HIGH,
    SeverityHint.MEDIUM,
    SeverityHint.LOW,
    SeverityHint.INFO,
    SeverityHint.INFO,
    SeverityHint.INFO,
)
SSH_METHODS: Final = {
    "password": AuthMethod.PASSWORD,
    "publickey": AuthMethod.PUBLIC_KEY,
    "keyboard-interactive/pam": AuthMethod.KEYBOARD_INTERACTIVE,
    "keyboard-interactive": AuthMethod.KEYBOARD_INTERACTIVE,
    "gssapi-with-mic": AuthMethod.KERBEROS,
    "hostbased": AuthMethod.OTHER,
    "none": AuthMethod.OTHER,
}

_PRI: Final = re.compile(rb"^<(\d{1,3})>")
_RFC5424: Final = re.compile(
    r"^1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$",
    re.DOTALL,
)
_RFC3164_CLASSIC: Final = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (?:(?P<host>\S+) )?(?P<rest>.*)$",
    re.DOTALL,
)
_RFC3164_ISO: Final = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) "
    r"(?P<host>\S+) (?P<rest>.*)$",
    re.DOTALL,
)
_TAG: Final = re.compile(
    r"^(?P<app>[^\s\[:]{1,48})(?:\[(?P<pid>[^\]]{1,16})\])?: ?(?P<msg>.*)$", re.DOTALL
)
_HOST_ID: Final = re.compile(IDENTIFIER_PATTERN)

_SSH_ACCEPTED: Final = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_FAILED: Final = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) "
    r"port (?P<port>\d+)"
)
_SSH_INVALID: Final = re.compile(
    r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)
_SSH_CLOSED_AUTH: Final = re.compile(
    r"^Connection closed by authenticating user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+) "
    r"\[preauth\]"
)
_PAM_SESSION: Final = re.compile(
    r"^pam_unix\((?P<service>[\w-]+):session\): session (?P<state>opened|closed) for user "
    r"(?P<user>[^\s(]+)"
)
_PAM_AUTH_FAILURE: Final = re.compile(
    r"^pam_unix\((?P<service>[\w-]+):auth\): authentication failure;(?P<fields>.*)$"
)
_PAM_FIELD: Final = re.compile(r"(\w+)=(\S*)")
_INVALID_USER_NAME: Final = re.compile(r"(?i)\b(invalid user )(?!from\b)\S+")


@dataclass(frozen=True, slots=True)
class SyslogMessage:
    """One parsed syslog message."""

    facility: int
    severity: int
    timestamp: datetime | None
    reported_timestamp: str | None
    hostname: str | None
    app_name: str | None
    procid: str | None
    msgid: str | None
    structured_data: str | None
    message: str
    syslog_format: str


def parse_syslog(data: bytes) -> SyslogMessage | None:
    """Parse one syslog message (RFC 5424, or RFC 3164 with a classic or ISO date).

    Returns ``None`` when there is no valid ``<PRI>`` header.
    """
    match = _PRI.match(data)
    if match is None or int(match.group(1)) > 191:
        return None
    pri = int(match.group(1))
    text = data[match.end() :].decode("utf-8", errors="replace").rstrip("\r\n\x00")
    text = text.removeprefix("﻿")
    facility, severity = divmod(pri, 8)
    if (rfc5424 := _RFC5424.match(text)) is not None:
        return SyslogMessage(
            facility=facility,
            severity=severity,
            timestamp=_iso_timestamp(rfc5424.group("ts")),
            reported_timestamp=_nil(rfc5424.group("ts")),
            hostname=_nil(rfc5424.group("host")),
            app_name=_nil(rfc5424.group("app")),
            procid=_nil(rfc5424.group("procid")),
            msgid=_nil(rfc5424.group("msgid")),
            structured_data=_nil(rfc5424.group("sd")),
            message=(rfc5424.group("msg") or "").removeprefix("﻿"),
            syslog_format="rfc5424",
        )
    timestamp: datetime | None = None
    header = _RFC3164_ISO.match(text)
    if header is not None:
        timestamp = _iso_timestamp(header.group("ts"))
    else:
        header = _RFC3164_CLASSIC.match(text)
    if header is None:
        return SyslogMessage(
            facility, severity, None, None, None, None, None, None, None, text, "rfc3164"
        )
    rest = header.group("rest")
    tag = _TAG.match(rest)
    return SyslogMessage(
        facility=facility,
        severity=severity,
        timestamp=timestamp,
        reported_timestamp=header.group("ts"),
        hostname=header.group("host"),
        app_name=tag.group("app") if tag else None,
        procid=tag.group("pid") if tag else None,
        msgid=None,
        structured_data=None,
        message=tag.group("msg") if tag else rest,
        syslog_format="rfc3164",
    )


def _withheld(
    metadata: dict[str, JsonValue], text: str, match: re.Match[str]
) -> dict[str, JsonValue]:
    """``metadata`` with the typed account name blanked out of the message.

    The name of a login attempt for an account that does not exist may be a password
    typed into the user name prompt, so it never leaves the host.
    """
    start, end = match.span("user")
    return {**metadata, "message": f"{text[:start]}[WITHHELD]{text[end:]}"}


def _nil(value: str | None) -> str | None:
    return None if value in (None, "-") else value


def _iso_timestamp(value: str) -> datetime | None:
    if value == "-":
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def _ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


class SyslogMapper:
    """Parsed messages → canonical events (authentication, sessions, system)."""

    def __init__(
        self,
        context: CollectorContext,
        *,
        max_message_bytes: int,
        failure_window: timedelta,
        max_open_sessions: int,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._context = context
        self._max_message = max_message_bytes
        self._sessions = SessionTracker(max_open=max_open_sessions, failure_window=failure_window)
        self._accepted: OrderedDict[tuple[str, str], tuple[str, str]] = OrderedDict()
        self._failed: OrderedDict[tuple[str, str], bool] = OrderedDict()
        self._clock = clock

    def to_events(self, message: SyslogMessage, sender: str) -> list[AnyCanonicalEvent]:
        """The events of one message."""
        received = self._clock()
        timestamp = message.timestamp or received
        clock_ahead: float | None = None
        if timestamp - received > MAX_FUTURE_SKEW:
            clock_ahead = round((timestamp - received).total_seconds(), 3)
            timestamp = received
        host_id = self._host_id(message, sender)
        # rsyslog's RFC 5424 output keeps the space that followed "sshd[22]:" (found by the
        # real-data lab), so surrounding whitespace is dropped before matching and storing.
        text = redact_text(message.message.strip())
        if (message.app_name or "").lower() == "sshd":
            # Every sshd line about a nonexistent account ("Invalid user X", "Connection
            # closed by invalid user X", ...) withholds the typed name.
            text = _INVALID_USER_NAME.sub(r"\1[WITHHELD]", text)
        if len(text.encode("utf-8")) > self._max_message:
            text = text.encode("utf-8")[: self._max_message].decode("utf-8", errors="ignore")
        metadata: dict[str, JsonValue] = {
            "sender_address": sender,
            "syslog_format": message.syslog_format,
            "facility": FACILITIES[message.facility],
            "severity": SEVERITIES[message.severity],
            "app_name": message.app_name,
            "procid": message.procid,
            "msgid": message.msgid,
            "hostname_reported": message.hostname,
            "reported_timestamp": message.reported_timestamp,
            "message": text,
        }
        if message.structured_data:
            metadata["structured_data"] = redact_text(message.structured_data)[:1024]
        if clock_ahead is not None:
            metadata["sender_clock_ahead_seconds"] = clock_ahead
        metadata = {key: value for key, value in metadata.items() if value is not None}
        auth = self._authentication(message, text, timestamp, host_id, metadata)
        if auth:
            return auth
        return [
            SystemEvent.model_validate(
                {
                    "event_id": uuid4(),
                    "event_type": SYSTEM_EVENT_TYPE,
                    "timestamp": timestamp,
                    "source_type": SOURCE_TYPE,
                    "source_name": self._context.source_name("syslog"),
                    "host_id": host_id,
                    "agent_id": self._context.agent_id,
                    "severity_hint": SEVERITY_HINTS[message.severity],
                    "metadata": metadata,
                }
            )
        ]

    def _host_id(self, message: SyslogMessage, sender: str) -> str:
        if message.hostname and _HOST_ID.match(message.hostname):
            return message.hostname.lower()
        return sender

    def _authentication(
        self,
        message: SyslogMessage,
        text: str,
        at: datetime,
        host_id: str,
        metadata: dict[str, JsonValue],
    ) -> list[AnyCanonicalEvent]:
        app = (message.app_name or "").lower()
        pid = message.procid or ""
        events: list[AnyCanonicalEvent] = []
        if app == "sshd":
            if accepted := _SSH_ACCEPTED.match(text):
                user, ip = accepted.group("user"), accepted.group("ip")
                self._remember(host_id, pid, ip, accepted.group("method"))
                events.append(
                    self._auth(
                        "authentication.login.ssh", at, host_id, metadata, user=user, ip=ip,
                        success=True, method=accepted.group("method"),
                        port=accepted.group("port"),
                    )
                )  # fmt: skip
            elif failed := _SSH_FAILED.match(text):
                unknown = bool(failed.group("invalid"))
                user = None if unknown else failed.group("user")
                self._sessions.failure(user, at, failed.group("ip"))
                self._note_failure(host_id, pid)
                shown = _withheld(metadata, text, failed) if unknown else metadata
                events.append(
                    self._auth(
                        "authentication.login.ssh", at, host_id, shown, user=user,
                        ip=failed.group("ip"), success=False, method=failed.group("method"),
                        port=failed.group("port"),
                        reason=AuthFailureReason.UNKNOWN_USER if unknown
                        else AuthFailureReason.INVALID_CREDENTIALS,
                        withheld=unknown,
                    )
                )  # fmt: skip
            elif invalid := _SSH_INVALID.match(text):
                events.append(
                    self._auth(
                        "authentication.login.ssh", at, host_id,
                        _withheld(metadata, text, invalid), user=None,
                        ip=invalid.group("ip"), success=False, port=invalid.group("port"),
                        reason=AuthFailureReason.UNKNOWN_USER, withheld=True,
                    )
                )  # fmt: skip
            elif closed := _SSH_CLOSED_AUTH.match(text):
                if self._failed.pop((host_id, pid), None) is not None:
                    return events  # the "Failed ..." line of this connection was counted
                self._sessions.failure(closed.group("user"), at, closed.group("ip"))
                events.append(
                    self._auth(
                        "authentication.login.ssh", at, host_id, metadata,
                        user=closed.group("user"), ip=closed.group("ip"), success=False,
                        port=closed.group("port"), reason=AuthFailureReason.OTHER,
                        outcome="closed_during_authentication",
                    )
                )  # fmt: skip
        if session := _PAM_SESSION.match(text):
            event = self._session(session, at, host_id, pid, metadata)
            if event is not None:
                events.append(event)
        elif pam_failure := _PAM_AUTH_FAILURE.match(text):
            fields = dict(_PAM_FIELD.findall(pam_failure.group("fields")))
            user = fields.get("user") or None
            rhost = fields.get("rhost") or None
            self._sessions.failure(user, at, rhost)
            events.append(
                self._auth(
                    "authentication.login.pam", at, host_id, metadata, user=user,
                    ip=rhost, success=False, reason=AuthFailureReason.INVALID_CREDENTIALS,
                    service=pam_failure.group("service"),
                )
            )  # fmt: skip
        return events

    def _remember(self, host_id: str, pid: str, ip: str, method: str) -> None:
        key = (host_id, pid)
        self._accepted[key] = (ip, method)
        self._accepted.move_to_end(key)
        while len(self._accepted) > 1_000:
            self._accepted.popitem(last=False)

    def _note_failure(self, host_id: str, pid: str) -> None:
        """Count a rejected key once although sshd logs it twice.

        With ``LogLevel VERBOSE`` a rejected key is logged as ``Failed publickey`` and again
        as ``Connection closed by authenticating user``; the connection's process id ties
        the two lines together.
        """
        self._failed[(host_id, pid)] = True
        while len(self._failed) > 1_000:
            self._failed.popitem(last=False)

    def _session(
        self,
        match: re.Match[str],
        at: datetime,
        host_id: str,
        pid: str,
        metadata: dict[str, JsonValue],
    ) -> AuthenticationEvent | None:
        user, service = match.group("user"), match.group("service")
        session_id = f"{host_id}:{service}:{pid}"
        source_ip, _method = self._accepted.get((host_id, pid), (None, None))
        if match.group("state") == "opened":
            vector = self._sessions.start(
                session_id, user, at, source_ip=source_ip, privileged=user == "root"
            )
            event_type = "authentication.session_started"
        else:
            ended = self._sessions.end(session_id, user, at)
            if ended is None:
                return None
            vector, event_type = ended, "authentication.session_ended"
        return AuthenticationEvent.model_validate(
            {
                "event_id": uuid4(),
                "event_type": event_type,
                "timestamp": at,
                "source_type": SOURCE_TYPE,
                "source_name": self._context.source_name("syslog"),
                "host_id": host_id,
                "agent_id": self._context.agent_id,
                "username": user,
                "success": True,
                "src_ip": _ip(source_ip),
                "metadata": {
                    **metadata,
                    "record_kind": "session_vector",
                    "service": service,
                    "session_vector": vector,
                },
            }
        )

    def _auth(
        self,
        event_type: str,
        at: datetime,
        host_id: str,
        metadata: dict[str, JsonValue],
        *,
        user: str | None,
        ip: str | None,
        success: bool,
        method: str | None = None,
        port: str | None = None,
        reason: AuthFailureReason | None = None,
        withheld: bool = False,
        outcome: str | None = None,
        service: str | None = None,
    ) -> AuthenticationEvent:
        extra: dict[str, JsonValue] = {}
        if port and port.isdigit():
            extra["source_port"] = int(port)
        if withheld:
            extra["account_name_withheld"] = True
        if outcome:
            extra["outcome"] = outcome
        if service:
            extra["service"] = service
        if method:
            extra["ssh_method"] = method
        return AuthenticationEvent.model_validate(
            {
                "event_id": uuid4(),
                "event_type": event_type,
                "timestamp": at,
                "source_type": SOURCE_TYPE,
                "source_name": self._context.source_name("syslog"),
                "host_id": host_id,
                "agent_id": self._context.agent_id,
                "username": user,
                "auth_method": SSH_METHODS.get(method or "", None),
                "success": success,
                "failure_reason": None if success else reason,
                "src_ip": _ip(ip),
                "metadata": {**metadata, **extra},
            }
        )


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: "SyslogReceiver") -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        self._receiver.received(data, str(addr[0]))


class SyslogReceiver:
    """Receives syslog over UDP and/or TCP and spools the mapped events in batches."""

    name = "syslog"

    def __init__(
        self,
        mapper: SyslogMapper,
        *,
        udp_listen: tuple[str, int] | None,
        tcp_listen: tuple[str, int] | None,
        allowed_senders: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
        max_message_bytes: int,
        max_pending_events: int = MAX_PENDING_EVENTS,
    ) -> None:
        self._mapper = mapper
        self._udp_listen = udp_listen
        self._tcp_listen = tcp_listen
        self._allowed = list(allowed_senders)
        self._max_message = max_message_bytes
        self._max_pending = max_pending_events
        self._pending: list[AnyCanonicalEvent] = []
        self._in_flight = 0
        self._room = asyncio.Event()
        self._room.set()
        self._wake = asyncio.Event()
        self.counters: Counter[str] = Counter()
        self._refused_senders: set[str] = set()
        self._connections = 0
        self._dropped_since_full = 0

    @property
    def backlog(self) -> int:
        """Received events not yet spooled: pending, plus those being submitted."""
        return len(self._pending) + self._in_flight

    def allowed(self, sender: str) -> bool:
        """Whether ``sender`` may send syslog to this receiver."""
        address = _ip(sender)
        return address is not None and any(
            address.version == network.version and address in network for network in self._allowed
        )

    def received(self, data: bytes, sender: str, *, stream: bool = False) -> None:
        """Handle one message (called by the UDP and TCP handlers).

        While the backlog is full a datagram is dropped and counted. A ``stream`` (TCP)
        message is kept: its connection waits for room before reading the next one.
        """
        sender = str(_ip(sender) or sender)
        if not self.allowed(sender):
            self._refuse(sender)
            return
        if not stream and not self._room.is_set():
            self.counters["dropped_queue_full"] += 1
            self._dropped_since_full += 1
            return
        message = parse_syslog(data[: self._max_message + 64])
        if message is None:
            self.counters["unparsed"] += 1
            return
        try:
            events = self._mapper.to_events(message, sender)
        except (ValidationError, ValueError):
            self.counters["unmappable"] += 1
            return
        self.counters["received"] += 1
        self._pending.extend(events)
        if len(self._pending) >= BATCH_EVENTS:
            self._wake.set()
        if self.backlog >= self._max_pending and self._room.is_set():
            self._room.clear()
            self._wake.set()
            logger.warning(
                "syslog backlog full while the spool is full: UDP messages are dropped and "
                "TCP senders paused",
                extra={"action": "agent_syslog_backlog_full", "backlog": self.backlog},
            )

    def _update_room(self) -> None:
        if self._room.is_set() or self.backlog >= self._max_pending:
            return
        self._room.set()
        logger.info(
            "syslog backlog has room again; receiving resumed",
            extra={
                "action": "agent_syslog_backlog_resumed",
                "dropped": self._dropped_since_full,
            },
        )
        self._dropped_since_full = 0

    def _refuse(self, sender: str) -> None:
        self.counters["refused_sender"] += 1
        if sender not in self._refused_senders and len(self._refused_senders) < 256:
            self._refused_senders.add(sender)
            logger.warning(
                "syslog from a sender outside AGENT_SYSLOG_ALLOWED_SENDERS dropped",
                extra={"action": "agent_syslog_refused_sender"},
            )

    async def run(self, sink: EventSink) -> None:
        """Listen until cancelled, spooling received events every second or 500 events."""
        loop = asyncio.get_running_loop()
        transport: asyncio.DatagramTransport | None = None
        server: asyncio.Server | None = None
        try:
            if self._udp_listen is not None:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _UdpProtocol(self), local_addr=self._udp_listen
                )
            if self._tcp_listen is not None:
                host, port = self._tcp_listen
                server = await asyncio.start_server(self._tcp_client, host, port)
            logger.info(
                "syslog receiver listening",
                extra={
                    "action": "agent_syslog_listening",
                    "udp": _endpoint(self._udp_listen),
                    "tcp": _endpoint(self._tcp_listen),
                },
            )
            while True:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._wake.wait(), FLUSH_SECONDS)
                self._wake.clear()
                await self.flush(sink)
        finally:
            if transport is not None:
                transport.close()
            if server is not None:
                server.close()
            if self._pending:
                try:
                    await self.flush(sink)
                except asyncio.CancelledError:
                    logger.warning(
                        "received syslog not spooled at shutdown",
                        extra={"action": "agent_syslog_lost", "events": len(self._pending)},
                    )

    async def flush(self, sink: EventSink) -> int:
        """Spool every pending event; returns how many."""
        events, self._pending = self._pending, []
        if events:
            # While the spool is full, submit waits; the events still count in the backlog.
            self._in_flight = len(events)
            try:
                await sink.submit(events)
            finally:
                self._in_flight = 0
                self._update_room()
        return len(events)

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        sender = str(peer[0]) if peer else ""
        if not self.allowed(sender):
            self._refuse(sender)
            writer.close()
            return
        if self._connections >= MAX_TCP_CONNECTIONS:
            self.counters["refused_connection"] += 1
            writer.close()
            return
        self._connections += 1
        try:
            while True:
                # Not reading while the backlog is full lets TCP flow control stop the sender.
                await self._room.wait()
                frame = await _read_frame(reader, self._max_message)
                if frame is None:
                    return
                if frame:
                    self.received(frame, sender, stream=True)
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            return
        finally:
            self._connections -= 1
            writer.close()


async def _read_frame(reader: asyncio.StreamReader, limit: int) -> bytes | None:
    """One TCP syslog frame: octet-counted (RFC 6587) or newline-delimited."""
    first = await reader.read(1)
    if not first:
        return None
    if first.isdigit():
        digits = first + await reader.readuntil(b" ")
        length = int(digits[:-1])
        if length > limit + 64:
            raise ValueError("frame too large")
        return await reader.readexactly(length)
    line = first + await reader.readline()
    return line[: limit + 64]


def _endpoint(listen: tuple[str, int] | None) -> str | None:
    return f"{listen[0]}:{listen[1]}" if listen else None
