"""Windows Event Log collection: System and Application channels (system logs).

Reads the local computer's channels through the native Evt* API (pywin32) and turns each
selected event into a canonical ``SystemEvent``. The Security channel uses the same loop
with the authentication mapper in :mod:`apps.agent.collectors.windows_auth`.

- **Read-only.** Only the local computer is queried; audit policies and group memberships
  are never changed. System and Application need no administrator rights; Security needs
  membership of "Event Log Readers" or an elevated process.
- **Checkpoints.** The last handled ``EventRecordID`` of each channel is stored in the
  same spool transaction as the events it covers, so a restart resumes exactly there.
  A first run starts at the newest record (or ``backfill_minutes`` back).
- **Identity.** Event ids are UUIDv5 of the computer, channel, record id and time, so an
  event read twice keeps its id and is deduplicated by the normalizer.
- **Privacy.** Event data fields whose names look like secrets are dropped, secret-looking
  text is redacted, values are truncated, the rendered message is sent only on request and
  personal SIDs never.
- **Resilience.** A missing or access-denied channel is reported and retried; the other
  channels keep working. A cleared or wrapped log is detected and reported.
"""

import asyncio
import logging
import re
import time
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable, Collection, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Protocol
from uuid import UUID, uuid5

from pydantic import JsonValue, ValidationError

from apps.agent.collectors.base import CollectorContext, EventSink
from packages.events.canonical import AnyCanonicalEvent, SeverityHint, SystemEvent
from packages.events.validation import normalize_key
from packages.observability import redact_text

logger = logging.getLogger(__name__)

SOURCE_TYPE: Final = "windows_eventlog"
EVENT_ID_NAMESPACE: Final = UUID("8c3f6d1e-5b2a-4f47-9d0e-2a6b7c1d4e90")
"""Namespace of Windows event ids (the same event always gets the same id)."""

MAX_EVENTS_PER_POLL: Final = 500
CHANNEL_RETRY_SECONDS: Final = 60.0
MAX_FIELD_LENGTH: Final = 256
MAX_FIELDS: Final = 32
MAX_MESSAGE_LENGTH: Final = 1_024

LEVEL_NAMES: Final = {1: "critical", 2: "error", 3: "warning", 4: "information", 5: "verbose"}
SEVERITY_FOR_LEVEL: Final = {
    "critical": SeverityHint.CRITICAL,
    "error": SeverityHint.HIGH,
    "warning": SeverityHint.MEDIUM,
    "information": SeverityHint.INFO,
    "verbose": SeverityHint.INFO,
}
WELL_KNOWN_ACCOUNTS: Final = {
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
}
SYSTEM_EVENT_TYPES: Final = {
    ("Microsoft-Windows-Kernel-General", 1): "system.time_changed",
    ("Microsoft-Windows-Kernel-General", 12): "system.os_started",
    ("Microsoft-Windows-Kernel-General", 13): "system.os_shutdown",
    ("Microsoft-Windows-Kernel-Power", 41): "system.unexpected_reboot",
    ("Microsoft-Windows-Power-Troubleshooter", 1): "system.resumed_from_sleep",
    ("Microsoft-Windows-Eventlog", 104): "system.event_log_cleared",
    ("EventLog", 6005): "system.eventlog_service_started",
    ("EventLog", 6006): "system.eventlog_service_stopped",
    ("EventLog", 6008): "system.unexpected_shutdown",
    ("User32", 1074): "system.shutdown_initiated",
    ("Service Control Manager", 7000): "system.service_start_failed",
    ("Service Control Manager", 7009): "system.service_start_timeout",
    ("Service Control Manager", 7031): "system.service_crashed",
    ("Service Control Manager", 7034): "system.service_crashed",
    ("Service Control Manager", 7036): "system.service_state_changed",
    ("Service Control Manager", 7040): "system.service_start_type_changed",
    ("Service Control Manager", 7045): "system.service_installed",
    ("Microsoft-Windows-WindowsUpdateClient", 19): "system.update_installed",
    ("Microsoft-Windows-WindowsUpdateClient", 20): "system.update_install_failed",
    ("Application Error", 1000): "system.application_crash",
    ("Application Hang", 1002): "system.application_hang",
    ("Windows Error Reporting", 1001): "system.error_report",
    (".NET Runtime", 1026): "system.dotnet_unhandled_exception",
    ("MsiInstaller", 1033): "system.software_installed",
    ("MsiInstaller", 1034): "system.software_removed",
    ("MsiInstaller", 11707): "system.software_installed",
    ("MsiInstaller", 11724): "system.software_removed",
}
GENERIC_EVENT_TYPE: Final = "system.windows_event"

_NS: Final = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_SYSTEM_TIME: Final = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z")
_RECORD_ID: Final = re.compile(r"<EventRecordID>\s*(\d+)\s*</EventRecordID>")
_PROVIDER_NAME: Final = re.compile(r"<Provider\s+Name=['\"]([^'\"]+)['\"]")
_MAX_KEY_LENGTH: Final = 64
_SECRET_KEY_FRAGMENTS: Final = (
    "password",
    "passwd",
    "passphrase",
    "passcode",
    "secret",
    "privatekey",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "sessiontoken",
    "bearertoken",
    "authtoken",
    "sessionkey",
)
_SECRET_KEYS: Final = frozenset({"pwd", "pass", "token", "authorization", "cookie", "credential"})
_NON_SECRET_KEYS: Final = frozenset(
    {"passwordlastset", "passwordneverexpires", "passwordnotrequired", "passwordexpired"}
)

ERROR_ACCESS_DENIED: Final = 5
ERROR_EVT_CHANNEL_NOT_FOUND: Final = 15007

Clock = Callable[[], float]
Sleep = Callable[[float], Awaitable[None]]


class EventParseError(ValueError):
    """The event XML is malformed or lacks a required field."""


class ChannelUnavailableError(Exception):
    """A channel cannot be read now: missing, access denied, or an Event Log error."""

    def __init__(self, channel: str, reason: str, *, access_denied: bool = False) -> None:
        super().__init__(reason)
        self.channel = channel
        self.reason = reason
        self.access_denied = access_denied


@dataclass(frozen=True, slots=True)
class WindowsEvent:
    """The fields of one rendered Windows event that the mappers use."""

    channel: str
    provider: str
    event_id: int
    record_id: int
    time_created: datetime
    computer: str
    level: int
    task: int | None = None
    opcode: int | None = None
    keywords: str | None = None
    process_id: int | None = None
    user_sid: str | None = None
    data: tuple[tuple[str | None, str], ...] = ()
    """EventData/UserData fields in document order; the name is ``None`` for unnamed data."""

    def fields(self) -> dict[str, str]:
        """Named data fields (the first value wins for repeated names)."""
        named: dict[str, str] = {}
        for name, value in self.data:
            if name and name not in named:
                named[name] = value
        return named


@dataclass(frozen=True, slots=True)
class RawEvent:
    """One event as rendered by the Event Log API."""

    xml: str
    message: str | None = None


class EventSource(Protocol):
    """What the collector needs from an event log. Tests provide an in-memory one."""

    def newest_record_id(self, channel: str) -> int | None:
        """The newest record id of ``channel``."""
        ...

    def oldest_record_id(self, channel: str) -> int | None:
        """The oldest record id still in ``channel``."""
        ...

    def first_record_id_since(self, channel: str, minutes: int) -> int | None:
        """The first record id written in the last ``minutes``."""
        ...

    def read_after(
        self, channel: str, record_id: int, limit: int, event_ids: Collection[int] | None
    ) -> list[RawEvent]:
        """Up to ``limit`` events newer than ``record_id``, optionally of these Event IDs."""
        ...


class WindowsEventLogReader:
    """``EventSource`` backed by EvtQuery/EvtNext/EvtRender on the local computer."""

    def __init__(self, *, include_message: bool = False) -> None:
        try:
            import pywintypes
            import win32evtlog
        except ImportError as error:  # pragma: no cover - only without pywin32
            raise RuntimeError("reading the Windows Event Log needs pywin32") from error
        self._evt: Any = win32evtlog
        self._error: Any = pywintypes.error
        self._include_message = include_message
        self._publishers: dict[str, object] = {}

    def newest_record_id(self, channel: str) -> int | None:
        """The newest record id of ``channel``."""
        return self._first_record_id(channel, "*", reverse=True)

    def oldest_record_id(self, channel: str) -> int | None:
        """The oldest record id still in ``channel``."""
        return self._first_record_id(channel, "*", reverse=False)

    def first_record_id_since(self, channel: str, minutes: int) -> int | None:
        """The first record id written in the last ``minutes``."""
        xpath = f"*[System[TimeCreated[timediff(@SystemTime) <= {int(minutes) * 60_000}]]]"
        return self._first_record_id(channel, xpath, reverse=False)

    def read_after(
        self, channel: str, record_id: int, limit: int, event_ids: Collection[int] | None
    ) -> list[RawEvent]:
        """Up to ``limit`` events newer than ``record_id``."""
        query = self._query(channel, after_record_xpath(record_id, event_ids), reverse=False)
        events: list[RawEvent] = []
        while len(events) < limit:
            batch = self._next(channel, query, min(50, limit - len(events)))
            if not batch:
                break
            for handle in batch:
                xml = self._render(channel, handle)
                message = self._message(handle, xml) if self._include_message else None
                events.append(RawEvent(xml, message))
        return events

    def _first_record_id(self, channel: str, xpath: str, *, reverse: bool) -> int | None:
        batch = self._next(channel, self._query(channel, xpath, reverse=reverse), 1)
        return record_id_hint(self._render(channel, batch[0])) if batch else None

    def _query(self, channel: str, xpath: str, *, reverse: bool) -> object:
        evt = self._evt
        direction = evt.EvtQueryReverseDirection if reverse else evt.EvtQueryForwardDirection
        try:
            return evt.EvtQuery(channel, evt.EvtQueryChannelPath | direction, xpath)
        except self._error as error:
            raise _unavailable(channel, error) from error

    def _next(self, channel: str, query: object, count: int) -> tuple[object, ...]:
        try:
            return tuple(self._evt.EvtNext(query, count))
        except self._error as error:
            raise _unavailable(channel, error) from error

    def _render(self, channel: str, handle: object) -> str:
        try:
            return str(self._evt.EvtRender(handle, self._evt.EvtRenderEventXml))
        except self._error as error:
            raise _unavailable(channel, error) from error

    def _message(self, handle: object, xml: str) -> str | None:
        match = _PROVIDER_NAME.search(xml)
        if match is None:
            return None
        provider = match.group(1)
        if provider not in self._publishers:
            try:
                self._publishers[provider] = self._evt.EvtOpenPublisherMetadata(provider)
            except self._error:
                self._publishers[provider] = None
        metadata = self._publishers[provider]
        if metadata is None:
            return None
        try:
            return str(
                self._evt.EvtFormatMessage(metadata, handle, self._evt.EvtFormatMessageEvent)
            )
        except self._error:
            return None


def after_record_xpath(record_id: int, event_ids: Collection[int] | None = None) -> str:
    """XPath of events newer than ``record_id``, optionally only of ``event_ids``.

    Filtering inside the query lets the Event Log service skip unwanted events itself,
    which matters for the busy Security log.
    """
    condition = f"EventRecordID > {int(record_id)}"
    if event_ids:
        ids = " or ".join(f"EventID={int(event_id)}" for event_id in sorted(set(event_ids)))
        condition = f"({ids}) and {condition}"
    return f"*[System[{condition}]]"


def _unavailable(channel: str, error: object) -> ChannelUnavailableError:
    code = getattr(error, "winerror", None)
    if code == ERROR_ACCESS_DENIED:
        return ChannelUnavailableError(
            channel,
            f"access denied reading the '{channel}' log; run the agent as a member of "
            "'Event Log Readers' or elevated (ADIS never changes this itself)",
            access_denied=True,
        )
    if code == ERROR_EVT_CHANNEL_NOT_FOUND:
        return ChannelUnavailableError(channel, f"the '{channel}' log does not exist here")
    detail = getattr(error, "strerror", None) or str(error)
    return ChannelUnavailableError(channel, f"cannot read the '{channel}' log ({code}: {detail})")


# --------------------------------------------------------------------------- parsing


def record_id_hint(xml: str) -> int | None:
    """EventRecordID found by a text search, for events that cannot be parsed."""
    match = _RECORD_ID.search(xml)
    return int(match.group(1)) if match else None


def parse_system_time(value: str | None) -> datetime:
    """Parse ``TimeCreated/@SystemTime`` (UTC, up to 9 fractional digits)."""
    if not value:
        raise EventParseError("event has no TimeCreated/@SystemTime")
    match = _SYSTEM_TIME.fullmatch(value.strip())
    if match is None:
        raise EventParseError("unrecognized SystemTime")
    base = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    return base.replace(microsecond=int((match.group(2) or "0")[:6].ljust(6, "0")))


def parse_event_xml(xml: str) -> WindowsEvent:
    """Parse the XML the Event Log API renders for one event.

    Raises:
        EventParseError: If the XML is malformed, has a DTD, or lacks required fields.
    """
    if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
        raise EventParseError("event XML must not contain a DTD")
    try:
        root = ET.fromstring(xml)  # noqa: S314 - no DTD (checked above), local API output
    except ET.ParseError:
        raise EventParseError("malformed event XML") from None
    system = root.find(f"{_NS}System")
    if system is None:
        raise EventParseError("event XML has no <System> element")
    provider = system.find(f"{_NS}Provider")
    time_created = system.find(f"{_NS}TimeCreated")
    execution = system.find(f"{_NS}Execution")
    security = system.find(f"{_NS}Security")
    return WindowsEvent(
        channel=_required_text(system, "Channel"),
        provider=(provider.get("Name") if provider is not None else None) or "unknown",
        event_id=_required_int(system, "EventID"),
        record_id=_required_int(system, "EventRecordID"),
        time_created=parse_system_time(
            time_created.get("SystemTime") if time_created is not None else None
        ),
        computer=_required_text(system, "Computer"),
        level=_to_int(_optional_text(system, "Level")) or 0,
        task=_to_int(_optional_text(system, "Task")),
        opcode=_to_int(_optional_text(system, "Opcode")),
        keywords=_optional_text(system, "Keywords"),
        process_id=_to_int(execution.get("ProcessID")) if execution is not None else None,
        user_sid=(security.get("UserID") or None) if security is not None else None,
        data=tuple(_event_fields(root)),
    )


def _event_fields(root: ET.Element) -> Iterator[tuple[str | None, str]]:
    event_data = root.find(f"{_NS}EventData")
    if event_data is not None:
        for item in event_data.findall(f"{_NS}Data"):
            yield item.get("Name"), item.text or ""
    user_data = root.find(f"{_NS}UserData")
    if user_data is not None:
        for container in user_data:
            for item in container:
                if len(item) == 0:
                    yield item.tag.rsplit("}", 1)[-1], item.text or ""


def _optional_text(parent: ET.Element, name: str) -> str | None:
    element = parent.find(f"{_NS}{name}")
    text = (element.text or "").strip() if element is not None else ""
    return text or None


def _required_text(parent: ET.Element, name: str) -> str:
    text = _optional_text(parent, name)
    if text is None:
        raise EventParseError(f"event has no <{name}>")
    return text


def _to_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    text = value.strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _required_int(parent: ET.Element, name: str) -> int:
    value = _to_int(_optional_text(parent, name))
    if value is None:
        raise EventParseError(f"event has no numeric <{name}>")
    return value


# --------------------------------------------------------------------------- mapping


def level_name(level: int) -> str:
    """Windows level number to name; 0 (LogAlways) and custom levels are information."""
    return LEVEL_NAMES.get(level, "information")


def windows_event_id(event: WindowsEvent) -> UUID:
    """The deterministic canonical event id of ``event``."""
    identity = (
        f"{event.computer.lower()}|{event.channel}|{event.record_id}|"
        f"{event.time_created.isoformat()}"
    )
    return uuid5(EVENT_ID_NAMESPACE, identity)


def is_secret_key(name: str) -> bool:
    """Whether a data field name suggests it holds a password, token or other secret."""
    compact = normalize_key(name)
    if compact in _NON_SECRET_KEYS:
        return False
    return compact in _SECRET_KEYS or any(fragment in compact for fragment in _SECRET_KEY_FRAGMENTS)


def truncate(text: str, limit: int) -> str:
    """``text`` cut to ``limit`` characters (with an ellipsis)."""
    return text if len(text) <= limit else text[: limit - 3] + "..."


def safe_event_fields(
    data: Sequence[tuple[str | None, str]],
) -> tuple[dict[str, JsonValue], list[str]]:
    """``(fields to send, names left out)``: secrets dropped, values redacted and bounded."""
    fields: dict[str, JsonValue] = {}
    omitted: list[str] = []
    unnamed = 0
    for name, raw_value in data:
        if name is None or not name.strip():
            unnamed += 1
            key = f"data_{unnamed}"
        else:
            key = name.strip()[:_MAX_KEY_LENGTH]
        if is_secret_key(key):
            omitted.append(key)
            continue
        value = raw_value.strip()
        if not value:
            continue
        if len(fields) >= MAX_FIELDS:
            omitted.append(key)
            continue
        while key in fields:
            key += "_"
        fields[key] = truncate(redact_text(value), MAX_FIELD_LENGTH)
    return fields, omitted


def windows_metadata(event: WindowsEvent) -> dict[str, JsonValue]:
    """Identity and classification fields every Windows-sourced event carries."""
    metadata: dict[str, JsonValue] = {
        "windows_event_id": event.event_id,
        "windows_record_id": event.record_id,
        "windows_channel": event.channel,
        "windows_provider": event.provider,
        "windows_computer": event.computer,
        "windows_level": event.level,
        "windows_level_name": level_name(event.level),
    }
    optional: dict[str, JsonValue] = {
        "windows_task": event.task,
        "windows_opcode": event.opcode,
        "windows_keywords": event.keywords,
        "windows_process_id": event.process_id,
    }
    metadata.update({key: value for key, value in optional.items() if value is not None})
    return metadata


class EventMapper(Protocol):
    """Which channels are read, which events are kept, and what each becomes."""

    @property
    def channels(self) -> tuple[str, ...]:
        """Channels to read."""
        ...

    def event_ids(self, channel: str) -> frozenset[int] | None:
        """Event IDs to request from ``channel`` (``None``: all)."""
        ...

    def select(self, channel: str, event: WindowsEvent) -> bool:
        """Whether ``event`` is collected."""
        ...

    def to_events(self, event: WindowsEvent, message: str | None) -> list[AnyCanonicalEvent]:
        """The canonical events ``event`` becomes."""
        ...


@dataclass(frozen=True, slots=True)
class SystemLogRules:
    """Selection and privacy rules of the System/Application collector."""

    channels: tuple[str, ...]
    levels: frozenset[str]
    extra_event_ids: frozenset[int]
    exclude_event_ids: frozenset[int]
    include_message: bool = False


class SystemEventMapper:
    """System/Application events → ``SystemEvent``."""

    def __init__(self, rules: SystemLogRules, context: CollectorContext) -> None:
        self._rules = rules
        self._context = context

    @property
    def channels(self) -> tuple[str, ...]:
        """Channels to read."""
        return self._rules.channels

    def event_ids(self, channel: str) -> frozenset[int] | None:
        """Selection depends on the level too, so every event is read."""
        return None

    def select(self, channel: str, event: WindowsEvent) -> bool:
        """Selected levels and extra Event IDs, minus excluded ones."""
        if event.event_id in self._rules.exclude_event_ids:
            return False
        return (
            level_name(event.level) in self._rules.levels
            or event.event_id in self._rules.extra_event_ids
        )

    def to_events(self, event: WindowsEvent, message: str | None) -> list[AnyCanonicalEvent]:
        """One ``SystemEvent``."""
        metadata = windows_metadata(event)
        fields, omitted = safe_event_fields(event.data)
        if fields:
            metadata["event_data"] = fields
        if omitted:
            omitted_names: list[JsonValue] = [*sorted(set(omitted))]
            metadata["event_data_omitted"] = omitted_names
        if self._rules.include_message and message and message.strip():
            metadata["message"] = truncate(redact_text(message.strip()), MAX_MESSAGE_LENGTH)
        account = WELL_KNOWN_ACCOUNTS.get(event.user_sid or "")
        if account:
            metadata["account"] = account
        identity = self._context.identity
        return [
            SystemEvent(
                event_id=windows_event_id(event),
                event_type=SYSTEM_EVENT_TYPES.get(
                    (event.provider, event.event_id), GENERIC_EVENT_TYPE
                ),
                timestamp=event.time_created,
                source_type=SOURCE_TYPE,
                source_name=self._context.source_name("windows_eventlog"),
                host_id=identity.host_id,
                agent_id=self._context.agent_id,
                severity_hint=SEVERITY_FOR_LEVEL[level_name(event.level)],
                metadata=metadata,
            )
        ]


# --------------------------------------------------------------------------- collector


class EventLogCollector:
    """Polls Event Log channels and spools the mapped events with their checkpoints."""

    def __init__(
        self,
        name: str,
        source: EventSource,
        mapper: EventMapper,
        *,
        poll_interval_seconds: float,
        backfill_minutes: int = 0,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = time.monotonic,
    ) -> None:
        self._name = name
        self._source = source
        self._mapper = mapper
        self._poll_interval = poll_interval_seconds
        self._backfill_minutes = backfill_minutes
        self._sleep = sleep
        self._clock = clock
        self._positions: dict[str, int] = {}
        self._retry_at: dict[str, float] = {}

    @property
    def name(self) -> str:
        """Collector name, used in ``source_name`` and checkpoint keys."""
        return self._name

    async def run(self, sink: EventSink) -> None:
        """Poll every channel until cancelled."""
        while True:
            await self.poll(sink)
            await self._sleep(self._poll_interval)

    async def poll(self, sink: EventSink) -> int:
        """Read each channel once; returns how many events were spooled."""
        spooled = 0
        for channel in self._mapper.channels:
            if self._clock() < self._retry_at.get(channel, 0.0):
                continue
            try:
                spooled += await self._poll_channel(channel, sink)
            except ChannelUnavailableError as unavailable:
                self._retry_at[channel] = self._clock() + CHANNEL_RETRY_SECONDS
                logger.warning(
                    "event log channel unavailable; retrying later",
                    extra={
                        "action": "agent_eventlog_unavailable",
                        "collector": self._name,
                        "channel": channel,
                        "reason": unavailable.reason,
                        "access_denied": unavailable.access_denied,
                    },
                )
        return spooled

    async def _poll_channel(self, channel: str, sink: EventSink) -> int:
        checkpoint = await self._checkpoint(channel, sink)
        checkpoint = await asyncio.to_thread(self._continuity, channel, checkpoint)
        raws = await asyncio.to_thread(
            self._source.read_after,
            channel,
            checkpoint,
            MAX_EVENTS_PER_POLL,
            self._mapper.event_ids(channel),
        )
        events: list[AnyCanonicalEvent] = []
        last = checkpoint
        unparsed = 0
        for raw in raws:
            try:
                event = parse_event_xml(raw.xml)
            except EventParseError:
                unparsed += 1
                last = max(last, record_id_hint(raw.xml) or last)
                continue
            last = max(last, event.record_id)
            if self._mapper.select(channel, event):
                events.extend(self._mapped(channel, event, raw.message))
        if unparsed:
            logger.warning(
                "skipped unreadable event log records",
                extra={"action": "agent_eventlog_unparsed", "channel": channel, "count": unparsed},
            )
        if last != checkpoint or channel not in self._positions:
            await sink.submit(events, checkpoints={self._key(channel): str(last)})
        self._positions[channel] = last
        return len(events)

    def _mapped(
        self, channel: str, event: WindowsEvent, message: str | None
    ) -> list[AnyCanonicalEvent]:
        try:
            return self._mapper.to_events(event, message)
        except (ValidationError, ValueError):
            logger.warning(
                "event log record does not fit the canonical schema; skipped",
                extra={
                    "action": "agent_eventlog_unmappable",
                    "channel": channel,
                    "windows_event_id": event.event_id,
                    "windows_record_id": event.record_id,
                },
            )
            return []

    async def _checkpoint(self, channel: str, sink: EventSink) -> int:
        known = self._positions.get(channel)
        if known is not None:
            return known
        stored = await sink.checkpoint(self._key(channel))
        if stored is not None and stored.isdigit():
            return int(stored)
        return await asyncio.to_thread(self._first_run, channel)

    def _first_run(self, channel: str) -> int:
        if self._backfill_minutes > 0:
            first = self._source.first_record_id_since(channel, self._backfill_minutes)
            if first is not None:
                logger.info(
                    "first run: collecting the recent past of the channel",
                    extra={
                        "action": "agent_eventlog_backfill",
                        "channel": channel,
                        "minutes": self._backfill_minutes,
                    },
                )
                return first - 1
        return self._source.newest_record_id(channel) or 0

    def _continuity(self, channel: str, checkpoint: int) -> int:
        newest = self._source.newest_record_id(channel)
        if checkpoint > 0 and (newest is None or newest < checkpoint):
            logger.warning(
                "event log was cleared; collecting the new log from its start",
                extra={"action": "agent_eventlog_cleared", "channel": channel},
            )
            return 0
        oldest = self._source.oldest_record_id(channel)
        if checkpoint > 0 and oldest is not None and oldest > checkpoint + 1:
            logger.warning(
                "event log wrapped before records were collected",
                extra={
                    "action": "agent_eventlog_wrapped",
                    "channel": channel,
                    "lost_records": oldest - checkpoint - 1,
                },
            )
        return checkpoint

    def _key(self, channel: str) -> str:
        return f"{self._name}:{channel}"
