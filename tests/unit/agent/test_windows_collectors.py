"""Windows Event Log collectors: parsing, system and authentication mapping, polling loop."""

from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import timedelta
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from apps.agent.collectors.base import CollectorContext
from apps.agent.collectors.windows_auth import AuthenticationMapper
from apps.agent.collectors.windows_events import (
    ChannelUnavailableError,
    EventLogCollector,
    EventParseError,
    RawEvent,
    SystemEventMapper,
    SystemLogRules,
    after_record_xpath,
    parse_event_xml,
    record_id_hint,
    safe_event_fields,
    windows_event_id,
)
from packages.events.canonical import (
    AuthenticationEvent,
    AuthFailureReason,
    AuthMethod,
    SeverityHint,
    SystemEvent,
    parse_canonical_event,
    serialize_canonical_event,
)
from tests.unit.agent.fakes import MemorySink, make_identity

FIXTURES = Path(__file__).parent / "fixtures" / "windows"


def _xml(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _context() -> CollectorContext:
    return CollectorContext(make_identity(hostname="WIN-LAB-01", host_id="win-lab-01"))


def _system_mapper() -> SystemEventMapper:
    rules = SystemLogRules(
        channels=("System", "Application"),
        levels=frozenset({"critical", "error", "warning"}),
        extra_event_ids=frozenset({104, 7045, 11707}),
        exclude_event_ids=frozenset({10016}),
    )
    return SystemEventMapper(rules, _context())


def _auth_mapper() -> AuthenticationMapper:
    return AuthenticationMapper(
        _context(),
        exclude_logon_types=frozenset({5}),
        session_logon_types=frozenset({2, 7, 10, 11}),
        failure_window=timedelta(hours=1),
        max_open_sessions=100,
    )


# ---------------------------------------------------------------------------------- parsing


def test_event_xml_is_parsed() -> None:
    event = parse_event_xml(_xml("system_7045_service_installed.xml"))

    assert (event.channel, event.provider, event.event_id) == (
        "System",
        "Service Control Manager",
        7045,
    )
    assert event.computer == "WIN-LAB-01"
    assert event.time_created.tzinfo is not None
    assert "ServiceName" in event.fields()


@pytest.mark.parametrize(
    "xml",
    [
        "<Event><System></System></Event>",
        "not xml",
        '<!DOCTYPE x [<!ENTITY a "b">]><Event/>',
    ],
)
def test_malformed_xml_is_refused(xml: str) -> None:
    with pytest.raises(EventParseError):
        parse_event_xml(xml)


def test_record_id_hint_reads_unparseable_records() -> None:
    assert record_id_hint("<x><EventRecordID> 42 </EventRecordID>") == 42
    assert record_id_hint("<x/>") is None


def test_event_ids_are_deterministic() -> None:
    first = parse_event_xml(_xml("system_104_log_cleared.xml"))
    again = parse_event_xml(_xml("system_104_log_cleared.xml"))

    assert windows_event_id(first) == windows_event_id(again)


def test_query_filters_by_record_and_event_ids() -> None:
    assert after_record_xpath(10) == "*[System[EventRecordID > 10]]"
    assert after_record_xpath(10, {4625, 4624}) == (
        "*[System[(EventID=4624 or EventID=4625) and EventRecordID > 10]]"
    )


def test_secret_fields_are_dropped_and_text_redacted() -> None:
    fields, omitted = safe_event_fields(
        [("Password", "hunter2"), ("CommandLine", "tool --password=hunter2"), (None, "x")]
    )

    assert "Password" in omitted
    assert "hunter2" not in str(fields)
    assert fields["data_1"] == "x"


# ------------------------------------------------------------------------- system mapping


def test_system_events_are_selected_by_level_and_extra_ids() -> None:
    mapper = _system_mapper()

    selected = {
        name: mapper.select("System", parse_event_xml(_xml(name)))
        for name in (
            "system_7045_service_installed.xml",
            "system_10016_dcom.xml",
            "system_7036_service_state_changed.xml",
            "system_41_kernel_power.xml",
        )
    }

    assert selected == {
        "system_7045_service_installed.xml": True,
        "system_10016_dcom.xml": False,
        "system_7036_service_state_changed.xml": False,
        "system_41_kernel_power.xml": True,
    }


def test_system_event_becomes_a_canonical_system_event() -> None:
    [event] = _system_mapper().to_events(
        parse_event_xml(_xml("system_7045_service_installed.xml")), None
    )

    assert isinstance(event, SystemEvent)
    assert event.event_type == "system.service_installed"
    assert event.source_type == "windows_eventlog"
    assert event.host_id == "win-lab-01"
    assert event.metadata["windows_event_id"] == 7045
    assert parse_canonical_event(serialize_canonical_event(event)) == event


def test_kernel_power_is_critical() -> None:
    [event] = _system_mapper().to_events(parse_event_xml(_xml("system_41_kernel_power.xml")), None)

    assert event.event_type == "system.unexpected_reboot"
    assert event.severity_hint is SeverityHint.CRITICAL


def test_application_secrets_never_leave_the_host() -> None:
    [event] = _system_mapper().to_events(
        parse_event_xml(_xml("application_warning_with_secrets.xml")), "message"
    )

    serialized = serialize_canonical_event(event).decode()
    assert "message" not in event.metadata  # the rendered message is opt-in
    assert "event_data_omitted" in event.metadata or "[REDACTED]" in serialized


# ------------------------------------------------------------------- authentication mapping


def _auth(name: str, mapper: AuthenticationMapper | None = None) -> list[AuthenticationEvent]:
    mapper = mapper or _auth_mapper()
    event = parse_event_xml(_xml(name))
    assert mapper.select("Security", event)
    events = mapper.to_events(event, None)
    assert all(isinstance(e, AuthenticationEvent) for e in events)
    return [e for e in events if isinstance(e, AuthenticationEvent)]


def test_successful_logon_is_a_login_with_a_session_start() -> None:
    login, session = _auth("security_4624_interactive_logon.xml")

    assert (login.event_type, login.success, login.username) == (
        "authentication.login",
        True,
        "WIN-LAB-01\\lab.user01",
    )
    assert login.auth_method is AuthMethod.OTHER
    assert login.metadata["logon_type_name"] == "interactive"
    assert login.src_ip is None  # loopback is not a remote source
    assert session.event_type == "authentication.session_started"
    vector = session.metadata["session_vector"]
    assert isinstance(vector, dict)
    fields = vector["fields"]
    assert isinstance(fields, list)
    assert fields[:3] == ["duration_seconds", "start_hour_utc", "start_weekday_utc"]


def test_wrong_password_is_a_failed_login_with_a_reason() -> None:
    [failure] = _auth("security_4625_wrong_password.xml")

    assert failure.success is False
    assert failure.failure_reason is AuthFailureReason.INVALID_CREDENTIALS
    assert failure.username == "WIN-LAB-01\\lab.user01"


def test_unknown_account_name_is_withheld() -> None:
    [failure] = _auth("security_4625_unknown_account.xml")

    assert failure.failure_reason is AuthFailureReason.UNKNOWN_USER
    assert failure.username is None
    assert failure.metadata["account_name_withheld"] is True
    assert "FIXTURE-MISTYPED-PASSWORD" not in serialize_canonical_event(failure).decode()


def test_service_logons_are_excluded() -> None:
    event = parse_event_xml(_xml("security_4624_service_logon.xml"))

    assert not _auth_mapper().select("Security", event)


def test_session_vector_covers_failures_privileges_and_duration() -> None:
    mapper = _auth_mapper()
    _auth("security_4625_wrong_password.xml", mapper)
    _auth("security_4624_interactive_logon.xml", mapper)
    _auth("security_4672_special_privileges.xml", mapper)
    logout, ended = _auth("security_4634_logoff.xml", mapper)

    assert logout.event_type == "authentication.logout"
    assert ended.event_type == "authentication.session_ended"
    vector = ended.metadata["session_vector"]
    assert isinstance(vector, dict)
    values = vector["values"]
    assert isinstance(values, dict)
    assert values["duration_seconds"] == pytest.approx(5400.0)
    assert values["failed_attempts_before"] == 1
    assert values["privileged"] == 1  # 4672 names the linked logon id
    assert len(vector["vector"]) == len(vector["fields"])  # type: ignore[arg-type]


def test_user_requested_logoff_ends_the_session_once() -> None:
    mapper = _auth_mapper()
    _auth("security_4624_interactive_logon.xml", mapper)

    requested = _auth("security_4647_user_logoff.xml", mapper)
    logoff = _auth("security_4634_logoff.xml", mapper)

    assert [e.event_type for e in requested] == [
        "authentication.logout_requested",
        "authentication.session_ended",
    ]
    assert [e.event_type for e in logoff] == ["authentication.logout"]


def test_lockout_and_explicit_credentials() -> None:
    [locked] = _auth("security_4740_account_locked_out.xml")
    [explicit] = _auth("security_4648_explicit_credentials.xml")

    assert (locked.event_type, locked.failure_reason) == (
        "authentication.account_locked",
        AuthFailureReason.ACCOUNT_LOCKED,
    )
    assert explicit.event_type == "authentication.explicit_credentials"
    assert "target_account" in explicit.metadata


def test_events_of_other_computers_are_skipped() -> None:
    event = parse_event_xml(_xml("security_4624_network_logon.xml").replace("WIN-LAB-01", "DC-9"))

    assert not _auth_mapper().select("Security", event)


def test_network_logon_keeps_its_remote_source() -> None:
    [login] = _auth("security_4624_network_logon.xml")

    assert isinstance(login.src_ip, IPv4Address)
    assert login.metadata["logon_type"] == 3


# ------------------------------------------------------------------------- polling loop


@dataclass
class MemoryEventLog:
    """An in-memory ``EventSource``."""

    channels: dict[str, list[str]] = field(default_factory=dict)
    unavailable: set[str] = field(default_factory=set)
    reads: list[tuple[str, int]] = field(default_factory=list)

    def _ids(self, channel: str) -> list[int]:
        if channel in self.unavailable:
            raise ChannelUnavailableError(channel, "denied", access_denied=True)
        return [record_id_hint(xml) or 0 for xml in self.channels.get(channel, [])]

    def newest_record_id(self, channel: str) -> int | None:
        return max(self._ids(channel), default=None)

    def oldest_record_id(self, channel: str) -> int | None:
        return min(self._ids(channel), default=None)

    def first_record_id_since(self, channel: str, minutes: int) -> int | None:
        return self.oldest_record_id(channel)

    def read_after(
        self, channel: str, record_id: int, limit: int, event_ids: Collection[int] | None
    ) -> list[RawEvent]:
        self._ids(channel)
        self.reads.append((channel, record_id))
        events = [
            RawEvent(xml)
            for xml in self.channels.get(channel, [])
            if (record_id_hint(xml) or 0) > record_id
        ]
        return events[:limit]


def _with_record(name: str, record_id: int) -> str:
    xml = _xml(name)
    original = record_id_hint(xml)
    return xml.replace(
        f"<EventRecordID>{original}</EventRecordID>", f"<EventRecordID>{record_id}</EventRecordID>"
    )


async def _no_sleep(_: float) -> None:
    return None


async def test_first_run_starts_at_the_newest_record_and_checkpoints() -> None:
    log = MemoryEventLog({"System": [_with_record("system_7045_service_installed.xml", 5)]})
    collector = EventLogCollector(
        "windows_eventlog", log, _system_mapper(), poll_interval_seconds=1, sleep=_no_sleep
    )
    sink = MemorySink()

    assert await collector.poll(sink) == 0
    assert sink.checkpoints["windows_eventlog:System"] == "5"

    log.channels["System"].append(_with_record("system_41_kernel_power.xml", 6))
    assert await collector.poll(sink) == 1
    assert sink.checkpoints["windows_eventlog:System"] == "6"


async def test_backfill_reads_the_recent_past() -> None:
    log = MemoryEventLog(
        {
            "System": [
                _with_record("system_7045_service_installed.xml", 5),
                _with_record("system_10016_dcom.xml", 6),
            ]
        }
    )
    collector = EventLogCollector(
        "windows_eventlog",
        log,
        _system_mapper(),
        poll_interval_seconds=1,
        backfill_minutes=60,
        sleep=_no_sleep,
    )
    sink = MemorySink()

    assert await collector.poll(sink) == 1  # 7045 kept, 10016 excluded
    assert sink.checkpoints["windows_eventlog:System"] == "6"


async def test_restart_resumes_from_the_stored_checkpoint() -> None:
    log = MemoryEventLog({"System": [_with_record("system_41_kernel_power.xml", 9)]})
    sink = MemorySink(checkpoints={"windows_eventlog:System": "8"})
    collector = EventLogCollector(
        "windows_eventlog", log, _system_mapper(), poll_interval_seconds=1, sleep=_no_sleep
    )

    assert await collector.poll(sink) == 1
    assert log.reads[0] == ("System", 8)


async def test_cleared_log_restarts_from_its_beginning() -> None:
    log = MemoryEventLog({"System": [_with_record("system_41_kernel_power.xml", 2)]})
    sink = MemorySink(checkpoints={"windows_eventlog:System": "500"})
    collector = EventLogCollector(
        "windows_eventlog", log, _system_mapper(), poll_interval_seconds=1, sleep=_no_sleep
    )

    assert await collector.poll(sink) == 1
    assert sink.checkpoints["windows_eventlog:System"] == "2"


async def test_unavailable_channel_does_not_stop_the_others() -> None:
    log = MemoryEventLog(
        {"Application": [_with_record("application_1000_application_crash.xml", 3)]},
        unavailable={"System"},
    )
    clock = [0.0]
    collector = EventLogCollector(
        "windows_eventlog",
        log,
        _system_mapper(),
        poll_interval_seconds=1,
        sleep=_no_sleep,
        clock=lambda: clock[0],
    )
    sink = MemorySink()

    await collector.poll(sink)
    reads_before = len(log.reads)
    await collector.poll(sink)  # System is not retried before its delay

    assert "windows_eventlog:Application" in sink.checkpoints
    assert all(channel == "Application" for channel, _ in log.reads)
    assert len(log.reads) >= reads_before


async def test_unparseable_records_are_skipped_but_passed() -> None:
    broken = "<Event><System><EventRecordID>7</EventRecordID></System></Event>"
    log = MemoryEventLog({"System": [_with_record("system_41_kernel_power.xml", 6), broken]})
    sink = MemorySink(checkpoints={"windows_eventlog:System": "5"})
    collector = EventLogCollector(
        "windows_eventlog", log, _system_mapper(), poll_interval_seconds=1, sleep=_no_sleep
    )

    assert await collector.poll(sink) == 1
    assert sink.checkpoints["windows_eventlog:System"] == "7"
