"""Collector settings: safeguards, parsing helpers and which collectors the agent builds."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from apps.agent.agent import build_collectors
from apps.agent.collectors import (
    EventLogCollector,
    LiveCaptureCollector,
    NetflowRecordsFileCollector,
    PcapFileCollector,
    SyscallFileCollector,
    SyslogReceiver,
)
from packages.config import parse_exporters, parse_listen_address, parse_networks
from tests.unit.agent.fakes import agent_settings, make_context


def test_listen_addresses_name_one_interface() -> None:
    assert parse_listen_address("127.0.0.1:5514") == ("127.0.0.1", 5514)
    assert parse_listen_address("[::1]:2055") == ("::1", 2055)
    for invalid in ("0.0.0.0:514", "[::]:514", "localhost:514", "127.0.0.1", "127.0.0.1:0"):
        with pytest.raises(ValueError, match=r".+"):
            parse_listen_address(invalid)


def test_exporters_and_networks_are_parsed() -> None:
    assert parse_exporters("Edge-1=192.0.2.1, core=2001:db8::1") == {
        "192.0.2.1": "edge-1",
        "2001:db8::1": "core",
    }
    assert [str(n) for n in parse_networks("10.0.0.0/8, ::1/128")] == ["10.0.0.0/8", "::1/128"]
    with pytest.raises(ValueError, match="listed only once"):
        parse_exporters("a=192.0.2.1,b=192.0.2.1")


def test_live_capture_needs_explicit_authorization(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="AGENT_LIVE_CAPTURE_AUTHORIZED"):
        agent_settings(tmp_path, agent_live_capture_interface="Ethernet")


def test_promiscuous_capture_needs_lab_networks(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="AGENT_FLOW_ALLOWED_NETWORKS"):
        agent_settings(
            tmp_path,
            agent_live_capture_interface="Ethernet",
            agent_live_capture_authorized=True,
            agent_live_capture_promiscuous=True,
        )


def test_non_loopback_listeners_need_explicit_approval(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="AGENT_SYSLOG_UDP_LISTEN"):
        agent_settings(tmp_path, agent_syslog_udp_listen="192.0.2.10:514")
    settings = agent_settings(
        tmp_path, agent_syslog_udp_listen="192.0.2.10:514", agent_syslog_allow_non_loopback=True
    )
    assert settings.agent_syslog_udp_listen == "192.0.2.10:514"


def test_flow_collection_needs_listed_exporters(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="AGENT_NETFLOW_EXPORTERS"):
        agent_settings(tmp_path, agent_netflow_records_file="flows.jsonl")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_windows_eventlog_levels", "critical,loud"),
        ("agent_windows_eventlog_extra_event_ids", "7045,70000"),
        ("agent_session_logon_types", "2,x"),
        ("agent_flow_allowed_networks", "10.0.0.0/33"),
        ("agent_netflow_exporters", "Bad Name=192.0.2.1"),
    ],
)
def test_malformed_values_are_refused(tmp_path: Path, field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        agent_settings(tmp_path, **{field: value})


def test_no_collector_is_enabled_by_default(tmp_path: Path) -> None:
    assert build_collectors(agent_settings(tmp_path), make_context()) == []


def test_every_collector_can_be_enabled(tmp_path: Path) -> None:
    settings = agent_settings(
        tmp_path,
        agent_pcap_files=str(tmp_path / "a.pcap"),
        agent_live_capture_interface="Ethernet",
        agent_live_capture_authorized=True,
        agent_netflow_exporters="edge=192.0.2.1",
        agent_netflow_records_file=str(tmp_path / "flows.jsonl"),
        agent_syslog_udp_listen="127.0.0.1:5514",
        agent_syslog_tcp_listen="127.0.0.1:5514",
        agent_audit_log_file=str(tmp_path / "audit.log"),
        agent_ebpf_events_file=str(tmp_path / "ebpf.jsonl"),
    )

    collectors = build_collectors(settings, make_context())

    assert [type(c) for c in collectors] == [
        PcapFileCollector,
        LiveCaptureCollector,
        NetflowRecordsFileCollector,
        SyslogReceiver,
        SyscallFileCollector,
        SyscallFileCollector,
    ]
    assert [c.name for c in collectors][-2:] == ["auditd", "ebpf"]


@pytest.mark.skipif("sys.platform != 'win32'", reason="needs the Windows Event Log API")
def test_windows_collectors_are_built_on_windows(tmp_path: Path) -> None:
    settings = agent_settings(
        tmp_path,
        agent_windows_eventlog_channels="System,Application",
        agent_windows_security_enabled=True,
    )

    collectors = build_collectors(settings, make_context())

    assert [c.name for c in collectors] == ["windows_eventlog", "windows_security"]
    assert all(isinstance(c, EventLogCollector) for c in collectors)
