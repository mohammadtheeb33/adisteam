"""Telemetry collectors of the endpoint agent.

Every collector reads what the host or its operator already produces (log files, the
Windows Event Log, capture files, an interface the operator authorized, flow exports,
syslog, the audit log, an eBPF tracer's output); none changes system or audit settings.
"""

from apps.agent.collectors.base import Collector, CollectorContext, EventSink
from apps.agent.collectors.live_capture import LiveCaptureCollector
from apps.agent.collectors.logfile import LogFileCollector
from apps.agent.collectors.netflow import GoFlow2ProcessCollector, NetflowRecordsFileCollector
from apps.agent.collectors.pcap import PcapFileCollector
from apps.agent.collectors.simulation import AuthEventSimulator, NetworkFlowSimulator
from apps.agent.collectors.syscalls import (
    SyscallFileCollector,
    parse_audit_line,
    parse_ebpf_line,
)
from apps.agent.collectors.syslog import SyslogMapper, SyslogReceiver
from apps.agent.collectors.windows_auth import AuthenticationMapper
from apps.agent.collectors.windows_events import (
    EventLogCollector,
    SystemEventMapper,
    SystemLogRules,
    WindowsEventLogReader,
)

__all__ = [
    "AuthEventSimulator",
    "AuthenticationMapper",
    "Collector",
    "CollectorContext",
    "EventLogCollector",
    "EventSink",
    "GoFlow2ProcessCollector",
    "LiveCaptureCollector",
    "LogFileCollector",
    "NetflowRecordsFileCollector",
    "NetworkFlowSimulator",
    "PcapFileCollector",
    "SyscallFileCollector",
    "SyslogMapper",
    "SyslogReceiver",
    "SystemEventMapper",
    "SystemLogRules",
    "WindowsEventLogReader",
    "parse_audit_line",
    "parse_ebpf_line",
]
