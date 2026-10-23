# Phase 1 completion per the specification: real-data verification

**Result: PASS, with the limits listed below.** Run of 2026-10-19 (20:03–20:15 UTC), script
`scripts/lab_phase1.py scenario`, lab `infrastructure/lab/compose.yaml`.

Phase 1 of the specification (pentra.pdf §2) asks for four data types collected through
agents, a FastAPI gateway and Kafka topics named `system_logs`, `network_flows` and
`auth_events`. This report verifies the implementation of 2026-10-19 (decision OD-39 in
[ARCHITECTURE.md](ARCHITECTURE.md)): the separate "muna" implementation's collectors merged
into the agent, plus a syslog receiver, auditd and eBPF system calls, and session vectors.

## 1. Setup

A separate compose project (`adis-lab`) with its own Kafka 3.9.1, PostgreSQL 17, ingestion
API, normalizer and a Linux collector agent, all from the `adis-python:local` image built
from this repository. The developer's `.env` and the hosted Supabase project were not used.
Secrets were random (`.adis-lab/lab.env`, git-ignored).

| Agent ("device") | Runs on | Collectors |
|---|---|---|
| `lab-linux-collector` | container in the lab network | syslog receiver (UDP + TCP), NetFlow/IPFIX (GoFlow2 output), PCAP file, eBPF system calls, live capture of its own interface (libpcap) |
| `lab-windows-agent` | this Windows 11 computer | Windows Event Log (System, Application, 24 h backfill), Security log, PCAP file |

Real telemetry sources:

| Source | What is real |
|---|---|
| `web-client` | DNS, HTTPS and ICMP traffic of one lab container to public web sites |
| `capture` | `tcpdump` in that container's network namespace (snaplen 160) → `web-client.pcap` |
| `flow-exporter` + `goflow2` | `softflowd` exporting IPFIX of the same traffic; GoFlow2 v2.2.3 decoding it |
| `ssh-server` + `ssh-client` | Debian OpenSSH with PAM, logging through rsyslog (RFC 5424/TCP for auth, RFC 3164/UDP for the rest); key logins, attempts for a nonexistent account, an unknown key (no passwords) |
| `ebpf` | `infrastructure/ebpf/adis-syscalls.bt` (bpftrace 0.20.4) tracing the Docker VM kernel for 180 s |
| this computer | its own System and Application event logs; its Security log (refused, see §5) |
| omran's capture | 208,949 real packets of the owner's networks (Oct 10–12), rebuilt from the packet log as a header-only PCAP (no TCP flags or time zone in the source) |

Timeline (seconds from start): 21 lab up and Windows agent started · 57 **ingestion API
stopped** · 88 API started again · 228 real sources finished · 324 Windows agent finished ·
355 first-pass results · 356 Linux agent restarted · 376–527 Windows agent replay with an
empty data directory · 548 final results; then a replay with the same agent identity.

## 2. Results

| Source | `source_type` | Events stored | Event types |
|---|---|---:|---|
| eBPF | `ebpf` | 5,243 | 2,738 `process.syscall_sequence`, 2,505 `process.started` |
| omran PCAP (Windows agent) | `pcap` | 3,751 | `network.flow` from 208,949 packets |
| lab PCAP (Linux agent) | `pcap` | 84 | `network.flow` |
| Windows Event Log | `windows_eventlog` | 181 → 182 | 149 `system.windows_event`, 15 `system.service_start_type_changed`, 6 `system.update_installed`, 4 `system.service_installed`, boot/shutdown/time events |
| NetFlow/IPFIX | `netflow` | 109 | `network.flow` (104 TCP, 4 ICMP, 1 ICMPv6; 17.0 MB exported) |
| syslog | `syslog` | 76 | 58 `system.syslog`, 10 `authentication.login.ssh`, 4 `authentication.session_started`, 4 `authentication.session_ended` |
| live capture | `live_capture` | 4 | `network.flow` (the agent's own syslog traffic; API and Kafka excluded) |
| registrations | `agent` | 3 | `system.agent_registered` |

- **Topics.** Raw records: `system_logs` 5,484, `network_flows` 3,948, `auth_events` 18 in
  the first pass; every stored event also on `adis.security.events`.
- **Totals.** 9,450 events stored in the first pass, 9,450 distinct ids, 4 hosts, **0 dead
  letters**.
- **Latency (API receipt → stored), p50 / p95.** Windows Event Log 0.18 / 0.19 s, NetFlow
  0.07 / 0.12 s, live capture 0.04 / 0.09 s, syslog 0.05 / 0.98 s, eBPF 0.15 / 0.98 s, PCAP
  bulk 0.67 / 1.60 s. Peak storage rate 805 events/s (3,104 in the busiest 10 s).
- **Authentication (sshd via syslog).** Exactly the scenario: 4 successful key logins, 3
  failures `invalid_credentials` (unknown key), 3 failures `unknown_user` with the name
  withheld, 4 sessions. The typed nonexistent account name appears in **0** stored events.
- **Session vectors.** Durations 3.09, 3.06, 3.06 and 20.05 s; `failed_attempts_before`
  0, 1, 2, 3 as the unknown-key attempts accumulated; `remote` 1.
- **Call sequences.** Up to 256 calls per sequence, e.g. `dockerd`: `bind`, `mount`,
  `setns`, `listen`, `accept4`, `connect`, `fchmodat`, `fchownat`.

## 3. Resilience and duplicates

| Check | Result |
|---|---|
| **API outage of 30 s** during the SSH scenarios | 1,163 events produced during the outage (1,114 eBPF, 30 syslog incl. 7 SSH authentication/session events, 1 NetFlow, 18 PCAP) were held in the agents' spools for up to 36 s ("ingestion API unavailable; events are kept") and stored after recovery. The SSH counts above are exact, so nothing was lost. |
| **Agent restart** | The Linux agent restarted with its spool: its registration was re-sent identically and absorbed (no dead letter). |
| **Same agent re-sends everything** (same identity, no checkpoints) | 3,751 flows and 179 Windows events published again to the raw topics; **no new row and no dead letter** (one genuinely new Windows event was stored). One dead letter for the registration, because the copied directory lacked the stored registration time. |
| **Reinstalled agent re-reads history** (new identity) | The same 3,751 flows and 177 Windows events arrived with a different `agent_id`; the normalizer refused all 3,928 as *conflicting duplicates* (dead-lettered, nothing stored twice). See §5. |

## 4. Defects the real data found (all fixed, each with a regression test)

| # | Defect | Fix |
|---|---|---|
| 1 | Live capture holds Scapy's process-wide layer filter; reading a PCAP file at the same time failed with "Already filtered". | A shared, reference-counted filter (`packets.LAYER_FILTER`). |
| 2 | rsyslog's RFC 5424 output keeps a space before the message, so no sshd line was recognized (0 authentication events). | Messages are stripped before matching and storing. |
| 3 | The name typed for a nonexistent account was withheld from the event but still in follow-up lines ("Connection closed by invalid user X"). | Every sshd line withholds the name after "invalid user". |
| 4 | With `LogLevel VERBOSE` a rejected key was counted twice ("Failed publickey" and "Connection closed by authenticating user"). | The connection's process id ties the lines; one failure is counted. |
| 5 | Pre-existing: every agent restart re-sent its registration with the same id and a new time, which the normalizer dead-lettered as a conflicting duplicate. | The first registration time is kept with the registration checkpoint and reused. |
| 6 | Scapy on Linux defaults to raw sockets, so live capture was "unavailable" although libpcap was installed. | Scapy is switched to libpcap when the library is present. |

## 5. Limits and open points

- **Kernel audit** could not run here: the kernel accepts audit requests only from its initial
  PID namespace, which Docker Desktop containers never are. The auditd collector is verified
  with records in the audit daemon's real format (RAW and ENRICHED); eBPF covers system calls
  on real data.
- **Windows Security log**: refused without "Event Log Readers" or elevation (verified: the
  collector reports *access denied*, retries every 60 s, the other channels keep working).
  Logons are verified with real-format fixtures and, on real data, through sshd/PAM.
- **Live capture on Windows** needs Npcap (not installed; the agent never installs drivers).
  Live capture is verified on Linux with libpcap.
- **Throughput**: the specification's "millions of messages per second" and "MTTD < 50 ms"
  are not demonstrated; measured peak 805 events/s stored, receipt-to-store p50 0.04–0.67 s.
- **Reinstalled agents**: deterministic event ids come from source facts, so another agent
  identity reporting the same events is a conflicting duplicate. Nothing is stored twice, but
  the records fill the dead-letter topic; decide whether `agent_id` should be ignored in that
  comparison (owner decision).
- omran's capture has no TCP flags or time zone; its timestamps were read as UTC.

## 6. Reproduce

```
python scripts/lab_phase1.py scenario --pcap <optional capture>   # about 9 minutes
python scripts/lab_phase1.py report --out .adis-lab/results.json
python scripts/lab_phase1.py down
```

Results, timeline and container logs of this run: `.adis-lab/final/` (git-ignored).
