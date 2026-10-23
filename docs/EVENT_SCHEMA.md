# Canonical security event schema

Every piece of telemetry ADIS ingests is normalized into one **canonical event** before it
reaches detection. The schema lives in `packages/events/canonical/`:

- `v1.py` holds the models of schema version 1.
- `codec.py` handles parsing, serialization, envelopes and JSON Schema.
- `schemas/canonical-event-1.0.schema.json` is the published contract (JSON Schema,
  draft 2020-12).

**Current version: 1.0.**

## Categories

`category` selects the model. `event_type` is a dotted lower-case type that **must start
with the category**.

| Model | `category` | Kafka topic | `event_type` examples | Extra required fields |
|---|---|---|---|---|
| `SystemEvent` | `system` | `system_logs` | `system.boot`, `system.service_stopped`, `system.config_changed` | none |
| `AuthenticationEvent` | `authentication` | `auth_events` | `authentication.login`, `authentication.logout` | `success` |
| `NetworkFlowEvent` | `network` | `network_flows` | `network.flow`, `network.connection_opened` | `src_ip`, `dst_ip`, `protocol`; ports for TCP/UDP/SCTP |
| `ProcessEvent` | `process` | `system_logs` | `process.started`, `process.terminated` | `process_id`, and `process_name` (or `executable_path`) |
| `SecurityEvent` | `security` | `system_logs` | `security.alert`, `security.malware_detected` | none |

The topic mapping is `packages.kafka.telemetry_topic(category)`. These are the *accepted*
telemetry topics; their names are the ones the specification gives them (pentra.pdf §2,
step 1; until 2026-10-19 they were `adis.system.events`, `adis.auth.events` and
`adis.network.events`). The [normalizer](NORMALIZER.md) consumes them and publishes every
category, normalized, deduplicated and stored, to `adis.security.events`, which is what
detection reads.

### Event types produced by the agent's collectors

| `event_type` | Model | Producer | Notes |
|---|---|---|---|
| `system.log_entry` | System | log files | one line |
| `system.<name>` / `system.windows_event` | System | Windows Event Log | named for known provider/ID pairs (`system.service_installed`, `system.event_log_cleared`, ...); `metadata.windows_event_id` always |
| `system.syslog` | System | syslog receiver | facility, severity, app name and message in `metadata` |
| `authentication.login` / `authentication.login.ssh` / `authentication.login.pam` | Authentication | Windows Security log / sshd / PAM | the only login attempts for the feature generator |
| `authentication.logout`, `.logout_requested`, `.explicit_credentials`, `.special_privileges`, `.account_locked` | Authentication | Windows Security log | 4634, 4647, 4648, 4672, 4740 |
| `authentication.session_started`, `authentication.session_ended` | Authentication | Windows Security log, PAM via syslog | `metadata.session_vector` (`adis.session_vector.v1`): user behavior as session vectors |
| `network.flow` | NetworkFlow | PCAP files, live capture, NetFlow/IPFIX | bidirectional (packet-derived) or as exported; extracted features in `metadata` |
| `process.syscall_sequence` | Process | auditd, eBPF | `metadata.syscalls` (`adis.syscall_sequence.v1`): call sequences |
| `process.started` | Process | auditd, eBPF | successful `execve`/`execveat` |

## Fields

### Base fields (every category)

| Field | Type | Required | Rules |
|---|---|---|---|
| `schema_version` | `"1.0"` | defaults to current | Must be declared on the wire (see [Versioning](#versioning)). |
| `category` | enum | fixed per model | Discriminator. |
| `event_id` | UUID | generated | Unique; consumers deduplicate on it. |
| `event_type` | string ≤ 128 | yes | `category.sub[.sub]`, lower-case `[a-z0-9_]` segments. |
| `timestamp` | datetime | yes | When the event happened at the source. Must carry a UTC offset; normalized to UTC. |
| `received_at` | datetime | defaults to now | When ADIS received it. Same rules as `timestamp`. |
| `source_type` | string | yes | Kind of source: `^[a-z][a-z0-9_]{0,63}$` (e.g. `auditd`, `windows_eventlog`, `zeek`, `suricata`, `agent`). |
| `source_name` | string ≤ 256 | yes | Configured instance name (e.g. `zeek@sensor-1`); no control characters, no surrounding spaces. |
| `host_id` | identifier | no | ADIS's identifier of the host concerned, *not* an untrusted hostname from a log line. |
| `agent_id` | identifier | no | Collecting agent, if any. |
| `severity_hint` | `info` \| `low` \| `medium` \| `high` \| `critical` | no | Severity claimed by the source. ADIS computes its own threat score. |
| `trace_id` | 32 lowercase hex | inherited or new | W3C trace id. Inherited from the current correlation context when omitted. |
| `metadata` | JSON object | defaults to `{}` | Vendor-specific data; see [Metadata](#metadata). |

Identifiers (`host_id`, `agent_id`) match `^[A-Za-z0-9][A-Za-z0-9._:@/+=-]{0,254}$`.

### Network fields

These are required on `NetworkFlowEvent` and optional on `AuthenticationEvent` (the
login's origin) and `SecurityEvent`.

| Field | Type | Rules |
|---|---|---|
| `src_ip`, `dst_ip` | IPv4/IPv6 address | Textual addresses only. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) becomes IPv4. Rejected: octets with leading zeros, networks, surrounding spaces, integers. A flow's endpoints must share an IP version. |
| `src_port`, `dst_port` | integer 0–65535 | Only for `tcp`, `udp`, `sctp` (ICMP type/code go in `metadata`). Required on TCP/UDP/SCTP flows. |
| `protocol` | `tcp`, `udp`, `sctp`, `icmp`, `icmpv6`, `igmp`, `gre`, `esp`, `ah`, `other` | Case-insensitive. IANA numbers are mapped (6 → `tcp`); unknown numbers become `other`. |
| `bytes_sent`, `bytes_received` | integer 0 – 2⁶³−1 | Bytes from and to the source. |

### Authentication fields (`AuthenticationEvent`)

| Field | Type | Rules |
|---|---|---|
| `username` | string | Observed value: never rejected (see below). |
| `auth_method` | `password`, `public_key`, `keyboard_interactive`, `certificate`, `kerberos`, `ntlm`, `oauth`, `saml`, `oidc`, `token`, `mfa`, `other` | Case-insensitive. |
| `success` | boolean | Required; JSON `true`/`false` only. |
| `failure_reason` | `invalid_credentials`, `unknown_user`, `account_locked`, `account_disabled`, `expired_credentials`, `mfa_failed`, `policy_denied`, `other` | Only when `success` is false. Keep the raw vendor reason in `metadata`. |

### Process fields

These are required on `ProcessEvent` and optional on `SecurityEvent`.

| Field | Type | Rules |
|---|---|---|
| `process_name` | string | Observed value. Defaults to the basename of `executable_path` (`/` or `\` separators). |
| `process_id`, `parent_process_id` | integer 0 – 2³²−1 | |
| `executable_path` | string | Observed value. |

### Metadata

Vendor data that has no canonical field goes in `metadata`. It is preserved as-is
when it is safe JSON:

- Values must be JSON types. `datetime` (with an offset; converted to UTC `Z`), `UUID`,
  IP addresses and enums are converted to strings. Bytes, sets, arbitrary objects and
  NaN/infinite numbers are **rejected**. Encode binary data yourself, e.g. as base64.
- Keys are strings of 1–256 characters. Objects and arrays nest at most 10 levels. The
  whole object serializes to at most 64 KiB.
- NUL characters and lone surrogates in keys and strings become U+FFFD, because
  PostgreSQL cannot store them.
- **Credential keys are redacted:** the values of `password`, `passwd`, `pwd`,
  `passphrase`, `secret`, `client_secret`, `api_key`, `access_token`, `refresh_token`,
  `id_token`, `session_token`, `authorization`, `proxy_authorization`, `cookie`,
  `set_cookie` and `private_key` become `[REDACTED]`, at any depth.
  - Matching ignores case and `_`, `-` and spaces, but is otherwise **exact**, so
    security signal such as `registry_key` or `TokenElevationType` is kept.
- `metadata` is its own namespace and cannot override canonical fields.
- `metadata.adis_ingestion` is **reserved** for the normalizer's ingestion metadata
  ([NORMALIZER.md](NORMALIZER.md#ingestion-metadata)). A producer-supplied value is
  replaced. It includes `timestamp_skew_seconds` when `timestamp` lies further in the
  future than `received_at` allows, so detection can treat the time as suspect.

## Normalization and safety rules

- **Controlled values are strict.** Identifiers, types, enums, IPs, ports and
  timestamps are produced by ADIS normalizers, so a malformed value is a bug and is
  rejected. The error names the field but never echoes the value.
- **Observed values are never rejected.** `username`, `process_name` and
  `executable_path` are attacker-influenced. Rejecting unusual content would let an
  attacker hide activity behind a crafted name.
  - These values keep terminal escapes, bidi overrides and non-ASCII text.
  - NUL and lone surrogates become U+FFFD.
  - Values are truncated at 256 characters (names) or 4096 (paths).
- **Timestamps** must carry an offset. Epoch numbers, including numeric strings such as
  `"1790000000"`, are refused because seconds and
  milliseconds cannot be told apart reliably. Normalizers resolve source time zones.
- **No unknown top-level fields.** Anything non-canonical belongs in `metadata`.
- **Events are immutable** once validated.
- **Size:** a serialized event may not exceed 128 KiB.

Normalizers must not drop an event because optional enrichment is invalid. If metadata is
rejected, retry with less metadata. A normalizer that cannot build a valid event raises
`NonRetriableError`, so the record is dead-lettered rather than lost.

## JSON representation

```json
{
  "schema_version": "1.0",
  "category": "authentication",
  "event_id": "0f8b0a8e-5d0c-4d7b-9d0e-2b8f3f0c9a11",
  "event_type": "authentication.login",
  "timestamp": "2026-09-25T09:00:00Z",
  "received_at": "2026-09-25T09:00:01.482113Z",
  "source_type": "auditd",
  "source_name": "auditd@web-1",
  "host_id": "web-1",
  "agent_id": "agent-7",
  "severity_hint": null,
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "username": "root",
  "auth_method": "password",
  "success": false,
  "failure_reason": "invalid_credentials",
  "src_ip": "203.0.113.7",
  "dst_ip": "10.0.0.9",
  "src_port": 50522,
  "dst_port": 22,
  "protocol": "tcp",
  "bytes_sent": null,
  "bytes_received": null,
  "metadata": {"pam_service": "sshd", "raw_reason": "authentication failure"}
}
```

Timestamps use UTC `Z` notation, addresses are strings, enums are their values, unknown
optional fields are `null`, and `metadata` comes last.

## Using the schema

```python
from packages.events.canonical import (
    AuthenticationEvent,
    from_envelope,
    parse_canonical_event,
    serialize_canonical_event,
    to_envelope,
)
from packages.kafka import telemetry_topic

event = AuthenticationEvent(
    event_type="authentication.login",
    timestamp=observed_at,  # aware datetime or ISO 8601 with offset
    source_type="auditd",
    source_name="auditd@web-1",
    host_id="web-1",
    username=raw_user,
    success=False,
    failure_reason="invalid_credentials",
    src_ip=remote_addr,
    metadata={"pam_service": "sshd"},
)

raw = serialize_canonical_event(event)  # compact UTF-8 JSON
same = parse_canonical_event(raw)  # version- and category-aware

await producer.publish(
    telemetry_topic(event.category),
    to_envelope(event, producer=settings.app_name),
    key=event.host_id,
)
# consumer side
event = from_envelope(envelope)  # validates payload/envelope consistency
```

`to_envelope` copies `event_id`, `event_type`, `timestamp` and `trace_id` into the
envelope and sets `event_version` to the schema's major version. `from_envelope` rejects
envelopes that disagree with their payload. Parsing errors raise `CanonicalEventError`;
an unknown `schema_version` raises `UnsupportedSchemaVersionError`.

## Versioning

`schema_version` is `MAJOR.MINOR`. Documents on the wire must declare it;
`parse_canonical_event` rejects documents without it. New events built from the models
get the current version.

- **Minor version** (1.0 → 1.1): backward-compatible changes only. These are new
  *optional* fields, new enum values, and relaxed constraints. Add the new version to
  the `schema_version` literal in `v1.py` and register it in `codec.py`. Deploy
  **consumers before producers**, because older consumers reject fields and enum values
  they do not know.
- **Major version** (1.x → 2.0): anything else, such as renamed, removed or retyped
  fields, new required fields, tighter constraints, or changed limits.
  1. Create `v2.py` next to `v1.py` and register it in `codec.py`.
  2. Keep v1 parseable while old events exist in Kafka and the database.
  3. The envelope's `event_version` tells consumers which major version a payload uses.
- **Contract snapshot:** `tests/unit/events/canonical/test_schema_contract.py` compares
  the models with the committed JSON Schema, so *any* schema change fails the build until
  someone decides deliberately.
  - For an intentional, correctly versioned change, run `make schemas` (or
    `python scripts/generate_event_schemas.py`) and commit the regenerated file.
  - Once 1.0 events are persisted outside development, never regenerate a released
    version's file for an incompatible change.

## Limits (version 1)

| Limit | Value |
|---|---|
| Serialized event | 131,072 bytes |
| Serialized `metadata` | 65,536 bytes |
| `metadata` nesting | 10 levels |
| `metadata` key length | 256 characters |
| `username`, `process_name` | 256 characters (truncated) |
| `executable_path` | 4,096 characters (truncated) |
| `event_type` | 128 characters |
| `source_name` | 256 characters |
| Identifiers | 255 characters |
| Byte counters | 2⁶³−1 |
| Process ids | 2³²−1 |
