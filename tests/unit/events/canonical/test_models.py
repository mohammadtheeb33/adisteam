"""Canonical event models: base fields, categories and cross-field rules."""

import re
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

import pytest
from pydantic import ValidationError

from packages.events.canonical import (
    AuthenticationEvent,
    AuthFailureReason,
    AuthMethod,
    CanonicalEvent,
    EventCategory,
    NetworkFlowEvent,
    NetworkProtocol,
    ProcessEvent,
    SecurityEvent,
    SeverityHint,
    SystemEvent,
)
from packages.events.canonical.v1 import MAX_PATH_LENGTH, MAX_USERNAME_LENGTH, PORT_PROTOCOLS
from packages.observability import TRACE_ID_PATTERN, log_context
from tests.unit.events.canonical.samples import (
    BUILDERS,
    authentication,
    network,
    process,
    security,
    system,
)

MODELS: dict[str, type[CanonicalEvent]] = {
    "system": SystemEvent,
    "authentication": AuthenticationEvent,
    "network": NetworkFlowEvent,
    "process": ProcessEvent,
    "security": SecurityEvent,
}
TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


def _invalid(model: type[CanonicalEvent], document: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(document)


# ------------------------------------------------------------------------------ base fields


@pytest.mark.parametrize("category", sorted(MODELS))
def test_every_category_validates_its_sample(category: str) -> None:
    event = MODELS[category].model_validate(BUILDERS[category]())

    assert event.category is EventCategory(category)
    assert event.schema_version == "1.0"


def test_defaults_are_generated() -> None:
    event = SystemEvent(
        event_type="system.boot",
        timestamp=datetime(2026, 9, 25, 12, tzinfo=UTC),
        source_type="journald",
        source_name="journald@web-1",
    )

    assert isinstance(event.event_id, UUID)
    assert event.schema_version == "1.0"
    assert event.category is EventCategory.SYSTEM
    assert abs(datetime.now(UTC) - event.received_at) < timedelta(seconds=5)
    assert re.fullmatch(TRACE_ID_PATTERN, event.trace_id)
    assert (event.host_id, event.agent_id, event.severity_hint) == (None, None, None)
    assert event.metadata == {}


def test_category_is_fixed_by_the_model() -> None:
    _invalid(SystemEvent, system(category="network"))


@pytest.mark.parametrize(
    ("category", "event_type"),
    [
        ("system", "network.flow"),
        ("system", "system"),
        ("system", "System.Boot"),
        ("authentication", "auth.login"),
        ("network", "network..flow"),
        ("process", "process.started!"),
        ("security", ""),
    ],
)
def test_event_type_must_belong_to_the_category(category: str, event_type: str) -> None:
    _invalid(MODELS[category], BUILDERS[category](event_type=event_type))


def test_nested_event_types_are_allowed() -> None:
    event = SecurityEvent.model_validate(security(event_type="security.alert.ids"))

    assert event.event_type == "security.alert.ids"


@pytest.mark.parametrize("field", ["timestamp", "received_at"])
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-09-25T15:00:00+03:00", datetime(2026, 9, 25, 12, tzinfo=UTC)),
        ("2026-09-25T12:00:00Z", datetime(2026, 9, 25, 12, tzinfo=UTC)),
        ("2026-09-25T07:00:00-05:00", datetime(2026, 9, 25, 12, tzinfo=UTC)),
        (
            datetime(2026, 9, 25, 14, tzinfo=timezone(timedelta(hours=2))),
            datetime(2026, 9, 25, 12, tzinfo=UTC),
        ),
    ],
)
def test_timestamps_are_normalized_to_utc(field: str, value: object, expected: datetime) -> None:
    event = SystemEvent.model_validate(system(**{field: value}))

    moment = getattr(event, field)
    assert moment == expected
    assert moment.tzinfo is UTC


@pytest.mark.parametrize("field", ["timestamp", "received_at"])
@pytest.mark.parametrize(
    "value",
    [
        "2026-09-25T12:00:00",  # no offset: ambiguous
        datetime(2026, 9, 25, 12),  # naive on purpose
        1_790_000_000,
        1_790_000_000.5,
        "1790000000",  # numeric strings too: pydantic would read them as Unix time
        "1790000000.5",
        "1.79e9",
        "2026",
        "-5",
        True,
        "yesterday",
        "",
    ],
)
def test_ambiguous_or_malformed_timestamps_are_rejected(field: str, value: object) -> None:
    _invalid(SystemEvent, system(**{field: value}))


def test_timestamp_is_required() -> None:
    document = system()
    del document["timestamp"]

    _invalid(SystemEvent, document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_type", "Auditd"),
        ("source_type", "audit d"),
        ("source_type", ""),
        ("source_name", " padded"),
        ("source_name", "line\nbreak"),
        ("source_name", ""),
        ("source_name", "x" * 257),
        ("host_id", "has space"),
        ("host_id", "-leading-dash"),
        ("host_id", ""),
        ("host_id", "h" * 256),
        ("agent_id", "tab\tseparated"),
        ("severity_hint", "severe"),
        ("trace_id", TRACE.upper()),
        ("trace_id", "0" * 32),
        ("trace_id", "abc"),
        ("schema_version", "1.1"),
        ("schema_version", "2.0"),
    ],
)
def test_malformed_base_fields_are_rejected(field: str, value: object) -> None:
    _invalid(SystemEvent, system(**{field: value}))


@pytest.mark.parametrize(
    "host_id",
    ["web-1", "web-1.example.com", "i-0abc123def456", "3f2b1c9e-8d7a-4b6c-9e5f-1a2b3c4d5e6f"],
)
def test_identifier_formats(host_id: str) -> None:
    assert SystemEvent.model_validate(system(host_id=host_id)).host_id == host_id


def test_severity_hint_is_case_insensitive() -> None:
    assert SecurityEvent.model_validate(security(severity_hint=" HIGH ")).severity_hint is (
        SeverityHint.HIGH
    )


def test_trace_id_is_inherited_from_the_log_context() -> None:
    document = system()

    with log_context(trace_id=TRACE):
        inherited = SystemEvent.model_validate(document)
    explicit = SystemEvent.model_validate(system(trace_id="a" * 32))

    assert inherited.trace_id == TRACE
    assert explicit.trace_id == "a" * 32


def test_unknown_top_level_fields_are_rejected() -> None:
    _invalid(SecurityEvent, security(rule_id="ET-1"))


def test_events_are_immutable() -> None:
    event = SystemEvent.model_validate(system())

    with pytest.raises(ValidationError):
        event.host_id = "other"  # type: ignore[misc]


def test_validation_errors_do_not_echo_input() -> None:
    with pytest.raises(ValidationError) as caught:
        AuthenticationEvent.model_validate(
            authentication(username="sentinel-user", src_port=70_000, host_id="sentinel host")
        )

    assert "sentinel" not in str(caught.value)


# --------------------------------------------------------------------------- network fields


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("10.0.0.5", IPv4Address("10.0.0.5")),
        ("2001:db8::1", IPv6Address("2001:db8::1")),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", IPv6Address("2001:db8::1")),
        ("::ffff:10.0.0.5", IPv4Address("10.0.0.5")),
        ("fe80::1%eth0", IPv6Address("fe80::1%eth0")),
        (IPv4Address("192.0.2.1"), IPv4Address("192.0.2.1")),
    ],
)
def test_ip_addresses_are_parsed_and_normalized(
    raw: object, expected: IPv4Address | IPv6Address
) -> None:
    assert NetworkFlowEvent.model_validate(network(src_ip=raw, dst_ip=raw)).src_ip == expected


@pytest.mark.parametrize(
    "address",
    [
        "256.0.0.1",
        "10.0.0",
        "10.0.0.1.2",
        "010.0.0.1",
        " 10.0.0.1",
        "10.0.0.1 ",
        "10.0.0.0/24",
        "2001:db8::g",
        "2001:db8:::1",
        "",
        "localhost",
        167_772_161,
        b"10.0.0.1",
        None,
    ],
)
def test_malformed_addresses_are_rejected(address: object) -> None:
    _invalid(NetworkFlowEvent, network(src_ip=address))


@pytest.mark.parametrize("port", [0, 1, 443, 65_535])
def test_valid_ports(port: int) -> None:
    event = NetworkFlowEvent.model_validate(network(src_port=port, dst_port=port))

    assert (event.src_port, event.dst_port) == (port, port)


@pytest.mark.parametrize("port", [-1, 65_536, "443", 443.0, True, None])
@pytest.mark.parametrize("field", ["src_port", "dst_port"])
def test_invalid_ports_are_rejected(field: str, port: object) -> None:
    _invalid(NetworkFlowEvent, network(**{field: port}))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("TCP", NetworkProtocol.TCP),
        (" udp ", NetworkProtocol.UDP),
        (6, NetworkProtocol.TCP),
        (17, NetworkProtocol.UDP),
        (132, NetworkProtocol.SCTP),
        (1, NetworkProtocol.ICMP),
        (58, NetworkProtocol.ICMPV6),
        (47, NetworkProtocol.GRE),
        (41, NetworkProtocol.OTHER),
    ],
)
def test_protocol_names_and_iana_numbers(raw: object, expected: NetworkProtocol) -> None:
    document = network(protocol=raw)
    if expected not in PORT_PROTOCOLS:
        del document["src_port"], document["dst_port"]

    assert NetworkFlowEvent.model_validate(document).protocol is expected


@pytest.mark.parametrize("protocol", [256, -1, "tcpx", True, ""])
def test_invalid_protocols_are_rejected(protocol: object) -> None:
    _invalid(NetworkFlowEvent, network(protocol=protocol))


@pytest.mark.parametrize("protocol", ["icmp", "icmpv6", "gre", "esp"])
def test_ports_are_rejected_for_portless_protocols(protocol: str) -> None:
    _invalid(NetworkFlowEvent, network(protocol=protocol))


def test_icmp_flow_without_ports() -> None:
    document = network(protocol="icmp")
    del document["src_port"], document["dst_port"]

    event = NetworkFlowEvent.model_validate(document)

    assert (event.src_port, event.dst_port) == (None, None)


@pytest.mark.parametrize("protocol", ["tcp", "udp", "sctp"])
@pytest.mark.parametrize("missing", ["src_port", "dst_port"])
def test_port_protocol_flows_require_both_ports(protocol: str, missing: str) -> None:
    document = network(protocol=protocol)
    del document[missing]

    _invalid(NetworkFlowEvent, document)


@pytest.mark.parametrize("missing", ["src_ip", "dst_ip", "protocol"])
def test_flows_require_endpoints_and_protocol(missing: str) -> None:
    document = network()
    del document[missing]

    _invalid(NetworkFlowEvent, document)


def test_flow_endpoints_must_share_an_ip_version() -> None:
    _invalid(NetworkFlowEvent, network(src_ip="10.0.0.5", dst_ip="2001:db8::1"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bytes_sent", -1),
        ("bytes_received", 2**63),
        ("bytes_sent", "100"),
        ("bytes_received", 1.5),
    ],
)
def test_invalid_byte_counters_are_rejected(field: str, value: object) -> None:
    _invalid(NetworkFlowEvent, network(**{field: value}))


def test_byte_counters_accept_zero_and_int64_max() -> None:
    event = NetworkFlowEvent.model_validate(network(bytes_sent=0, bytes_received=2**63 - 1))

    assert (event.bytes_sent, event.bytes_received) == (0, 2**63 - 1)


def test_authentication_network_context_is_optional() -> None:
    document = authentication()
    for field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
        del document[field]

    event = AuthenticationEvent.model_validate(document)

    assert event.src_ip is None


def test_ports_without_protocol_are_allowed_in_context() -> None:
    document = authentication(protocol=None)

    assert AuthenticationEvent.model_validate(document).src_port == 50_522


# ---------------------------------------------------------------------- authentication fields


@pytest.mark.parametrize("success", ["false", 0, 1, None])
def test_success_must_be_a_boolean(success: object) -> None:
    _invalid(AuthenticationEvent, authentication(success=success))


def test_success_is_required() -> None:
    document = authentication()
    del document["success"]

    _invalid(AuthenticationEvent, document)


def test_failure_reason_is_only_allowed_on_failure() -> None:
    _invalid(AuthenticationEvent, authentication(success=True))

    event = AuthenticationEvent.model_validate(authentication(success=True, failure_reason=None))
    assert event.success is True


def test_authentication_vocabularies_are_case_insensitive() -> None:
    event = AuthenticationEvent.model_validate(
        authentication(auth_method="PUBLIC_KEY", failure_reason="Account_Locked")
    )

    assert event.auth_method is AuthMethod.PUBLIC_KEY
    assert event.failure_reason is AuthFailureReason.ACCOUNT_LOCKED


@pytest.mark.parametrize(
    ("field", "value"), [("auth_method", "telepathy"), ("failure_reason", "bad luck")]
)
def test_unknown_authentication_vocabulary_is_rejected(field: str, value: str) -> None:
    _invalid(AuthenticationEvent, authentication(**{field: value}))


@pytest.mark.parametrize(
    ("raw", "stored"),
    [
        ("alice", "alice"),
        ("DOMAIN\\alice", "DOMAIN\\alice"),
        ("", ""),
        ("root\x00", "root\ufffd"),
        ("bad\ud800surrogate", "bad\ufffdsurrogate"),
        ("\x1b[31mred\x1b[0m", "\x1b[31mred\x1b[0m"),
        ("admin\u202egnp.exe", "admin\u202egnp.exe"),
        ("José", "José"),
    ],
)
def test_usernames_are_preserved_but_made_storable(raw: str, stored: str) -> None:
    assert AuthenticationEvent.model_validate(authentication(username=raw)).username == stored


def test_overlong_usernames_are_truncated_not_rejected() -> None:
    event = AuthenticationEvent.model_validate(authentication(username="u" * 10_000))

    assert event.username == "u" * MAX_USERNAME_LENGTH


# ----------------------------------------------------------------------------- process fields


@pytest.mark.parametrize(
    ("path", "name"),
    [
        ("/usr/sbin/sshd", "sshd"),
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
        ("relative/tool", "tool"),
        ("plain", "plain"),
    ],
)
def test_process_name_is_derived_from_the_executable_path(path: str, name: str) -> None:
    document = process(executable_path=path)
    del document["process_name"]

    assert ProcessEvent.model_validate(document).process_name == name


def test_explicit_process_name_is_kept() -> None:
    event = ProcessEvent.model_validate(process(process_name="svchost.exe"))

    assert event.process_name == "svchost.exe"


def test_process_event_requires_a_name_or_path_and_a_pid() -> None:
    nameless = process()
    del nameless["process_name"], nameless["executable_path"]
    pidless = process()
    del pidless["process_id"]

    _invalid(ProcessEvent, nameless)
    _invalid(ProcessEvent, pidless)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("process_id", -1),
        ("process_id", 2**32),
        ("process_id", "4242"),
        ("parent_process_id", -5),
        ("parent_process_id", 1.0),
    ],
)
def test_invalid_process_ids_are_rejected(field: str, value: object) -> None:
    _invalid(ProcessEvent, process(**{field: value}))


def test_executable_paths_are_made_storable_and_truncated() -> None:
    event = ProcessEvent.model_validate(
        process(executable_path="/opt/\x00evil/" + "d" * 10_000, process_name="evil")
    )

    assert event.executable_path is not None
    assert event.executable_path.startswith("/opt/\ufffdevil/")
    assert len(event.executable_path) == MAX_PATH_LENGTH


# ---------------------------------------------------------------------------- security event


def test_security_event_carries_network_and_process_context() -> None:
    event = SecurityEvent.model_validate(security())

    assert event.dst_port == 22
    assert event.process_name == "nc"
    assert event.metadata["rule_id"] == "ET-2001219"


def test_minimal_security_event() -> None:
    event = SecurityEvent.model_validate(
        {
            "event_type": "security.malware_detected",
            "timestamp": "2026-09-25T12:00:00Z",
            "source_type": "edr",
            "source_name": "edr@web-1",
        }
    )

    assert event.src_ip is None
    assert event.process_name is None


# ------------------------------------------------------------------------------- field order


@pytest.mark.parametrize("category", sorted(MODELS))
def test_base_fields_come_first_and_metadata_last(category: str) -> None:
    fields = list(MODELS[category].model_fields)

    assert fields[:2] == ["schema_version", "category"]
    assert fields[-1] == "metadata"


@pytest.mark.parametrize("model", list(MODELS.values()), ids=lambda model: model.__name__)
def test_every_field_is_documented(model: type[CanonicalEvent]) -> None:
    undocumented = [name for name, field in model.model_fields.items() if not field.description]

    assert undocumented == []


def test_no_process_name_is_derived_from_a_directory_path() -> None:
    event = SecurityEvent.model_validate(security(process_name=None, executable_path="/usr/bin/"))

    assert event.process_name is None
    assert event.executable_path == "/usr/bin/"
