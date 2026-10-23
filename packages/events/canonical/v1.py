"""Canonical ADIS security event schema, version 1.

Every normalized telemetry event is one of five categories, distinguished by
``category``; ``event_type`` must start with the category:

- :class:`SystemEvent` (``system``): ``system.boot``, ``system.service_stopped``
- :class:`AuthenticationEvent` (``authentication``): ``authentication.login``
- :class:`NetworkFlowEvent` (``network``): ``network.flow``
- :class:`ProcessEvent` (``process``): ``process.started``, ``process.terminated``
- :class:`SecurityEvent` (``security``): ``security.alert``

The limits and vocabularies in this module are part of the version 1 contract; changing
them is a schema change (see docs/EVENT_SCHEMA.md).
"""

from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Final, Literal, Self
from uuid import UUID, uuid4

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    Strict,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from packages.events.envelope import EVENT_TYPE_PATTERN
from packages.events.validation import (
    json_metadata,
    lower_if_str,
    observed_text,
    parse_ip_address,
    reject_numeric_timestamp,
    to_utc,
)
from packages.observability.context import TRACE_ID_PATTERN, current_trace_id, new_trace_id
from packages.observability.redaction import REDACTED

SCHEMA_VERSION: Final = "1.0"
SCHEMA_MAJOR: Final = 1

MAX_EVENT_BYTES: Final = 131_072
MAX_METADATA_BYTES: Final = 65_536
MAX_METADATA_DEPTH: Final = 10
MAX_METADATA_KEY_LENGTH: Final = 256
MAX_USERNAME_LENGTH: Final = 256
MAX_PROCESS_NAME_LENGTH: Final = 256
MAX_PATH_LENGTH: Final = 4_096
MAX_COUNTER: Final = 2**63 - 1
MAX_PROCESS_ID: Final = 2**32 - 1

IDENTIFIER_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._:@/+=-]{0,254}$"
SOURCE_TYPE_PATTERN: Final = r"^[a-z][a-z0-9_]{0,63}$"
SOURCE_NAME_PATTERN: Final = r"^[^\s\x00-\x1f\x7f](?:[^\x00-\x1f\x7f]{0,254}[^\s\x00-\x1f\x7f])?$"

REDACTED_METADATA_KEYS: Final = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "client_secret",
        "api_key",
        "access_token",
        "refresh_token",
        "id_token",
        "session_token",
        "authorization",
        "proxy_authorization",
        "cookie",
        "set_cookie",
        "private_key",
    }
)
"""Metadata keys whose values are always replaced by ``[REDACTED]``.

Matching is exact after lower-casing and removing ``_``, ``-`` and spaces, so
credential fields are caught while security-relevant names such as ``registry_key`` or
``TokenElevationType`` are preserved.
"""


class EventCategory(StrEnum):
    """Top-level event category; the discriminator of the canonical schema."""

    SYSTEM = "system"
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    SECURITY = "security"


class SeverityHint(StrEnum):
    """Severity reported or implied by the source. ADIS computes its own threat score."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NetworkProtocol(StrEnum):
    """Transport or network protocol of a flow."""

    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    IGMP = "igmp"
    GRE = "gre"
    ESP = "esp"
    AH = "ah"
    OTHER = "other"


PORT_PROTOCOLS: Final = frozenset({NetworkProtocol.TCP, NetworkProtocol.UDP, NetworkProtocol.SCTP})

_IANA_PROTOCOL_NUMBERS: Final = {
    1: NetworkProtocol.ICMP,
    2: NetworkProtocol.IGMP,
    6: NetworkProtocol.TCP,
    17: NetworkProtocol.UDP,
    47: NetworkProtocol.GRE,
    50: NetworkProtocol.ESP,
    51: NetworkProtocol.AH,
    58: NetworkProtocol.ICMPV6,
    132: NetworkProtocol.SCTP,
}
_MAX_PROTOCOL_NUMBER: Final = 255


class AuthMethod(StrEnum):
    """How the principal tried to authenticate."""

    PASSWORD = "password"  # noqa: S105 - vocabulary value, not a credential
    PUBLIC_KEY = "public_key"
    KEYBOARD_INTERACTIVE = "keyboard_interactive"
    CERTIFICATE = "certificate"
    KERBEROS = "kerberos"
    NTLM = "ntlm"
    OAUTH = "oauth"
    SAML = "saml"
    OIDC = "oidc"
    TOKEN = "token"  # noqa: S105 - vocabulary value, not a credential
    MFA = "mfa"
    OTHER = "other"


class AuthFailureReason(StrEnum):
    """Normalized reason of a failed authentication. Keep the raw reason in ``metadata``."""

    INVALID_CREDENTIALS = "invalid_credentials"
    UNKNOWN_USER = "unknown_user"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"
    EXPIRED_CREDENTIALS = "expired_credentials"
    MFA_FAILED = "mfa_failed"
    POLICY_DENIED = "policy_denied"
    OTHER = "other"


def _protocol(value: object) -> object:
    if isinstance(value, bool):
        return value  # rejected by enum validation
    if isinstance(value, int):
        if not 0 <= value <= _MAX_PROTOCOL_NUMBER:
            raise PydanticCustomError("protocol_number", "IANA protocol numbers are 0-255")
        return _IANA_PROTOCOL_NUMBERS.get(value, NetworkProtocol.OTHER)
    return lower_if_str(value)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _inherited_or_new_trace_id() -> str:
    return current_trace_id() or new_trace_id()


UtcDatetime = Annotated[
    AwareDatetime, BeforeValidator(reject_numeric_timestamp), AfterValidator(to_utc)
]
IpAddress = Annotated[IPv4Address | IPv6Address, BeforeValidator(parse_ip_address)]
Port = Annotated[int, Strict(), Field(ge=0, le=65_535)]
ProcessId = Annotated[int, Strict(), Field(ge=0, le=MAX_PROCESS_ID)]
Counter = Annotated[int, Strict(), Field(ge=0, le=MAX_COUNTER)]
Identifier = Annotated[str, Field(pattern=IDENTIFIER_PATTERN)]
Username = Annotated[str, AfterValidator(observed_text(MAX_USERNAME_LENGTH))]
ProcessName = Annotated[str, AfterValidator(observed_text(MAX_PROCESS_NAME_LENGTH))]
ExecutablePath = Annotated[str, AfterValidator(observed_text(MAX_PATH_LENGTH))]
Metadata = Annotated[
    dict[str, JsonValue],
    BeforeValidator(
        json_metadata(
            max_depth=MAX_METADATA_DEPTH,
            max_bytes=MAX_METADATA_BYTES,
            max_key_length=MAX_METADATA_KEY_LENGTH,
            redacted_keys=REDACTED_METADATA_KEYS,
            redaction=REDACTED,
        )
    ),
]


_CATEGORY_DESCRIPTION: Final = "Event category (schema discriminator)."


class _CanonicalModel(BaseModel):
    """Shared configuration: immutable, no unknown fields, no input echoed in errors."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


class CanonicalEvent(_CanonicalModel):
    """Fields shared by every canonical event. Use one of the category models."""

    schema_version: Literal["1.0"] = Field(
        default=SCHEMA_VERSION, description="Canonical schema version (MAJOR.MINOR)."
    )
    category: EventCategory = Field(description=_CATEGORY_DESCRIPTION)
    event_id: UUID = Field(default_factory=uuid4, description="Unique id; used to deduplicate.")
    event_type: str = Field(
        pattern=EVENT_TYPE_PATTERN,
        max_length=128,
        description="Dotted lower-case type, prefixed by the category (e.g. process.started).",
    )
    timestamp: UtcDatetime = Field(description="When the event occurred at the source (UTC).")
    received_at: UtcDatetime = Field(
        default_factory=_utc_now, description="When ADIS received the event (UTC)."
    )
    source_type: str = Field(
        pattern=SOURCE_TYPE_PATTERN,
        description="Kind of telemetry source (e.g. auditd, windows_eventlog, zeek, agent).",
    )
    source_name: str = Field(
        pattern=SOURCE_NAME_PATTERN,
        description="Configured name of the source instance (e.g. zeek@sensor-1).",
    )
    host_id: Identifier | None = Field(
        default=None, description="ADIS identifier of the host the event concerns."
    )
    agent_id: Identifier | None = Field(
        default=None, description="ADIS identifier of the collecting agent, if any."
    )
    severity_hint: SeverityHint | None = Field(
        default=None, description="Severity reported by the source; not the ADIS score."
    )
    trace_id: str = Field(
        default_factory=_inherited_or_new_trace_id,
        pattern=TRACE_ID_PATTERN,
        description="W3C trace id; inherited from the current context when omitted.",
    )

    @field_validator("severity_hint", mode="before")
    @classmethod
    def _normalize_severity(cls, value: object) -> object:
        return lower_if_str(value)

    @field_validator("trace_id")
    @classmethod
    def _reject_all_zero_trace_id(cls, value: str) -> str:
        if value == "0" * 32:
            raise PydanticCustomError("invalid_trace_id", "must not be all zeros")
        return value

    @model_validator(mode="after")
    def _event_type_matches_category(self) -> Self:
        prefix = EventCategory(self.category).value
        if not self.event_type.startswith(f"{prefix}."):
            raise PydanticCustomError(
                "event_type_category",
                "event_type must start with '{prefix}.' for this category",
                {"prefix": prefix},
            )
        return self


class NetworkContext(_CanonicalModel):
    """Network fields; optional unless the category requires them."""

    src_ip: IpAddress | None = Field(default=None, description="Source address.")
    dst_ip: IpAddress | None = Field(default=None, description="Destination address.")
    src_port: Port | None = Field(default=None, description="Source port (TCP/UDP/SCTP).")
    dst_port: Port | None = Field(default=None, description="Destination port (TCP/UDP/SCTP).")
    protocol: NetworkProtocol | None = Field(
        default=None, description="Protocol name or IANA protocol number."
    )
    bytes_sent: Counter | None = Field(default=None, description="Bytes from source.")
    bytes_received: Counter | None = Field(default=None, description="Bytes to source.")

    @field_validator("protocol", mode="before")
    @classmethod
    def _normalize_protocol(cls, value: object) -> object:
        return _protocol(value)

    @model_validator(mode="after")
    def _ports_only_for_port_protocols(self) -> Self:
        has_ports = self.src_port is not None or self.dst_port is not None
        if has_ports and self.protocol is not None and self.protocol not in PORT_PROTOCOLS:
            raise PydanticCustomError(
                "ports_without_port_protocol",
                "ports are only valid for tcp, udp and sctp; put ICMP type/code in metadata",
            )
        return self


class AuthenticationContext(_CanonicalModel):
    """Authentication outcome."""

    username: Username | None = Field(
        default=None, description="Principal as presented; observed value, never rejected."
    )
    auth_method: AuthMethod | None = Field(default=None, description="Authentication method.")
    success: bool = Field(strict=True, description="Whether authentication succeeded.")
    failure_reason: AuthFailureReason | None = Field(
        default=None, description="Normalized reason; only when success is false."
    )

    @field_validator("auth_method", "failure_reason", mode="before")
    @classmethod
    def _normalize_vocabulary(cls, value: object) -> object:
        return lower_if_str(value)

    @model_validator(mode="after")
    def _failure_reason_only_on_failure(self) -> Self:
        if self.success and self.failure_reason is not None:
            raise PydanticCustomError(
                "failure_reason_on_success", "failure_reason is only allowed when success is false"
            )
        return self


class ProcessContext(_CanonicalModel):
    """Process identity. ``process_name`` defaults to the basename of ``executable_path``."""

    process_name: ProcessName | None = Field(
        default=None, description="Process image name; observed value, never rejected."
    )
    process_id: ProcessId | None = Field(default=None, description="Operating-system PID.")
    parent_process_id: ProcessId | None = Field(default=None, description="Parent PID.")
    executable_path: ExecutablePath | None = Field(
        default=None, description="Full path of the executable; observed value."
    )

    @model_validator(mode="before")
    @classmethod
    def _derive_process_name(cls, data: object) -> object:
        if isinstance(data, dict) and data.get("process_name") is None:
            path = data.get("executable_path")
            if isinstance(path, str):
                name = path.replace("\\", "/").rsplit("/", 1)[-1]
                if name:
                    return {**data, "process_name": name}
        return data


class _MetadataField(_CanonicalModel):
    """Vendor-specific data; kept last so canonical fields read first."""

    metadata: Metadata = Field(
        default_factory=dict,
        description="Vendor-specific data: JSON only, bounded, credentials redacted.",
    )


class SystemEvent(_MetadataField, CanonicalEvent):
    """Host and operating-system activity (boot, services, configuration, accounts)."""

    category: Literal[EventCategory.SYSTEM] = Field(
        default=EventCategory.SYSTEM, description=_CATEGORY_DESCRIPTION
    )


class AuthenticationEvent(_MetadataField, NetworkContext, AuthenticationContext, CanonicalEvent):
    """A login, logout or other authentication attempt, with its network origin if known."""

    category: Literal[EventCategory.AUTHENTICATION] = Field(
        default=EventCategory.AUTHENTICATION, description=_CATEGORY_DESCRIPTION
    )


class NetworkFlowEvent(_MetadataField, NetworkContext, CanonicalEvent):
    """A network flow or connection between two endpoints."""

    category: Literal[EventCategory.NETWORK] = Field(
        default=EventCategory.NETWORK, description=_CATEGORY_DESCRIPTION
    )
    src_ip: IpAddress = Field(description="Source address.")
    dst_ip: IpAddress = Field(description="Destination address.")
    protocol: NetworkProtocol = Field(description="Protocol name or IANA protocol number.")

    @model_validator(mode="after")
    def _complete_flow(self) -> Self:
        if self.src_ip.version != self.dst_ip.version:
            raise PydanticCustomError(
                "mixed_ip_versions", "src_ip and dst_ip must be the same IP version"
            )
        if self.protocol in PORT_PROTOCOLS and (self.src_port is None or self.dst_port is None):
            raise PydanticCustomError(
                "missing_ports", "tcp, udp and sctp flows require src_port and dst_port"
            )
        return self


class ProcessEvent(_MetadataField, ProcessContext, CanonicalEvent):
    """A process lifecycle event (start, termination, injection...)."""

    category: Literal[EventCategory.PROCESS] = Field(
        default=EventCategory.PROCESS, description=_CATEGORY_DESCRIPTION
    )
    process_name: ProcessName = Field(
        description="Process image name; derived from executable_path when omitted."
    )
    process_id: ProcessId = Field(description="Operating-system PID.")


class SecurityEvent(_MetadataField, ProcessContext, NetworkContext, CanonicalEvent):
    """A finding from a security tool (IDS, EDR, antivirus, audit), with optional context."""

    category: Literal[EventCategory.SECURITY] = Field(
        default=EventCategory.SECURITY, description=_CATEGORY_DESCRIPTION
    )


AnyCanonicalEvent = Annotated[
    SystemEvent | AuthenticationEvent | NetworkFlowEvent | ProcessEvent | SecurityEvent,
    Field(discriminator="category"),
]
"""Any version 1 canonical event, discriminated by ``category``."""

CanonicalEventV1 = (
    SystemEvent | AuthenticationEvent | NetworkFlowEvent | ProcessEvent | SecurityEvent
)

CATEGORY_MODELS: Final[dict[EventCategory, type[CanonicalEvent]]] = {
    EventCategory.SYSTEM: SystemEvent,
    EventCategory.AUTHENTICATION: AuthenticationEvent,
    EventCategory.NETWORK: NetworkFlowEvent,
    EventCategory.PROCESS: ProcessEvent,
    EventCategory.SECURITY: SecurityEvent,
}
