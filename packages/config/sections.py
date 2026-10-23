"""Validated settings for Phase 1 collection and ingestion only."""

import base64
import binascii
import re
import socket
from collections.abc import Callable
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from pathlib import Path
from typing import Annotated, Final, Self
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import (
    AfterValidator,
    ConfigDict,
    Field,
    HttpUrl,
    RedisDsn,
    SecretStr,
    TypeAdapter,
    UrlConstraints,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError, Url

from packages.config.base import DEV_DEFAULT, ADISSettings, Environment

_IDENTIFIER_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"


_BOOTSTRAP_HOST: Final = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9._-]*)$")


_MAX_PORT: Final = 65_535


_HIDDEN_INPUT: Final = ConfigDict(hide_input_in_errors=True)


_ASYNC_POSTGRES_DSN: Final[TypeAdapter[Url]] = TypeAdapter(
    Annotated[
        Url,
        UrlConstraints(
            host_required=True,
            allowed_schemes=["postgres", "postgresql", "postgresql+asyncpg"],
        ),
    ],
    config=_HIDDEN_INPUT,
)


_REDIS_DSN: Final = TypeAdapter(RedisDsn, config=_HIDDEN_INPUT)


class LogLevel(StrEnum):
    """Log verbosity, selected by ``LOG_LEVEL``."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class KafkaSecurityProtocol(StrEnum):
    """Kafka client security protocols supported by aiokafka."""

    PLAINTEXT = "PLAINTEXT"
    SSL = "SSL"
    SASL_PLAINTEXT = "SASL_PLAINTEXT"
    SASL_SSL = "SASL_SSL"


class KafkaSaslMechanism(StrEnum):
    """SASL mechanisms for ``SASL_SSL``/``SASL_PLAINTEXT`` (username and password)."""

    PLAIN = "PLAIN"
    SCRAM_SHA_256 = "SCRAM-SHA-256"
    SCRAM_SHA_512 = "SCRAM-SHA-512"


class RateLimitBackend(StrEnum):
    """Where the ingestion API keeps rate-limit budgets."""

    MEMORY = "memory"
    REDIS = "redis"


class DatabaseSslMode(StrEnum):
    """PostgreSQL SSL modes, with libpq semantics as implemented by asyncpg."""

    DISABLE = "disable"
    PREFER = "prefer"
    REQUIRE = "require"
    VERIFY_CA = "verify-ca"
    VERIFY_FULL = "verify-full"


def _non_blank_secret(value: SecretStr) -> SecretStr:
    if not value.get_secret_value().strip():
        raise PydanticCustomError("blank_secret", "must not be blank")
    return value


def _secret_url(adapter: TypeAdapter[object], expected: str) -> Callable[[SecretStr], SecretStr]:
    """Build a validator that checks a secret URL's format without exposing its value."""

    def validate(value: SecretStr) -> SecretStr:
        try:
            adapter.validate_python(value.get_secret_value())
        except ValidationError:
            raise PydanticCustomError("invalid_secret_url", f"must be {expected}") from None
        return value

    return validate


def _encoded_credentials(value: SecretStr) -> SecretStr:
    """Reject a URL whose user name or password contains a raw ``@``.

    URL parsers disagree on where such an address ends (SQLAlchemy splits at the first
    ``@``), so part of the password would silently become the host name and fail as a
    DNS error. The message names the fix, never the value.
    """
    if urlsplit(value.get_secret_value()).netloc.count("@") > 1:
        raise PydanticCustomError(
            "unencoded_credentials",
            "the user name or password contains '@': percent-encode it as %40",
        )
    return value


def _upper_if_str(value: object) -> object:
    return value.strip().upper() if isinstance(value, str) else value


def _production(info: ValidationInfo) -> bool:
    return info.data.get("app_env") is Environment.PRODUCTION


_SECURE_DATABASE_SSL_MODES: Final = frozenset({"require", "verify-ca", "verify-full"})


_KEY_PREFIX_PATTERN: Final = r"^[a-z][a-z0-9_-]{0,31}$"


_SPOOL_KEY_BYTES: Final = 32


NonBlankSecret = Annotated[SecretStr, AfterValidator(_non_blank_secret)]


AsyncPostgresDsnSecret = Annotated[
    SecretStr,
    AfterValidator(_non_blank_secret),
    AfterValidator(_encoded_credentials),
    AfterValidator(
        _secret_url(
            _ASYNC_POSTGRES_DSN,
            "a PostgreSQL DSN using postgresql://, postgres:// or postgresql+asyncpg://",
        )
    ),
]


RedisDsnSecret = Annotated[
    SecretStr,
    AfterValidator(_non_blank_secret),
    AfterValidator(_secret_url(_REDIS_DSN, "a Redis DSN using redis:// or rediss://")),
]


class AppSettings(ADISSettings):
    """Settings every service loads: identity, logging, metrics and the safety switch."""

    app_name: Annotated[str, Field(pattern=_IDENTIFIER_PATTERN)] = "adis"
    log_level: LogLevel = LogLevel.INFO
    dry_run: bool = True
    prometheus_enabled: bool = True
    log_event_lifecycle: bool = True

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: object) -> object:
        return _upper_if_str(value)


class DatabaseSettings(ADISSettings):
    """Direct Supabase PostgreSQL access through SQLAlchemy async and asyncpg."""

    supabase_db_url: AsyncPostgresDsnSecret
    db_ssl_mode: Annotated[DatabaseSslMode, DEV_DEFAULT] = DatabaseSslMode.PREFER
    db_transaction_pooler: bool = False
    db_pool_size: Annotated[int, Field(ge=1, le=100)] = 5
    db_max_overflow: Annotated[int, Field(ge=0, le=100)] = 10
    db_pool_timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 30.0
    db_pool_recycle_seconds: Annotated[int, Field(ge=60, le=86_400)] = 1_800
    db_connect_timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 10.0
    db_command_timeout_seconds: Annotated[float, Field(gt=0, le=86_400)] = 60.0
    db_health_check_timeout_seconds: Annotated[float, Field(gt=0, le=60)] = 5.0

    @field_validator("db_ssl_mode", mode="before")
    @classmethod
    def _normalize_ssl_mode(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("db_ssl_mode")
    @classmethod
    def _database_tls_in_production(
        cls, value: DatabaseSslMode, info: ValidationInfo
    ) -> DatabaseSslMode:
        if _production(info) and value.value not in _SECURE_DATABASE_SSL_MODES:
            raise PydanticCustomError(
                "insecure_ssl_mode",
                "must be require, verify-ca or verify-full in production",
            )
        return value


class RedisSettings(ADISSettings):
    """Redis access for caching and transient state (never a source of truth)."""

    redis_url: RedisDsnSecret
    redis_key_prefix: Annotated[str, Field(pattern=_KEY_PREFIX_PATTERN)] = "adis"
    redis_connect_timeout_seconds: Annotated[float, Field(gt=0, le=60)] = 2.0
    redis_socket_timeout_seconds: Annotated[float, Field(gt=0, le=60)] = 2.0
    redis_health_check_timeout_seconds: Annotated[float, Field(gt=0, le=60)] = 2.0


class KafkaSettings(ADISSettings):
    """Kafka client connection settings."""

    kafka_bootstrap_servers: Annotated[str, DEV_DEFAULT] = "localhost:9092"
    kafka_client_id: Annotated[str, Field(pattern=_IDENTIFIER_PATTERN)] = "adis"
    kafka_security_protocol: Annotated[KafkaSecurityProtocol, DEV_DEFAULT] = (
        KafkaSecurityProtocol.PLAINTEXT
    )
    kafka_topic_partitions: Annotated[int, Field(ge=1, le=1_000)] = 3
    kafka_topic_replication_factor: Annotated[int, Field(ge=1, le=10), DEV_DEFAULT] = 1
    kafka_topic_retention_hours: Annotated[int, Field(ge=1, le=87_600)] = 168
    kafka_deadletter_retention_hours: Annotated[int, Field(ge=1, le=87_600)] = 720
    kafka_retry_max_attempts: Annotated[int, Field(ge=1, le=20)] = 5
    kafka_retry_initial_backoff_ms: Annotated[int, Field(ge=1, le=60_000)] = 100
    kafka_retry_max_backoff_ms: Annotated[int, Field(ge=1, le=300_000)] = 10_000
    kafka_sasl_mechanism: KafkaSaslMechanism | None = Field(default=None, validate_default=True)
    kafka_sasl_username: str | None = Field(default=None, validate_default=True)
    kafka_sasl_password: SecretStr | None = Field(default=None, validate_default=True)

    @field_validator("kafka_security_protocol", "kafka_sasl_mechanism", mode="before")
    @classmethod
    def _normalize_security_protocol(cls, value: object) -> object:
        return _upper_if_str(value)

    @field_validator("kafka_security_protocol")
    @classmethod
    def _kafka_encryption_in_production(
        cls, value: KafkaSecurityProtocol, info: ValidationInfo
    ) -> KafkaSecurityProtocol:
        if _production(info) and value not in {
            KafkaSecurityProtocol.SSL,
            KafkaSecurityProtocol.SASL_SSL,
        }:
            raise PydanticCustomError(
                "insecure_security_protocol", "must be SSL or SASL_SSL in production"
            )
        return value

    @field_validator("kafka_sasl_mechanism", "kafka_sasl_username", "kafka_sasl_password")
    @classmethod
    def _sasl_setting_required(cls, value: object, info: ValidationInfo) -> object:
        protocol = info.data.get("kafka_security_protocol")
        uses_sasl = protocol in {
            KafkaSecurityProtocol.SASL_SSL,
            KafkaSecurityProtocol.SASL_PLAINTEXT,
        }
        blank = value is None or (
            isinstance(value, SecretStr | str)
            and not (value.get_secret_value() if isinstance(value, SecretStr) else value).strip()
        )
        if uses_sasl and blank:
            raise PydanticCustomError(
                "sasl_setting_required",
                "is required when KAFKA_SECURITY_PROTOCOL is SASL_SSL or SASL_PLAINTEXT",
            )
        return None if blank else value

    @field_validator("kafka_retry_max_backoff_ms")
    @classmethod
    def _max_backoff_not_below_initial(cls, value: int, info: ValidationInfo) -> int:
        initial = info.data.get("kafka_retry_initial_backoff_ms")
        if isinstance(initial, int) and value < initial:
            raise PydanticCustomError(
                "backoff_below_initial",
                "must be greater than or equal to KAFKA_RETRY_INITIAL_BACKOFF_MS",
            )
        return value

    @field_validator("kafka_bootstrap_servers")
    @classmethod
    def _normalize_bootstrap_servers(cls, value: str) -> str:
        servers = [entry.strip() for entry in value.split(",")]
        if not all(_is_host_port(entry) for entry in servers):
            raise PydanticCustomError(
                "invalid_bootstrap_servers",
                "must be a comma-separated list of host:port entries",
            )
        return ",".join(servers)


def _is_host_port(entry: str) -> bool:
    host, separator, port = entry.rpartition(":")
    if not separator or not port.isdigit():
        return False
    return bool(_BOOTSTRAP_HOST.match(host)) and 0 < int(port) <= _MAX_PORT


_HOSTNAME: Final = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


_INGEST_TOKEN_ENTRY: Final = re.compile(
    r"^(?P<client>[A-Za-z0-9][A-Za-z0-9._-]{0,63}):(?P<token>[A-Za-z0-9._~+/=-]{32,256})$"
)


_CLIENT_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


_HOST_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+=-]{0,254}$")


_MAX_HOSTS_PER_CLIENT: Final = 1_000


AGENT_CLIENT_PREFIX: Final = "agent-"


def bound_agent_id(client_id: str) -> UUID | None:
    """The agent a client id is bound to (``agent-<uuid>``), or ``None`` for other clients."""
    if not client_id.startswith(AGENT_CLIENT_PREFIX):
        return None
    try:
        return UUID(client_id.removeprefix(AGENT_CLIENT_PREFIX))
    except ValueError:
        return None


def _bind_host(value: str) -> str:
    try:
        ip_address(value)
    except ValueError:
        if not _HOSTNAME.match(value):
            raise PydanticCustomError(
                "invalid_host", "must be an IP address or a hostname"
            ) from None
    return value


def parse_ingest_tokens(raw: str) -> dict[str, str]:
    """Parse ``client:token[,client:token...]`` into ``{client: token}``.

    Raises:
        ValueError: If an entry is malformed or a client or token repeats. The message
            never contains token values.
    """
    credentials: dict[str, str] = {}
    for position, entry in enumerate(raw.split(","), start=1):
        match = _INGEST_TOKEN_ENTRY.match(entry.strip())
        if match is None:
            raise ValueError(
                f"entry {position} must be client:token, with a client id of "
                "[A-Za-z0-9._-] and a token of 32-256 [A-Za-z0-9._~+/=-] characters"
            )
        client, token = match["client"], match["token"]
        if client in credentials or token in credentials.values():
            raise ValueError(f"entry {position} repeats a client id or token")
        credentials[client] = token
    return credentials


def _ingest_tokens(value: SecretStr) -> SecretStr:
    try:
        parse_ingest_tokens(value.get_secret_value())
    except ValueError as error:
        raise PydanticCustomError("invalid_ingest_tokens", str(error)) from None
    return value


IngestTokensSecret = Annotated[
    SecretStr, AfterValidator(_non_blank_secret), AfterValidator(_ingest_tokens)
]


def parse_ingest_client_hosts(raw: str) -> dict[str, frozenset[str]]:
    """Parse ``client=host[|host...][,client=host[|host...]...]`` into ``{client: hosts}``.

    A blank value means no client is restricted to hosts.

    Raises:
        ValueError: If an entry is malformed, a client repeats, or a host is not a valid
            ``host_id`` or repeats within its client. The message never contains more than
            the position of the entry.
    """
    if not raw.strip():
        return {}
    hosts_by_client: dict[str, frozenset[str]] = {}
    for position, entry in enumerate(raw.split(","), start=1):
        client, separator, listed = entry.strip().partition("=")
        names = [name.strip() for name in listed.split("|")]
        if (
            not separator
            or _CLIENT_ID.fullmatch(client) is None
            or any(_HOST_PATTERN.fullmatch(name) is None for name in names)
        ):
            raise ValueError(
                f"entry {position} must be client=host[|host...], with a client id of "
                "[A-Za-z0-9._-] and hosts of 1-255 [A-Za-z0-9._:@/+=-] characters"
            )
        if client in hosts_by_client or len(set(names)) != len(names):
            raise ValueError(f"entry {position} repeats a client id or a host")
        if len(names) > _MAX_HOSTS_PER_CLIENT:
            raise ValueError(f"entry {position} lists more than {_MAX_HOSTS_PER_CLIENT} hosts")
        hosts_by_client[client] = frozenset(names)
    return hosts_by_client


def _ingest_client_hosts(value: str) -> str:
    try:
        parse_ingest_client_hosts(value)
    except ValueError as error:
        raise PydanticCustomError("invalid_ingest_client_hosts", str(error)) from None
    return value


class ApiSettings(ADISSettings):
    """Ingestion API: listener, request limits, rate limit and client credentials."""

    api_host: Annotated[str, AfterValidator(_bind_host), DEV_DEFAULT] = "127.0.0.1"
    api_port: Annotated[int, Field(ge=1, le=65_535)] = 8_000
    api_max_request_bytes: Annotated[int, Field(ge=1_024, le=33_554_432)] = 1_048_576
    api_max_batch_size: Annotated[int, Field(ge=1, le=10_000)] = 500
    api_rate_limit_events: Annotated[int, Field(ge=1, le=10_000_000)] = 6_000
    api_rate_limit_window_seconds: Annotated[int, Field(ge=1, le=3_600)] = 60
    api_publish_timeout_seconds: Annotated[float, Field(gt=0, le=60)] = 5.0
    api_max_concurrent_requests: Annotated[int, Field(ge=1, le=100_000)] = 256
    api_rate_limit_backend: RateLimitBackend = RateLimitBackend.MEMORY
    api_ingest_tokens: IngestTokensSecret
    api_ingest_client_hosts: Annotated[str, AfterValidator(_ingest_client_hosts)] = ""

    @field_validator("api_rate_limit_backend", mode="before")
    @classmethod
    def _normalize_rate_limit_backend(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("api_rate_limit_events")
    @classmethod
    def _batches_fit_the_rate_limit(cls, value: int, info: ValidationInfo) -> int:
        batch = info.data.get("api_max_batch_size")
        if isinstance(batch, int) and value < batch:
            raise PydanticCustomError(
                "rate_limit_below_batch",
                "must be at least API_MAX_BATCH_SIZE, or full batches could never be accepted",
            )
        return value

    def ingest_credentials(self) -> dict[str, str]:
        """``{client_id: token}`` from ``API_INGEST_TOKENS``. Never log the result."""
        return parse_ingest_tokens(self.api_ingest_tokens.get_secret_value())

    def ingest_client_hosts(self) -> dict[str, frozenset[str]]:
        """``{client_id: hosts}`` from ``API_INGEST_CLIENT_HOSTS``; unlisted clients are free."""
        return parse_ingest_client_hosts(self.api_ingest_client_hosts)

    @model_validator(mode="after")
    def _client_hosts_match_the_clients(self) -> Self:
        hosts = self.ingest_client_hosts()
        clients = set(self.ingest_credentials())
        unknown = sorted(set(hosts) - clients)
        if unknown:
            raise ValueError(
                "API_INGEST_CLIENT_HOSTS names clients that are not in API_INGEST_TOKENS: "
                + ", ".join(unknown)
            )
        if not self.app_env.allows_development_defaults:
            unrestricted = sorted(
                client
                for client in clients
                if bound_agent_id(client) is not None and client not in hosts
            )
            if unrestricted:
                raise ValueError(
                    "API_INGEST_CLIENT_HOSTS must list the hosts of every agent-bound client "
                    "in staging and production, or its token could write any host's "
                    "telemetry: " + ", ".join(unrestricted)
                )
        return self


def _default_agent_name() -> str:
    """The host name, made to fit the identifier pattern."""
    name = re.sub(r"[^A-Za-z0-9._-]", "-", socket.gethostname()).strip("-._")[:64]
    return name if name else "adis-agent"


def _strict_environment(info: ValidationInfo) -> bool:
    environment = info.data.get("app_env")
    return isinstance(environment, Environment) and not environment.allows_development_defaults


_WINDOWS_LEVELS: Final = frozenset({"critical", "error", "warning", "information", "verbose"})


_EXPORTER_ID: Final = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63})*$")


def comma_list(raw: str) -> tuple[str, ...]:
    """Non-empty, stripped entries of a comma-separated value."""
    return tuple(entry.strip() for entry in raw.split(",") if entry.strip())


def _int_list(value: str, *, low: int, high: int) -> str:
    for entry in comma_list(value):
        if not entry.isdigit() or not low <= int(entry) <= high:
            raise PydanticCustomError(
                "invalid_number_list",
                "must be comma-separated integers from {low} to {high}",
                {"low": low, "high": high},
            )
    return value


def parse_listen_address(raw: str) -> tuple[str, int]:
    """``host:port`` (``[v6]:port`` for IPv6) into ``(host, port)``."""
    host, separator, port = raw.strip().rpartition(":")
    host = host.strip().removeprefix("[").removesuffix("]")
    if not separator or not port.isdigit() or not 1 <= int(port) <= _MAX_PORT:
        raise ValueError("must be HOST:PORT, e.g. 127.0.0.1:5514")
    address = ip_address(host)
    if address.is_unspecified:
        raise ValueError("must name one interface address, never 0.0.0.0 or ::")
    return str(address), int(port)


def _listen_address(value: str) -> str:
    if value.strip():
        try:
            parse_listen_address(value)
        except ValueError as error:
            raise PydanticCustomError(
                "invalid_listen_address", "{reason}", {"reason": str(error)}
            ) from None
    return value


def parse_networks(raw: str) -> tuple[IPv4Network | IPv6Network, ...]:
    """CIDR networks of a comma-separated value."""
    return tuple(ip_network(entry, strict=False) for entry in comma_list(raw))


def _networks(value: str) -> str:
    try:
        parse_networks(value)
    except ValueError:
        raise PydanticCustomError(
            "invalid_networks", "must be comma-separated CIDR networks, e.g. 192.0.2.0/24"
        ) from None
    return value


def parse_exporters(raw: str) -> dict[str, str]:
    """``id=address[,id=address...]`` into ``{address: id}`` (authorized flow exporters)."""
    exporters: dict[str, str] = {}
    for entry in comma_list(raw):
        exporter_id, separator, address = entry.partition("=")
        exporter_id = exporter_id.strip().lower()
        if not separator or not _EXPORTER_ID.match(exporter_id):
            raise ValueError(f"exporter entry {entry!r} must be NAME=ADDRESS")
        normalized = str(ip_address(address.strip()))
        if normalized in exporters or exporter_id in exporters.values():
            raise ValueError("each exporter name and address may be listed only once")
        exporters[normalized] = exporter_id
    return exporters


def _exporters(value: str) -> str:
    try:
        parse_exporters(value)
    except ValueError as error:
        raise PydanticCustomError("invalid_exporters", "{reason}", {"reason": str(error)}) from None
    return value


def _windows_levels(value: str) -> str:
    unknown = sorted({entry.lower() for entry in comma_list(value)} - _WINDOWS_LEVELS)
    if unknown:
        raise PydanticCustomError(
            "invalid_windows_levels",
            "must be comma-separated levels among critical, error, warning, information, verbose",
        )
    return value


EventIdList = Annotated[str, AfterValidator(lambda v: _int_list(v, low=0, high=65_535))]


LogonTypeList = Annotated[str, AfterValidator(lambda v: _int_list(v, low=0, high=15))]


ListenAddress = Annotated[str, AfterValidator(_listen_address)]


NetworkList = Annotated[str, AfterValidator(_networks)]


class AgentSettings(ADISSettings):
    """Endpoint agent: server, identity, local buffering, retries and collectors."""

    agent_server_url: Annotated[HttpUrl, DEV_DEFAULT] = HttpUrl("http://127.0.0.1:8000")
    agent_token: NonBlankSecret
    agent_name: Annotated[str, Field(pattern=_IDENTIFIER_PATTERN)] = Field(
        default_factory=_default_agent_name
    )
    agent_data_dir: Annotated[Path, DEV_DEFAULT] = Path(".adis-agent")
    agent_flush_interval_seconds: Annotated[float, Field(gt=0, le=3_600)] = 5.0
    agent_batch_size: Annotated[int, Field(ge=1, le=10_000)] = 100
    agent_max_queue_events: Annotated[int, Field(ge=1, le=10_000_000)] = 100_000
    agent_retry_initial_backoff_seconds: Annotated[float, Field(gt=0, le=3_600)] = 1.0
    agent_retry_max_backoff_seconds: Annotated[float, Field(gt=0, le=86_400)] = 300.0
    agent_http_timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 10.0
    agent_log_files: str = ""
    agent_log_poll_interval_seconds: Annotated[float, Field(gt=0, le=3_600)] = 1.0
    agent_log_read_from_start: bool = False
    agent_simulate_auth_per_minute: Annotated[int, Field(ge=0, le=60_000)] = 0
    agent_simulate_flows_per_minute: Annotated[int, Field(ge=0, le=60_000)] = 0
    agent_spool_encryption: bool = True
    agent_spool_key: SecretStr | None = Field(default=None, validate_default=True)

    # Windows Event Log: System/Application channels (system logs).
    agent_windows_eventlog_channels: str = ""
    agent_windows_eventlog_levels: Annotated[str, AfterValidator(_windows_levels)] = (
        "critical,error,warning"
    )
    agent_windows_eventlog_extra_event_ids: EventIdList = (
        "1,12,13,19,104,1033,1034,1074,6005,6006,7040,7045,11707,11724"
    )
    agent_windows_eventlog_exclude_event_ids: EventIdList = "10016"
    agent_windows_eventlog_backfill_minutes: Annotated[int, Field(ge=0, le=10_080)] = 0
    agent_windows_eventlog_poll_interval_seconds: Annotated[float, Field(gt=0, le=3_600)] = 5.0
    agent_windows_eventlog_include_message: bool = False
    # Windows Security log: logons, logoffs and session vectors (user behavior).
    agent_windows_security_enabled: bool = False
    agent_windows_security_exclude_logon_types: LogonTypeList = "5"
    agent_session_logon_types: LogonTypeList = "2,7,10,11"
    agent_session_failure_window_seconds: Annotated[int, Field(ge=60, le=86_400)] = 3_600
    agent_session_max_open: Annotated[int, Field(ge=10, le=100_000)] = 1_000
    # Network flows built from packets: offline PCAP files and live capture.
    agent_pcap_files: str = ""
    agent_flow_idle_timeout_seconds: Annotated[float, Field(gt=0, le=3_600)] = 30.0
    agent_flow_active_timeout_seconds: Annotated[float, Field(gt=0, le=86_400)] = 120.0
    agent_flow_max_active: Annotated[int, Field(ge=100, le=5_000_000)] = 100_000
    agent_flow_allowed_networks: NetworkList = ""
    agent_live_capture_interface: str = ""
    agent_live_capture_authorized: bool = False
    agent_live_capture_promiscuous: bool = False
    agent_live_capture_snaplen: Annotated[int, Field(ge=96, le=65_535)] = 160
    agent_live_capture_filter: str = ""
    # NetFlow v5/v9 and IPFIX from authorized exporters, decoded by GoFlow2.
    agent_netflow_exporters: Annotated[str, AfterValidator(_exporters)] = ""
    agent_netflow_goflow2_path: str = ""
    agent_netflow_mapping_file: str = "infrastructure/goflow2/adis-mapping.yaml"
    agent_netflow_listen: ListenAddress = "127.0.0.1:2055"
    agent_netflow_allow_non_loopback: bool = False
    agent_netflow_records_file: str = ""
    # Syslog receiver (RFC 3164 and RFC 5424 over UDP and TCP).
    agent_syslog_udp_listen: ListenAddress = ""
    agent_syslog_tcp_listen: ListenAddress = ""
    agent_syslog_allowed_senders: NetworkList = "127.0.0.0/8,::1/128"
    agent_syslog_allow_non_loopback: bool = False
    agent_syslog_max_message_bytes: Annotated[int, Field(ge=480, le=65_536)] = 8_192
    agent_syslog_max_pending_events: Annotated[int, Field(ge=100, le=1_000_000)] = 10_000
    # System calls: auditd log and eBPF tracer output, aggregated into call sequences.
    agent_audit_log_file: str = ""
    agent_ebpf_events_file: str = ""
    agent_syscall_window_seconds: Annotated[float, Field(gt=0, le=3_600)] = 10.0
    agent_syscall_max_sequence: Annotated[int, Field(ge=8, le=4_096)] = 256
    agent_syscall_read_from_start: bool = False

    @field_validator("agent_spool_key")
    @classmethod
    def _spool_key_is_32_bytes(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        text = value.get_secret_value().strip()
        try:
            key = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except (binascii.Error, ValueError):
            key = b""
        if len(key) != _SPOOL_KEY_BYTES:
            raise PydanticCustomError("invalid_spool_key", "must be 32 bytes encoded as base64url")
        return value

    @field_validator("agent_server_url")
    @classmethod
    def _https_outside_development(cls, value: HttpUrl, info: ValidationInfo) -> HttpUrl:
        if _strict_environment(info) and value.scheme != "https":
            raise PydanticCustomError(
                "insecure_server_url",
                "must use https in staging and production (the agent token is sent with "
                "every request)",
            )
        return value

    @field_validator("agent_retry_max_backoff_seconds")
    @classmethod
    def _agent_backoff_not_below_initial(cls, value: float, info: ValidationInfo) -> float:
        initial = info.data.get("agent_retry_initial_backoff_seconds")
        if isinstance(initial, float | int) and value < initial:
            raise PydanticCustomError(
                "backoff_below_initial",
                "must be greater than or equal to AGENT_RETRY_INITIAL_BACKOFF_SECONDS",
            )
        return value

    @field_validator("agent_simulate_auth_per_minute", "agent_simulate_flows_per_minute")
    @classmethod
    def _simulation_only_in_development(cls, value: int, info: ValidationInfo) -> int:
        if value and _strict_environment(info):
            raise PydanticCustomError(
                "simulation_not_allowed",
                "synthetic telemetry is only allowed when APP_ENV is development or test",
            )
        return value

    @model_validator(mode="after")
    def _collector_safeguards(self) -> Self:
        if self.agent_live_capture_interface.strip():
            if not self.agent_live_capture_authorized:
                raise ValueError(
                    "AGENT_LIVE_CAPTURE_AUTHORIZED must be true to capture on "
                    "AGENT_LIVE_CAPTURE_INTERFACE: confirm the network is yours or that you "
                    "are authorized to monitor it"
                )
            if self.agent_live_capture_promiscuous and not self.agent_flow_allowed_networks:
                raise ValueError(
                    "AGENT_LIVE_CAPTURE_PROMISCUOUS needs AGENT_FLOW_ALLOWED_NETWORKS, the lab "
                    "networks you are authorized to monitor"
                )
        flows_enabled = self.agent_netflow_goflow2_path or self.agent_netflow_records_file
        if flows_enabled and not self.agent_netflow_exporters:
            raise ValueError("NetFlow/IPFIX collection needs AGENT_NETFLOW_EXPORTERS")
        netflow_allowed = self.agent_netflow_allow_non_loopback
        syslog_allowed = self.agent_syslog_allow_non_loopback
        for name, raw, allowed in (
            ("AGENT_NETFLOW_LISTEN", self.agent_netflow_listen, netflow_allowed),
            ("AGENT_SYSLOG_UDP_LISTEN", self.agent_syslog_udp_listen, syslog_allowed),
            ("AGENT_SYSLOG_TCP_LISTEN", self.agent_syslog_tcp_listen, syslog_allowed),
        ):
            if not raw.strip() or allowed:
                continue
            if not ip_address(parse_listen_address(raw)[0]).is_loopback:
                raise ValueError(
                    f"{name} is not a loopback address; allow it explicitly only for an "
                    "approved collection interface"
                )
        if self.agent_flow_active_timeout_seconds < self.agent_flow_idle_timeout_seconds:
            raise ValueError(
                "AGENT_FLOW_ACTIVE_TIMEOUT_SECONDS must not be shorter than "
                "AGENT_FLOW_IDLE_TIMEOUT_SECONDS"
            )
        return self

    def log_file_paths(self) -> tuple[Path, ...]:
        """Paths from ``AGENT_LOG_FILES`` (comma-separated), without empty entries."""
        return tuple(
            Path(entry.strip()) for entry in self.agent_log_files.split(",") if entry.strip()
        )

    def windows_eventlog_channels(self) -> tuple[str, ...]:
        """Channels from ``AGENT_WINDOWS_EVENTLOG_CHANNELS``."""
        return comma_list(self.agent_windows_eventlog_channels)

    def pcap_file_paths(self) -> tuple[Path, ...]:
        """Capture files from ``AGENT_PCAP_FILES``."""
        return tuple(Path(entry) for entry in comma_list(self.agent_pcap_files))

    @staticmethod
    def int_set(raw: str) -> frozenset[int]:
        """The integers of a validated comma-separated setting."""
        return frozenset(int(entry) for entry in comma_list(raw))


class NormalizerSettings(ADISSettings):
    """Normalization pipeline: consumer group, batching, publish bound and retries."""

    normalizer_consumer_group: Annotated[str, Field(pattern=_IDENTIFIER_PATTERN)] = (
        "adis-normalizer"
    )
    normalizer_batch_max_records: Annotated[int, Field(ge=1, le=10_000)] = 500
    normalizer_poll_timeout_ms: Annotated[int, Field(ge=10, le=60_000)] = 1_000
    normalizer_publish_timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 30.0
    normalizer_retry_initial_backoff_seconds: Annotated[float, Field(gt=0, le=3_600)] = 0.5
    normalizer_retry_max_backoff_seconds: Annotated[float, Field(gt=0, le=3_600)] = 30.0
    normalizer_max_attempts: Annotated[int, Field(ge=1, le=20)] = 3
    normalizer_health_host: Annotated[str, AfterValidator(_bind_host), DEV_DEFAULT] = "127.0.0.1"
    normalizer_health_port: Annotated[int, Field(ge=0, le=65_535)] = 9_102
    normalizer_max_future_skew_seconds: Annotated[int, Field(ge=0, le=31_536_000)] = 300

    @field_validator("normalizer_retry_max_backoff_seconds")
    @classmethod
    def _normalizer_backoff_not_below_initial(cls, value: float, info: ValidationInfo) -> float:
        initial = info.data.get("normalizer_retry_initial_backoff_seconds")
        if isinstance(initial, float | int) and value < initial:
            raise PydanticCustomError(
                "backoff_below_initial",
                "must be greater than or equal to NORMALIZER_RETRY_INITIAL_BACKOFF_SECONDS",
            )
        return value


SETTINGS_SECTIONS: Final[tuple[type[ADISSettings], ...]] = (
    AppSettings,
    DatabaseSettings,
    RedisSettings,
    KafkaSettings,
    ApiSettings,
    AgentSettings,
    NormalizerSettings,
)
