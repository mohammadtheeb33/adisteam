"""Parsing and validation rules of each configuration section."""

import base64
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from packages.config import (
    ADISSettings,
    AgentSettings,
    ApiSettings,
    AppSettings,
    ConfigurationError,
    DatabaseSettings,
    DatabaseSslMode,
    Environment,
    KafkaSaslMechanism,
    KafkaSecurityProtocol,
    KafkaSettings,
    LogLevel,
    RedisSettings,
    load_settings,
)

LoadError = Callable[[type[ADISSettings]], ConfigurationError]


def test_app_settings_defaults() -> None:
    settings = load_settings(AppSettings)
    assert settings.app_env is Environment.DEVELOPMENT
    assert settings.app_name == "adis"
    assert settings.log_level is LogLevel.INFO
    assert settings.dry_run is True
    assert settings.prometheus_enabled is True


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" Production ", Environment.PRODUCTION),
        ("STAGING", Environment.STAGING),
        ("test", Environment.TEST),
    ],
)
def test_app_env_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: Environment
) -> None:
    monkeypatch.setenv("APP_ENV", raw)
    assert load_settings(AppSettings).app_env is expected


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("APP_ENV", "prod"),
        ("APP_NAME", "adis api"),
        ("APP_NAME", "-adis"),
        ("LOG_LEVEL", "VERBOSE"),
        ("DRY_RUN", "maybe"),
        ("PROMETHEUS_ENABLED", "sometimes"),
    ],
)
def test_invalid_app_values_are_rejected(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, variable: str, value: str
) -> None:
    monkeypatch.setenv(variable, value)
    assert load_error(AppSettings).variables == {variable}


def test_log_level_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "debug")
    assert load_settings(AppSettings).log_level is LogLevel.DEBUG


@pytest.mark.parametrize(
    ("raw", "expected"), [("false", False), ("0", False), ("true", True), ("1", True)]
)
def test_boolean_flags_are_parsed(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
) -> None:
    monkeypatch.setenv("DRY_RUN", raw)
    monkeypatch.setenv("PROMETHEUS_ENABLED", raw)
    settings = load_settings(AppSettings)
    assert settings.dry_run is expected
    assert settings.prometheus_enabled is expected


def test_dry_run_defaults_to_true_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    assert load_settings(AppSettings).dry_run is True


def test_settings_are_immutable() -> None:
    settings = load_settings(AppSettings)
    with pytest.raises(ValidationError):
        settings.dry_run = False  # type: ignore[misc]  # test frozen settings at runtime


def test_unrelated_variables_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAFANA_ADMIN_PASSWORD", "compose-only")
    monkeypatch.setenv("SOME_UNRELATED_VARIABLE", "1")
    assert load_settings(AppSettings).app_name == "adis"


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://adis:pw@db.example.test:5432/postgres",
        "postgres://adis:pw@db.example.test/postgres",
        "postgresql+asyncpg://adis:pw@db.example.test:6543/postgres",
    ],
)
def test_database_url_accepts_postgres_dsns(monkeypatch: pytest.MonkeyPatch, dsn: str) -> None:
    monkeypatch.setenv("SUPABASE_DB_URL", dsn)
    assert load_settings(DatabaseSettings).supabase_db_url.get_secret_value() == dsn


@pytest.mark.parametrize(
    "dsn",
    [
        "mysql://adis:pw@db.example.test/adis",
        "postgresql+psycopg2://adis:pw@db.example.test/postgres",
        "postgresql:///postgres",
        "not a dsn",
    ],
)
def test_database_url_rejects_other_dsns(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, dsn: str
) -> None:
    monkeypatch.setenv("SUPABASE_DB_URL", dsn)
    assert load_error(DatabaseSettings).variables == {"SUPABASE_DB_URL"}


def test_database_url_with_a_raw_at_sign_in_the_password_is_explained(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError
) -> None:
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://adis:p@ss@db.example.test/postgres")
    error = load_error(DatabaseSettings)
    assert error.variables == {"SUPABASE_DB_URL"}
    assert "%40" in str(error)
    assert "p@ss" not in str(error)


def test_database_url_with_an_encoded_at_sign_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    dsn = "postgresql://adis:p%40ss@db.example.test/postgres"
    monkeypatch.setenv("SUPABASE_DB_URL", dsn)
    assert load_settings(DatabaseSettings).supabase_db_url.get_secret_value() == dsn


def test_database_url_is_required(load_error: LoadError) -> None:
    assert load_error(DatabaseSettings).variables == {"SUPABASE_DB_URL"}


def test_database_url_rejects_multi_host_dsn(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError
) -> None:
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://adis:pw@db-1:5432,db-2:5432/postgres")
    assert load_error(DatabaseSettings).variables == {"SUPABASE_DB_URL"}


def test_database_tuning_defaults(secrets: dict[str, str]) -> None:
    settings = load_settings(DatabaseSettings)
    assert settings.db_ssl_mode is DatabaseSslMode.PREFER
    assert settings.db_transaction_pooler is False
    assert settings.db_pool_size == 5
    assert settings.db_max_overflow == 10
    assert settings.db_pool_timeout_seconds == 30.0
    assert settings.db_pool_recycle_seconds == 1800
    assert settings.db_connect_timeout_seconds == 10.0
    assert settings.db_command_timeout_seconds == 60.0
    assert settings.db_health_check_timeout_seconds == 5.0


def test_database_ssl_mode_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch, secrets: dict[str, str]
) -> None:
    monkeypatch.setenv("DB_SSL_MODE", " Verify-Full ")
    assert load_settings(DatabaseSettings).db_ssl_mode is DatabaseSslMode.VERIFY_FULL


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("DB_SSL_MODE", "allow"),
        ("DB_TRANSACTION_POOLER", "sometimes"),
        ("DB_POOL_SIZE", "0"),
        ("DB_POOL_SIZE", "101"),
        ("DB_MAX_OVERFLOW", "-1"),
        ("DB_POOL_TIMEOUT_SECONDS", "0"),
        ("DB_POOL_RECYCLE_SECONDS", "59"),
        ("DB_CONNECT_TIMEOUT_SECONDS", "-5"),
        ("DB_COMMAND_TIMEOUT_SECONDS", "0"),
        ("DB_HEALTH_CHECK_TIMEOUT_SECONDS", "61"),
    ],
)
def test_invalid_database_tuning_values_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    secrets: dict[str, str],
    load_error: LoadError,
    variable: str,
    value: str,
) -> None:
    monkeypatch.setenv(variable, value)
    assert load_error(DatabaseSettings).variables == {variable}


@pytest.mark.parametrize(
    "url", ["redis://:pw@localhost:6379/0", "rediss://cache.example.test:6380/1"]
)
def test_redis_url_accepts_redis_dsns(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setenv("REDIS_URL", url)
    assert load_settings(RedisSettings).redis_url.get_secret_value() == url


@pytest.mark.parametrize("url", ["http://localhost:6379", "localhost:6379"])
def test_redis_url_rejects_other_urls(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, url: str
) -> None:
    monkeypatch.setenv("REDIS_URL", url)
    assert load_error(RedisSettings).variables == {"REDIS_URL"}


def test_redis_url_is_required(load_error: LoadError) -> None:
    assert load_error(RedisSettings).variables == {"REDIS_URL"}


def test_kafka_settings_development_defaults() -> None:
    settings = load_settings(KafkaSettings)
    assert settings.kafka_bootstrap_servers == "localhost:9092"
    assert settings.kafka_client_id == "adis"
    assert settings.kafka_security_protocol is KafkaSecurityProtocol.PLAINTEXT
    assert settings.kafka_topic_partitions == 3
    assert settings.kafka_topic_replication_factor == 1
    assert settings.kafka_topic_retention_hours == 168
    assert settings.kafka_deadletter_retention_hours == 720
    assert settings.kafka_retry_max_attempts == 5
    assert settings.kafka_retry_initial_backoff_ms == 100
    assert settings.kafka_retry_max_backoff_ms == 10000


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" broker-1:9092 , broker-2:9093", "broker-1:9092,broker-2:9093"),
        ("10.0.0.5:9092", "10.0.0.5:9092"),
        ("[::1]:9092", "[::1]:9092"),
    ],
)
def test_kafka_bootstrap_servers_are_normalized(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: str
) -> None:
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", raw)
    assert load_settings(KafkaSettings).kafka_bootstrap_servers == expected


@pytest.mark.parametrize(
    "raw",
    [
        "localhost",
        "localhost:",
        ":9092",
        "localhost:0",
        "localhost:65536",
        "broker-1:9092,,broker-2:9092",
        "bad host:9092",
    ],
)
def test_kafka_bootstrap_servers_are_validated(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, raw: str
) -> None:
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", raw)
    assert load_error(KafkaSettings).variables == {"KAFKA_BOOTSTRAP_SERVERS"}


def test_kafka_security_protocol_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "sasl_ssl")
    monkeypatch.setenv("KAFKA_SASL_MECHANISM", "scram-sha-512")
    monkeypatch.setenv("KAFKA_SASL_USERNAME", "adis")
    monkeypatch.setenv("KAFKA_SASL_PASSWORD", "s" * 24)
    settings = load_settings(KafkaSettings)
    assert settings.kafka_security_protocol is KafkaSecurityProtocol.SASL_SSL
    assert settings.kafka_sasl_mechanism is KafkaSaslMechanism.SCRAM_SHA_512


@pytest.mark.parametrize("protocol", ["SASL_SSL", "SASL_PLAINTEXT"])
def test_sasl_protocols_require_credentials(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, protocol: str
) -> None:
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", protocol)
    monkeypatch.setenv("KAFKA_SASL_USERNAME", "  ")
    assert load_error(KafkaSettings).variables == {
        "KAFKA_SASL_MECHANISM",
        "KAFKA_SASL_USERNAME",
        "KAFKA_SASL_PASSWORD",
    }


def test_sasl_credentials_are_optional_without_sasl() -> None:
    settings = load_settings(KafkaSettings)
    assert (settings.kafka_sasl_mechanism, settings.kafka_sasl_password) == (None, None)


@pytest.mark.parametrize("protocol", ["PLAINTEXT", "SASL_PLAINTEXT"])
def test_production_requires_encrypted_kafka(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, protocol: str
) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "kafka.example.test:9093")
    monkeypatch.setenv("KAFKA_TOPIC_REPLICATION_FACTOR", "3")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", protocol)
    monkeypatch.setenv("KAFKA_SASL_MECHANISM", "PLAIN")
    monkeypatch.setenv("KAFKA_SASL_USERNAME", "adis")
    monkeypatch.setenv("KAFKA_SASL_PASSWORD", "s" * 24)
    assert load_error(KafkaSettings).variables == {"KAFKA_SECURITY_PROTOCOL"}


@pytest.mark.parametrize("mode", ["disable", "prefer"])
def test_production_requires_database_tls(
    monkeypatch: pytest.MonkeyPatch, secrets: dict[str, str], load_error: LoadError, mode: str
) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DB_SSL_MODE", mode)
    assert load_error(DatabaseSettings).variables == {"DB_SSL_MODE"}


@pytest.mark.parametrize("mode", ["require", "verify-ca", "verify-full"])
def test_production_accepts_database_tls(
    monkeypatch: pytest.MonkeyPatch, secrets: dict[str, str], mode: str
) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DB_SSL_MODE", mode)
    assert load_settings(DatabaseSettings).db_ssl_mode.value == mode


def test_staging_may_use_plaintext_on_private_networks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "kafka.internal:9092")
    monkeypatch.setenv("KAFKA_TOPIC_REPLICATION_FACTOR", "3")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
    assert load_settings(KafkaSettings).kafka_security_protocol is KafkaSecurityProtocol.PLAINTEXT


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("KAFKA_SECURITY_PROTOCOL", "TLS"),
        ("KAFKA_CLIENT_ID", "adis client"),
        ("KAFKA_TOPIC_PARTITIONS", "0"),
        ("KAFKA_TOPIC_REPLICATION_FACTOR", "11"),
        ("KAFKA_TOPIC_RETENTION_HOURS", "0"),
        ("KAFKA_DEADLETTER_RETENTION_HOURS", "-1"),
        ("KAFKA_RETRY_MAX_ATTEMPTS", "0"),
        ("KAFKA_RETRY_INITIAL_BACKOFF_MS", "0"),
        ("KAFKA_RETRY_MAX_BACKOFF_MS", "50"),
    ],
)
def test_invalid_kafka_values_are_rejected(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, variable: str, value: str
) -> None:
    monkeypatch.setenv(variable, value)
    assert load_error(KafkaSettings).variables == {variable}


TOKEN_A = "a" * 32
TOKEN_B = "B-b_b.b~b+b/b=" + "b" * 20


def test_api_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_INGEST_TOKENS", f"agent-a:{TOKEN_A}")
    settings = load_settings(ApiSettings)
    assert (settings.api_host, settings.api_port) == ("127.0.0.1", 8000)
    assert settings.api_max_request_bytes == 1048576
    assert settings.api_max_batch_size == 500
    assert (settings.api_rate_limit_events, settings.api_rate_limit_window_seconds) == (6000, 60)
    assert settings.api_publish_timeout_seconds == 5.0
    assert settings.ingest_credentials() == {"agent-a": TOKEN_A}


def test_ingest_tokens_accept_several_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_INGEST_TOKENS", f"agent-a:{TOKEN_A}, sensor.1:{TOKEN_B}")
    assert load_settings(ApiSettings).ingest_credentials() == {
        "agent-a": TOKEN_A,
        "sensor.1": TOKEN_B,
    }


@pytest.mark.parametrize(
    "tokens",
    [
        "no-separator",
        f":{TOKEN_A}",
        "agent-a:short-token",
        f"agent a:{TOKEN_A}",
        f"agent-a:{TOKEN_A},",
        f"agent-a:{TOKEN_A},agent-a:{TOKEN_B}",
        f"agent-a:{TOKEN_A},agent-b:{TOKEN_A}",
        f"agent-a:{'x' * 257}",
        f"agent-a:{'x' * 31}!",
    ],
)
def test_malformed_ingest_tokens_are_rejected_without_echo(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, tokens: str
) -> None:
    monkeypatch.setenv("API_INGEST_TOKENS", tokens)
    error = load_error(ApiSettings)
    assert error.variables == {"API_INGEST_TOKENS"}
    assert TOKEN_A not in str(error)


def test_ingest_tokens_are_required(load_error: LoadError) -> None:
    assert load_error(ApiSettings).variables == {"API_INGEST_TOKENS"}


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("API_HOST", "not a host"),
        ("API_HOST", "-bad.example"),
        ("API_PORT", "0"),
        ("API_MAX_REQUEST_BYTES", "100"),
        ("API_MAX_BATCH_SIZE", "0"),
        ("API_MAX_BATCH_SIZE", "10001"),
        ("API_RATE_LIMIT_WINDOW_SECONDS", "0"),
        ("API_PUBLISH_TIMEOUT_SECONDS", "0"),
        ("API_RATE_LIMIT_EVENTS", "499"),
    ],
)
def test_invalid_api_values_are_rejected(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, variable: str, value: str
) -> None:
    monkeypatch.setenv("API_INGEST_TOKENS", f"agent-a:{TOKEN_A}")
    monkeypatch.setenv(variable, value)
    assert load_error(ApiSettings).variables == {variable}


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "api.internal", "localhost"])  # noqa: S104
def test_api_host_accepts_addresses_and_hostnames(
    monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    monkeypatch.setenv("API_INGEST_TOKENS", f"agent-a:{TOKEN_A}")
    monkeypatch.setenv("API_HOST", host)
    assert load_settings(ApiSettings).api_host == host


def test_agent_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_TOKEN", "t" * 40)
    settings = load_settings(AgentSettings)
    assert str(settings.agent_server_url) == "http://127.0.0.1:8000/"
    assert settings.agent_data_dir == Path(".adis-agent")
    assert (settings.agent_flush_interval_seconds, settings.agent_batch_size) == (5.0, 100)
    assert settings.agent_max_queue_events == 100000
    assert settings.log_file_paths() == ()
    assert (settings.agent_simulate_auth_per_minute, settings.agent_simulate_flows_per_minute) == (
        0,
        0,
    )
    assert settings.agent_name
    assert (settings.agent_spool_encryption, settings.agent_spool_key) == (True, None)


def test_agent_spool_key_accepts_32_bytes_of_base64url(monkeypatch: pytest.MonkeyPatch) -> None:
    key = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    monkeypatch.setenv("AGENT_TOKEN", "t" * 40)
    monkeypatch.setenv("AGENT_SPOOL_KEY", key)
    stored = load_settings(AgentSettings).agent_spool_key
    assert stored is not None
    assert stored.get_secret_value() == key


@pytest.mark.parametrize(
    "value", ["not-base64!!", base64.urlsafe_b64encode(b"sixteen bytes!!!").decode()]
)
def test_agent_spool_key_must_be_32_bytes(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, value: str
) -> None:
    monkeypatch.setenv("AGENT_TOKEN", "t" * 40)
    monkeypatch.setenv("AGENT_SPOOL_KEY", value)
    error = load_error(AgentSettings)
    assert error.variables == {"AGENT_SPOOL_KEY"}
    assert value not in str(error)


def test_agent_log_files_are_split(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_TOKEN", "t" * 40)
    monkeypatch.setenv("AGENT_LOG_FILES", "/var/log/syslog, /var/log/app.log,,")
    assert load_settings(AgentSettings).log_file_paths() == (
        Path("/var/log/syslog"),
        Path("/var/log/app.log"),
    )


@pytest.mark.parametrize("app_env", ["staging", "production"])
def test_agent_requires_https_outside_development(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, app_env: str
) -> None:
    monkeypatch.setenv("APP_ENV", app_env)
    monkeypatch.setenv("AGENT_TOKEN", "t" * 40)
    monkeypatch.setenv("AGENT_DATA_DIR", "/var/lib/adis-agent")
    monkeypatch.setenv("AGENT_SERVER_URL", "http://ingest.example.test")
    assert load_error(AgentSettings).variables == {"AGENT_SERVER_URL"}


@pytest.mark.parametrize(
    "variable", ["AGENT_SIMULATE_AUTH_PER_MINUTE", "AGENT_SIMULATE_FLOWS_PER_MINUTE"]
)
def test_agent_simulation_is_refused_outside_development(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, variable: str
) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("AGENT_TOKEN", "t" * 40)
    monkeypatch.setenv("AGENT_DATA_DIR", "/var/lib/adis-agent")
    monkeypatch.setenv("AGENT_SERVER_URL", "https://ingest.example.test")
    monkeypatch.setenv(variable, "60")
    assert load_error(AgentSettings).variables == {variable}


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("AGENT_NAME", "has space"),
        ("AGENT_FLUSH_INTERVAL_SECONDS", "0"),
        ("AGENT_BATCH_SIZE", "0"),
        ("AGENT_MAX_QUEUE_EVENTS", "0"),
        ("AGENT_RETRY_INITIAL_BACKOFF_SECONDS", "0"),
        ("AGENT_RETRY_MAX_BACKOFF_SECONDS", "0.5"),
        ("AGENT_HTTP_TIMEOUT_SECONDS", "0"),
        ("AGENT_SIMULATE_AUTH_PER_MINUTE", "-1"),
        ("AGENT_SERVER_URL", "ftp://ingest.example.test"),
    ],
)
def test_invalid_agent_values_are_rejected(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, variable: str, value: str
) -> None:
    monkeypatch.setenv("AGENT_TOKEN", "t" * 40)
    monkeypatch.setenv(variable, value)
    assert load_error(AgentSettings).variables == {variable}


def test_agent_token_is_required(load_error: LoadError) -> None:
    assert load_error(AgentSettings).variables == {"AGENT_TOKEN"}
