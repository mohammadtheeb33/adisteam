"""Environment-dependent rules: development defaults, fail-fast strict environments, sources."""

from collections.abc import Callable
from pathlib import Path

import pytest

from packages.config import (
    SETTINGS_SECTIONS,
    ADISSettings,
    AgentSettings,
    ApiSettings,
    AppSettings,
    ConfigurationError,
    DatabaseSettings,
    KafkaSettings,
    NormalizerSettings,
    RedisSettings,
    load_settings,
)

LoadError = Callable[[type[ADISSettings]], ConfigurationError]
LENIENT_ENVIRONMENTS = ("development", "test")
STRICT_ENVIRONMENTS = ("staging", "production")
SECTIONS_WITH_DEVELOPMENT_DEFAULTS = [
    section for section in SETTINGS_SECTIONS if section.development_default_fields()
]


class AllSettings(
    AppSettings,
    DatabaseSettings,
    RedisSettings,
    KafkaSettings,
    ApiSettings,
    AgentSettings,
    NormalizerSettings,
):
    """Every section composed into one class."""


def _section_id(section: type[ADISSettings]) -> str:
    return section.__name__


def _variables(names: frozenset[str]) -> set[str]:
    return {name.upper() for name in names}


def test_explicit_values_fixture_covers_every_development_default(
    explicit_values: dict[str, str],
) -> None:
    fields = frozenset().union(
        *(section.development_default_fields() for section in SETTINGS_SECTIONS)
    )
    assert set(explicit_values) == _variables(fields)


@pytest.mark.parametrize("app_env", LENIENT_ENVIRONMENTS)
@pytest.mark.parametrize("section", SETTINGS_SECTIONS, ids=_section_id)
def test_lenient_environments_allow_development_defaults(
    monkeypatch: pytest.MonkeyPatch,
    secrets: dict[str, str],
    section: type[ADISSettings],
    app_env: str,
) -> None:
    monkeypatch.setenv("APP_ENV", app_env)
    assert load_settings(section).app_env == app_env


@pytest.mark.parametrize("app_env", STRICT_ENVIRONMENTS)
@pytest.mark.parametrize("section", SECTIONS_WITH_DEVELOPMENT_DEFAULTS, ids=_section_id)
def test_strict_environments_reject_development_defaults(
    monkeypatch: pytest.MonkeyPatch,
    secrets: dict[str, str],
    load_error: LoadError,
    section: type[ADISSettings],
    app_env: str,
) -> None:
    monkeypatch.setenv("APP_ENV", app_env)
    error = load_error(section)
    assert error.variables == _variables(section.development_default_fields())
    assert all("set explicitly" in issue.message for issue in error.issues)


@pytest.mark.parametrize("app_env", STRICT_ENVIRONMENTS)
@pytest.mark.parametrize("section", SETTINGS_SECTIONS, ids=_section_id)
def test_strict_environments_accept_explicit_configuration(
    monkeypatch: pytest.MonkeyPatch,
    secrets: dict[str, str],
    explicit_values: dict[str, str],
    section: type[ADISSettings],
    app_env: str,
) -> None:
    monkeypatch.setenv("APP_ENV", app_env)
    assert load_settings(section).app_env == app_env


def test_production_accepts_explicit_value_equal_to_development_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
    monkeypatch.setenv("KAFKA_TOPIC_REPLICATION_FACTOR", "1")
    assert load_settings(KafkaSettings).kafka_bootstrap_servers == "localhost:9092"


@pytest.mark.parametrize("app_env", LENIENT_ENVIRONMENTS + STRICT_ENVIRONMENTS)
def test_secrets_are_required_in_every_environment(
    monkeypatch: pytest.MonkeyPatch,
    explicit_values: dict[str, str],
    load_error: LoadError,
    app_env: str,
) -> None:
    monkeypatch.setenv("APP_ENV", app_env)
    assert load_error(AllSettings).variables == _variables(AllSettings.required_secret_fields())


def test_production_reports_every_problem_at_once(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError
) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    error = load_error(AllSettings)
    assert error.variables == _variables(
        AllSettings.required_secret_fields() | AllSettings.development_default_fields()
    )


def test_composed_settings_combine_sections(secrets: dict[str, str]) -> None:

    class DetectorSettings(AppSettings, KafkaSettings, RedisSettings):
        """Example service composition."""

    settings = load_settings(DetectorSettings)
    assert settings.app_name == "adis"
    assert settings.kafka_bootstrap_servers == "localhost:9092"
    assert settings.redis_url.get_secret_value() == secrets["REDIS_URL"]
    assert DetectorSettings.secret_fields() == {"redis_url", "kafka_sasl_password"}
    assert DetectorSettings.required_secret_fields() == {"redis_url"}
    assert DetectorSettings.development_default_fields() == {
        "kafka_bootstrap_servers",
        "kafka_security_protocol",
        "kafka_topic_replication_factor",
    }


def test_composed_settings_only_require_their_own_secrets() -> None:

    class AgentSettings(AppSettings, KafkaSettings):
        """A service that must not need database or Supabase credentials."""

    assert load_settings(AgentSettings).kafka_client_id == "adis"


def test_values_are_read_from_dotenv_file(isolated_environment: Path) -> None:
    (isolated_environment / ".env").write_text(
        "KAFKA_BOOTSTRAP_SERVERS=broker.example.test:9092\n", encoding="utf-8"
    )
    assert load_settings(KafkaSettings).kafka_bootstrap_servers == "broker.example.test:9092"


def test_environment_variables_override_dotenv_file(
    isolated_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (isolated_environment / ".env").write_text("APP_NAME=from-dotenv\n", encoding="utf-8")
    monkeypatch.setenv("APP_NAME", "from-environment")
    assert load_settings(AppSettings).app_name == "from-environment"


def test_empty_value_does_not_satisfy_strict_environment(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError
) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "SSL")
    monkeypatch.setenv("KAFKA_TOPIC_REPLICATION_FACTOR", "3")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "")
    assert load_error(KafkaSettings).variables == {"KAFKA_BOOTSTRAP_SERVERS"}


def test_composed_sections_keep_every_validator(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError
) -> None:
    """Validators with clashing names in two sections would silently override each other."""
    monkeypatch.setenv("KAFKA_RETRY_INITIAL_BACKOFF_MS", "500")
    monkeypatch.setenv("KAFKA_RETRY_MAX_BACKOFF_MS", "100")
    monkeypatch.setenv("AGENT_RETRY_INITIAL_BACKOFF_SECONDS", "10")
    monkeypatch.setenv("AGENT_RETRY_MAX_BACKOFF_SECONDS", "5")

    class Composed(KafkaSettings, AgentSettings):
        """Two sections that both validate backoff ordering."""

    assert {"KAFKA_RETRY_MAX_BACKOFF_MS", "AGENT_RETRY_MAX_BACKOFF_SECONDS"} <= load_error(
        Composed
    ).variables
