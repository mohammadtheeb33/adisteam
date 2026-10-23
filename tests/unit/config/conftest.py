"""Fixtures isolating configuration tests from the developer's shell and ``.env`` file."""

from collections.abc import Callable
from pathlib import Path

import pytest

from packages.config import SETTINGS_SECTIONS, ADISSettings, ConfigurationError, load_settings

SUPPORTED_VARIABLES = frozenset(
    name.upper() for section in SETTINGS_SECTIONS for name in section.model_fields
)
SECRET_VALUES = {
    "SUPABASE_DB_URL": "postgresql+asyncpg://adis:db-password-sentinel-91d4@db.example.test:5432/postgres",
    "REDIS_URL": "redis://:redis-password-sentinel-44af@cache.example.test:6379/0",
    "API_INGEST_TOKENS": "agent-a:ingest-token-sentinel-0123456789abcdef0123",
    "AGENT_TOKEN": "agent-token-sentinel-0123456789abcdef",
}
EXPLICIT_VALUES = {
    "DB_SSL_MODE": "verify-full",
    "KAFKA_BOOTSTRAP_SERVERS": "kafka-1.example.test:9093,kafka-2.example.test:9093",
    "KAFKA_SECURITY_PROTOCOL": "SSL",
    "KAFKA_TOPIC_REPLICATION_FACTOR": "3",
    "API_HOST": "0.0.0.0",  # noqa: S104 - explicit container listen address
    "AGENT_SERVER_URL": "https://ingest.example.test",
    "AGENT_DATA_DIR": "/var/lib/adis-agent",
    "NORMALIZER_HEALTH_HOST": "0.0.0.0",  # noqa: S104 - explicit container listen address
}


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Clear every supported variable and run in an empty directory (no stray ``.env``)."""
    for variable in SUPPORTED_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def secrets(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Provide a valid value for every secret."""
    for variable, value in SECRET_VALUES.items():
        monkeypatch.setenv(variable, value)
    return SECRET_VALUES


@pytest.fixture
def explicit_values(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Explicitly set every field that otherwise falls back to a development default."""
    for variable, value in EXPLICIT_VALUES.items():
        monkeypatch.setenv(variable, value)
    return EXPLICIT_VALUES


@pytest.fixture
def load_error() -> Callable[[type[ADISSettings]], ConfigurationError]:
    """Return a helper that loads settings and returns the expected ``ConfigurationError``."""

    def load(settings_cls: type[ADISSettings]) -> ConfigurationError:
        with pytest.raises(ConfigurationError) as caught:
            load_settings(settings_cls)
        return caught.value

    return load
