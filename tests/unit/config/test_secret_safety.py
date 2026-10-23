"""Secrets and rejected values must never surface in reprs, dumps or error messages."""

import json
import traceback
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from packages.config import (
    ADISSettings,
    AppSettings,
    ConfigurationError,
    DatabaseSettings,
    KafkaSettings,
    RedisSettings,
    load_settings,
)

LoadError = Callable[[type[ADISSettings]], ConfigurationError]
MARKER = "sentinel"


class SecretBearingSettings(AppSettings, DatabaseSettings, RedisSettings):
    """All sections that hold secrets."""


def test_secrets_are_masked_in_repr_str_and_redacted_dump(secrets: dict[str, str]) -> None:
    settings = load_settings(SecretBearingSettings)
    for rendered in (repr(settings), str(settings), json.dumps(settings.redacted())):
        assert MARKER not in rendered
    assert settings.supabase_db_url.get_secret_value() == secrets["SUPABASE_DB_URL"]


def test_redacted_dump_is_keyed_by_variable_and_masks_every_secret(secrets: dict[str, str]) -> None:
    redacted = load_settings(SecretBearingSettings).redacted()
    assert set(redacted) == {name.upper() for name in SecretBearingSettings.model_fields}
    for name in SecretBearingSettings.secret_fields():
        assert redacted[name.upper()] == "**********"
    assert redacted["APP_NAME"] == "adis"


@pytest.mark.parametrize(
    ("variable", "rejected_value"),
    [
        ("SUPABASE_DB_URL", "mysql://adis:sentinel-password@db.example.test/adis"),
        ("REDIS_URL", "http://:sentinel-password@cache.example.test:6379"),
        ("APP_ENV", "sentinel-environment"),
        ("LOG_LEVEL", "sentinel-level"),
    ],
)
def test_rejected_values_are_not_echoed_in_configuration_errors(
    monkeypatch: pytest.MonkeyPatch,
    secrets: dict[str, str],
    load_error: LoadError,
    variable: str,
    rejected_value: str,
) -> None:
    monkeypatch.setenv(variable, rejected_value)
    error = load_error(SecretBearingSettings)
    assert error.variables == {variable}
    assert MARKER not in "".join(traceback.format_exception(error))
    assert MARKER not in repr(error.issues)


def test_configuration_error_does_not_chain_the_validation_error(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError
) -> None:
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "sentinel-host-without-port")
    error = load_error(KafkaSettings)
    assert error.__cause__ is None
    assert error.__suppress_context__ is True


def test_raw_validation_errors_hide_input_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPABASE_DB_URL", "mysql://adis:sentinel-password@db.example.test/adis")
    with pytest.raises(ValidationError) as caught:
        DatabaseSettings()
    assert MARKER not in str(caught.value)
    assert MARKER not in repr(caught.value)
