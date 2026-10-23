"""Shared settings base class and environment rules."""

from enum import StrEnum
from typing import Final, get_args

from pydantic import SecretStr, field_validator, model_validator
from pydantic_core import PydanticCustomError
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Deployment environment, selected by ``APP_ENV``."""

    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def allows_development_defaults(self) -> bool:
        """Whether fields marked with :data:`DEV_DEFAULT` may fall back to their default."""
        return self in {Environment.DEVELOPMENT, Environment.TEST}


class DevelopmentDefault:
    """Field metadata: the declared default is only acceptable in development and test.

    Attach the :data:`DEV_DEFAULT` instance through ``Annotated``. Only non-sensitive
    fields may carry a development default; secrets never have defaults.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "DEV_DEFAULT"


DEV_DEFAULT: Final = DevelopmentDefault()


class _ExplicitValueRequired:
    """Sentinel standing in for development defaults left unset in strict environments."""

    __slots__ = ()


_EXPLICIT_VALUE_REQUIRED: Final = _ExplicitValueRequired()


class ADISSettings(BaseSettings):
    """Base class for every ADIS configuration section.

    Behavior shared by all sections:

    - Values come from unprefixed, case-insensitive environment variables, then from a
      ``.env`` file in the working directory. Real environment variables take precedence.
    - Empty values are treated as unset.
    - Instances are immutable.
    - Validation errors never echo input values, so secrets cannot leak through them.
    - In staging and production every field marked :data:`DEV_DEFAULT` must be set
      explicitly, so a misconfigured deployment fails at start-up.

    Services compose only the sections they need, which keeps secrets away from
    services that have no use for them::

        class DetectorSettings(AppSettings, KafkaSettings, RedisSettings):
            \"\"\"Configuration for the detector service.\"\"\"
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        case_sensitive=False,
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    app_env: Environment = Environment.DEVELOPMENT

    @classmethod
    def development_default_fields(cls) -> frozenset[str]:
        """Names of fields whose default is only acceptable in development and test."""
        return frozenset(
            name
            for name, field in cls.model_fields.items()
            if any(isinstance(item, DevelopmentDefault) for item in field.metadata)
        )

    @classmethod
    def secret_fields(cls) -> frozenset[str]:
        """Names of fields holding secret values, required or optional."""
        return frozenset(
            name
            for name, field in cls.model_fields.items()
            if field.annotation is SecretStr or SecretStr in get_args(field.annotation)
        )

    @classmethod
    def required_secret_fields(cls) -> frozenset[str]:
        """Names of secret fields that must always be set."""
        return frozenset(
            name
            for name, field in cls.model_fields.items()
            if field.annotation is SecretStr and field.is_required()
        )

    def redacted(self) -> dict[str, object]:
        """Return the configuration keyed by environment variable, with secrets masked.

        This is the only representation of settings that may be logged.
        """
        return {name.upper(): value for name, value in self.model_dump(mode="json").items()}

    @field_validator("app_env", mode="before")
    @classmethod
    def _normalize_app_env(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @model_validator(mode="before")
    @classmethod
    def _require_explicit_values_in_strict_environments(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        raw_environment = data.get("app_env", Environment.DEVELOPMENT)
        if isinstance(raw_environment, str):
            raw_environment = raw_environment.strip().lower()
        try:
            environment = Environment(raw_environment)
        except ValueError:
            # An invalid APP_ENV is reported by field validation.
            return data
        if environment.allows_development_defaults:
            return data
        unset = {
            name: _EXPLICIT_VALUE_REQUIRED
            for name in cls.development_default_fields()
            if name not in data
        }
        return {**data, **unset}

    @field_validator("*", mode="before")
    @classmethod
    def _reject_unset_development_defaults(cls, value: object) -> object:
        if value is _EXPLICIT_VALUE_REQUIRED:
            raise PydanticCustomError(
                "explicit_value_required",
                "must be set explicitly in staging and production "
                "(development defaults are not allowed)",
            )
        return value
