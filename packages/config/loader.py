"""Fail-fast settings loading with errors that never expose configuration values."""

from dataclasses import dataclass
from typing import Self

from pydantic import ValidationError

from packages.config.base import ADISSettings


@dataclass(frozen=True, slots=True)
class ConfigurationIssue:
    """One missing or invalid configuration value.

    Attributes:
        variable: Environment variable name, or ``None`` for issues spanning several.
        message: Human-readable description; never contains the offending value.
    """

    variable: str | None
    message: str

    def __str__(self) -> str:
        return f"{self.variable}: {self.message}" if self.variable else self.message


class ConfigurationError(Exception):
    """Raised when configuration is missing or invalid.

    The message names the offending environment variables but never their values, so
    it is safe to log.
    """

    def __init__(self, settings_name: str, issues: tuple[ConfigurationIssue, ...]) -> None:
        self.settings_name = settings_name
        self.issues = issues
        details = "\n".join(f"  - {issue}" for issue in issues)
        super().__init__(f"Invalid configuration for {settings_name}:\n{details}")

    @property
    def variables(self) -> frozenset[str]:
        """Environment variable names that caused this error."""
        return frozenset(issue.variable for issue in self.issues if issue.variable)

    @classmethod
    def from_validation_error(
        cls, settings_cls: type[ADISSettings], error: ValidationError
    ) -> Self:
        """Build a value-free error from a pydantic ``ValidationError``."""
        issues: list[ConfigurationIssue] = []
        for details in error.errors(include_url=False, include_context=False, include_input=False):
            location = details["loc"]
            missing = details["type"] == "missing"
            issues.append(
                ConfigurationIssue(
                    variable=str(location[0]).upper() if location else None,
                    message="is required but not set" if missing else details["msg"],
                )
            )
        return cls(settings_cls.__name__, tuple(issues))


def load_settings[SettingsT: ADISSettings](settings_cls: type[SettingsT]) -> SettingsT:
    """Load and validate a settings class, failing fast on missing or invalid values.

    Call this once at service start-up and pass the result to components through
    dependency injection instead of storing it in module-level state.

    Args:
        settings_cls: The section, or composition of sections, the service needs.

    Returns:
        The validated, immutable settings.

    Raises:
        ConfigurationError: If any value is missing or invalid. Its message lists every
            problem at once and never contains configuration values.
    """
    try:
        return settings_cls()
    except ValidationError as error:
        raise ConfigurationError.from_validation_error(settings_cls, error) from None
