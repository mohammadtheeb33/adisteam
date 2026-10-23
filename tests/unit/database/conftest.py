"""Fixtures for database unit tests: isolated environment and settings factory."""

from collections.abc import Callable
from pathlib import Path

import pytest

from packages.config import DatabaseSettings, load_settings

# The password contains "sentinel" so any leak is detectable with one substring check.
DSN = "postgresql://adis:db-password-sentinel@db.example.test:5432/postgres"

MakeSettings = Callable[..., DatabaseSettings]


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Clear database variables and run in an empty directory (no stray ``.env``)."""
    for name in DatabaseSettings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def make_settings(monkeypatch: pytest.MonkeyPatch) -> MakeSettings:
    """Return a factory that loads ``DatabaseSettings`` with variable overrides."""

    def make(**overrides: str) -> DatabaseSettings:
        monkeypatch.setenv("SUPABASE_DB_URL", DSN)
        for variable, value in overrides.items():
            monkeypatch.setenv(variable, value)
        return load_settings(DatabaseSettings)

    return make
