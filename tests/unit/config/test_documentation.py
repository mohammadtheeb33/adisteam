"""Every variable must be documented, and ``.env.example`` must be valid and secret-free."""

import shutil
from pathlib import Path

import pytest

from packages.config import SETTINGS_SECTIONS, load_settings

REPO_ROOT = Path(__file__).resolve().parents[3]
ENV_EXAMPLE = REPO_ROOT / ".env.example"
DEVELOPMENT_GUIDE = REPO_ROOT / "docs" / "DEVELOPMENT.md"
SUPPORTED_VARIABLES = sorted(
    {name.upper() for section in SETTINGS_SECTIONS for name in section.model_fields}
)
SECRET_VARIABLES = sorted(
    {name.upper() for section in SETTINGS_SECTIONS for name in section.secret_fields()}
)


def _env_example() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and (not stripped.startswith("#")):
            key, _, value = stripped.partition("=")
            entries[key.strip()] = value.strip()
    return entries


@pytest.mark.parametrize("variable", SUPPORTED_VARIABLES)
def test_supported_variable_is_listed_in_env_example(variable: str) -> None:
    assert variable in _env_example()


@pytest.mark.parametrize("variable", sorted(_env_example()))
def test_env_example_variable_is_documented_in_development_guide(variable: str) -> None:
    assert f"`{variable}`" in DEVELOPMENT_GUIDE.read_text(encoding="utf-8")


@pytest.mark.parametrize("variable", SECRET_VARIABLES)
def test_secret_has_no_value_in_env_example(variable: str) -> None:
    assert _env_example()[variable] == ""


def test_env_example_values_are_valid(isolated_environment: Path, secrets: dict[str, str]) -> None:
    shutil.copyfile(ENV_EXAMPLE, isolated_environment / ".env")
    for section in SETTINGS_SECTIONS:
        load_settings(section)
