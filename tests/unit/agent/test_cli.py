"""Command-line interface: generate, status, simulate guards and configuration errors."""

import json
from pathlib import Path

import pytest

from apps.agent import __main__ as cli
from packages.events.canonical import parse_canonical_event

SETTINGS_VARIABLES = (
    "APP_ENV",
    "AGENT_TOKEN",
    "AGENT_DATA_DIR",
    "AGENT_SERVER_URL",
    "AGENT_SIMULATE_AUTH_PER_MINUTE",
    "AGENT_SIMULATE_FLOWS_PER_MINUTE",
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for variable in SETTINGS_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.mark.parametrize("kind", ["auth", "flows"])
def test_generate_prints_valid_canonical_events(
    kind: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["generate", kind, "--count", "5", "--seed", "1"]) == cli.EXIT_OK

    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 5
    for line in lines:
        event = parse_canonical_event(line)
        assert event.metadata["simulated"] is True


def test_generate_batch_body(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["generate", "auth", "--count", "3", "--batch"])

    body = json.loads(capsys.readouterr().out)
    assert len(body["events"]) == 3


def test_generate_is_refused_outside_development(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")

    with pytest.raises(SystemExit, match="development"):
        cli.main(["generate", "auth"])


def test_simulate_is_refused_outside_development(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("AGENT_TOKEN", "t" * 40)
    monkeypatch.setenv("AGENT_SERVER_URL", "https://ingest.example.test")
    monkeypatch.setenv("AGENT_DATA_DIR", "agent-data")

    with pytest.raises(SystemExit, match="development"):
        cli.main(["simulate", "--duration", "0"])


def test_missing_configuration_is_reported(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["run"]) == cli.EXIT_CONFIGURATION


def test_status_reports_identity_and_queues(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AGENT_TOKEN", "t" * 40)
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path / "agent"))

    assert cli.main(["status"]) == cli.EXIT_OK
    first = json.loads(capsys.readouterr().out)
    cli.main(["status"])
    second = json.loads(capsys.readouterr().out)

    assert first["agent_id"] == second["agent_id"]
    assert (first["queued"], first["quarantined"], first["registration"]) == (0, 0, None)
    assert first["capacity"] == 100_000
    assert "token" not in json.dumps(first).lower()
