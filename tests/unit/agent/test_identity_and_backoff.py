"""Stable identity and retry backoff."""

import os
import platform
import shutil
import subprocess
from pathlib import Path
from uuid import UUID

import pytest

from apps.agent.backoff import Backoff
from apps.agent.identity import (
    IDENTITY_FILE,
    IdentityError,
    build_identity,
    load_or_create_agent_id,
    prepare_data_directory,
)
from tests.unit.agent.fakes import agent_settings


def test_agent_id_is_created_once_and_stays_stable(tmp_path: Path) -> None:
    first = load_or_create_agent_id(tmp_path / "data")
    second = load_or_create_agent_id(tmp_path / "data")

    assert first == second
    assert (tmp_path / "data" / IDENTITY_FILE).read_text().strip() == str(first)


def test_corrupt_identity_is_never_replaced(tmp_path: Path) -> None:
    (tmp_path / IDENTITY_FILE).write_text("not-a-uuid")

    with pytest.raises(IdentityError, match="restore it"):
        load_or_create_agent_id(tmp_path)

    assert (tmp_path / IDENTITY_FILE).read_text() == "not-a-uuid"


def test_interrupted_creation_is_completed(tmp_path: Path) -> None:
    (tmp_path / IDENTITY_FILE).write_text("")

    agent_id = load_or_create_agent_id(tmp_path)

    assert isinstance(agent_id, UUID)
    assert load_or_create_agent_id(tmp_path) == agent_id


@pytest.mark.skipif(platform.system() == "Windows", reason="POSIX permissions")
def test_identity_file_is_private(tmp_path: Path) -> None:
    load_or_create_agent_id(tmp_path)

    assert os.stat(tmp_path / IDENTITY_FILE).st_mode & 0o077 == 0


def test_identity_describes_the_host(tmp_path: Path) -> None:
    settings = agent_settings(tmp_path, agent_name="edge-7")
    agent_id = load_or_create_agent_id(tmp_path)

    identity = build_identity(settings, agent_id)

    assert identity.agent_id == agent_id
    assert identity.name == "edge-7"
    assert identity.os_type in {"linux", "windows", "macos", "other"}
    assert identity.host_id == identity.host_id.lower()
    assert identity.agent_version


def test_backoff_doubles_up_to_the_cap_and_resets() -> None:
    backoff = Backoff(initial_seconds=1, max_seconds=5, jitter=lambda low, high: high)

    delays = [backoff.next_delay() for _ in range(5)]
    failures = backoff.failures
    backoff.reset()

    assert delays == [1, 2, 4, 5, 5]
    assert failures == 5
    assert backoff.next_delay() == 1


def test_backoff_always_waits_half_the_ceiling() -> None:
    backoff = Backoff(initial_seconds=2, max_seconds=8, jitter=lambda low, high: low)

    assert [backoff.next_delay() for _ in range(3)] == [1, 2, 4]


@pytest.mark.parametrize(
    "options",
    [
        {"initial_seconds": 0, "max_seconds": 1},
        {"initial_seconds": 2, "max_seconds": 1},
        {"initial_seconds": 1, "max_seconds": 2, "multiplier": 0.5},
    ],
)
def test_invalid_backoff(options: dict[str, float]) -> None:
    with pytest.raises(ValueError, match="initial_seconds"):
        Backoff(**options)  # type: ignore[arg-type]


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows ACLs")
def test_data_directory_is_private_on_windows(tmp_path: Path) -> None:
    data_dir = prepare_data_directory(tmp_path / "agent")

    acl = subprocess.run(  # noqa: S603 - fixed arguments
        [shutil.which("icacls") or "icacls", str(data_dir)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    assert os.environ["USERNAME"].lower() in acl.lower()
    assert "(I)" not in acl  # nothing inherited from the parent any more
    for broad in ("Everyone", r"BUILTIN\Users", "Authenticated Users"):
        assert broad not in acl
