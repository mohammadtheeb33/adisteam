"""Stable agent identity.

The agent UUID is generated once and stored in ``AGENT_DATA_DIR/agent_id``. It must
survive restarts and upgrades: the server links events to registered agents by this id.
An unreadable identity file is an error, never silently replaced, because a new id would
make the agent look like a different machine.
"""

import logging
import os
import platform
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Final
from uuid import UUID, uuid4

from apps.agent.settings import AgentServiceSettings

IDENTITY_FILE: Final = "agent_id"
_HOST_ID_INVALID: Final = re.compile(r"[^A-Za-z0-9._:@/+=-]")
_OS_TYPES: Final = {"Linux": "linux", "Windows": "windows", "Darwin": "macos"}
logger = logging.getLogger(__name__)

_SYSTEM_SID: Final = "*S-1-5-18"  # NT AUTHORITY\SYSTEM
_PRIVATE_FILE_MODE: Final = 0o600
_PRIVATE_DIRECTORY_MODE: Final = 0o700


class IdentityError(RuntimeError):
    """The stored agent id cannot be read."""


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    """Who this agent is and where it runs."""

    agent_id: UUID
    name: str
    hostname: str
    host_id: str
    os_type: str
    agent_version: str


def prepare_data_directory(data_dir: Path) -> Path:
    """Create ``data_dir``, readable by its owner only, and return it.

    POSIX modes do not apply on Windows, where the directory would otherwise inherit
    its parent's ACL; there, inheritance is removed and only the current user and
    ``SYSTEM`` keep access (files created inside inherit that).
    """
    data_dir.mkdir(mode=_PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
    if os.name == "nt":
        _restrict_windows_acl(data_dir)
    return data_dir


def _restrict_windows_acl(directory: Path) -> None:
    user, domain = os.environ.get("USERNAME"), os.environ.get("USERDOMAIN")
    icacls = shutil.which("icacls")
    if not user or icacls is None:
        logger.warning(
            "could not restrict the agent data directory's permissions",
            extra={"action": "agent_data_dir_acl_skipped"},
        )
        return
    principal = f"{domain}\\{user}" if domain else user
    command = [
        icacls,
        str(directory),
        "/inheritance:r",
        "/grant:r",
        f"{principal}:(OI)(CI)F",
        "/grant:r",
        f"{_SYSTEM_SID}:(OI)(CI)F",
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, timeout=30)  # noqa: S603 - fixed arguments
    except (OSError, subprocess.SubprocessError) as error:
        logger.warning(
            "could not restrict the agent data directory's permissions",
            extra={"action": "agent_data_dir_acl_failed", "error_type": type(error).__name__},
        )


def load_or_create_agent_id(data_dir: Path) -> UUID:
    """The persisted agent UUID, created on first use.

    Raises:
        IdentityError: If the identity file exists but does not hold a UUID.
    """
    path = prepare_data_directory(data_dir) / IDENTITY_FILE
    existing = _read_agent_id(path)
    if existing is not None:
        return existing
    candidate = uuid4()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _PRIVATE_FILE_MODE)
    except FileExistsError:
        # Another process created it first, or an earlier creation was interrupted.
        existing = _read_agent_id(path)
        if existing is not None:
            return existing
        descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(f"{candidate}\n")
        handle.flush()
        os.fsync(handle.fileno())
    return candidate


def _read_agent_id(path: Path) -> UUID | None:
    """The stored UUID; ``None`` if absent or empty (creation never completed)."""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    if not text:
        return None
    try:
        return UUID(text)
    except ValueError:
        raise IdentityError(
            f"{path} does not contain an agent UUID; restore it from backup rather than "
            "deleting it, or the agent will register as a new machine"
        ) from None


def build_identity(settings: AgentServiceSettings, agent_id: UUID) -> AgentIdentity:
    """Describe this agent and its host."""
    hostname = socket.gethostname()
    host_id = _HOST_ID_INVALID.sub("-", hostname.lower()).strip("-.") or f"agent-{agent_id}"
    if not host_id[0].isalnum():
        host_id = f"host-{host_id}"
    return AgentIdentity(
        agent_id=agent_id,
        name=settings.agent_name,
        hostname=hostname[:255],
        host_id=host_id[:255],
        os_type=_OS_TYPES.get(platform.system(), "other"),
        agent_version=version("adis"),
    )
