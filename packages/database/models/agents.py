"""Registered telemetry agents."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import CheckConstraint, Enum, String, func, text
from sqlalchemy.orm import Mapped, mapped_column

from packages.database.base import Base
from packages.database.ids import uuid7


class OsType(StrEnum):
    """Operating system family of an agent's host."""

    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    OTHER = "other"


class AgentStatus(StrEnum):
    """Lifecycle of an agent."""

    PENDING = "pending"
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"


def _enum_values(enum: type[StrEnum]) -> list[str]:
    return [member.value for member in enum]


class AgentRecord(Base):
    """A telemetry agent installed on a monitored host.

    ``first_seen``/``last_seen`` stay empty until the agent first reports.
    Decommission agents by status rather than deleting them; deleting one sets
    ``security_events.agent_id`` to NULL.
    """

    __tablename__ = "agents"
    __table_args__ = (
        CheckConstraint(
            "first_seen IS NULL OR last_seen IS NULL OR last_seen >= first_seen",
            name="seen_order",
        ),
    )
    __mapper_args__ = {"eager_defaults": True}  # noqa: RUF012 - SQLAlchemy declarative API

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid7, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(String(255))
    hostname: Mapped[str] = mapped_column(String(255))
    os_type: Mapped[OsType] = mapped_column(
        Enum(
            OsType,
            name="os_type",
            native_enum=False,
            create_constraint=True,
            length=32,
            values_callable=_enum_values,
            validate_strings=True,
        )
    )
    agent_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[AgentStatus] = mapped_column(
        Enum(
            AgentStatus,
            name="status",
            native_enum=False,
            create_constraint=True,
            length=32,
            values_callable=_enum_values,
            validate_strings=True,
        ),
        default=AgentStatus.PENDING,
        server_default=AgentStatus.PENDING.value,
    )
    first_seen: Mapped[datetime | None]
    last_seen: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
