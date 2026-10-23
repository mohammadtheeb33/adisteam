"""Stored canonical security events."""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, func, text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from packages.database.base import Base
from packages.database.ids import uuid7
from packages.database.models.agents import AgentRecord
from packages.events.canonical import AnyCanonicalEvent, parse_canonical_event


class SecurityEventRecord(Base):
    """One canonical security event.

    ``payload`` holds the complete canonical event as JSON and is the authoritative copy;
    the other columns are an indexed projection for querying.

    Indexing (kept deliberately small for an append-heavy table):

    - ``event_id``: unique, for idempotent ingestion under at-least-once delivery.
    - ``timestamp``: time-range queries across all hosts.
    - ``(event_type, timestamp)``, ``(host_id, timestamp)``, ``(agent_id, timestamp)``:
      filtered, newest-first queries. The host and agent indexes are partial (non-NULL
      rows only), and the agent index also serves the foreign key's ``ON DELETE``.
    - ``src_ip``, ``dst_ip``: partial, for indicator lookups.
    - ``received_at``: BRIN. Rows arrive in ``received_at`` order, so a BRIN index a few
      pages in size makes retention deletes (``received_at < cutoff``) cheap. Retention
      keys on ingest time, which sources cannot forge, rather than on ``timestamp``.
    """

    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("src_port IS NULL OR src_port BETWEEN 0 AND 65535", name="src_port_range"),
        CheckConstraint("dst_port IS NULL OR dst_port BETWEEN 0 AND 65535", name="dst_port_range"),
        Index("ix_security_events_timestamp", "timestamp"),
        Index("ix_security_events_received_at_brin", "received_at", postgresql_using="brin"),
        Index("ix_security_events_event_type_timestamp", "event_type", "timestamp"),
        Index(
            "ix_security_events_host_id_timestamp",
            "host_id",
            "timestamp",
            postgresql_where=text("host_id IS NOT NULL"),
        ),
        Index(
            "ix_security_events_agent_id_timestamp",
            "agent_id",
            "timestamp",
            postgresql_where=text("agent_id IS NOT NULL"),
        ),
        Index("ix_security_events_src_ip", "src_ip", postgresql_where=text("src_ip IS NOT NULL")),
        Index("ix_security_events_dst_ip", "dst_ip", postgresql_where=text("dst_ip IS NOT NULL")),
    )
    __mapper_args__ = {"eager_defaults": True}  # noqa: RUF012 - SQLAlchemy declarative API

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid7, server_default=text("gen_random_uuid()")
    )
    event_id: Mapped[UUID] = mapped_column(unique=True)
    timestamp: Mapped[datetime]
    received_at: Mapped[datetime]
    event_type: Mapped[str] = mapped_column(String(128))
    source_type: Mapped[str] = mapped_column(String(64))
    source_name: Mapped[str] = mapped_column(String(256))
    agent_id: Mapped[UUID | None] = mapped_column(ForeignKey(AgentRecord.id, ondelete="SET NULL"))
    host_id: Mapped[str | None] = mapped_column(String(255))
    severity_hint: Mapped[str | None] = mapped_column(String(16))
    src_ip: Mapped[IPv4Address | IPv6Address | None] = mapped_column(INET)
    dst_ip: Mapped[IPv4Address | IPv6Address | None] = mapped_column(INET)
    src_port: Mapped[int | None]
    dst_port: Mapped[int | None]
    protocol: Mapped[str | None] = mapped_column(String(16))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    def to_canonical(self) -> AnyCanonicalEvent:
        """Rebuild the canonical event from ``payload``."""
        return parse_canonical_event(self.payload)
