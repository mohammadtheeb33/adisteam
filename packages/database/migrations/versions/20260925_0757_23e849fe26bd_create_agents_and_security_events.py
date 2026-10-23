"""create agents and security events

Revision ID: 23e849fe26bd
Revises:
Create Date: 2026-09-25 07:57:24.591128

First ADIS tables. Values are written out literally (no application imports) so this
revision keeps producing the same schema when the models evolve.

Row-level security is enabled without policies: the owning role used by ADIS services is
unaffected, while any other role (e.g. Supabase ``anon``/``authenticated``, should the
``adis`` schema ever be exposed) is denied by default.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "23e849fe26bd"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "adis"
TIMESTAMPTZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    """Apply this revision."""
    op.create_table(
        "agents",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("os_type", sa.String(32), nullable=False),
        sa.Column("agent_version", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), server_default="pending", nullable=False),
        sa.Column("first_seen", TIMESTAMPTZ, nullable=True),
        sa.Column("last_seen", TIMESTAMPTZ, nullable=True),
        sa.Column("created_at", TIMESTAMPTZ, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", TIMESTAMPTZ, server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agents")),
        sa.CheckConstraint(
            "first_seen IS NULL OR last_seen IS NULL OR last_seen >= first_seen",
            name=op.f("ck_agents_seen_order"),
        ),
        sa.CheckConstraint(
            "os_type IN ('linux', 'windows', 'macos', 'other')", name=op.f("ck_agents_os_type")
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'active', 'inactive', 'decommissioned')",
            name=op.f("ck_agents_status"),
        ),
        schema=SCHEMA,
    )

    op.create_table(
        "security_events",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("timestamp", TIMESTAMPTZ, nullable=False),
        sa.Column("received_at", TIMESTAMPTZ, nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("source_type", sa.String(64), nullable=False),
        sa.Column("source_name", sa.String(256), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("host_id", sa.String(255), nullable=True),
        sa.Column("severity_hint", sa.String(16), nullable=True),
        sa.Column("src_ip", postgresql.INET(), nullable=True),
        sa.Column("dst_ip", postgresql.INET(), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(16), nullable=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", TIMESTAMPTZ, server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_events")),
        sa.UniqueConstraint("event_id", name=op.f("uq_security_events_event_id")),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            [f"{SCHEMA}.agents.id"],
            name=op.f("fk_security_events_agent_id_agents"),
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "src_port IS NULL OR src_port BETWEEN 0 AND 65535",
            name=op.f("ck_security_events_src_port_range"),
        ),
        sa.CheckConstraint(
            "dst_port IS NULL OR dst_port BETWEEN 0 AND 65535",
            name=op.f("ck_security_events_dst_port_range"),
        ),
        schema=SCHEMA,
    )

    _index("ix_security_events_timestamp", ["timestamp"])
    _index("ix_security_events_received_at_brin", ["received_at"], using="brin")
    _index("ix_security_events_event_type_timestamp", ["event_type", "timestamp"])
    _index(
        "ix_security_events_host_id_timestamp",
        ["host_id", "timestamp"],
        where="host_id IS NOT NULL",
    )
    _index(
        "ix_security_events_agent_id_timestamp",
        ["agent_id", "timestamp"],
        where="agent_id IS NOT NULL",
    )
    _index("ix_security_events_src_ip", ["src_ip"], where="src_ip IS NOT NULL")
    _index("ix_security_events_dst_ip", ["dst_ip"], where="dst_ip IS NOT NULL")

    for table in ("agents", "security_events"):
        op.execute(sa.text(f"ALTER TABLE {SCHEMA}.{table} ENABLE ROW LEVEL SECURITY"))


def downgrade() -> None:
    """Revert this revision."""
    op.drop_table("security_events", schema=SCHEMA)
    op.drop_table("agents", schema=SCHEMA)


def _index(
    name: str, columns: list[str], *, using: str | None = None, where: str | None = None
) -> None:
    op.create_index(
        op.f(name),
        "security_events",
        columns,
        schema=SCHEMA,
        postgresql_using=using,
        postgresql_where=None if where is None else sa.text(where),
    )
