"""enable row level security on alembic_version

Revision ID: 5b8e2c4f1a93
Revises: 23e849fe26bd
Create Date: 2026-09-26 19:00:00

Alembic creates ``adis.alembic_version`` itself, outside the first revision. Like the ADIS
tables it now has row-level security without policies, so every table in the ``adis``
schema denies other roles by default (Supabase's security advisor flags any table without
it). Migrations are unaffected: they run as the table owner, which RLS does not restrict.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "5b8e2c4f1a93"
down_revision: str | Sequence[str] | None = "23e849fe26bd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply this revision."""
    op.execute(sa.text("ALTER TABLE adis.alembic_version ENABLE ROW LEVEL SECURITY"))


def downgrade() -> None:
    """Revert this revision."""
    op.execute(sa.text("ALTER TABLE adis.alembic_version DISABLE ROW LEVEL SECURITY"))
