"""Allow evidence uploaded manually (no scan job).

Relaxes ``evidence.job_id`` to NULLable. Purely additive: existing rows and
RLS policies are untouched; downgrade refuses to run if manual evidence exists.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("evidence", "job_id", existing_type=sa.String(length=36), nullable=True)


def downgrade() -> None:
    connection = op.get_bind()
    orphaned = connection.execute(
        sa.text("SELECT count(*) FROM evidence WHERE job_id IS NULL")
    ).scalar()
    if orphaned:
        raise RuntimeError(
            f"{orphaned} manually uploaded evidence rows have no job; refusing to downgrade"
        )
    op.alter_column("evidence", "job_id", existing_type=sa.String(length=36), nullable=False)
