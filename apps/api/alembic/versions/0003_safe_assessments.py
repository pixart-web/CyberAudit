"""Phase 3 safe assessments, evidence, imports and retests."""

import sqlalchemy as sa

from alembic import op
from cyberaudit import models  # noqa: F401
from cyberaudit.db import Base

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


FINDING_COLUMNS = [
    sa.Column("recommendation_type", sa.String(60), nullable=False, server_default="configuration"),
    sa.Column("remediation_effort", sa.String(30), nullable=False, server_default="low"),
    sa.Column("remediation_priority", sa.String(30), nullable=False, server_default="normal"),
    sa.Column("standards", sa.JSON(), nullable=False, server_default="[]"),
    sa.Column("references", sa.JSON(), nullable=False, server_default="[]"),
    sa.Column("observed_value", sa.Text(), nullable=True),
    sa.Column("expected_value", sa.Text(), nullable=True),
    sa.Column("location", sa.String(500), nullable=True),
    sa.Column("reproducibility", sa.String(30), nullable=False, server_default="consistent"),
    sa.Column("imported", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("simulated", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("verification_status", sa.String(30), nullable=False, server_default="unverified"),
]


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("findings")}
    for column in FINDING_COLUMNS:
        if column.name not in existing:
            op.add_column("findings", column)
    table_names = [
        "evidence",
        "retests",
        "asset_observations",
        "asset_suggestions",
        "external_imports",
        "finding_evidence",
    ]
    Base.metadata.create_all(
        bind=op.get_bind(), tables=[Base.metadata.tables[name] for name in table_names]
    )


def downgrade() -> None:
    for table_name in [
        "finding_evidence",
        "external_imports",
        "asset_suggestions",
        "asset_observations",
        "retests",
        "evidence",
    ]:
        op.drop_table(table_name)
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("findings")}
    for column in reversed(FINDING_COLUMNS):
        if column.name in existing:
            op.drop_column("findings", column.name)
