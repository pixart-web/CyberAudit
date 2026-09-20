"""Phase 8 governance, risk and compliance."""

from alembic import op
from cyberaudit import enterprise_models  # noqa: F401
from cyberaudit.db import Base

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

TABLES = [
    "control_frameworks",
    "unified_controls",
    "framework_control_mappings",
    "governance_policies",
    "enterprise_risks",
    "risk_treatment_plans",
    "control_assessments",
    "grc_evidence_links",
    "grc_exceptions",
]


def upgrade() -> None:
    Base.metadata.create_all(
        bind=op.get_bind(),
        tables=[Base.metadata.tables[name] for name in TABLES],
        checkfirst=True,
    )


def downgrade() -> None:
    for table in reversed(TABLES):
        op.drop_table(table)
