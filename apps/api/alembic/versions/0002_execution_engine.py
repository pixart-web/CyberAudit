"""Phase 2 execution engine."""

from alembic import op
from cyberaudit import models  # noqa: F401
from cyberaudit.db import Base

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    for table_name in [
        "findings",
        "raw_results",
        "approvals",
        "tool_adapter_definitions",
        "job_events",
        "scan_jobs",
        "scan_profiles",
    ]:
        op.drop_table(table_name)
