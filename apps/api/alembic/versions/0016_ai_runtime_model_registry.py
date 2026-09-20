"""Phase 10.3 sovereign AI runtime: local model registry."""

from alembic import op
from cyberaudit import ai_runtime_models  # noqa: F401
from cyberaudit.db import Base

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

TABLES = ["ai_model_manifests"]


def upgrade() -> None:
    Base.metadata.create_all(
        bind=op.get_bind(),
        tables=[Base.metadata.tables[name] for name in TABLES],
        checkfirst=True,
    )


def downgrade() -> None:
    for table in reversed(TABLES):
        op.drop_table(table)
