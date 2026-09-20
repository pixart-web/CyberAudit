"""Phase 9 knowledge graph and advisory AI."""

from alembic import op
from cyberaudit import enterprise_models  # noqa: F401
from cyberaudit.db import Base

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

TABLES = [
    "knowledge_nodes",
    "knowledge_edges",
    "ai_assistant_requests",
    "ai_provider_policies",
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
