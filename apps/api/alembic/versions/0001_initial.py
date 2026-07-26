"""Initial CyberAudit schema."""

from alembic import op
from cyberaudit import models  # noqa: F401
from cyberaudit.db import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
