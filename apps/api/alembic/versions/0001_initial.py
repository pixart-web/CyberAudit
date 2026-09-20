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
    table_names = [
        "organizations",
        "users",
        "roles",
        "permissions",
        "user_roles",
        "role_permissions",
        "clients",
        "engagements",
        "authorization_documents",
        "scopes",
        "scope_targets",
        "assets",
        "audit_logs",
        "refresh_tokens",
    ]
    Base.metadata.create_all(bind=bind, tables=[Base.metadata.tables[name] for name in table_names])


def downgrade() -> None:
    bind = op.get_bind()
    table_names = [
        "refresh_tokens",
        "audit_logs",
        "assets",
        "scope_targets",
        "scopes",
        "authorization_documents",
        "engagements",
        "clients",
        "role_permissions",
        "user_roles",
        "permissions",
        "roles",
        "users",
        "organizations",
    ]
    Base.metadata.drop_all(bind=bind, tables=[Base.metadata.tables[name] for name in table_names])
