"""Constrain non-tenant lookup and association tables for the runtime role."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        sa.text("GRANT SELECT ON TABLE roles, permissions, role_permissions TO cyberaudit_runtime")
    )
    connection.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "
            "organizations, user_roles TO cyberaudit_runtime"
        )
    )
    connection.execute(sa.text("ALTER TABLE organizations ENABLE ROW LEVEL SECURITY"))
    connection.execute(
        sa.text(
            "CREATE POLICY cyberaudit_tenant_isolation_organizations ON organizations "
            "AS PERMISSIVE FOR ALL TO cyberaudit_runtime "
            "USING (id::text = NULLIF(current_setting("
            "'app.current_organization_id', true), '')) "
            "WITH CHECK (id::text = NULLIF(current_setting("
            "'app.current_organization_id', true), ''))"
        )
    )
    connection.execute(sa.text("ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY"))
    connection.execute(
        sa.text(
            "CREATE POLICY cyberaudit_tenant_isolation_user_roles ON user_roles "
            "AS PERMISSIVE FOR ALL TO cyberaudit_runtime "
            "USING (EXISTS (SELECT 1 FROM users "
            "WHERE users.id = user_roles.user_id)) "
            "WITH CHECK (EXISTS (SELECT 1 FROM users "
            "WHERE users.id = user_roles.user_id))"
        )
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        sa.text("DROP POLICY IF EXISTS cyberaudit_tenant_isolation_user_roles ON user_roles")
    )
    connection.execute(sa.text("ALTER TABLE user_roles DISABLE ROW LEVEL SECURITY"))
    connection.execute(
        sa.text("DROP POLICY IF EXISTS cyberaudit_tenant_isolation_organizations ON organizations")
    )
    connection.execute(sa.text("ALTER TABLE organizations DISABLE ROW LEVEL SECURITY"))
