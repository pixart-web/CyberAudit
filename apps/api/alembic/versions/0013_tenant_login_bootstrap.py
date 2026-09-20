"""Add the minimal tenant bootstrap function for OIDC login."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    connection.execute(sa.text("""
            CREATE OR REPLACE FUNCTION cyberaudit_resolve_active_organization(requested_slug text)
            RETURNS uuid
            LANGUAGE sql
            SECURITY DEFINER
            STABLE
            SET search_path = pg_catalog, public
            AS $$
              SELECT id::uuid
              FROM public.organizations
              WHERE slug = requested_slug
                AND status = 'active'
                AND deleted_at IS NULL
              LIMIT 1
            $$
            """))
    connection.execute(
        sa.text(
            "REVOKE ALL ON FUNCTION " "cyberaudit_resolve_active_organization(text) FROM PUBLIC"
        )
    )
    connection.execute(
        sa.text(
            "GRANT EXECUTE ON FUNCTION "
            "cyberaudit_resolve_active_organization(text) TO cyberaudit_runtime"
        )
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text("DROP FUNCTION IF EXISTS cyberaudit_resolve_active_organization(text)")
        )
