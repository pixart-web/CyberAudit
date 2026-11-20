"""Resolve the tenant for a local login without bypassing tenant RLS."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

FUNCTION = "cyberaudit_resolve_local_user_organization(text)"
INITIALIZED_FUNCTION = "cyberaudit_is_initialized()"
ASSOCIATION_TABLES = (
    "attack_path_steps",
    "finding_evidence",
    "refresh_tokens",
    "sbom_components",
    "sbom_dependencies",
    "scope_targets",
)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    connection.execute(sa.text("""
            CREATE OR REPLACE FUNCTION cyberaudit_resolve_local_user_organization(
              requested_email text
            )
            RETURNS uuid
            LANGUAGE sql
            SECURITY DEFINER
            STABLE
            SET search_path = pg_catalog, public
            AS $$
              SELECT users.organization_id::uuid
              FROM public.users
              JOIN public.organizations
                ON organizations.id = users.organization_id
              WHERE lower(users.email) = lower(requested_email)
                AND users.status = 'active'
                AND users.deleted_at IS NULL
                AND organizations.status = 'active'
                AND organizations.deleted_at IS NULL
              LIMIT 1
            $$
            """))
    connection.execute(sa.text(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC"))
    connection.execute(sa.text(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO cyberaudit_runtime"))
    connection.execute(sa.text("""
            CREATE OR REPLACE FUNCTION cyberaudit_is_initialized()
            RETURNS boolean
            LANGUAGE sql
            SECURITY DEFINER
            STABLE
            SET search_path = pg_catalog, public
            AS $$
              SELECT EXISTS (
                SELECT 1
                FROM public.users
                WHERE deleted_at IS NULL
              )
            $$
            """))
    connection.execute(sa.text(f"REVOKE ALL ON FUNCTION {INITIALIZED_FUNCTION} FROM PUBLIC"))
    connection.execute(
        sa.text(f"GRANT EXECUTE ON FUNCTION {INITIALIZED_FUNCTION} TO cyberaudit_runtime")
    )
    preparer = connection.dialect.identifier_preparer
    for table in ASSOCIATION_TABLES:
        quoted = preparer.quote(table)
        connection.execute(
            sa.text(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {quoted} " "TO cyberaudit_runtime"
            )
        )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        preparer = connection.dialect.identifier_preparer
        for table in ASSOCIATION_TABLES:
            quoted = preparer.quote(table)
            connection.execute(
                sa.text(
                    f"REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE {quoted} "
                    "FROM cyberaudit_runtime"
                )
            )
        connection.execute(sa.text(f"DROP FUNCTION IF EXISTS {INITIALIZED_FUNCTION}"))
        connection.execute(sa.text(f"DROP FUNCTION IF EXISTS {FUNCTION}"))
