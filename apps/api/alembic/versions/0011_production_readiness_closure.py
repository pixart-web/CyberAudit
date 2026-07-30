"""WebAuthn, universal DLQ, readiness evidence and tenant RLS."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from cyberaudit import (  # noqa: F401
    domain_expansion_models,
    enterprise_models,
    hardening_models,
    models,
    phase4_models,
    phase5_models,
)
from cyberaudit.db import Base

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

NEW_TABLES = [
    "dead_letter_messages",
    "production_readiness_evidence",
    "production_readiness_approvals",
]


def _tenant_tables(connection: sa.Connection) -> list[str]:
    inspector = sa.inspect(connection)
    result: list[str] = []
    for table in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns(table)}
        if "organization_id" in columns:
            result.append(table)
    return result


def _enable_postgresql_rls(connection: sa.Connection) -> None:
    if connection.dialect.name != "postgresql":
        return
    connection.execute(sa.text("""
            DO $$
            BEGIN
              IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cyberaudit_runtime') THEN
                CREATE ROLE cyberaudit_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                  NOINHERIT NOBYPASSRLS;
              END IF;
            END
            $$;
            """))
    connection.execute(sa.text("GRANT USAGE ON SCHEMA public TO cyberaudit_runtime"))
    connection.execute(sa.text("GRANT cyberaudit_runtime TO CURRENT_USER"))
    preparer = connection.dialect.identifier_preparer
    for table in _tenant_tables(connection):
        quoted = preparer.quote(table)
        policy = preparer.quote(f"cyberaudit_tenant_isolation_{table}"[:63])
        connection.execute(sa.text(f"ALTER TABLE {quoted} ENABLE ROW LEVEL SECURITY"))
        connection.execute(sa.text(f"DROP POLICY IF EXISTS {policy} ON {quoted}"))
        connection.execute(sa.text(f"""
                CREATE POLICY {policy} ON {quoted}
                AS PERMISSIVE FOR ALL TO cyberaudit_runtime
                USING (
                  organization_id::text =
                  NULLIF(current_setting('app.current_organization_id', true), '')
                )
                WITH CHECK (
                  organization_id::text =
                  NULLIF(current_setting('app.current_organization_id', true), '')
                )
                """))
        connection.execute(
            sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {quoted} TO cyberaudit_runtime")
        )
    connection.execute(
        sa.text("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cyberaudit_runtime")
    )


def upgrade() -> None:
    connection = op.get_bind()
    Base.metadata.create_all(
        bind=connection,
        tables=[Base.metadata.tables[name] for name in NEW_TABLES],
        checkfirst=True,
    )
    with op.batch_alter_table("mfa_factors") as batch:
        batch.add_column(sa.Column("transports", sa.JSON(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("aaguid", sa.String(length=80), nullable=True))
        batch.add_column(sa.Column("authenticator_attachment", sa.String(length=30), nullable=True))
        batch.add_column(
            sa.Column("discoverable", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(
            sa.Column("backup_eligible", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(
            sa.Column("backup_state", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("revoked_by", sa.String(length=36), nullable=True))
        batch.create_foreign_key(
            "fk_mfa_factors_revoked_by_users",
            "users",
            ["revoked_by"],
            ["id"],
        )
    _enable_postgresql_rls(connection)


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        preparer = connection.dialect.identifier_preparer
        for table in _tenant_tables(connection):
            if table in NEW_TABLES:
                continue
            quoted = preparer.quote(table)
            policy = preparer.quote(f"cyberaudit_tenant_isolation_{table}"[:63])
            connection.execute(sa.text(f"DROP POLICY IF EXISTS {policy} ON {quoted}"))
            connection.execute(sa.text(f"ALTER TABLE {quoted} DISABLE ROW LEVEL SECURITY"))
    with op.batch_alter_table("mfa_factors") as batch:
        batch.drop_constraint("fk_mfa_factors_revoked_by_users", type_="foreignkey")
        for column in (
            "revoked_by",
            "revoked_at",
            "backup_state",
            "backup_eligible",
            "discoverable",
            "authenticator_attachment",
            "aaguid",
            "transports",
        ):
            batch.drop_column(column)
    for table in reversed(NEW_TABLES):
        op.drop_table(table)
