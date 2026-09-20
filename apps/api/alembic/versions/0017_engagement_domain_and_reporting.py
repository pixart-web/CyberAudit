"""Phase 10.3.6 engagement domain completion and reporting."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from cyberaudit import engagement_models  # noqa: F401
from cyberaudit.db import Base

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

TABLES = [
    "engagement_notes",
    "engagement_timeline_entries",
    "reports",
    "report_sections",
]

# Direct tenant-isolation policy: these tables carry organization_id.
TENANT_TABLES = ("engagement_notes", "engagement_timeline_entries", "reports")

# Association policy: report_sections has no organization_id of its own,
# so isolation is enforced transitively through its parent report.
ASSOCIATION_POLICIES = {
    "report_sections": (
        "EXISTS (SELECT 1 FROM reports parent WHERE parent.id = report_sections.report_id)"
    ),
}


def _enable_direct_rls(connection: sa.Connection, table: str) -> None:
    preparer = connection.dialect.identifier_preparer
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


def _enable_association_rls(connection: sa.Connection, table: str, predicate: str) -> None:
    preparer = connection.dialect.identifier_preparer
    quoted = preparer.quote(table)
    policy = preparer.quote(f"cyberaudit_tenant_isolation_{table}"[:63])
    connection.execute(sa.text(f"ALTER TABLE {quoted} ENABLE ROW LEVEL SECURITY"))
    connection.execute(sa.text(f"DROP POLICY IF EXISTS {policy} ON {quoted}"))
    connection.execute(
        sa.text(
            f"CREATE POLICY {policy} ON {quoted} "
            f"AS PERMISSIVE FOR ALL TO cyberaudit_runtime "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )
    )
    connection.execute(
        sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {quoted} TO cyberaudit_runtime")
    )


def upgrade() -> None:
    connection = op.get_bind()
    Base.metadata.create_all(
        bind=connection,
        tables=[Base.metadata.tables[name] for name in TABLES],
        checkfirst=True,
    )
    if connection.dialect.name != "postgresql":
        return
    for table in TENANT_TABLES:
        _enable_direct_rls(connection, table)
    for table, predicate in ASSOCIATION_POLICIES.items():
        _enable_association_rls(connection, table, predicate)


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        preparer = connection.dialect.identifier_preparer
        for table in (*TENANT_TABLES, *ASSOCIATION_POLICIES):
            quoted = preparer.quote(table)
            policy = preparer.quote(f"cyberaudit_tenant_isolation_{table}"[:63])
            connection.execute(sa.text(f"DROP POLICY IF EXISTS {policy} ON {quoted}"))
            connection.execute(sa.text(f"ALTER TABLE {quoted} DISABLE ROW LEVEL SECURITY"))
    for table in reversed(TABLES):
        op.drop_table(table)
