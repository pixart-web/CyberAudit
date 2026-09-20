"""Apply transitive RLS to tenant-owned association tables."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

GLOBAL_READ_TABLES = (
    "alembic_version",
    "permissions",
    "role_permissions",
    "roles",
    "software_products",
    "tool_adapter_definitions",
    "tool_execution_manifests",
    "vulnerabilities",
    "vulnerability_feeds",
)

ASSOCIATION_POLICIES = {
    "attack_path_steps": (
        "EXISTS (SELECT 1 FROM attack_paths parent "
        "WHERE parent.id = attack_path_steps.attack_path_id)"
    ),
    "finding_evidence": (
        "EXISTS (SELECT 1 FROM findings parent " "WHERE parent.id = finding_evidence.finding_id)"
    ),
    "refresh_tokens": (
        "EXISTS (SELECT 1 FROM users parent WHERE parent.id = refresh_tokens.user_id)"
    ),
    "sbom_components": (
        "EXISTS (SELECT 1 FROM sboms parent WHERE parent.id = sbom_components.sbom_id)"
    ),
    "sbom_dependencies": (
        "EXISTS (SELECT 1 FROM sboms parent WHERE parent.id = sbom_dependencies.sbom_id)"
    ),
    "scope_targets": (
        "EXISTS (SELECT 1 FROM scopes parent WHERE parent.id = scope_targets.scope_id)"
    ),
}

BOOTSTRAP_RESOURCES = {
    "scan_job": "scan_jobs",
    "connector_execution": "connector_executions",
    "security_event": "security_events",
}


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    preparer = connection.dialect.identifier_preparer
    for table in GLOBAL_READ_TABLES:
        quoted = preparer.quote(table)
        connection.execute(sa.text(f"GRANT SELECT ON TABLE {quoted} TO cyberaudit_runtime"))
    connection.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "
            "vulnerability_feed_syncs TO cyberaudit_runtime"
        )
    )
    connection.execute(
        sa.text(
            "GRANT INSERT, UPDATE ON TABLE vulnerabilities, "
            "vulnerability_feeds TO cyberaudit_runtime"
        )
    )
    for table, predicate in ASSOCIATION_POLICIES.items():
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
    for resource, table in BOOTSTRAP_RESOURCES.items():
        function = f"cyberaudit_resolve_{resource}_organization"
        connection.execute(
            sa.text(
                f"CREATE OR REPLACE FUNCTION {function}(resource_id text) "  # noqa: S608 -- fixed identifiers
                "RETURNS uuid LANGUAGE sql SECURITY DEFINER STABLE "
                "SET search_path = pg_catalog, public AS $$ "
                f"SELECT organization_id::uuid FROM public.{table} "
                "WHERE id = resource_id LIMIT 1 $$"
            )
        )
        connection.execute(sa.text(f"REVOKE ALL ON FUNCTION {function}(text) FROM PUBLIC"))
        connection.execute(
            sa.text(f"GRANT EXECUTE ON FUNCTION {function}(text) TO cyberaudit_runtime")
        )
        connection.execute(
            sa.text(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE " f"{quoted} TO cyberaudit_runtime"
            )
        )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    preparer = connection.dialect.identifier_preparer
    for table in ASSOCIATION_POLICIES:
        quoted = preparer.quote(table)
        policy = preparer.quote(f"cyberaudit_tenant_isolation_{table}"[:63])
        connection.execute(sa.text(f"DROP POLICY IF EXISTS {policy} ON {quoted}"))
        connection.execute(sa.text(f"ALTER TABLE {quoted} DISABLE ROW LEVEL SECURITY"))
    for resource in BOOTSTRAP_RESOURCES:
        function = f"cyberaudit_resolve_{resource}_organization"
        connection.execute(sa.text(f"DROP FUNCTION IF EXISTS {function}(text)"))
