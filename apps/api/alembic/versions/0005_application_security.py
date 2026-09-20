"""Phase 5 application security and software supply chain."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from cyberaudit import phase5_models  # noqa: F401
from cyberaudit.db import Base

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

PHASE5_TABLES = [
    "application_assets",
    "api_assets",
    "api_endpoints",
    "code_repositories",
    "sboms",
    "sbom_components",
    "sbom_dependencies",
    "software_releases",
    "api_specification_imports",
    "secret_observations",
    "assessment_credentials",
    "appsec_scores",
    "security_gate_policies",
    "security_gate_evaluations",
    "appsec_exceptions",
    "appsec_remediations",
    "component_reachability",
]

FINDING_COLUMNS = [
    sa.Column("application_id", sa.String(36), nullable=True),
    sa.Column("api_id", sa.String(36), nullable=True),
    sa.Column("endpoint_id", sa.String(36), nullable=True),
    sa.Column("repository_id", sa.String(36), nullable=True),
    sa.Column("release_id", sa.String(36), nullable=True),
    sa.Column("component_id", sa.String(36), nullable=True),
]


def upgrade() -> None:
    Base.metadata.create_all(
        bind=op.get_bind(),
        tables=[Base.metadata.tables[name] for name in PHASE5_TABLES],
        checkfirst=True,
    )
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("findings")}
    for column in FINDING_COLUMNS:
        if column.name not in existing:
            op.add_column("findings", column)
    inspector = sa.inspect(op.get_bind())
    foreign_keys = {item.get("name") for item in inspector.get_foreign_keys("findings")}
    targets = {
        "application_id": "application_assets",
        "api_id": "api_assets",
        "endpoint_id": "api_endpoints",
        "repository_id": "code_repositories",
        "release_id": "software_releases",
        "component_id": "sbom_components",
    }
    for column, table in targets.items():
        name = f"fk_findings_{column}"
        if name not in foreign_keys:
            op.create_foreign_key(name, "findings", table, [column], ["id"])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    foreign_keys = {item.get("name") for item in inspector.get_foreign_keys("findings")}
    for column in reversed([item.name for item in FINDING_COLUMNS]):
        name = f"fk_findings_{column}"
        if name in foreign_keys:
            op.drop_constraint(name, "findings", type_="foreignkey")
        if column in {item["name"] for item in sa.inspect(op.get_bind()).get_columns("findings")}:
            op.drop_column("findings", column)
    for table in reversed(PHASE5_TABLES):
        if table in sa.inspect(op.get_bind()).get_table_names():
            op.drop_table(table)
