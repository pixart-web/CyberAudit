"""Phase 4 Cyber Asset Graph, exposure and risk domain."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from cyberaudit import phase4_models  # noqa: F401
from cyberaudit.db import Base

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


ASSET_COLUMNS = [
    sa.Column("environment_id", sa.String(36), nullable=True),
    sa.Column("network_zone_id", sa.String(36), nullable=True),
    sa.Column("parent_asset_id", sa.String(36), nullable=True),
    sa.Column("subtype", sa.String(80), nullable=True),
    sa.Column("fqdn", sa.String(255), nullable=True),
    sa.Column("primary_ip", sa.String(45), nullable=True),
    sa.Column("mac_address", sa.String(32), nullable=True),
    sa.Column("manufacturer", sa.String(160), nullable=True),
    sa.Column("model", sa.String(160), nullable=True),
    sa.Column("serial_number", sa.String(160), nullable=True),
    sa.Column("operating_system_version", sa.String(120), nullable=True),
    sa.Column("kernel_version", sa.String(120), nullable=True),
    sa.Column("architecture", sa.String(80), nullable=True),
    sa.Column("ownership", sa.String(40), nullable=False, server_default="unknown"),
    sa.Column("lifecycle_status", sa.String(40), nullable=False, server_default="active"),
    sa.Column("internet_exposed", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("externally_managed", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("managed", sa.Boolean(), nullable=False, server_default=sa.true()),
    sa.Column("agent_installed", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("business_criticality", sa.String(30), nullable=False, server_default="medium"),
    sa.Column("data_classification", sa.String(40), nullable=False, server_default="internal"),
    sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
    sa.Column("exposure_score", sa.Float(), nullable=False, server_default="0"),
    sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
    sa.Column("source", sa.String(120), nullable=False, server_default="manual"),
    sa.Column("last_assessed_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
    sa.Column("custom_fields", sa.JSON(), nullable=False, server_default="{}"),
]

PHASE4_TABLES = [
    "environments",
    "discovery_policies",
    "network_zones",
    "networks",
    "ip_addresses",
    "services",
    "software_products",
    "software_instances",
    "vulnerabilities",
    "vulnerability_matches",
    "asset_relationships",
    "asset_changes",
    "tool_execution_manifests",
    "vulnerability_feeds",
    "vulnerability_feed_syncs",
    "exposure_scores",
    "attack_paths",
    "attack_path_steps",
    "risk_reduction_scenarios",
    "assessment_coverage",
    "assessment_schedules",
    "notifications",
]


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing_columns = {column["name"] for column in inspector.get_columns("assets")}
    for column in ASSET_COLUMNS:
        if column.name not in existing_columns:
            op.add_column("assets", column)
    Base.metadata.create_all(
        bind=op.get_bind(),
        tables=[Base.metadata.tables[name] for name in PHASE4_TABLES],
        checkfirst=True,
    )
    inspector = sa.inspect(op.get_bind())
    foreign_keys = {item.get("name") for item in inspector.get_foreign_keys("assets")}
    if "fk_assets_environment_id" not in foreign_keys:
        op.create_foreign_key(
            "fk_assets_environment_id", "assets", "environments", ["environment_id"], ["id"]
        )
    if "fk_assets_network_zone_id" not in foreign_keys:
        op.create_foreign_key(
            "fk_assets_network_zone_id", "assets", "network_zones", ["network_zone_id"], ["id"]
        )
    if "fk_assets_parent_asset_id" not in foreign_keys:
        op.create_foreign_key(
            "fk_assets_parent_asset_id", "assets", "assets", ["parent_asset_id"], ["id"]
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    foreign_keys = {item.get("name") for item in inspector.get_foreign_keys("assets")}
    for name in [
        "fk_assets_parent_asset_id",
        "fk_assets_network_zone_id",
        "fk_assets_environment_id",
    ]:
        if name in foreign_keys:
            op.drop_constraint(name, "assets", type_="foreignkey")
    for table_name in reversed(PHASE4_TABLES):
        if table_name in sa.inspect(op.get_bind()).get_table_names():
            op.drop_table(table_name)
    existing_columns = {
        column["name"] for column in sa.inspect(op.get_bind()).get_columns("assets")
    }
    for column in reversed(ASSET_COLUMNS):
        if column.name in existing_columns:
            op.drop_column("assets", column.name)
