"""Product hardening and enterprise readiness records."""

from alembic import op
from cyberaudit import hardening_models  # noqa: F401
from cyberaudit.db import Base

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

TABLES = [
    "authentication_providers",
    "external_group_role_mappings",
    "user_sessions",
    "mfa_factors",
    "recovery_codes",
    "feature_flags",
    "license_records",
    "retention_policies",
    "stored_objects",
    "backup_records",
    "restore_records",
    "telemetry_preferences",
    "service_level_objectives",
]


def upgrade() -> None:
    Base.metadata.create_all(
        bind=op.get_bind(),
        tables=[Base.metadata.tables[name] for name in TABLES],
        checkfirst=True,
    )


def downgrade() -> None:
    for table in reversed(TABLES):
        op.drop_table(table)
