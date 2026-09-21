"""Phase 7 SOC, detection and incident response."""

from alembic import op
from cyberaudit import enterprise_models  # noqa: F401
from cyberaudit.db import Base

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

TABLES = [
    "security_events",
    "detection_rules",
    "detection_alerts",
    "threat_intel_feeds",
    "threat_indicators",
    "incidents",
    "case_records",
    "incident_timeline_entries",
    "threat_hunts",
    "response_playbooks",
    "security_data_objects",
    "purple_team_exercises",
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
