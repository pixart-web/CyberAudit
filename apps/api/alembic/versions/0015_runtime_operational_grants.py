"""Grant bounded writes to system-owned operational registries."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        sa.text("GRANT UPDATE ON TABLE tool_adapter_definitions TO cyberaudit_runtime")
    )
    connection.execute(
        sa.text("GRANT INSERT, UPDATE ON TABLE software_products TO cyberaudit_runtime")
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        sa.text("REVOKE UPDATE ON TABLE tool_adapter_definitions FROM cyberaudit_runtime")
    )
    connection.execute(
        sa.text("REVOKE INSERT, UPDATE ON TABLE software_products FROM cyberaudit_runtime")
    )
