"""Identity, cloud, workload, device and Zero Trust domains."""

from alembic import op
from cyberaudit import domain_expansion_models  # noqa: F401
from cyberaudit.db import Base

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

TABLES = [
    "enterprise_connectors",
    "connector_credentials",
    "connector_scopes",
    "connector_executions",
    "enterprise_change_events",
    "identity_providers",
    "external_identities",
    "external_groups",
    "external_roles",
    "external_permissions",
    "identity_relationships",
    "permission_grants",
    "authentication_postures",
    "directory_objects",
    "entra_objects",
    "saas_posture_objects",
    "cloud_accounts",
    "cloud_resources",
    "cloud_networks",
    "cloud_identities",
    "cloud_roles",
    "cloud_role_assignments",
    "cloud_configuration_snapshots",
    "kubernetes_clusters",
    "kubernetes_objects",
    "container_runtime_hosts",
    "running_containers",
    "endpoint_devices",
    "endpoint_software",
    "mobile_devices",
    "mobile_application_metadata",
    "zero_trust_assessments",
    "zero_trust_dimensions",
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
