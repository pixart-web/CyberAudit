"""Identity, cloud, workload and device posture domain models.

These tables contain inventory and posture only. Secrets, commands and external
write operations are intentionally absent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from cyberaudit.db import Base
from cyberaudit.enterprise_models import EnterpriseMixin, utcnow


class EnterpriseConnector(Base, EnterpriseMixin):
    __tablename__ = "enterprise_connectors"
    __table_args__ = (
        UniqueConstraint("organization_id", "name"),
        Index(
            "ix_enterprise_connectors_org_type_status",
            "organization_id",
            "connector_type",
            "status",
        ),
    )
    connector_type: Mapped[str] = mapped_column(String(80), index=True)
    provider: Mapped[str] = mapped_column(String(80), index=True)
    name: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text, default="")
    environment_id: Mapped[str | None] = mapped_column(ForeignKey("environments.id"))
    credential_id: Mapped[str | None] = mapped_column(String(36))
    requested_permissions: Mapped[list[str]] = mapped_column(JSON, default=list)
    detected_permissions: Mapped[list[str]] = mapped_column(JSON, default=list)
    read_only: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(30), default="draft", index=True)
    version: Mapped[str] = mapped_column(String(40), default="1.0.0")
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    retention_days: Mapped[int] = mapped_column(Integer, default=90)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sync_cursor: Mapped[str | None] = mapped_column(String(1000))
    rate_limit_state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    health_status: Mapped[str] = mapped_column(String(30), default="unknown")
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(100))
    last_error_message: Mapped[str | None] = mapped_column(String(500))
    connector_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ConnectorCredential(Base, EnterpriseMixin):
    __tablename__ = "connector_credentials"
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    credential_type: Mapped[str] = mapped_column(String(60))
    secret_reference: Mapped[str] = mapped_column(String(500))
    reference_fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), default="active")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class ConnectorScope(Base, EnterpriseMixin):
    __tablename__ = "connector_scopes"
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    scope_type: Mapped[str] = mapped_column(String(60), index=True)
    scope_value: Mapped[str] = mapped_column(String(500))
    normalized_value: Mapped[str] = mapped_column(String(500))
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ConnectorExecution(Base, EnterpriseMixin):
    __tablename__ = "connector_executions"
    __table_args__ = (
        UniqueConstraint("organization_id", "idempotency_key"),
        Index(
            "ix_connector_exec_org_connector_status", "organization_id", "connector_id", "status"
        ),
    )
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    execution_type: Mapped[str] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    idempotency_key: Mapped[str] = mapped_column(String(64))
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    worker_id: Mapped[str | None] = mapped_column(String(180))
    cursor_before: Mapped[str | None] = mapped_column(String(1000))
    cursor_after: Mapped[str | None] = mapped_column(String(1000))
    records_processed: Mapped[int] = mapped_column(Integer, default=0)
    records_created: Mapped[int] = mapped_column(Integer, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, default=0)
    records_removed: Mapped[int] = mapped_column(Integer, default=0)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timeout_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(String(500))
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class EnterpriseChangeEvent(Base, EnterpriseMixin):
    __tablename__ = "enterprise_change_events"
    __table_args__ = (
        UniqueConstraint("organization_id", "fingerprint"),
        Index("ix_enterprise_changes_org_domain_seen", "organization_id", "domain", "observed_at"),
    )
    connector_id: Mapped[str | None] = mapped_column(ForeignKey("enterprise_connectors.id"))
    execution_id: Mapped[str | None] = mapped_column(ForeignKey("connector_executions.id"))
    domain: Mapped[str] = mapped_column(String(60), index=True)
    change_type: Mapped[str] = mapped_column(String(100), index=True)
    subject_type: Mapped[str] = mapped_column(String(80), index=True)
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    subject_external_id: Mapped[str] = mapped_column(String(500))
    before_hash: Mapped[str | None] = mapped_column(String(64))
    after_hash: Mapped[str | None] = mapped_column(String(64))
    changed_fields: Mapped[list[str]] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    fingerprint: Mapped[str] = mapped_column(String(64))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    processed: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"))


class IdentityProvider(Base, EnterpriseMixin):
    __tablename__ = "identity_providers"
    __table_args__ = (UniqueConstraint("organization_id", "provider_type", "tenant_identifier"),)
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    provider_type: Mapped[str] = mapped_column(String(60), index=True)
    name: Mapped[str] = mapped_column(String(180))
    tenant_identifier: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(30), default="active")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    provider_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class ExternalIdentity(Base, EnterpriseMixin):
    __tablename__ = "external_identities"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider_id", "external_id"),
        Index("ix_external_identity_org_risk_priv", "organization_id", "risk_score", "privileged"),
        Index("ix_external_identity_org_seen", "organization_id", "last_seen_at"),
    )
    provider_id: Mapped[str] = mapped_column(ForeignKey("identity_providers.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(500), index=True)
    identity_type: Mapped[str] = mapped_column(String(60), index=True)
    username: Mapped[str] = mapped_column(String(320))
    display_name: Mapped[str] = mapped_column(String(300))
    email: Mapped[str | None] = mapped_column(String(320))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    privileged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    guest: Mapped[bool] = mapped_column(Boolean, default=False)
    service_account: Mapped[bool] = mapped_column(Boolean, default=False)
    managed_identity: Mapped[bool] = mapped_column(Boolean, default=False)
    owner: Mapped[str | None] = mapped_column(String(300))
    department: Mapped[str | None] = mapped_column(String(180))
    job_title: Mapped[str | None] = mapped_column(String(180))
    manager_external_id: Mapped[str | None] = mapped_column(String(500))
    created_at_source: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_last_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    mfa_state: Mapped[str] = mapped_column(String(30), default="unknown")
    authentication_methods: Mapped[list[str]] = mapped_column(JSON, default=list)
    risk_state: Mapped[str] = mapped_column(String(30), default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, default=0, index=True)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deleted_at_source: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ExternalGroup(Base, EnterpriseMixin):
    __tablename__ = "external_groups"
    __table_args__ = (UniqueConstraint("organization_id", "provider_id", "external_id"),)
    provider_id: Mapped[str] = mapped_column(ForeignKey("identity_providers.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    group_type: Mapped[str] = mapped_column(String(60), default="security")
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    dynamic: Mapped[bool] = mapped_column(Boolean, default=False)
    mail_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    security_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExternalRole(Base, EnterpriseMixin):
    __tablename__ = "external_roles"
    __table_args__ = (UniqueConstraint("organization_id", "provider_id", "external_id"),)
    provider_id: Mapped[str] = mapped_column(ForeignKey("identity_providers.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(300))
    role_type: Mapped[str] = mapped_column(String(60))
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    built_in: Mapped[bool] = mapped_column(Boolean, default=False)
    assignable_scope: Mapped[str | None] = mapped_column(String(500))
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ExternalPermission(Base, EnterpriseMixin):
    __tablename__ = "external_permissions"
    __table_args__ = (UniqueConstraint("organization_id", "provider_id", "external_id"),)
    provider_id: Mapped[str] = mapped_column(ForeignKey("identity_providers.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(300))
    permission_type: Mapped[str] = mapped_column(String(60))
    resource_type: Mapped[str | None] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(500))
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    wildcard: Mapped[bool] = mapped_column(Boolean, default=False)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class IdentityRelationship(Base, EnterpriseMixin):
    __tablename__ = "identity_relationships"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "relationship_type",
            "source_type",
            "source_id",
            "target_type",
            "target_id",
        ),
        Index("ix_identity_rel_org_source", "organization_id", "source_type", "source_id"),
        Index("ix_identity_rel_org_target", "organization_id", "target_type", "target_id"),
    )
    relationship_type: Mapped[str] = mapped_column(String(80), index=True)
    source_type: Mapped[str] = mapped_column(String(80))
    source_id: Mapped[str] = mapped_column(String(36))
    target_type: Mapped[str] = mapped_column(String(80))
    target_id: Mapped[str] = mapped_column(String(36))
    direct: Mapped[bool] = mapped_column(Boolean, default=True)
    inherited: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    confidence: Mapped[float] = mapped_column(Float, default=1)
    source: Mapped[str] = mapped_column(String(120))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"))


class PermissionGrant(Base, EnterpriseMixin):
    __tablename__ = "permission_grants"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "principal_type", "principal_id", "permission_id", "scope"
        ),
    )
    principal_type: Mapped[str] = mapped_column(String(80))
    principal_id: Mapped[str] = mapped_column(String(36), index=True)
    role_id: Mapped[str | None] = mapped_column(ForeignKey("external_roles.id"))
    permission_id: Mapped[str] = mapped_column(ForeignKey("external_permissions.id"))
    scope: Mapped[str] = mapped_column(String(1000))
    grant_type: Mapped[str] = mapped_column(String(60), default="direct")
    inherited: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    granted_at_source: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"))


class AuthenticationPosture(Base, EnterpriseMixin):
    __tablename__ = "authentication_postures"
    __table_args__ = (UniqueConstraint("organization_id", "identity_id"),)
    identity_id: Mapped[str] = mapped_column(ForeignKey("external_identities.id"), index=True)
    mfa_registered: Mapped[str] = mapped_column(String(30), default="unknown")
    mfa_available: Mapped[str] = mapped_column(String(30), default="unknown")
    mfa_required: Mapped[str] = mapped_column(String(30), default="unknown")
    mfa_enforced: Mapped[str] = mapped_column(String(30), default="unknown")
    mfa_observed: Mapped[str] = mapped_column(String(30), default="unknown")
    passwordless_enabled: Mapped[str] = mapped_column(String(30), default="unknown")
    strong_authentication_available: Mapped[str] = mapped_column(String(30), default="unknown")
    legacy_authentication_allowed: Mapped[str] = mapped_column(String(30), default="unknown")
    conditional_access_covered: Mapped[str] = mapped_column(String(30), default="unknown")
    compliant_device_required: Mapped[str] = mapped_column(String(30), default="unknown")
    managed_device_required: Mapped[str] = mapped_column(String(30), default="unknown")
    sign_in_risk_policy: Mapped[str] = mapped_column(String(30), default="unknown")
    user_risk_policy: Mapped[str] = mapped_column(String(30), default="unknown")
    posture_score: Mapped[float] = mapped_column(Float, default=0)
    confidence: Mapped[float] = mapped_column(Float, default=0)
    unknown_factors: Mapped[list[str]] = mapped_column(JSON, default=list)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"))


class DirectoryObject(Base, EnterpriseMixin):
    __tablename__ = "directory_objects"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider_id", "object_type", "external_id"),
        Index(
            "ix_directory_object_org_type_seen", "organization_id", "object_type", "last_seen_at"
        ),
    )
    provider_id: Mapped[str] = mapped_column(ForeignKey("identity_providers.id"), index=True)
    object_type: Mapped[str] = mapped_column(String(80), index=True)
    external_id: Mapped[str] = mapped_column(String(500))
    parent_external_id: Mapped[str | None] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(30), default="active")
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    owner: Mapped[str | None] = mapped_column(String(300))
    configuration_hash: Mapped[str] = mapped_column(String(64))
    posture: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EntraObject(Base, EnterpriseMixin):
    __tablename__ = "entra_objects"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider_id", "object_type", "external_id"),
    )
    provider_id: Mapped[str] = mapped_column(ForeignKey("identity_providers.id"), index=True)
    object_type: Mapped[str] = mapped_column(String(80), index=True)
    external_id: Mapped[str] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(300))
    owner: Mapped[str | None] = mapped_column(String(300))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    configuration_hash: Mapped[str] = mapped_column(String(64))
    posture: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SaasPostureObject(Base, EnterpriseMixin):
    __tablename__ = "saas_posture_objects"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "connector_id", "service", "object_type", "external_id"
        ),
        Index("ix_saas_posture_org_service_type", "organization_id", "service", "object_type"),
    )
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    service: Mapped[str] = mapped_column(String(60), index=True)
    object_type: Mapped[str] = mapped_column(String(80), index=True)
    external_id: Mapped[str] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(30), default="unknown")
    owner: Mapped[str | None] = mapped_column(String(300))
    posture: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    configuration_hash: Mapped[str] = mapped_column(String(64))
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CloudAccount(Base, EnterpriseMixin):
    __tablename__ = "cloud_accounts"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", "external_id"),
        Index("ix_cloud_account_org_provider_status", "organization_id", "provider", "status"),
    )
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    provider: Mapped[str] = mapped_column(String(30), index=True)
    account_type: Mapped[str] = mapped_column(String(40))
    external_id: Mapped[str] = mapped_column(String(500))
    parent_external_id: Mapped[str | None] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(300))
    environment: Mapped[str] = mapped_column(String(60), default="unknown")
    owner: Mapped[str | None] = mapped_column(String(300))
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(30), default="active")
    risk_score: Mapped[float] = mapped_column(Float, default=0, index=True)
    tags: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CloudResource(Base, EnterpriseMixin):
    __tablename__ = "cloud_resources"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", "external_id"),
        Index(
            "ix_cloud_resource_org_provider_type", "organization_id", "provider", "resource_type"
        ),
        Index(
            "ix_cloud_resource_org_public_risk", "organization_id", "public_exposure", "risk_score"
        ),
        Index("ix_cloud_resource_org_seen", "organization_id", "last_seen_at"),
    )
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("cloud_accounts.id"), index=True)
    provider: Mapped[str] = mapped_column(String(30), index=True)
    external_id: Mapped[str] = mapped_column(String(1000))
    resource_type: Mapped[str] = mapped_column(String(120), index=True)
    name: Mapped[str] = mapped_column(String(500))
    region: Mapped[str | None] = mapped_column(String(100), index=True)
    environment: Mapped[str] = mapped_column(String(60), default="unknown")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    public_exposure: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    managed: Mapped[bool] = mapped_column(Boolean, default=True)
    owner: Mapped[str | None] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(30), default="active")
    risk_score: Mapped[float] = mapped_column(Float, default=0, index=True)
    tags: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    configuration_hash: Mapped[str] = mapped_column(String(64))
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deleted_at_source: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CloudNetwork(Base, EnterpriseMixin):
    __tablename__ = "cloud_networks"
    __table_args__ = (UniqueConstraint("organization_id", "provider", "external_id"),)
    account_id: Mapped[str] = mapped_column(ForeignKey("cloud_accounts.id"), index=True)
    provider: Mapped[str] = mapped_column(String(30), index=True)
    external_id: Mapped[str] = mapped_column(String(1000))
    network_type: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(300))
    region: Mapped[str | None] = mapped_column(String(100))
    cidrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    public_exposure: Mapped[bool] = mapped_column(Boolean, default=False)
    logging_enabled: Mapped[str] = mapped_column(String(30), default="unknown")
    configuration_hash: Mapped[str] = mapped_column(String(64))
    posture: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CloudIdentity(Base, EnterpriseMixin):
    __tablename__ = "cloud_identities"
    __table_args__ = (UniqueConstraint("organization_id", "provider", "external_id"),)
    account_id: Mapped[str] = mapped_column(ForeignKey("cloud_accounts.id"), index=True)
    external_identity_id: Mapped[str | None] = mapped_column(ForeignKey("external_identities.id"))
    provider: Mapped[str] = mapped_column(String(30))
    external_id: Mapped[str] = mapped_column(String(1000))
    identity_type: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(300))
    owner: Mapped[str | None] = mapped_column(String(300))
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    posture: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class CloudRole(Base, EnterpriseMixin):
    __tablename__ = "cloud_roles"
    __table_args__ = (UniqueConstraint("organization_id", "provider", "external_id"),)
    account_id: Mapped[str] = mapped_column(ForeignKey("cloud_accounts.id"), index=True)
    provider: Mapped[str] = mapped_column(String(30))
    external_id: Mapped[str] = mapped_column(String(1000))
    name: Mapped[str] = mapped_column(String(300))
    role_type: Mapped[str] = mapped_column(String(60))
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    actions: Mapped[list[str]] = mapped_column(JSON, default=list)
    wildcard: Mapped[bool] = mapped_column(Boolean, default=False)
    trust_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class CloudRoleAssignment(Base, EnterpriseMixin):
    __tablename__ = "cloud_role_assignments"
    __table_args__ = (
        UniqueConstraint("organization_id", "principal_type", "principal_id", "role_id", "scope"),
    )
    principal_type: Mapped[str] = mapped_column(String(80))
    principal_id: Mapped[str] = mapped_column(String(36), index=True)
    role_id: Mapped[str] = mapped_column(ForeignKey("cloud_roles.id"), index=True)
    scope: Mapped[str] = mapped_column(String(1000))
    assignment_type: Mapped[str] = mapped_column(String(60), default="direct")
    inherited: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"))


class CloudConfigurationSnapshot(Base, EnterpriseMixin):
    __tablename__ = "cloud_configuration_snapshots"
    __table_args__ = (UniqueConstraint("organization_id", "resource_id", "configuration_hash"),)
    resource_id: Mapped[str] = mapped_column(ForeignKey("cloud_resources.id"), index=True)
    configuration_hash: Mapped[str] = mapped_column(String(64))
    sanitized_configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source: Mapped[str] = mapped_column(String(120))
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"))


class KubernetesCluster(Base, EnterpriseMixin):
    __tablename__ = "kubernetes_clusters"
    __table_args__ = (UniqueConstraint("organization_id", "external_id"),)
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    cloud_resource_id: Mapped[str | None] = mapped_column(ForeignKey("cloud_resources.id"))
    external_id: Mapped[str] = mapped_column(String(1000))
    name: Mapped[str] = mapped_column(String(300))
    provider: Mapped[str] = mapped_column(String(60))
    version: Mapped[str | None] = mapped_column(String(80))
    environment: Mapped[str] = mapped_column(String(60), default="unknown")
    public_endpoint: Mapped[bool] = mapped_column(Boolean, default=False)
    audit_logging: Mapped[str] = mapped_column(String(30), default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    posture: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KubernetesObject(Base, EnterpriseMixin):
    __tablename__ = "kubernetes_objects"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "cluster_id", "object_type", "namespace", "external_id"
        ),
        Index("ix_k8s_object_org_cluster_type", "organization_id", "cluster_id", "object_type"),
    )
    cluster_id: Mapped[str] = mapped_column(ForeignKey("kubernetes_clusters.id"), index=True)
    object_type: Mapped[str] = mapped_column(String(80), index=True)
    external_id: Mapped[str] = mapped_column(String(1000))
    namespace: Mapped[str] = mapped_column(String(253), default="")
    name: Mapped[str] = mapped_column(String(300))
    owner_reference: Mapped[str | None] = mapped_column(String(1000))
    labels: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    annotations: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    configuration_hash: Mapped[str] = mapped_column(String(64))
    posture: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    public_exposure: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ContainerRuntimeHost(Base, EnterpriseMixin):
    __tablename__ = "container_runtime_hosts"
    __table_args__ = (UniqueConstraint("organization_id", "connector_id", "external_id"),)
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    endpoint_id: Mapped[str | None] = mapped_column(String(36))
    external_id: Mapped[str] = mapped_column(String(1000))
    hostname: Mapped[str] = mapped_column(String(300))
    runtime_type: Mapped[str] = mapped_column(String(40))
    runtime_version: Mapped[str | None] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(30), default="active")
    posture: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunningContainer(Base, EnterpriseMixin):
    __tablename__ = "running_containers"
    __table_args__ = (UniqueConstraint("organization_id", "runtime_host_id", "external_id"),)
    runtime_host_id: Mapped[str] = mapped_column(
        ForeignKey("container_runtime_hosts.id"), index=True
    )
    external_id: Mapped[str] = mapped_column(String(1000))
    name: Mapped[str] = mapped_column(String(300))
    image_reference: Mapped[str] = mapped_column(String(1000))
    image_digest: Mapped[str | None] = mapped_column(String(300))
    owner: Mapped[str | None] = mapped_column(String(300))
    environment: Mapped[str] = mapped_column(String(60), default="unknown")
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    run_as_root: Mapped[str] = mapped_column(String(30), default="unknown")
    network_mode: Mapped[str] = mapped_column(String(80), default="unknown")
    mounts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    environment_keys: Mapped[list[str]] = mapped_column(JSON, default=list)
    security_profile: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EndpointDevice(Base, EnterpriseMixin):
    __tablename__ = "endpoint_devices"
    __table_args__ = (
        UniqueConstraint("organization_id", "connector_id", "external_id"),
        Index(
            "ix_endpoint_org_compliant_seen", "organization_id", "compliance_state", "last_seen_at"
        ),
    )
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(1000))
    hostname: Mapped[str] = mapped_column(String(300))
    platform: Mapped[str] = mapped_column(String(30), index=True)
    os_name: Mapped[str] = mapped_column(String(120))
    os_version: Mapped[str] = mapped_column(String(120))
    owner: Mapped[str | None] = mapped_column(String(300))
    external_identity_id: Mapped[str | None] = mapped_column(ForeignKey("external_identities.id"))
    managed: Mapped[str] = mapped_column(String(30), default="unknown")
    compliance_state: Mapped[str] = mapped_column(String(30), default="unknown", index=True)
    encryption_state: Mapped[str] = mapped_column(String(30), default="unknown")
    firewall_state: Mapped[str] = mapped_column(String(30), default="unknown")
    antimalware_state: Mapped[str] = mapped_column(String(30), default="unknown")
    edr_state: Mapped[str] = mapped_column(String(30), default="unknown")
    patch_state: Mapped[str] = mapped_column(String(30), default="unknown")
    local_admin_observed: Mapped[str] = mapped_column(String(30), default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    posture: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EndpointSoftware(Base, EnterpriseMixin):
    __tablename__ = "endpoint_software"
    __table_args__ = (UniqueConstraint("organization_id", "endpoint_id", "name", "version"),)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoint_devices.id"), index=True)
    name: Mapped[str] = mapped_column(String(300))
    version: Mapped[str] = mapped_column(String(160))
    publisher: Mapped[str | None] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(30), default="observed")
    prohibited: Mapped[str] = mapped_column(String(30), default="unknown")
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class MobileDevice(Base, EnterpriseMixin):
    __tablename__ = "mobile_devices"
    __table_args__ = (
        UniqueConstraint("organization_id", "connector_id", "external_id"),
        Index(
            "ix_mobile_org_compliant_seen", "organization_id", "compliance_state", "last_seen_at"
        ),
    )
    connector_id: Mapped[str] = mapped_column(ForeignKey("enterprise_connectors.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(1000))
    name: Mapped[str] = mapped_column(String(300))
    platform: Mapped[str] = mapped_column(String(30), index=True)
    os_version: Mapped[str] = mapped_column(String(120))
    owner: Mapped[str | None] = mapped_column(String(300))
    external_identity_id: Mapped[str | None] = mapped_column(ForeignKey("external_identities.id"))
    managed: Mapped[str] = mapped_column(String(30), default="unknown")
    compliance_state: Mapped[str] = mapped_column(String(30), default="unknown", index=True)
    encryption_state: Mapped[str] = mapped_column(String(30), default="unknown")
    integrity_state: Mapped[str] = mapped_column(String(30), default="unknown")
    screen_lock_state: Mapped[str] = mapped_column(String(30), default="unknown")
    unknown_sources_allowed: Mapped[str] = mapped_column(String(30), default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    posture: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MobileApplicationMetadata(Base, EnterpriseMixin):
    __tablename__ = "mobile_application_metadata"
    __table_args__ = (UniqueConstraint("organization_id", "device_id", "bundle_identifier"),)
    device_id: Mapped[str] = mapped_column(ForeignKey("mobile_devices.id"), index=True)
    bundle_identifier: Mapped[str] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(300))
    version: Mapped[str | None] = mapped_column(String(160))
    managed: Mapped[str] = mapped_column(String(30), default="unknown")
    prohibited: Mapped[str] = mapped_column(String(30), default="unknown")


class ZeroTrustAssessment(Base, EnterpriseMixin):
    __tablename__ = "zero_trust_assessments"
    __table_args__ = (
        Index("ix_zero_trust_org_subject_time", "organization_id", "subject_type", "evaluated_at"),
    )
    subject_type: Mapped[str] = mapped_column(String(80), index=True)
    subject_id: Mapped[str | None] = mapped_column(String(36), index=True)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    score: Mapped[float] = mapped_column(Float, default=0, index=True)
    status: Mapped[str] = mapped_column(String(40), default="insufficient_evidence")
    confidence: Mapped[float] = mapped_column(Float, default=0)
    factors: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    unknown_factors: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommendations: Mapped[list[str]] = mapped_column(JSON, default=list)
    control_mappings: Mapped[list[str]] = mapped_column(JSON, default=list)
    algorithm_version: Mapped[str] = mapped_column(String(40), default="zero-trust-1.0.0")
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    demo_data: Mapped[bool] = mapped_column(Boolean, default=False)


class ZeroTrustDimension(Base, EnterpriseMixin):
    __tablename__ = "zero_trust_dimensions"
    __table_args__ = (UniqueConstraint("organization_id", "assessment_id", "dimension"),)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("zero_trust_assessments.id"), index=True)
    dimension: Mapped[str] = mapped_column(String(40), index=True)
    score: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str] = mapped_column(String(40), default="insufficient_evidence")
    weight: Mapped[float] = mapped_column(Float, default=1)
    confidence: Mapped[float] = mapped_column(Float, default=0)
    factors: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    unknown_factors: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
