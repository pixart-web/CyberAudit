"""Operational hardening models added in Phase 10."""

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


class AuthenticationProvider(Base, EnterpriseMixin):
    __tablename__ = "authentication_providers"
    __table_args__ = (UniqueConstraint("organization_id", "code"),)
    code: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(180))
    protocol: Mapped[str] = mapped_column(String(30), default="oidc")
    issuer: Mapped[str] = mapped_column(String(500))
    client_id: Mapped[str] = mapped_column(String(300))
    client_secret_reference: Mapped[str | None] = mapped_column(String(500))
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    required_group: Mapped[str | None] = mapped_column(String(300))
    jit_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    jit_requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    default_role_id: Mapped[str | None] = mapped_column(ForeignKey("roles.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class ExternalGroupRoleMapping(Base, EnterpriseMixin):
    __tablename__ = "external_group_role_mappings"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider_id", "external_group", "role_id", "version"),
    )
    provider_id: Mapped[str] = mapped_column(ForeignKey("authentication_providers.id"))
    external_group: Mapped[str] = mapped_column(String(500))
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"))
    version: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UserSession(Base, EnterpriseMixin):
    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("ix_user_sessions_org_user_status", "organization_id", "user_id", "status"),
        UniqueConstraint("organization_id", "session_token_hash"),
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    session_token_hash: Mapped[str] = mapped_column(String(64))
    csrf_token_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), default="active")
    authentication_method: Mapped[str] = mapped_column(String(30))
    authentication_strength: Mapped[str] = mapped_column(String(30), default="single_factor")
    provider_id: Mapped[str | None] = mapped_column(ForeignKey("authentication_providers.id"))
    device_label: Mapped[str | None] = mapped_column(String(160))
    source_ip_hash: Mapped[str | None] = mapped_column(String(64))
    user_agent_family: Mapped[str | None] = mapped_column(String(120))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    revoke_reason: Mapped[str | None] = mapped_column(String(300))


class MfaFactor(Base, EnterpriseMixin):
    __tablename__ = "mfa_factors"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    factor_type: Mapped[str] = mapped_column(String(30))
    label: Mapped[str] = mapped_column(String(120))
    secret_reference: Mapped[str | None] = mapped_column(String(500))
    credential_id: Mapped[str | None] = mapped_column(String(500))
    public_key: Mapped[str | None] = mapped_column(Text)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RecoveryCode(Base, EnterpriseMixin):
    __tablename__ = "recovery_codes"
    __table_args__ = (UniqueConstraint("organization_id", "code_hash"),)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FeatureFlag(Base, EnterpriseMixin):
    __tablename__ = "feature_flags"
    __table_args__ = (UniqueConstraint("organization_id", "code", "environment"),)
    code: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    environment: Mapped[str] = mapped_column(String(30))
    edition: Mapped[str | None] = mapped_column(String(30))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class LicenseRecord(Base, EnterpriseMixin):
    __tablename__ = "license_records"
    edition: Mapped[str] = mapped_column(String(30), default="community")
    provider: Mapped[str] = mapped_column(String(30), default="community")
    license_id: Mapped[str] = mapped_column(String(160))
    signed_payload: Mapped[str | None] = mapped_column(Text)
    payload_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), default="active")
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    limits: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    grace_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RetentionPolicy(Base, EnterpriseMixin):
    __tablename__ = "retention_policies"
    __table_args__ = (UniqueConstraint("organization_id", "data_category"),)
    data_category: Mapped[str] = mapped_column(String(80))
    active_days: Mapped[int] = mapped_column(Integer)
    archive_days: Mapped[int | None] = mapped_column(Integer)
    delete_after_days: Mapped[int | None] = mapped_column(Integer)
    legal_hold_supported: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class StoredObject(Base, EnterpriseMixin):
    __tablename__ = "stored_objects"
    __table_args__ = (
        UniqueConstraint("organization_id", "storage_key"),
        Index("ix_stored_objects_org_lifecycle", "organization_id", "lifecycle_state"),
    )
    object_type: Mapped[str] = mapped_column(String(80))
    provider: Mapped[str] = mapped_column(String(30))
    storage_key: Mapped[str] = mapped_column(String(1000))
    content_type: Mapped[str] = mapped_column(String(160))
    size_bytes: Mapped[int] = mapped_column(Integer)
    content_hash: Mapped[str] = mapped_column(String(64))
    encryption_status: Mapped[str] = mapped_column(String(30), default="provider_managed")
    scan_status: Mapped[str] = mapped_column(String(30), default="quarantine")
    lifecycle_state: Mapped[str] = mapped_column(String(30), default="active")
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    retain_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    original_filename: Mapped[str | None] = mapped_column(String(300))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class BackupRecord(Base, EnterpriseMixin):
    __tablename__ = "backup_records"
    backup_type: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="scheduled")
    storage_key: Mapped[str | None] = mapped_column(String(1000))
    manifest_hash: Mapped[str | None] = mapped_column(String(64))
    encrypted: Mapped[bool] = mapped_column(Boolean, default=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(100))
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class RestoreRecord(Base, EnterpriseMixin):
    __tablename__ = "restore_records"
    backup_id: Mapped[str] = mapped_column(ForeignKey("backup_records.id"))
    status: Mapped[str] = mapped_column(String(30), default="requested")
    isolated_environment: Mapped[bool] = mapped_column(Boolean, default=True)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(100))


class TelemetryPreference(Base, EnterpriseMixin):
    __tablename__ = "telemetry_preferences"
    __table_args__ = (UniqueConstraint("organization_id"),)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    last_preview: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    consented_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    consented_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ServiceLevelObjective(Base, EnterpriseMixin):
    __tablename__ = "service_level_objectives"
    __table_args__ = (UniqueConstraint("organization_id", "code"),)
    code: Mapped[str] = mapped_column(String(100))
    service: Mapped[str] = mapped_column(String(80))
    indicator: Mapped[str] = mapped_column(String(120))
    target: Mapped[float] = mapped_column(Float)
    window_days: Mapped[int] = mapped_column(Integer, default=30)
    status: Mapped[str] = mapped_column(String(30), default="unmeasured")
    owner: Mapped[str | None] = mapped_column(String(180))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
