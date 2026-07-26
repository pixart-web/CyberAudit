import enum
import uuid
from datetime import date, datetime, time, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    String,
    Text,
    Time,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cyberaudit.db import Base


def uuid4() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EngagementMode(enum.StrEnum):
    CLIENT = "client"
    LABORATORY = "laboratory"


class EngagementStatus(enum.StrEnum):
    DRAFT = "draft"
    PENDING_AUTHORIZATION = "pending_authorization"
    AUTHORIZED = "authorized"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class Intensity(enum.StrEnum):
    PASSIVE = "passive"
    LOW = "low"
    NORMAL = "normal"
    ELEVATED = "elevated"
    INTRUSIVE = "intrusive"


class TargetType(enum.StrEnum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    MOBILE_DEVICE = "mobile_device"
    CLOUD_ACCOUNT = "cloud_account"
    REPOSITORY = "repository"


class Criticality(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class SoftDeleteMixin:
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Organization(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(160))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(30), default="active")
    timezone: Mapped[str] = mapped_column(String(80), default="Europe/Lisbon")
    locale: Mapped[str] = mapped_column(String(10), default="pt-PT")


class User(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(30), default="active")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_login_attempts: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    roles: Mapped[list["Role"]] = relationship(secondary="user_roles", lazy="selectin")


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    permissions: Mapped[list["Permission"]] = relationship(
        secondary="role_permissions", lazy="selectin"
    )


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), primary_key=True)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), primary_key=True)
    permission_id: Mapped[str] = mapped_column(ForeignKey("permissions.id"), primary_key=True)


class Client(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "clients"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    legal_name: Mapped[str | None] = mapped_column(String(200))
    tax_number: Mapped[str | None] = mapped_column(String(40))
    email: Mapped[str | None] = mapped_column(String(254))
    phone: Mapped[str | None] = mapped_column(String(40))
    address: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="active")
    notes: Mapped[str | None] = mapped_column(Text)


class Engagement(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "engagements"
    __table_args__ = (UniqueConstraint("organization_id", "code"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"))
    name: Mapped[str] = mapped_column(String(160))
    code: Mapped[str] = mapped_column(String(40))
    description: Mapped[str | None] = mapped_column(Text)
    mode: Mapped[EngagementMode] = mapped_column(Enum(EngagementMode))
    status: Mapped[EngagementStatus] = mapped_column(
        Enum(EngagementStatus), default=EngagementStatus.DRAFT
    )
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    risk_level: Mapped[Criticality] = mapped_column(Enum(Criticality), default=Criticality.MEDIUM)
    notes: Mapped[str | None] = mapped_column(Text)


class AuthorizationDocument(Base):
    __tablename__ = "authorization_documents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    storage_key: Mapped[str] = mapped_column(String(255), unique=True)
    file_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), default="valid")
    valid_from: Mapped[date] = mapped_column(Date)
    valid_until: Mapped[date] = mapped_column(Date)
    signed_by: Mapped[str] = mapped_column(String(160))
    uploaded_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scope(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "scopes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="active")
    allowed_start_time: Mapped[time | None] = mapped_column(Time)
    allowed_end_time: Mapped[time | None] = mapped_column(Time)
    timezone: Mapped[str] = mapped_column(String(80), default="Europe/Lisbon")
    maximum_intensity: Mapped[Intensity] = mapped_column(Enum(Intensity), default=Intensity.NORMAL)
    emergency_stop_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)


class ScopeTarget(Base):
    __tablename__ = "scope_targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    scope_id: Mapped[str] = mapped_column(ForeignKey("scopes.id"), index=True)
    target_type: Mapped[TargetType] = mapped_column(Enum(TargetType))
    target_value: Mapped[str] = mapped_column(String(500))
    normalized_value: Mapped[str] = mapped_column(String(500), index=True)
    include_subdomains: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Asset(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    asset_type: Mapped[str] = mapped_column(String(60))
    identifier: Mapped[str] = mapped_column(String(255))
    hostname: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    domain: Mapped[str | None] = mapped_column(String(255))
    operating_system: Mapped[str | None] = mapped_column(String(120))
    owner: Mapped[str | None] = mapped_column(String(160))
    criticality: Mapped[Criticality] = mapped_column(Enum(Criticality))
    status: Mapped[str] = mapped_column(String(30), default="active")
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str | None] = mapped_column(String(36))
    result: Mapped[str] = mapped_column(String(30))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(500))
    event_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    family_id: Mapped[str] = mapped_column(String(36), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class JobStatus(enum.StrEnum):
    DRAFT = "draft"
    PENDING_POLICY = "pending_policy"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    QUEUED = "queued"
    STARTING = "starting"
    RUNNING = "running"
    PROCESSING_RESULTS = "processing_results"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"


class JobPriority(enum.StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class ApprovalStatus(enum.StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class EventType(enum.StrEnum):
    CREATED = "created"
    POLICY_EVALUATED = "policy_evaluated"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    QUEUED = "queued"
    WORKER_ASSIGNED = "worker_assigned"
    STARTED = "started"
    PROGRESS = "progress"
    OUTPUT_RECEIVED = "output_received"
    FINDING_CREATED = "finding_created"
    WARNING = "warning"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLATION_REQUESTED = "cancellation_requested"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


class ScanProfile(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "scan_profiles"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(80))
    adapter_code: Mapped[str] = mapped_column(String(160), index=True)
    target_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    default_intensity: Mapped[Intensity] = mapped_column(Enum(Intensity))
    maximum_intensity: Mapped[Intensity] = mapped_column(Enum(Intensity))
    timeout_seconds: Mapped[int] = mapped_column(default=60)
    cpu_limit: Mapped[float] = mapped_column(default=1.0)
    memory_limit_mb: Mapped[int] = mapped_column(default=256)
    network_access: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    configuration_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    default_configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class ScanJob(Base, TimestampMixin):
    __tablename__ = "scan_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    scope_id: Mapped[str] = mapped_column(ForeignKey("scopes.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    scan_profile_id: Mapped[str] = mapped_column(ForeignKey("scan_profiles.id"))
    adapter_code: Mapped[str] = mapped_column(String(160), index=True)
    target_type: Mapped[TargetType] = mapped_column(Enum(TargetType))
    target_value: Mapped[str] = mapped_column(String(500))
    normalized_target: Mapped[str] = mapped_column(String(500))
    technique: Mapped[str] = mapped_column(String(120))
    intensity: Mapped[Intensity] = mapped_column(Enum(Intensity))
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), default=JobStatus.DRAFT, index=True)
    priority: Mapped[JobPriority] = mapped_column(Enum(JobPriority), default=JobPriority.NORMAL)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    approval_id: Mapped[str | None] = mapped_column(String(36))
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timeout_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    progress: Mapped[int] = mapped_column(default=0)
    status_message: Mapped[str] = mapped_column(String(500), default="")
    worker_id: Mapped[str | None] = mapped_column(String(160))
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(default=0)


class JobEvent(Base):
    __tablename__ = "job_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    event_type: Mapped[EventType] = mapped_column(Enum(EventType))
    severity: Mapped[str] = mapped_column(String(30), default="info")
    message: Mapped[str] = mapped_column(String(500))
    event_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class ToolAdapterDefinition(Base, TimestampMixin):
    __tablename__ = "tool_adapter_definitions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    version: Mapped[str] = mapped_column(String(40))
    category: Mapped[str] = mapped_column(String(80))
    description: Mapped[str] = mapped_column(Text)
    supported_target_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    supported_intensities: Mapped[list[str]] = mapped_column(JSON, default=list)
    requires_network: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    default_timeout: Mapped[int] = mapped_column(default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    health_status: Mapped[str] = mapped_column(String(30), default="unknown")
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    adapter_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class Approval(Base, TimestampMixin):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    job_id: Mapped[str | None] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    reviewed_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    approval_type: Mapped[str] = mapped_column(String(80))
    reason: Mapped[str] = mapped_column(Text)
    risk_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[ApprovalStatus] = mapped_column(
        Enum(ApprovalStatus), default=ApprovalStatus.PENDING
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_notes: Mapped[str | None] = mapped_column(Text)


class RawResult(Base):
    __tablename__ = "raw_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    adapter_code: Mapped[str] = mapped_column(String(160))
    format: Mapped[str] = mapped_column(String(40))
    storage_key: Mapped[str | None] = mapped_column(String(255))
    content_hash: Mapped[str] = mapped_column(String(64))
    sanitized: Mapped[bool] = mapped_column(Boolean, default=True)
    size_bytes: Mapped[int] = mapped_column()
    untrusted_content: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("organization_id", "fingerprint"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(120))
    technical_severity: Mapped[Criticality] = mapped_column(Enum(Criticality))
    confidence: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), default="open")
    affected_component: Mapped[str] = mapped_column(String(255))
    affected_version: Mapped[str | None] = mapped_column(String(120))
    technical_impact: Mapped[str] = mapped_column(Text)
    business_impact: Mapped[str] = mapped_column(Text)
    remediation_summary: Mapped[str] = mapped_column(Text)
    validation_steps: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_adapter: Mapped[str] = mapped_column(String(160))
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    recommendation_type: Mapped[str] = mapped_column(String(60), default="configuration")
    remediation_effort: Mapped[str] = mapped_column(String(30), default="low")
    remediation_priority: Mapped[str] = mapped_column(String(30), default="normal")
    standards: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    observed_value: Mapped[str | None] = mapped_column(Text)
    expected_value: Mapped[str | None] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(String(500))
    reproducibility: Mapped[str] = mapped_column(String(30), default="consistent")
    imported: Mapped[bool] = mapped_column(Boolean, default=False)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_status: Mapped[str] = mapped_column(String(30), default="unverified")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceSensitivity(enum.StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"), index=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    evidence_type: Mapped[str] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    storage_key: Mapped[str | None] = mapped_column(String(255))
    content_hash: Mapped[str] = mapped_column(String(64))
    mime_type: Mapped[str] = mapped_column(String(120), default="application/json")
    size_bytes: Mapped[int] = mapped_column(default=0)
    sensitivity: Mapped[EvidenceSensitivity] = mapped_column(
        Enum(EvidenceSensitivity), default=EvidenceSensitivity.INTERNAL
    )
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    collected_by_adapter: Mapped[str] = mapped_column(String(160))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    sanitized_content: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RetestStatus(enum.StrEnum):
    REQUESTED = "requested"
    QUEUED = "queued"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    CANCELLED = "cancelled"


class Retest(Base):
    __tablename__ = "retests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    original_job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"))
    retest_job_id: Mapped[str | None] = mapped_column(ForeignKey("scan_jobs.id"))
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[RetestStatus] = mapped_column(Enum(RetestStatus), default=RetestStatus.REQUESTED)
    result: Mapped[str | None] = mapped_column(String(60))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AssetObservation(Base):
    __tablename__ = "asset_observations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    observation_type: Mapped[str] = mapped_column(String(80))
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_adapter: Mapped[str] = mapped_column(String(160))
    confidence: Mapped[str] = mapped_column(String(30), default="medium")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SuggestionStatus(enum.StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class AssetSuggestion(Base):
    __tablename__ = "asset_suggestions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    suggestion_type: Mapped[str] = mapped_column(String(80))
    proposed_value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[SuggestionStatus] = mapped_column(
        Enum(SuggestionStatus), default=SuggestionStatus.PENDING
    )
    reviewed_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExternalImportStatus(enum.StrEnum):
    UPLOADED = "uploaded"
    PREVIEWED = "previewed"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ExternalImport(Base, TimestampMixin):
    __tablename__ = "external_imports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    uploaded_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    filename: Mapped[str] = mapped_column(String(255))
    storage_key: Mapped[str] = mapped_column(String(255), unique=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    mime_type: Mapped[str] = mapped_column(String(120))
    format: Mapped[str] = mapped_column(String(40))
    size_bytes: Mapped[int] = mapped_column()
    status: Mapped[ExternalImportStatus] = mapped_column(
        Enum(ExternalImportStatus), default=ExternalImportStatus.UPLOADED
    )
    preview: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    confirmed_job_id: Mapped[str | None] = mapped_column(ForeignKey("scan_jobs.id"))
    error_message: Mapped[str | None] = mapped_column(Text)


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
