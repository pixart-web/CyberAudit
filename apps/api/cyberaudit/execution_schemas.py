from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cyberaudit.models import (
    ApprovalStatus,
    Intensity,
    JobPriority,
    JobStatus,
    TargetType,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ScanProfileCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    description: str = ""
    category: str = Field(min_length=2, max_length=80)
    adapter_code: str
    target_types: list[TargetType]
    default_intensity: Intensity = Intensity.NORMAL
    maximum_intensity: Intensity = Intensity.NORMAL
    timeout_seconds: int = Field(default=60, ge=10, le=3600)
    cpu_limit: float = Field(default=1.0, gt=0, le=4)
    memory_limit_mb: int = Field(default=256, ge=64, le=2048)
    network_access: bool = False
    requires_approval: bool = False
    enabled: bool = True
    default_configuration: dict[str, Any] = Field(default_factory=dict)


class ScanProfileRead(ScanProfileCreate, ORMModel):
    id: str
    organization_id: str
    configuration_schema: dict[str, Any]
    created_by: str
    created_at: datetime
    updated_at: datetime


class ScanProfilePatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = None
    timeout_seconds: int | None = Field(default=None, ge=10, le=3600)
    requires_approval: bool | None = None
    enabled: bool | None = None
    default_configuration: dict[str, Any] | None = None


class JobCreate(BaseModel):
    engagement_id: str
    scope_id: str
    asset_id: str | None = None
    scan_profile_id: str
    target_type: TargetType
    target_value: str
    technique: str = Field(min_length=2, max_length=120)
    intensity: Intensity
    configuration: dict[str, Any] = Field(default_factory=dict)
    priority: JobPriority = JobPriority.NORMAL
    approval_reason: str | None = Field(default=None, max_length=1000)


class JobRead(ORMModel):
    id: str
    organization_id: str
    engagement_id: str
    scope_id: str
    asset_id: str | None
    scan_profile_id: str
    adapter_code: str
    target_type: TargetType
    target_value: str
    normalized_target: str
    technique: str
    intensity: Intensity
    configuration: dict[str, Any]
    status: JobStatus
    priority: JobPriority
    requested_by: str
    approved_by: str | None
    approval_id: str | None
    queued_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    cancelled_at: datetime | None
    timeout_at: datetime | None
    progress: int
    status_message: str
    worker_id: str | None
    result_summary: dict[str, Any]
    error_code: str | None
    error_message: str | None
    retry_count: int
    created_at: datetime
    updated_at: datetime


class JobEventRead(ORMModel):
    id: str
    job_id: str
    event_type: str
    severity: str
    message: str
    event_metadata: dict[str, Any]
    created_at: datetime


class ApprovalRead(ORMModel):
    id: str
    organization_id: str
    engagement_id: str
    job_id: str | None
    requested_by: str
    reviewed_by: str | None
    approval_type: str
    reason: str
    risk_summary: dict[str, Any]
    status: ApprovalStatus
    expires_at: datetime
    reviewed_at: datetime | None
    review_notes: str | None
    created_at: datetime


class ApprovalReview(BaseModel):
    notes: str | None = Field(default=None, max_length=2000)


class FindingRead(ORMModel):
    id: str
    organization_id: str
    engagement_id: str
    asset_id: str | None
    job_id: str
    title: str
    description: str
    category: str
    technical_severity: str
    confidence: str
    status: str
    affected_component: str
    affected_version: str | None
    technical_impact: str
    business_impact: str
    remediation_summary: str
    validation_steps: list[str]
    source_adapter: str
    fingerprint: str
    evidence: list[dict[str, Any]]
    recommendation_type: str
    remediation_effort: str
    remediation_priority: str
    standards: list[dict[str, str]]
    references: list[str]
    observed_value: str | None
    expected_value: str | None
    location: str | None
    reproducibility: str
    imported: bool
    simulated: bool
    verification_status: str
    first_seen_at: datetime
    last_seen_at: datetime
