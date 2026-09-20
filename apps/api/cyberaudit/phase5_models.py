"""Application Security and software supply-chain domain for Phase 5."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from cyberaudit.db import Base


def uuid4() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Phase5Mixin:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ApplicationAsset(Base, Phase5Mixin):
    __tablename__ = "application_assets"
    __table_args__ = (UniqueConstraint("organization_id", "name", "environment_id"),)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    environment_id: Mapped[str] = mapped_column(ForeignKey("environments.id"), index=True)
    business_service_id: Mapped[str | None] = mapped_column(String(36))
    parent_application_id: Mapped[str | None] = mapped_column(ForeignKey("application_assets.id"))
    name: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text, default="")
    application_type: Mapped[str] = mapped_column(String(60), default="unknown")
    architecture_type: Mapped[str] = mapped_column(String(60), default="unknown")
    lifecycle_status: Mapped[str] = mapped_column(String(40), default="development")
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    internal_only: Mapped[bool] = mapped_column(Boolean, default=True)
    base_urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    repository_urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    documentation_urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    owners: Mapped[list[str]] = mapped_column(JSON, default=list)
    technical_owner: Mapped[str | None] = mapped_column(String(180))
    business_owner: Mapped[str | None] = mapped_column(String(180))
    development_team: Mapped[str | None] = mapped_column(String(180))
    support_team: Mapped[str | None] = mapped_column(String(180))
    data_classification: Mapped[str] = mapped_column(String(40), default="internal")
    business_criticality: Mapped[str] = mapped_column(String(30), default="medium")
    regulatory_scope: Mapped[list[str]] = mapped_column(JSON, default=list)
    authentication_type: Mapped[str] = mapped_column(String(60), default="unknown")
    authorization_model: Mapped[str] = mapped_column(String(80), default="unknown")
    session_model: Mapped[str] = mapped_column(String(80), default="unknown")
    deployment_model: Mapped[str] = mapped_column(String(80), default="unknown")
    hosting_model: Mapped[str] = mapped_column(String(80), default="unknown")
    technology_stack: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    exposure_score: Mapped[float] = mapped_column(Float, default=0)
    appsec_score: Mapped[float] = mapped_column(Float, default=0)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    source: Mapped[str] = mapped_column(String(120), default="manual")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    release_frequency: Mapped[str | None] = mapped_column(String(60))
    active_version: Mapped[str | None] = mapped_column(String(120))
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    application_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class ApiAsset(Base, Phase5Mixin):
    __tablename__ = "api_assets"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("application_assets.id"), index=True)
    environment_id: Mapped[str] = mapped_column(ForeignKey("environments.id"), index=True)
    name: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text, default="")
    api_type: Mapped[str] = mapped_column(String(40), default="unknown")
    visibility: Mapped[str] = mapped_column(String(30), default="unknown")
    base_url: Mapped[str] = mapped_column(String(1000))
    version: Mapped[str | None] = mapped_column(String(80))
    specification_type: Mapped[str | None] = mapped_column(String(40))
    specification_location: Mapped[str | None] = mapped_column(String(500))
    specification_hash: Mapped[str | None] = mapped_column(String(64))
    authentication_type: Mapped[str] = mapped_column(String(60), default="unknown")
    authorization_model: Mapped[str] = mapped_column(String(80), default="unknown")
    rate_limit_observed: Mapped[str | None] = mapped_column(String(120))
    data_classification: Mapped[str] = mapped_column(String(40), default="internal")
    business_criticality: Mapped[str] = mapped_column(String(30), default="medium")
    owner: Mapped[str | None] = mapped_column(String(180))
    lifecycle_status: Mapped[str] = mapped_column(String(40), default="development")
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    exposure_score: Mapped[float] = mapped_column(Float, default=0)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    source: Mapped[str] = mapped_column(String(120), default="manual")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    api_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class ApiEndpoint(Base, Phase5Mixin):
    __tablename__ = "api_endpoints"
    __table_args__ = (UniqueConstraint("organization_id", "api_id", "method", "normalized_path"),)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    api_id: Mapped[str] = mapped_column(ForeignKey("api_assets.id"), index=True)
    method: Mapped[str] = mapped_column(String(12))
    path_template: Mapped[str] = mapped_column(String(1000))
    normalized_path: Mapped[str] = mapped_column(String(1000))
    operation_id: Mapped[str | None] = mapped_column(String(180))
    summary: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    authentication_required: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_required: Mapped[bool] = mapped_column(Boolean, default=False)
    request_content_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    response_content_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    parameters: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    request_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    response_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    data_categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    rate_limit: Mapped[str | None] = mapped_column(String(120))
    exposure: Mapped[str] = mapped_column(String(30), default="unknown")
    source: Mapped[str] = mapped_column(String(120), default="specification")
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CodeRepository(Base, Phase5Mixin):
    __tablename__ = "code_repositories"
    __table_args__ = (UniqueConstraint("organization_id", "provider", "repository_identifier"),)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str | None] = mapped_column(ForeignKey("application_assets.id"))
    provider: Mapped[str] = mapped_column(String(60))
    repository_identifier: Mapped[str] = mapped_column(String(300))
    repository_url: Mapped[str] = mapped_column(String(1000))
    name: Mapped[str] = mapped_column(String(200))
    default_branch: Mapped[str] = mapped_column(String(160), default="main")
    visibility: Mapped[str] = mapped_column(String(30), default="private")
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    fork: Mapped[bool] = mapped_column(Boolean, default=False)
    owner_team: Mapped[str | None] = mapped_column(String(180))
    language_summary: Mapped[dict[str, float]] = mapped_column(JSON, default=dict)
    last_commit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    security_posture: Mapped[float] = mapped_column(Float, default=0)
    integration_status: Mapped[str] = mapped_column(String(40), default="manual")


class SoftwareBillOfMaterials(Base, Phase5Mixin):
    __tablename__ = "sboms"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str | None] = mapped_column(ForeignKey("application_assets.id"))
    release_id: Mapped[str | None] = mapped_column(String(36), index=True)
    repository_id: Mapped[str | None] = mapped_column(ForeignKey("code_repositories.id"))
    format: Mapped[str] = mapped_column(String(40))
    specification_version: Mapped[str] = mapped_column(String(40))
    serial_number: Mapped[str | None] = mapped_column(String(300))
    document_hash: Mapped[str] = mapped_column(String(64), index=True)
    component_count: Mapped[int] = mapped_column(Integer, default=0)
    dependency_count: Mapped[int] = mapped_column(Integer, default=0)
    direct_dependency_count: Mapped[int] = mapped_column(Integer, default=0)
    transitive_dependency_count: Mapped[int] = mapped_column(Integer, default=0)
    generated_by: Mapped[str] = mapped_column(String(160), default="unknown")
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    imported: Mapped[bool] = mapped_column(Boolean, default=True)
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    validation_errors: Mapped[list[str]] = mapped_column(JSON, default=list)
    storage_key: Mapped[str | None] = mapped_column(String(500))


class SbomComponent(Base, Phase5Mixin):
    __tablename__ = "sbom_components"
    sbom_id: Mapped[str] = mapped_column(ForeignKey("sboms.id"), index=True)
    component_type: Mapped[str] = mapped_column(String(60), default="library")
    name: Mapped[str] = mapped_column(String(300), index=True)
    group: Mapped[str | None] = mapped_column(String(300))
    version: Mapped[str | None] = mapped_column(String(160))
    supplier: Mapped[str | None] = mapped_column(String(300))
    author: Mapped[str | None] = mapped_column(String(300))
    purl: Mapped[str | None] = mapped_column(String(1000), index=True)
    cpe: Mapped[str | None] = mapped_column(String(1000), index=True)
    hashes: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)
    licenses: Mapped[list[str]] = mapped_column(JSON, default=list)
    direct_dependency: Mapped[bool] = mapped_column(Boolean, default=False)
    scope: Mapped[str] = mapped_column(String(40), default="required")
    properties: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class SbomDependency(Base):
    __tablename__ = "sbom_dependencies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    sbom_id: Mapped[str] = mapped_column(ForeignKey("sboms.id"), index=True)
    source_component_id: Mapped[str] = mapped_column(ForeignKey("sbom_components.id"))
    target_component_id: Mapped[str] = mapped_column(ForeignKey("sbom_components.id"))
    relationship_type: Mapped[str] = mapped_column(String(60), default="depends_on")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SoftwareRelease(Base, Phase5Mixin):
    __tablename__ = "software_releases"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("application_assets.id"), index=True)
    repository_id: Mapped[str | None] = mapped_column(ForeignKey("code_repositories.id"))
    version: Mapped[str] = mapped_column(String(160))
    commit_hash: Mapped[str | None] = mapped_column(String(128))
    branch: Mapped[str | None] = mapped_column(String(180))
    tag: Mapped[str | None] = mapped_column(String(180))
    build_id: Mapped[str | None] = mapped_column(String(180))
    pipeline_id: Mapped[str | None] = mapped_column(String(36))
    artifact_identifier: Mapped[str] = mapped_column(String(500))
    artifact_hash: Mapped[str] = mapped_column(String(128))
    image_digest: Mapped[str | None] = mapped_column(String(200))
    sbom_id: Mapped[str | None] = mapped_column(ForeignKey("sboms.id"))
    environment_id: Mapped[str | None] = mapped_column(ForeignKey("environments.id"))
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(40), default="built")
    signed: Mapped[bool] = mapped_column(Boolean, default=False)
    signature_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    provenance_available: Mapped[bool] = mapped_column(Boolean, default=False)
    provenance_verified: Mapped[bool] = mapped_column(Boolean, default=False)


class ApiSpecificationImport(Base, Phase5Mixin):
    __tablename__ = "api_specification_imports"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("application_assets.id"))
    api_id: Mapped[str | None] = mapped_column(ForeignKey("api_assets.id"))
    filename: Mapped[str] = mapped_column(String(255))
    storage_key: Mapped[str] = mapped_column(String(500))
    content_hash: Mapped[str] = mapped_column(String(64))
    specification_type: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="uploaded")
    preview: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    validation_errors: Mapped[list[str]] = mapped_column(JSON, default=list)
    uploaded_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class SecretObservation(Base, Phase5Mixin):
    __tablename__ = "secret_observations"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    repository_id: Mapped[str] = mapped_column(ForeignKey("code_repositories.id"), index=True)
    application_id: Mapped[str | None] = mapped_column(ForeignKey("application_assets.id"))
    secret_type: Mapped[str] = mapped_column(String(80))
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    location: Mapped[str] = mapped_column(String(1000))
    length: Mapped[int] = mapped_column(Integer)
    masked_prefix: Mapped[str | None] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(40), default="requires_review")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    commit_hash: Mapped[str | None] = mapped_column(String(128))
    branch: Mapped[str | None] = mapped_column(String(180))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AssessmentCredential(Base, Phase5Mixin):
    __tablename__ = "assessment_credentials"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"))
    application_id: Mapped[str] = mapped_column(ForeignKey("application_assets.id"))
    credential_type: Mapped[str] = mapped_column(String(60))
    secret_reference: Mapped[str] = mapped_column(String(500))
    username_label: Mapped[str | None] = mapped_column(String(180))
    role_label: Mapped[str] = mapped_column(String(180))
    environment: Mapped[str] = mapped_column(String(80))
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    usage_count: Mapped[int] = mapped_column(Integer, default=0)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    credential_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class AppSecScore(Base, Phase5Mixin):
    __tablename__ = "appsec_scores"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    entity_type: Mapped[str] = mapped_column(String(40))
    entity_id: Mapped[str] = mapped_column(String(36), index=True)
    score: Mapped[float] = mapped_column(Float)
    previous_score: Mapped[float | None] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    positive_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    negative_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    targets: Mapped[dict[str, float]] = mapped_column(JSON, default=dict)
    formula_version: Mapped[str] = mapped_column(String(60))
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecurityGatePolicy(Base, Phase5Mixin):
    __tablename__ = "security_gate_policies"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text, default="")
    scope_selector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    applies_to: Mapped[str] = mapped_column(String(60))
    environment: Mapped[str] = mapped_column(String(60))
    minimum_appsec_score: Mapped[float] = mapped_column(Float, default=70)
    maximum_critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    maximum_high_findings: Mapped[int] = mapped_column(Integer, default=0)
    block_known_exploited: Mapped[bool] = mapped_column(Boolean, default=True)
    block_confirmed_secrets: Mapped[bool] = mapped_column(Boolean, default=True)
    block_unsigned_artifacts: Mapped[bool] = mapped_column(Boolean, default=False)
    require_sbom: Mapped[bool] = mapped_column(Boolean, default=True)
    require_sast: Mapped[bool] = mapped_column(Boolean, default=False)
    require_sca: Mapped[bool] = mapped_column(Boolean, default=True)
    require_iac_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    require_container_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    maximum_scan_age: Mapped[int] = mapped_column(Integer, default=30)
    exceptions_allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class SecurityGateEvaluation(Base):
    __tablename__ = "security_gate_evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("security_gate_policies.id"))
    application_id: Mapped[str] = mapped_column(ForeignKey("application_assets.id"))
    release_id: Mapped[str | None] = mapped_column(ForeignKey("software_releases.id"))
    result: Mapped[str] = mapped_column(String(30))
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    override_id: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppSecException(Base, Phase5Mixin):
    __tablename__ = "appsec_exceptions"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"))
    vulnerability_match_id: Mapped[str | None] = mapped_column(
        ForeignKey("vulnerability_matches.id")
    )
    application_id: Mapped[str] = mapped_column(ForeignKey("application_assets.id"))
    release_id: Mapped[str | None] = mapped_column(ForeignKey("software_releases.id"))
    exception_type: Mapped[str] = mapped_column(String(60))
    reason: Mapped[str] = mapped_column(Text)
    business_justification: Mapped[str] = mapped_column(Text)
    compensating_controls: Mapped[list[str]] = mapped_column(JSON, default=list)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(30), default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    review_date: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AppSecRemediation(Base, Phase5Mixin):
    __tablename__ = "appsec_remediations"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("application_assets.id"))
    repository_id: Mapped[str | None] = mapped_column(ForeignKey("code_repositories.id"))
    owner_team: Mapped[str] = mapped_column(String(180))
    assignee: Mapped[str | None] = mapped_column(String(180))
    status: Mapped[str] = mapped_column(String(40), default="open")
    priority: Mapped[str] = mapped_column(String(30), default="normal")
    target_release: Mapped[str | None] = mapped_column(String(160))
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sla: Mapped[str | None] = mapped_column(String(80))
    remediation_plan: Mapped[str] = mapped_column(Text)
    validation_plan: Mapped[str] = mapped_column(Text)
    dependencies: Mapped[list[str]] = mapped_column(JSON, default=list)
    blockers: Mapped[list[str]] = mapped_column(JSON, default=list)
    ticket_reference: Mapped[str | None] = mapped_column(String(300))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ComponentReachability(Base):
    __tablename__ = "component_reachability"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("application_assets.id"))
    release_id: Mapped[str] = mapped_column(ForeignKey("software_releases.id"))
    component_id: Mapped[str] = mapped_column(ForeignKey("sbom_components.id"))
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"))
    reachability_status: Mapped[str] = mapped_column(String(40), default="not_analyzed")
    analysis_method: Mapped[str] = mapped_column(String(80))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
