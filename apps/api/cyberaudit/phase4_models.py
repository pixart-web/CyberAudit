"""CyberAudit OS Phase 4 domain models.

PostgreSQL remains the system of record.  Graph-oriented services consume these
relational entities through a repository abstraction so a dedicated graph
engine can be introduced later without changing the domain model.
"""

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
    Index,
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


class Phase4TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Environment(Base, Phase4TimestampMixin):
    __tablename__ = "environments"
    __table_args__ = (
        UniqueConstraint("organization_id", "client_id", "name"),
        Index("ix_environments_org_active", "organization_id", "active"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    environment_type: Mapped[str] = mapped_column(String(40), default="unknown")
    criticality: Mapped[str] = mapped_column(String(30), default="medium")
    exposure: Mapped[str] = mapped_column(String(30), default="internal")
    data_classification: Mapped[str] = mapped_column(String(40), default="internal")
    owner: Mapped[str | None] = mapped_column(String(160))
    business_owner: Mapped[str | None] = mapped_column(String(160))
    technical_owner: Mapped[str | None] = mapped_column(String(160))
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    environment_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class NetworkZone(Base, Phase4TimestampMixin):
    __tablename__ = "network_zones"
    __table_args__ = (
        UniqueConstraint("organization_id", "environment_id", "name"),
        Index("ix_network_zones_org_environment", "organization_id", "environment_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    environment_id: Mapped[str] = mapped_column(ForeignKey("environments.id"), index=True)
    parent_zone_id: Mapped[str | None] = mapped_column(ForeignKey("network_zones.id"))
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    zone_type: Mapped[str] = mapped_column(String(40), default="unknown")
    trust_level: Mapped[str] = mapped_column(String(30), default="untrusted")
    exposure: Mapped[str] = mapped_column(String(30), default="internal")
    internet_access: Mapped[bool] = mapped_column(Boolean, default=False)
    inbound_restrictions: Mapped[list[str]] = mapped_column(JSON, default=list)
    outbound_restrictions: Mapped[list[str]] = mapped_column(JSON, default=list)
    criticality: Mapped[str] = mapped_column(String(30), default="medium")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)


class DiscoveryPolicy(Base, Phase4TimestampMixin):
    __tablename__ = "discovery_policies"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    allowed_target_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    maximum_hosts: Mapped[int] = mapped_column(Integer, default=256)
    maximum_ports: Mapped[int] = mapped_column(Integer, default=32)
    maximum_packets_per_second: Mapped[int] = mapped_column(Integer, default=20)
    maximum_concurrent_hosts: Mapped[int] = mapped_column(Integer, default=8)
    maximum_concurrent_ports: Mapped[int] = mapped_column(Integer, default=8)
    host_timeout: Mapped[int] = mapped_column(Integer, default=3)
    total_timeout: Mapped[int] = mapped_column(Integer, default=300)
    permitted_protocols: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["tcp"])
    permitted_ports: Mapped[list[int]] = mapped_column(JSON, default=list)
    forbidden_ports: Mapped[list[int]] = mapped_column(JSON, default=list)
    allow_icmp: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_tcp_discovery: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_udp_discovery: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_service_detection: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_os_detection: Mapped[bool] = mapped_column(Boolean, default=False)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    active_hours: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    excluded_targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Network(Base, Phase4TimestampMixin):
    __tablename__ = "networks"
    __table_args__ = (
        UniqueConstraint("organization_id", "cidr"),
        Index("ix_networks_org_zone", "organization_id", "network_zone_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    environment_id: Mapped[str] = mapped_column(ForeignKey("environments.id"), index=True)
    network_zone_id: Mapped[str] = mapped_column(ForeignKey("network_zones.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    cidr: Mapped[str] = mapped_column(String(64), index=True)
    ip_version: Mapped[int] = mapped_column(Integer)
    gateway: Mapped[str | None] = mapped_column(String(45))
    vlan_id: Mapped[int | None] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str | None] = mapped_column(String(160))
    scan_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    discovery_policy_id: Mapped[str | None] = mapped_column(
        ForeignKey("discovery_policies.id"), index=True
    )
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)


class IPAddress(Base, Phase4TimestampMixin):
    __tablename__ = "ip_addresses"
    __table_args__ = (
        UniqueConstraint("organization_id", "address"),
        Index("ix_ip_addresses_org_asset_active", "organization_id", "asset_id", "active"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    address: Mapped[str] = mapped_column(String(45), index=True)
    version: Mapped[int] = mapped_column(Integer)
    scope_type: Mapped[str] = mapped_column(String(30))
    public: Mapped[bool] = mapped_column(Boolean, default=False)
    private: Mapped[bool] = mapped_column(Boolean, default=False)
    reserved: Mapped[bool] = mapped_column(Boolean, default=False)
    network_id: Mapped[str | None] = mapped_column(ForeignKey("networks.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True)
    hostname_id: Mapped[str | None] = mapped_column(String(36))
    source: Mapped[str] = mapped_column(String(120))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Service(Base, Phase4TimestampMixin):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "asset_id", "ip_address_id", "port", "transport_protocol"
        ),
        Index("ix_services_org_exposure_state", "organization_id", "exposure", "state"),
        Index("ix_services_org_asset_last_seen", "organization_id", "asset_id", "last_seen_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    ip_address_id: Mapped[str | None] = mapped_column(ForeignKey("ip_addresses.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    transport_protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    application_protocol: Mapped[str | None] = mapped_column(String(40))
    service_name: Mapped[str | None] = mapped_column(String(120))
    product: Mapped[str | None] = mapped_column(String(160))
    version: Mapped[str | None] = mapped_column(String(120))
    extra_info: Mapped[str | None] = mapped_column(Text)
    banner_hash: Mapped[str | None] = mapped_column(String(64))
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    certificate_id: Mapped[str | None] = mapped_column(String(36))
    authenticated: Mapped[bool] = mapped_column(Boolean, default=False)
    exposure: Mapped[str] = mapped_column(String(30), default="unknown")
    state: Mapped[str] = mapped_column(String(30), default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    fingerprint_method: Mapped[str] = mapped_column(String(80), default="observation")
    source_adapter: Mapped[str] = mapped_column(String(160))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SoftwareProduct(Base, Phase4TimestampMixin):
    __tablename__ = "software_products"
    __table_args__ = (UniqueConstraint("normalized_name", "ecosystem"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    vendor: Mapped[str] = mapped_column(String(160))
    product: Mapped[str] = mapped_column(String(160))
    normalized_name: Mapped[str] = mapped_column(String(320), index=True)
    ecosystem: Mapped[str] = mapped_column(String(60), default="generic")
    cpe: Mapped[str | None] = mapped_column(String(500), index=True)
    purl: Mapped[str | None] = mapped_column(String(500), index=True)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    product_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class SoftwareInstance(Base, Phase4TimestampMixin):
    __tablename__ = "software_instances"
    __table_args__ = (
        UniqueConstraint("organization_id", "asset_id", "software_product_id", "version"),
        Index("ix_software_instances_org_active", "organization_id", "active"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    service_id: Mapped[str | None] = mapped_column(ForeignKey("services.id"), index=True)
    software_product_id: Mapped[str] = mapped_column(ForeignKey("software_products.id"), index=True)
    version: Mapped[str] = mapped_column(String(120))
    edition: Mapped[str | None] = mapped_column(String(120))
    installation_path: Mapped[str | None] = mapped_column(String(500))
    source: Mapped[str] = mapped_column(String(120))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"))


class Vulnerability(Base, Phase4TimestampMixin):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("source", "external_id"),
        Index("ix_vulnerabilities_kev_severity", "known_exploited", "severity"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    external_id: Mapped[str] = mapped_column(String(80), index=True)
    source: Mapped[str] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_v2: Mapped[float | None] = mapped_column(Float)
    cvss_v3: Mapped[float | None] = mapped_column(Float)
    cvss_v4: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(30), index=True)
    exploitability_score: Mapped[float | None] = mapped_column(Float)
    impact_score: Mapped[float | None] = mapped_column(Float)
    attack_vector: Mapped[str | None] = mapped_column(String(40))
    attack_complexity: Mapped[str | None] = mapped_column(String(40))
    privileges_required: Mapped[str | None] = mapped_column(String(40))
    user_interaction: Mapped[str | None] = mapped_column(String(40))
    scope: Mapped[str | None] = mapped_column(String(40))
    confidentiality_impact: Mapped[str | None] = mapped_column(String(40))
    integrity_impact: Mapped[str | None] = mapped_column(String(40))
    availability_impact: Mapped[str | None] = mapped_column(String(40))
    cwes: Mapped[list[str]] = mapped_column(JSON, default=list)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_products: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    ransomware_associated: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_publicly_available: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    vendor_advisory_available: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(30), default="active")
    vulnerability_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class VulnerabilityMatch(Base, Phase4TimestampMixin):
    __tablename__ = "vulnerability_matches"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "vulnerability_id", "asset_id", "service_id", "software_instance_id"
        ),
        Index("ix_vulnerability_matches_org_status", "organization_id", "status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    service_id: Mapped[str | None] = mapped_column(ForeignKey("services.id"))
    software_instance_id: Mapped[str | None] = mapped_column(ForeignKey("software_instances.id"))
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"))
    matching_method: Mapped[str] = mapped_column(String(60))
    match_quality: Mapped[str] = mapped_column(String(40))
    observed_product: Mapped[str] = mapped_column(String(200))
    observed_version: Mapped[str | None] = mapped_column(String(120))
    affected_range: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(50), default="requires_review")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    requires_manual_validation: Mapped[bool] = mapped_column(Boolean, default=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reviewed_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AssetRelationship(Base, Phase4TimestampMixin):
    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "source_asset_id", "target_asset_id", "relationship_type"
        ),
        Index(
            "ix_asset_relationships_org_source_active",
            "organization_id",
            "source_asset_id",
            "active",
        ),
        Index(
            "ix_asset_relationships_org_target_active",
            "organization_id",
            "target_asset_id",
            "active",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    source_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    target_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    relationship_type: Mapped[str] = mapped_column(String(60))
    direction: Mapped[str] = mapped_column(String(20), default="directed")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    source: Mapped[str] = mapped_column(String(120))
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)


class AssetChange(Base):
    __tablename__ = "asset_changes"
    __table_args__ = (
        Index("ix_asset_changes_org_detected", "organization_id", "detected_at"),
        Index("ix_asset_changes_org_asset_type", "organization_id", "asset_id", "change_type"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    change_type: Mapped[str] = mapped_column(String(60), index=True)
    field_name: Mapped[str | None] = mapped_column(String(120))
    previous_value: Mapped[Any | None] = mapped_column(JSON)
    current_value: Mapped[Any | None] = mapped_column(JSON)
    source_job_id: Mapped[str | None] = mapped_column(ForeignKey("scan_jobs.id"))
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"))
    severity: Mapped[str] = mapped_column(String(30), default="informational")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ToolExecutionManifest(Base):
    __tablename__ = "tool_execution_manifests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    adapter_code: Mapped[str] = mapped_column(String(160), unique=True)
    tool_name: Mapped[str] = mapped_column(String(120))
    tool_version: Mapped[str] = mapped_column(String(80))
    binary_path: Mapped[str] = mapped_column(String(500))
    binary_hash: Mapped[str] = mapped_column(String(64))
    permitted_arguments: Mapped[list[str]] = mapped_column(JSON, default=list)
    forbidden_arguments: Mapped[list[str]] = mapped_column(JSON, default=list)
    execution_user: Mapped[str] = mapped_column(String(80))
    sandbox: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    timeout: Mapped[int] = mapped_column(Integer)
    network_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    parser_version: Mapped[str] = mapped_column(String(80))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VulnerabilityFeed(Base, Phase4TimestampMixin):
    __tablename__ = "vulnerability_feeds"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    provider: Mapped[str] = mapped_column(String(100))
    source_identifier: Mapped[str] = mapped_column(String(500))
    feed_type: Mapped[str] = mapped_column(String(60))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    synchronization_interval: Mapped[int] = mapped_column(Integer, default=86400)
    last_sync_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    records_processed: Mapped[int] = mapped_column(Integer, default=0)
    records_created: Mapped[int] = mapped_column(Integer, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, default=0)
    content_hash: Mapped[str | None] = mapped_column(String(64))
    signature_verified: Mapped[bool] = mapped_column(Boolean, default=False)


class VulnerabilityFeedSync(Base):
    __tablename__ = "vulnerability_feed_syncs"
    __table_args__ = (Index("ix_feed_syncs_feed_created", "feed_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    feed_id: Mapped[str] = mapped_column(ForeignKey("vulnerability_feeds.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    records_downloaded: Mapped[int] = mapped_column(Integer, default=0)
    records_processed: Mapped[int] = mapped_column(Integer, default=0)
    records_created: Mapped[int] = mapped_column(Integer, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, default=0)
    records_rejected: Mapped[int] = mapped_column(Integer, default=0)
    error_summary: Mapped[str | None] = mapped_column(Text)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExposureScore(Base):
    __tablename__ = "exposure_scores"
    __table_args__ = (
        Index(
            "ix_exposure_scores_org_entity_calculated",
            "organization_id",
            "entity_type",
            "calculated_at",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    entity_type: Mapped[str] = mapped_column(String(40))
    entity_id: Mapped[str] = mapped_column(String(36), index=True)
    score: Mapped[float] = mapped_column(Float)
    previous_score: Mapped[float | None] = mapped_column(Float)
    factors: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    recommendations: Mapped[list[str]] = mapped_column(JSON, default=list)
    calculation_version: Mapped[str] = mapped_column(String(30))
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AttackPath(Base, Phase4TimestampMixin):
    __tablename__ = "attack_paths"
    __table_args__ = (
        Index("ix_attack_paths_org_status_risk", "organization_id", "status", "overall_risk"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id"), index=True)
    name: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text)
    entry_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    target_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    path_type: Mapped[str] = mapped_column(String(60))
    severity: Mapped[str] = mapped_column(String(30))
    confidence: Mapped[float] = mapped_column(Float)
    likelihood: Mapped[float] = mapped_column(Float)
    impact: Mapped[float] = mapped_column(Float)
    overall_risk: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(30), default="candidate")
    generated_by: Mapped[str] = mapped_column(String(80), default="rules")
    calculation_version: Mapped[str] = mapped_column(String(30))
    reviewed_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))


class AttackPathStep(Base):
    __tablename__ = "attack_path_steps"
    __table_args__ = (UniqueConstraint("attack_path_id", "sequence"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    attack_path_id: Mapped[str] = mapped_column(ForeignKey("attack_paths.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    source_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    target_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    relationship_id: Mapped[str] = mapped_column(ForeignKey("asset_relationships.id"))
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"))
    condition: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitigation: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RiskReductionScenario(Base, Phase4TimestampMixin):
    __tablename__ = "risk_reduction_scenarios"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id"))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    selected_findings: Mapped[list[str]] = mapped_column(JSON, default=list)
    selected_controls: Mapped[list[str]] = mapped_column(JSON, default=list)
    selected_asset_changes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    baseline_risk: Mapped[float] = mapped_column(Float, default=0)
    projected_risk: Mapped[float] = mapped_column(Float, default=0)
    absolute_reduction: Mapped[float] = mapped_column(Float, default=0)
    percentage_reduction: Mapped[float] = mapped_column(Float, default=0)
    assumptions: Mapped[list[str]] = mapped_column(JSON, default=list)
    calculation_version: Mapped[str] = mapped_column(String(30), default="risk-2.0")
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class AssessmentCoverage(Base, Phase4TimestampMixin):
    __tablename__ = "assessment_coverage"
    __table_args__ = (
        UniqueConstraint("organization_id", "engagement_id", "asset_id", "assessment_category"),
        Index("ix_coverage_org_status_next", "organization_id", "status", "next_recommended_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    assessment_category: Mapped[str] = mapped_column(String(60))
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    assessment_depth: Mapped[str] = mapped_column(String(30), default="none")
    status: Mapped[str] = mapped_column(String(30), default="not_assessed")
    result: Mapped[str | None] = mapped_column(String(60))
    confidence: Mapped[float] = mapped_column(Float, default=0)
    next_recommended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    blocked_reason: Mapped[str | None] = mapped_column(Text)
    coverage_score: Mapped[float] = mapped_column(Float, default=0)


class AssessmentSchedule(Base, Phase4TimestampMixin):
    __tablename__ = "assessment_schedules"
    __table_args__ = (
        Index("ix_schedules_org_enabled_next", "organization_id", "enabled", "next_run_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    scan_profile_id: Mapped[str] = mapped_column(ForeignKey("scan_profiles.id"))
    target_selector: Mapped[dict[str, Any]] = mapped_column(JSON)
    recurrence: Mapped[str] = mapped_column(String(60))
    timezone: Mapped[str] = mapped_column(String(80))
    active_window: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    maximum_duration: Mapped[int] = mapped_column(Integer, default=3600)
    approval_policy: Mapped[str] = mapped_column(String(40), default="inherit")
    change_detection: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_on_change: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_on_failure: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class Notification(Base):
    __tablename__ = "notifications"
    __table_args__ = (
        Index("ix_notifications_org_read_created", "organization_id", "read_at", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(30))
    title: Mapped[str] = mapped_column(String(240))
    message: Mapped[str] = mapped_column(Text)
    resource_type: Mapped[str | None] = mapped_column(String(60))
    resource_id: Mapped[str | None] = mapped_column(String(36))
    notification_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
