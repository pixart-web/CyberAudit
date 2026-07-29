"""Tenant-isolated API for CyberAudit OS Phase 4."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Literal, cast

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.asset_graph import (
    AttackPathAnalysisService,
    CyberAssetGraphService,
    PostgreSQLAssetGraphRepository,
)
from cyberaudit.audit import write_audit
from cyberaudit.config import get_settings
from cyberaudit.db import get_db
from cyberaudit.models import (
    Asset,
    Client,
    Engagement,
    Finding,
    JobStatus,
    ScanJob,
    ScanProfile,
    Scope,
    ScopeTarget,
    TargetType,
    User,
    utcnow,
)
from cyberaudit.phase4_models import (
    AssessmentCoverage,
    AssessmentSchedule,
    AssetChange,
    AssetRelationship,
    AttackPath,
    AttackPathStep,
    DiscoveryPolicy,
    Environment,
    Network,
    NetworkZone,
    Notification,
    RiskReductionScenario,
    Service,
    SoftwareInstance,
    Vulnerability,
    VulnerabilityFeed,
    VulnerabilityFeedSync,
    VulnerabilityMatch,
)
from cyberaudit.risk_engine import ContextualRiskEngine, RiskContext
from cyberaudit.security import require_permission
from cyberaudit.vulnerability_intelligence import VulnerabilityIntelligenceService

router = APIRouter(prefix="/api/v1", tags=["cyberaudit-os"])
risk_engine = ContextualRiskEngine()

ENVIRONMENT_TYPES = {
    "production",
    "staging",
    "development",
    "testing",
    "disaster_recovery",
    "corporate",
    "laboratory",
    "cloud",
    "hybrid",
    "unknown",
}
ZONE_TYPES = {
    "internet",
    "dmz",
    "internal",
    "restricted",
    "management",
    "guest",
    "wireless",
    "vpn",
    "cloud",
    "development",
    "laboratory",
    "unknown",
}
TARGET_SELECTOR_KEYS = {
    "asset_ids",
    "network_ids",
    "network_zone_ids",
    "tags",
    "environment_ids",
    "asset_types",
}


def _default_discovery_target_types() -> list[Literal["ip", "cidr"]]:
    return ["ip", "cidr"]


def _default_tcp_protocols() -> list[Literal["tcp"]]:
    return ["tcp"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnvironmentPayload(StrictModel):
    client_id: str
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=5000)
    environment_type: str = "unknown"
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    exposure: str = "internal"
    data_classification: str = "internal"
    owner: str | None = Field(default=None, max_length=160)
    business_owner: str | None = Field(default=None, max_length=160)
    technical_owner: str | None = Field(default=None, max_length=160)
    tags: list[str] = Field(default_factory=list, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)
    active: bool = True

    @field_validator("environment_type")
    @classmethod
    def valid_type(cls, value: str) -> str:
        if value not in ENVIRONMENT_TYPES:
            raise ValueError("unsupported_environment_type")
        return value


class EnvironmentPatch(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=5000)
    environment_type: str | None = None
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    exposure: str | None = None
    data_classification: str | None = None
    owner: str | None = None
    business_owner: str | None = None
    technical_owner: str | None = None
    tags: list[str] | None = Field(default=None, max_length=50)
    metadata: dict[str, Any] | None = None
    active: bool | None = None


class ZonePayload(StrictModel):
    environment_id: str
    parent_zone_id: str | None = None
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=5000)
    zone_type: str = "unknown"
    trust_level: str = "untrusted"
    exposure: str = "internal"
    internet_access: bool = False
    inbound_restrictions: list[str] = Field(default_factory=list, max_length=100)
    outbound_restrictions: list[str] = Field(default_factory=list, max_length=100)
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    tags: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("zone_type")
    @classmethod
    def valid_type(cls, value: str) -> str:
        if value not in ZONE_TYPES:
            raise ValueError("unsupported_zone_type")
        return value


class NetworkPayload(StrictModel):
    environment_id: str
    network_zone_id: str
    name: str = Field(min_length=2, max_length=160)
    cidr: str
    gateway: str | None = None
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    description: str = Field(default="", max_length=5000)
    owner: str | None = Field(default=None, max_length=160)
    scan_allowed: bool = False
    discovery_policy_id: str | None = None
    tags: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("cidr")
    @classmethod
    def valid_cidr(cls, value: str) -> str:
        return str(ipaddress.ip_network(value, strict=False))


class DiscoveryPolicyPayload(StrictModel):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=5000)
    allowed_target_types: list[Literal["ip", "cidr"]] = Field(
        default_factory=_default_discovery_target_types
    )
    maximum_hosts: int = Field(default=64, ge=1, le=1024)
    maximum_ports: int = Field(default=32, ge=1, le=128)
    maximum_packets_per_second: int = Field(default=20, ge=1, le=100)
    maximum_concurrent_hosts: int = Field(default=8, ge=1, le=32)
    maximum_concurrent_ports: int = Field(default=8, ge=1, le=32)
    host_timeout: int = Field(default=3, ge=1, le=10)
    total_timeout: int = Field(default=300, ge=10, le=900)
    permitted_protocols: list[Literal["tcp"]] = Field(default_factory=_default_tcp_protocols)
    permitted_ports: list[int] = Field(default_factory=list, max_length=128)
    forbidden_ports: list[int] = Field(default_factory=list, max_length=128)
    allow_icmp: bool = False
    allow_tcp_discovery: bool = True
    allow_udp_discovery: bool = False
    allow_service_detection: bool = True
    allow_os_detection: bool = False
    require_approval: bool = False
    active_hours: dict[str, Any] = Field(default_factory=dict)
    excluded_targets: list[str] = Field(default_factory=list, max_length=100)
    active: bool = True

    @field_validator("permitted_ports", "forbidden_ports")
    @classmethod
    def valid_ports(cls, values: list[int]) -> list[int]:
        if any(value < 1 or value > 65535 for value in values):
            raise ValueError("invalid_port")
        return sorted(set(values))


class AssetPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    environment_id: str | None = None
    network_zone_id: str | None = None
    parent_asset_id: str | None = None
    subtype: str | None = None
    fqdn: str | None = None
    primary_ip: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    operating_system: str | None = None
    operating_system_version: str | None = None
    ownership: str | None = None
    lifecycle_status: str | None = None
    internet_exposed: bool | None = None
    externally_managed: bool | None = None
    managed: bool | None = None
    business_criticality: Literal["low", "medium", "high", "critical"] | None = None
    data_classification: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    tags: list[str] | None = Field(default=None, max_length=50)
    custom_fields: dict[str, Any] | None = None


class RelationshipPayload(StrictModel):
    source_asset_id: str
    target_asset_id: str
    relationship_type: str
    direction: Literal["directed", "bidirectional"] = "directed"
    confidence: float = Field(default=0.5, ge=0, le=1)
    source: str = Field(default="manual", max_length=120)
    evidence_id: str | None = None


class FeedPayload(StrictModel):
    name: str = Field(min_length=2, max_length=160)
    provider: Literal["NVD", "CISA KEV", "OSV", "vendor", "GitHub", "CyberAudit Demo"]
    source_identifier: str = Field(max_length=500)
    feed_type: str = Field(max_length=60)
    enabled: bool = True
    synchronization_interval: int = Field(default=86400, ge=3600, le=2_592_000)


class MatchReview(StrictModel):
    notes: str | None = Field(default=None, max_length=2000)


class RiskScenarioPayload(StrictModel):
    engagement_id: str | None = None
    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=5000)
    selected_findings: list[str] = Field(default_factory=list, max_length=500)
    selected_controls: list[str] = Field(default_factory=list, max_length=200)
    selected_asset_changes: list[dict[str, Any]] = Field(default_factory=list, max_length=200)
    assumptions: list[str] = Field(default_factory=list, max_length=100)


class SchedulePayload(StrictModel):
    engagement_id: str
    scan_profile_id: str
    target_selector: dict[str, list[str]]
    recurrence: Literal["hourly", "daily", "weekly", "monthly"]
    timezone: str = "Europe/Lisbon"
    active_window: dict[str, Any] = Field(default_factory=dict)
    maximum_duration: int = Field(default=3600, ge=60, le=86400)
    approval_policy: Literal["inherit", "always", "on_change"] = "inherit"
    change_detection: bool = True
    notify_on_change: bool = True
    notify_on_failure: bool = True
    enabled: bool = True
    next_run_at: datetime | None = None

    @field_validator("target_selector")
    @classmethod
    def valid_selector(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        if not value or set(value) - TARGET_SELECTOR_KEYS:
            raise ValueError("unsupported_target_selector")
        if sum(len(items) for items in value.values()) > 500:
            raise ValueError("target_selector_limit_exceeded")
        return value


async def _page(
    db: AsyncSession,
    model: Any,
    where: list[Any],
    page: int,
    page_size: int,
    order: Any,
) -> dict[str, Any]:
    total = await db.scalar(select(func.count()).select_from(model).where(*where))
    items = list(
        (
            await db.scalars(
                select(model)
                .where(*where)
                .order_by(order)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    )
    return {"items": items, "total": total or 0, "page": page, "page_size": page_size}


async def _tenant_row(db: AsyncSession, model: Any, row_id: str, organization_id: str) -> Any:
    row = await db.scalar(
        select(model).where(model.id == row_id, model.organization_id == organization_id)
    )
    if not row:
        raise HTTPException(404, "Resource not found")
    return row


async def _environment(db: AsyncSession, environment_id: str, organization_id: str) -> Environment:
    return await _tenant_row(db, Environment, environment_id, organization_id)


async def _network_authorized(db: AsyncSession, organization_id: str, cidr: str) -> bool:
    candidate = ipaddress.ip_network(cidr, strict=False)
    targets = list(
        (
            await db.scalars(
                select(ScopeTarget)
                .join(Scope, Scope.id == ScopeTarget.scope_id)
                .where(
                    Scope.organization_id == organization_id,
                    Scope.status == "active",
                    Scope.deleted_at.is_(None),
                    ScopeTarget.allowed.is_(True),
                    ScopeTarget.target_type == TargetType.CIDR,
                )
            )
        ).all()
    )
    for target in targets:
        try:
            authorized = ipaddress.ip_network(target.normalized_value, strict=False)
        except ValueError:
            continue
        if candidate.version == authorized.version and candidate.subnet_of(cast(Any, authorized)):
            return True
    return False


@router.get("/environments")
async def list_environments(
    q: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("environments.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [Environment.organization_id == user.organization_id]
    if q:
        where.append(Environment.name.ilike(f"%{q}%"))
    return await _page(db, Environment, where, page, page_size, Environment.name)


@router.post("/environments", status_code=201)
async def create_environment(
    payload: EnvironmentPayload,
    user: User = Depends(require_permission("environments.manage")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, Client, payload.client_id, user.organization_id)
    row = Environment(
        organization_id=user.organization_id,
        **payload.model_dump(exclude={"metadata"}),
        environment_metadata=payload.metadata,
    )
    db.add(row)
    await write_audit(db, user, "environment.created", "environment", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/environments/{environment_id}")
async def get_environment(
    environment_id: str,
    user: User = Depends(require_permission("environments.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _environment(db, environment_id, user.organization_id)


@router.patch("/environments/{environment_id}")
async def patch_environment(
    environment_id: str,
    payload: EnvironmentPatch,
    user: User = Depends(require_permission("environments.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _environment(db, environment_id, user.organization_id)
    values = payload.model_dump(exclude_unset=True, exclude={"metadata"})
    for key, value in values.items():
        setattr(row, key, value)
    if payload.metadata is not None:
        row.environment_metadata = payload.metadata
    await write_audit(db, user, "environment.updated", "environment", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.delete("/environments/{environment_id}", status_code=204)
async def deactivate_environment(
    environment_id: str,
    user: User = Depends(require_permission("environments.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _environment(db, environment_id, user.organization_id)
    row.active = False
    await write_audit(db, user, "environment.deactivated", "environment", row.id)
    await db.commit()


@router.get("/network-zones")
async def list_network_zones(
    environment_id: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("network_zones.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [NetworkZone.organization_id == user.organization_id]
    if environment_id:
        where.append(NetworkZone.environment_id == environment_id)
    return await _page(db, NetworkZone, where, page, page_size, NetworkZone.name)


@router.post("/network-zones", status_code=201)
async def create_network_zone(
    payload: ZonePayload,
    user: User = Depends(require_permission("network_zones.manage")),
    db: AsyncSession = Depends(get_db),
):
    await _environment(db, payload.environment_id, user.organization_id)
    if payload.parent_zone_id:
        await _tenant_row(db, NetworkZone, payload.parent_zone_id, user.organization_id)
    row = NetworkZone(organization_id=user.organization_id, **payload.model_dump())
    db.add(row)
    await write_audit(db, user, "network_zone.created", "network_zone", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/network-zones/{zone_id}")
async def get_network_zone(
    zone_id: str,
    user: User = Depends(require_permission("network_zones.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, NetworkZone, zone_id, user.organization_id)


@router.patch("/network-zones/{zone_id}")
async def patch_network_zone(
    zone_id: str,
    payload: ZonePayload,
    user: User = Depends(require_permission("network_zones.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, NetworkZone, zone_id, user.organization_id)
    await _environment(db, payload.environment_id, user.organization_id)
    if payload.parent_zone_id:
        parent = await _tenant_row(db, NetworkZone, payload.parent_zone_id, user.organization_id)
        if parent.id == row.id or parent.environment_id != payload.environment_id:
            raise HTTPException(422, "Invalid parent network zone")
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    await write_audit(db, user, "network_zone.updated", "network_zone", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/discovery-policies")
async def list_discovery_policies(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("discovery_policies.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _page(
        db,
        DiscoveryPolicy,
        [DiscoveryPolicy.organization_id == user.organization_id],
        page,
        page_size,
        DiscoveryPolicy.name,
    )


@router.post("/discovery-policies", status_code=201)
async def create_discovery_policy(
    payload: DiscoveryPolicyPayload,
    user: User = Depends(require_permission("discovery_policies.manage")),
    db: AsyncSession = Depends(get_db),
):
    if payload.allow_udp_discovery:
        raise HTTPException(422, "UDP discovery is not available in this phase")
    row = DiscoveryPolicy(
        organization_id=user.organization_id, created_by=user.id, **payload.model_dump()
    )
    db.add(row)
    await write_audit(db, user, "discovery_policy.created", "discovery_policy", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/networks")
async def list_networks(
    environment_id: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("networks.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [Network.organization_id == user.organization_id]
    if environment_id:
        where.append(Network.environment_id == environment_id)
    return await _page(db, Network, where, page, page_size, Network.name)


@router.post("/networks", status_code=201)
async def create_network(
    payload: NetworkPayload,
    user: User = Depends(require_permission("networks.manage")),
    db: AsyncSession = Depends(get_db),
):
    await _environment(db, payload.environment_id, user.organization_id)
    zone = await _tenant_row(db, NetworkZone, payload.network_zone_id, user.organization_id)
    if zone.environment_id != payload.environment_id:
        raise HTTPException(422, "Network zone belongs to another environment")
    if payload.discovery_policy_id:
        await _tenant_row(db, DiscoveryPolicy, payload.discovery_policy_id, user.organization_id)
    authorized = await _network_authorized(db, user.organization_id, payload.cidr)
    if payload.scan_allowed and not authorized:
        raise HTTPException(403, "Network is not covered by an active authorized scope")
    network_value = ipaddress.ip_network(payload.cidr, strict=False)
    row = Network(
        organization_id=user.organization_id,
        ip_version=network_value.version,
        **payload.model_dump(),
    )
    db.add(row)
    await write_audit(
        db,
        user,
        "network.created",
        "network",
        row.id,
        metadata={"scan_allowed": row.scan_allowed, "scope_authorized": authorized},
    )
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/networks/{network_id}")
async def get_network(
    network_id: str,
    user: User = Depends(require_permission("networks.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, Network, network_id, user.organization_id)


@router.patch("/networks/{network_id}")
async def patch_network(
    network_id: str,
    payload: NetworkPayload,
    user: User = Depends(require_permission("networks.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, Network, network_id, user.organization_id)
    await _environment(db, payload.environment_id, user.organization_id)
    zone = await _tenant_row(db, NetworkZone, payload.network_zone_id, user.organization_id)
    if zone.environment_id != payload.environment_id:
        raise HTTPException(422, "Network zone belongs to another environment")
    if payload.discovery_policy_id:
        await _tenant_row(db, DiscoveryPolicy, payload.discovery_policy_id, user.organization_id)
    authorized = await _network_authorized(db, user.organization_id, payload.cidr)
    if payload.scan_allowed and not authorized:
        raise HTTPException(403, "Network is not covered by an active authorized scope")
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    row.ip_version = ipaddress.ip_network(payload.cidr).version
    await write_audit(db, user, "network.updated", "network", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/assets/{asset_id}")
async def get_asset_360(
    asset_id: str,
    user: User = Depends(require_permission("assets.read")),
    db: AsyncSession = Depends(get_db),
):
    asset = await _tenant_row(db, Asset, asset_id, user.organization_id)
    services = list(
        (
            await db.scalars(
                select(Service).where(
                    Service.organization_id == user.organization_id,
                    Service.asset_id == asset.id,
                )
            )
        ).all()
    )
    findings = list(
        (
            await db.scalars(
                select(Finding).where(
                    Finding.organization_id == user.organization_id,
                    Finding.asset_id == asset.id,
                )
            )
        ).all()
    )
    return {"asset": asset, "services": services, "findings": findings}


@router.patch("/assets/{asset_id}")
async def patch_asset(
    asset_id: str,
    payload: AssetPatch,
    user: User = Depends(require_permission("assets.manage")),
    db: AsyncSession = Depends(get_db),
):
    asset = await _tenant_row(db, Asset, asset_id, user.organization_id)
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        previous = getattr(asset, key)
        if previous != value:
            db.add(
                AssetChange(
                    organization_id=user.organization_id,
                    asset_id=asset.id,
                    change_type=(
                        "criticality_changed"
                        if key == "business_criticality"
                        else (
                            "exposure_changed"
                            if key == "internet_exposed"
                            else "ownership_changed" if key == "ownership" else f"{key}_changed"
                        )
                    ),
                    field_name=key,
                    previous_value=previous,
                    current_value=value,
                    severity="medium",
                )
            )
            setattr(asset, key, value)
    await write_audit(db, user, "asset.updated", "asset", asset.id)
    await db.commit()
    await db.refresh(asset)
    return asset


async def _asset_subresource(
    db: AsyncSession, user: User, asset_id: str, model: Any, order: Any
) -> list[Any]:
    await _tenant_row(db, Asset, asset_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(model)
                .where(
                    model.organization_id == user.organization_id,
                    model.asset_id == asset_id,
                )
                .order_by(order)
                .limit(500)
            )
        ).all()
    )


@router.get("/assets/{asset_id}/services")
async def asset_services(
    asset_id: str,
    user: User = Depends(require_permission("services.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _asset_subresource(db, user, asset_id, Service, Service.port)


@router.get("/assets/{asset_id}/software")
async def asset_software(
    asset_id: str,
    user: User = Depends(require_permission("software.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _asset_subresource(
        db, user, asset_id, SoftwareInstance, SoftwareInstance.last_seen_at.desc()
    )


@router.get("/assets/{asset_id}/vulnerabilities")
async def asset_vulnerabilities(
    asset_id: str,
    user: User = Depends(require_permission("vulnerabilities.read")),
    db: AsyncSession = Depends(get_db),
):
    matches = await _asset_subresource(
        db, user, asset_id, VulnerabilityMatch, VulnerabilityMatch.last_seen_at.desc()
    )
    return {"items": matches}


@router.get("/assets/{asset_id}/relationships")
async def asset_relationships(
    asset_id: str,
    user: User = Depends(require_permission("assets.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, Asset, asset_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(AssetRelationship).where(
                    AssetRelationship.organization_id == user.organization_id,
                    or_(
                        AssetRelationship.source_asset_id == asset_id,
                        AssetRelationship.target_asset_id == asset_id,
                    ),
                )
            )
        ).all()
    )


@router.post("/asset-relationships", status_code=201)
async def create_asset_relationship(
    payload: RelationshipPayload,
    user: User = Depends(require_permission("assets.manage")),
    db: AsyncSession = Depends(get_db),
):
    from cyberaudit.asset_graph import ALLOWED_RELATIONSHIPS

    if payload.relationship_type not in ALLOWED_RELATIONSHIPS:
        raise HTTPException(422, "Unsupported relationship type")
    await _tenant_row(db, Asset, payload.source_asset_id, user.organization_id)
    await _tenant_row(db, Asset, payload.target_asset_id, user.organization_id)
    row = AssetRelationship(organization_id=user.organization_id, **payload.model_dump())
    db.add(row)
    await write_audit(db, user, "asset_relationship.created", "asset_relationship", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/assets/{asset_id}/changes")
@router.get("/assets/{asset_id}/timeline")
async def asset_changes(
    asset_id: str,
    user: User = Depends(require_permission("asset_changes.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _asset_subresource(db, user, asset_id, AssetChange, AssetChange.detected_at.desc())


@router.get("/asset-changes")
async def list_asset_changes(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("asset_changes.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _page(
        db,
        AssetChange,
        [AssetChange.organization_id == user.organization_id],
        page,
        page_size,
        AssetChange.created_at.desc(),
    )


@router.get("/assets/{asset_id}/risk")
async def asset_risk(
    asset_id: str,
    user: User = Depends(require_permission("risk.read")),
    db: AsyncSession = Depends(get_db),
):
    asset = await _tenant_row(db, Asset, asset_id, user.organization_id)
    findings = list(
        (
            await db.scalars(
                select(Finding).where(
                    Finding.organization_id == user.organization_id,
                    Finding.asset_id == asset_id,
                    Finding.status == "open",
                )
            )
        ).all()
    )
    severity = {"low": 25, "medium": 50, "high": 75, "critical": 100}
    maximum = max(
        [severity.get(str(finding.technical_severity), 20) for finding in findings],
        default=0,
    )
    result = risk_engine.calculate(
        RiskContext(
            asset_criticality=severity.get(asset.business_criticality, 50),
            exposure=90 if asset.internet_exposed else 30,
            reachability=90 if asset.internet_exposed else 30,
            vulnerability_severity=maximum,
            vulnerability_confidence=asset.confidence * 100,
            asset_owner=bool(asset.owner),
            evidence_quality=asset.confidence * 100,
        )
    )
    asset.risk_score = result.overall_risk_score
    await db.commit()
    return result


@router.get("/assets/{asset_id}/coverage")
async def asset_coverage(
    asset_id: str,
    user: User = Depends(require_permission("coverage.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _asset_subresource(
        db, user, asset_id, AssessmentCoverage, AssessmentCoverage.assessment_category
    )


@router.get("/asset-graph")
async def asset_graph(
    asset_id: str | None = None,
    limit: int = Query(200, ge=1, le=500),
    user: User = Depends(require_permission("assets.read")),
    db: AsyncSession = Depends(get_db),
):
    service = CyberAssetGraphService(PostgreSQLAssetGraphRepository(db))
    return await service.graph(user.organization_id, asset_id, limit)


@router.get("/services")
async def list_services(
    state: str | None = None,
    exposure: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("services.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [Service.organization_id == user.organization_id]
    if state:
        where.append(Service.state == state)
    if exposure:
        where.append(Service.exposure == exposure)
    return await _page(db, Service, where, page, page_size, Service.last_seen_at.desc())


@router.get("/services/{service_id}")
async def get_service(
    service_id: str,
    user: User = Depends(require_permission("services.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, Service, service_id, user.organization_id)


@router.get("/services/{service_id}/changes")
async def service_changes(
    service_id: str,
    user: User = Depends(require_permission("asset_changes.read")),
    db: AsyncSession = Depends(get_db),
):
    service = await _tenant_row(db, Service, service_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(AssetChange).where(
                    AssetChange.organization_id == user.organization_id,
                    AssetChange.asset_id == service.asset_id,
                    AssetChange.current_value["port"].as_integer() == service.port,
                )
            )
        ).all()
    )


@router.get("/services/{service_id}/vulnerabilities")
async def service_vulnerabilities(
    service_id: str,
    user: User = Depends(require_permission("vulnerabilities.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, Service, service_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(VulnerabilityMatch).where(
                    VulnerabilityMatch.organization_id == user.organization_id,
                    VulnerabilityMatch.service_id == service_id,
                )
            )
        ).all()
    )


@router.get("/vulnerabilities")
async def list_vulnerabilities(
    q: str = "",
    known_exploited: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    _: User = Depends(require_permission("vulnerabilities.read")),
    db: AsyncSession = Depends(get_db),
):
    where: list[Any] = []
    if q:
        where.append(
            or_(
                Vulnerability.external_id.ilike(f"%{q}%"),
                Vulnerability.title.ilike(f"%{q}%"),
            )
        )
    if known_exploited is not None:
        where.append(Vulnerability.known_exploited.is_(known_exploited))
    return await _page(db, Vulnerability, where, page, page_size, Vulnerability.modified_at.desc())


@router.get("/vulnerabilities/{vulnerability_id}")
async def get_vulnerability(
    vulnerability_id: str,
    _: User = Depends(require_permission("vulnerabilities.read")),
    db: AsyncSession = Depends(get_db),
):
    row = await db.get(Vulnerability, vulnerability_id)
    if not row:
        raise HTTPException(404, "Vulnerability not found")
    return row


@router.get("/vulnerability-matches")
async def list_vulnerability_matches(
    status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("vulnerabilities.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [VulnerabilityMatch.organization_id == user.organization_id]
    if status:
        where.append(VulnerabilityMatch.status == status)
    return await _page(
        db, VulnerabilityMatch, where, page, page_size, VulnerabilityMatch.last_seen_at.desc()
    )


async def _review_match(
    db: AsyncSession, user: User, match_id: str, status: str
) -> VulnerabilityMatch:
    match = await _tenant_row(db, VulnerabilityMatch, match_id, user.organization_id)
    match.status = status
    match.requires_manual_validation = False
    match.reviewed_by = user.id
    match.reviewed_at = utcnow()
    await write_audit(db, user, f"vulnerability_match.{status}", "vulnerability_match", match.id)
    await db.commit()
    await db.refresh(match)
    return match


@router.post("/vulnerability-matches/{match_id}/validate")
async def validate_vulnerability_match(
    match_id: str,
    _: MatchReview,
    user: User = Depends(require_permission("vulnerability_matches.review")),
    db: AsyncSession = Depends(get_db),
):
    return await _review_match(db, user, match_id, "confirmed_affected")


@router.post("/vulnerability-matches/{match_id}/reject")
async def reject_vulnerability_match(
    match_id: str,
    _: MatchReview,
    user: User = Depends(require_permission("vulnerability_matches.review")),
    db: AsyncSession = Depends(get_db),
):
    return await _review_match(db, user, match_id, "not_affected")


@router.post("/assets/{asset_id}/correlate-vulnerabilities")
async def correlate_vulnerabilities(
    asset_id: str,
    user: User = Depends(require_permission("vulnerabilities.manage")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, Asset, asset_id, user.organization_id)
    matches = await VulnerabilityIntelligenceService(db).correlate_asset(
        user.organization_id, asset_id
    )
    await write_audit(
        db,
        user,
        "vulnerabilities.correlated",
        "asset",
        asset_id,
        metadata={"matches": len(matches)},
    )
    await db.commit()
    return {"items": matches, "total": len(matches)}


@router.get("/vulnerability-feeds")
async def list_feeds(
    _: User = Depends(require_permission("vulnerability_feeds.read")),
    db: AsyncSession = Depends(get_db),
):
    return {"items": list((await db.scalars(select(VulnerabilityFeed))).all())}


@router.post("/vulnerability-feeds", status_code=201)
async def create_feed(
    payload: FeedPayload,
    user: User = Depends(require_permission("vulnerability_feeds.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = VulnerabilityFeed(**payload.model_dump())
    db.add(row)
    await write_audit(db, user, "vulnerability_feed.created", "vulnerability_feed", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.patch("/vulnerability-feeds/{feed_id}")
async def patch_feed(
    feed_id: str,
    payload: FeedPayload,
    user: User = Depends(require_permission("vulnerability_feeds.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await db.get(VulnerabilityFeed, feed_id)
    if not row:
        raise HTTPException(404, "Feed not found")
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    await write_audit(db, user, "vulnerability_feed.updated", "vulnerability_feed", row.id)
    await db.commit()
    return row


@router.post("/vulnerability-feeds/{feed_id}/sync", status_code=202)
async def sync_feed(
    feed_id: str,
    user: User = Depends(require_permission("vulnerability_feeds.sync")),
    db: AsyncSession = Depends(get_db),
):
    feed = await db.get(VulnerabilityFeed, feed_id)
    if not feed or not feed.enabled:
        raise HTTPException(404, "Enabled feed not found")
    if not feed.source_identifier.startswith("embedded://"):
        raise HTTPException(
            409,
            "External synchronization requires an approved feed connector; only embedded demo is enabled",
        )
    from cyberaudit.phase4_worker import sync_vulnerability_feed

    sync_vulnerability_feed.send(feed.id)
    await write_audit(db, user, "vulnerability_feed.sync_requested", "vulnerability_feed", feed.id)
    await db.commit()
    return {"status": "queued", "feed_id": feed.id}


@router.get("/vulnerability-feeds/{feed_id}/syncs")
async def list_feed_syncs(
    feed_id: str,
    _: User = Depends(require_permission("vulnerability_feeds.read")),
    db: AsyncSession = Depends(get_db),
):
    return {
        "items": list(
            (
                await db.scalars(
                    select(VulnerabilityFeedSync)
                    .where(VulnerabilityFeedSync.feed_id == feed_id)
                    .order_by(VulnerabilityFeedSync.created_at.desc())
                )
            ).all()
        )
    }


@router.get("/attack-paths")
async def list_attack_paths(
    status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("attack_paths.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [AttackPath.organization_id == user.organization_id]
    if status:
        where.append(AttackPath.status == status)
    return await _page(db, AttackPath, where, page, page_size, AttackPath.overall_risk.desc())


@router.post("/attack-paths/analyze", status_code=201)
async def analyze_attack_paths(
    engagement_id: str | None = None,
    user: User = Depends(require_permission("attack_paths.analyze")),
    db: AsyncSession = Depends(get_db),
):
    if engagement_id:
        await _tenant_row(db, Engagement, engagement_id, user.organization_id)
    created = await AttackPathAnalysisService(db).analyze(user.organization_id, engagement_id)
    await write_audit(
        db,
        user,
        "attack_paths.analyzed",
        "attack_path",
        None,
        metadata={"candidate_paths": len(created)},
    )
    await db.commit()
    return {"items": created, "total": len(created), "status": "candidate"}


@router.get("/attack-paths/{path_id}")
async def get_attack_path(
    path_id: str,
    user: User = Depends(require_permission("attack_paths.read")),
    db: AsyncSession = Depends(get_db),
):
    path = await _tenant_row(db, AttackPath, path_id, user.organization_id)
    steps = list(
        (
            await db.scalars(
                select(AttackPathStep)
                .where(AttackPathStep.attack_path_id == path.id)
                .order_by(AttackPathStep.sequence)
            )
        ).all()
    )
    return {"path": path, "steps": steps, "automatic": True, "fact_vs_inference": True}


async def _review_path(db: AsyncSession, user: User, path_id: str, status: str) -> AttackPath:
    path = await _tenant_row(db, AttackPath, path_id, user.organization_id)
    path.status = status
    path.reviewed_by = user.id
    await write_audit(db, user, f"attack_path.{status}", "attack_path", path.id)
    await db.commit()
    await db.refresh(path)
    return path


@router.post("/attack-paths/{path_id}/validate")
async def validate_path(
    path_id: str,
    user: User = Depends(require_permission("attack_paths.review")),
    db: AsyncSession = Depends(get_db),
):
    return await _review_path(db, user, path_id, "validated")


@router.post("/attack-paths/{path_id}/reject")
async def reject_path(
    path_id: str,
    user: User = Depends(require_permission("attack_paths.review")),
    db: AsyncSession = Depends(get_db),
):
    return await _review_path(db, user, path_id, "rejected")


@router.post("/attack-paths/{path_id}/archive")
async def archive_path(
    path_id: str,
    user: User = Depends(require_permission("attack_paths.review")),
    db: AsyncSession = Depends(get_db),
):
    return await _review_path(db, user, path_id, "archived")


async def _risk_overview(db: AsyncSession, organization_id: str) -> dict[str, Any]:
    assets = list(
        (
            await db.scalars(
                select(Asset).where(
                    Asset.organization_id == organization_id,
                    Asset.deleted_at.is_(None),
                )
            )
        ).all()
    )
    scores = [asset.risk_score for asset in assets]
    return {
        "assets": len(assets),
        "overall_risk": round(sum(scores) / max(1, len(scores)), 2),
        "critical_assets": sum(score >= 80 for score in scores),
        "high_assets": sum(60 <= score < 80 for score in scores),
        "internet_exposed": sum(asset.internet_exposed for asset in assets),
        "unmanaged": sum(not asset.managed for asset in assets),
        "calculation_version": risk_engine.version,
    }


@router.get("/risk/overview")
@router.get("/risk/assets")
@router.get("/risk/environments")
@router.get("/risk/networks")
@router.get("/risk/trends")
async def risk_overview(
    user: User = Depends(require_permission("risk.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _risk_overview(db, user.organization_id)


@router.get("/risk-scenarios")
async def list_risk_scenarios(
    user: User = Depends(require_permission("risk.read")),
    db: AsyncSession = Depends(get_db),
):
    return {
        "items": list(
            (
                await db.scalars(
                    select(RiskReductionScenario).where(
                        RiskReductionScenario.organization_id == user.organization_id
                    )
                )
            ).all()
        )
    }


@router.post("/risk-scenarios", status_code=201)
async def create_risk_scenario(
    payload: RiskScenarioPayload,
    user: User = Depends(require_permission("risk_scenarios.create")),
    db: AsyncSession = Depends(get_db),
):
    row = RiskReductionScenario(
        organization_id=user.organization_id,
        created_by=user.id,
        **payload.model_dump(),
    )
    db.add(row)
    await write_audit(db, user, "risk_scenario.created", "risk_scenario", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/risk-scenarios/{scenario_id}")
async def get_risk_scenario(
    scenario_id: str,
    user: User = Depends(require_permission("risk.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, RiskReductionScenario, scenario_id, user.organization_id)


@router.post("/risk-scenarios/{scenario_id}/calculate")
async def calculate_risk_scenario(
    scenario_id: str,
    user: User = Depends(require_permission("risk_scenarios.create")),
    db: AsyncSession = Depends(get_db),
):
    scenario = await _tenant_row(db, RiskReductionScenario, scenario_id, user.organization_id)
    findings = list(
        (
            await db.scalars(
                select(Finding).where(
                    Finding.organization_id == user.organization_id,
                    Finding.status == "open",
                )
            )
        ).all()
    )
    weights = {"low": 20, "medium": 45, "high": 70, "critical": 95}
    baseline = sum(weights.get(str(item.technical_severity), 20) for item in findings)
    selected = {finding.id for finding in findings if finding.id in scenario.selected_findings}
    removed = sum(
        weights.get(str(finding.technical_severity), 20)
        for finding in findings
        if finding.id in selected
    )
    scenario.baseline_risk = baseline
    scenario.projected_risk = max(0, baseline - removed)
    scenario.absolute_reduction = removed
    scenario.percentage_reduction = 0 if baseline == 0 else round(removed / baseline * 100, 2)
    scenario.calculation_version = risk_engine.version
    await write_audit(db, user, "risk_scenario.calculated", "risk_scenario", scenario.id)
    await db.commit()
    return {
        "scenario": scenario,
        "statement": (
            f"Corrigir as ações selecionadas poderá reduzir o risco estimado "
            f"em {scenario.percentage_reduction:.1f}%."
        ),
        "immutable_projection": True,
    }


@router.delete("/risk-scenarios/{scenario_id}", status_code=204)
async def delete_risk_scenario(
    scenario_id: str,
    user: User = Depends(require_permission("risk.manage")),
    db: AsyncSession = Depends(get_db),
):
    scenario = await _tenant_row(db, RiskReductionScenario, scenario_id, user.organization_id)
    await db.delete(scenario)
    await write_audit(db, user, "risk_scenario.deleted", "risk_scenario", scenario.id)
    await db.commit()


@router.get("/assessment-coverage")
async def list_coverage(
    status: str | None = None,
    user: User = Depends(require_permission("coverage.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [AssessmentCoverage.organization_id == user.organization_id]
    if status:
        where.append(AssessmentCoverage.status == status)
    return {"items": list((await db.scalars(select(AssessmentCoverage).where(*where))).all())}


@router.get("/assessment-coverage/summary")
async def coverage_summary(
    user: User = Depends(require_permission("coverage.read")),
    db: AsyncSession = Depends(get_db),
):
    rows = list(
        (
            await db.scalars(
                select(AssessmentCoverage).where(
                    AssessmentCoverage.organization_id == user.organization_id
                )
            )
        ).all()
    )
    by_category: dict[str, list[float]] = {}
    for row in rows:
        by_category.setdefault(row.assessment_category, []).append(row.coverage_score)
    return {
        "overall": round(sum(row.coverage_score for row in rows) / max(1, len(rows)), 2),
        "by_category": {
            category: round(sum(scores) / len(scores), 2)
            for category, scores in by_category.items()
        },
        "stale": sum(
            bool(row.next_recommended_at and row.next_recommended_at < utcnow()) for row in rows
        ),
        "blocked": sum(row.status == "blocked" for row in rows),
    }


@router.get("/assessment-schedules")
async def list_schedules(
    user: User = Depends(require_permission("assessment_schedules.read")),
    db: AsyncSession = Depends(get_db),
):
    return {
        "items": list(
            (
                await db.scalars(
                    select(AssessmentSchedule).where(
                        AssessmentSchedule.organization_id == user.organization_id
                    )
                )
            ).all()
        )
    }


@router.post("/assessment-schedules", status_code=201)
async def create_schedule(
    payload: SchedulePayload,
    user: User = Depends(require_permission("assessment_schedules.manage")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, Engagement, payload.engagement_id, user.organization_id)
    await _tenant_row(db, ScanProfile, payload.scan_profile_id, user.organization_id)
    row = AssessmentSchedule(
        organization_id=user.organization_id,
        created_by=user.id,
        **payload.model_dump(),
    )
    db.add(row)
    await write_audit(db, user, "assessment_schedule.created", "assessment_schedule", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.patch("/assessment-schedules/{schedule_id}")
async def patch_schedule(
    schedule_id: str,
    payload: SchedulePayload,
    user: User = Depends(require_permission("assessment_schedules.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, AssessmentSchedule, schedule_id, user.organization_id)
    await _tenant_row(db, Engagement, payload.engagement_id, user.organization_id)
    await _tenant_row(db, ScanProfile, payload.scan_profile_id, user.organization_id)
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    await write_audit(db, user, "assessment_schedule.updated", "assessment_schedule", row.id)
    await db.commit()
    return row


async def _toggle_schedule(
    db: AsyncSession, user: User, schedule_id: str, enabled: bool
) -> AssessmentSchedule:
    row = await _tenant_row(db, AssessmentSchedule, schedule_id, user.organization_id)
    row.enabled = enabled
    await write_audit(
        db,
        user,
        "assessment_schedule.resumed" if enabled else "assessment_schedule.paused",
        "assessment_schedule",
        row.id,
    )
    await db.commit()
    return row


@router.post("/assessment-schedules/{schedule_id}/pause")
async def pause_schedule(
    schedule_id: str,
    user: User = Depends(require_permission("assessment_schedules.manage")),
    db: AsyncSession = Depends(get_db),
):
    return await _toggle_schedule(db, user, schedule_id, False)


@router.post("/assessment-schedules/{schedule_id}/resume")
async def resume_schedule(
    schedule_id: str,
    user: User = Depends(require_permission("assessment_schedules.manage")),
    db: AsyncSession = Depends(get_db),
):
    return await _toggle_schedule(db, user, schedule_id, True)


@router.delete("/assessment-schedules/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str,
    user: User = Depends(require_permission("assessment_schedules.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, AssessmentSchedule, schedule_id, user.organization_id)
    await db.delete(row)
    await write_audit(db, user, "assessment_schedule.deleted", "assessment_schedule", row.id)
    await db.commit()


@router.get("/notifications")
async def list_notifications(
    unread_only: bool = False,
    user: User = Depends(require_permission("notifications.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [
        Notification.organization_id == user.organization_id,
        or_(Notification.user_id.is_(None), Notification.user_id == user.id),
    ]
    if unread_only:
        where.append(Notification.read_at.is_(None))
    return {
        "items": list(
            (
                await db.scalars(
                    select(Notification)
                    .where(*where)
                    .order_by(Notification.created_at.desc())
                    .limit(100)
                )
            ).all()
        )
    }


@router.post("/notifications/{notification_id}/read")
async def read_notification(
    notification_id: str,
    user: User = Depends(require_permission("notifications.read")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, Notification, notification_id, user.organization_id)
    if row.user_id not in {None, user.id}:
        raise HTTPException(404, "Notification not found")
    row.read_at = utcnow()
    await db.commit()
    return row


@router.get("/command-center")
async def command_center(
    user: User = Depends(require_permission("risk.read")),
    db: AsyncSession = Depends(get_db),
):
    assets = list(
        (
            await db.scalars(
                select(Asset).where(
                    Asset.organization_id == user.organization_id,
                    Asset.deleted_at.is_(None),
                )
            )
        ).all()
    )
    services = list(
        (
            await db.scalars(select(Service).where(Service.organization_id == user.organization_id))
        ).all()
    )
    findings = list(
        (
            await db.scalars(select(Finding).where(Finding.organization_id == user.organization_id))
        ).all()
    )
    vulnerabilities = list((await db.scalars(select(Vulnerability))).all())
    coverage = list(
        (
            await db.scalars(
                select(AssessmentCoverage).where(
                    AssessmentCoverage.organization_id == user.organization_id
                )
            )
        ).all()
    )
    running_jobs = await db.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(
            ScanJob.organization_id == user.organization_id,
            ScanJob.status.in_(
                [
                    JobStatus.QUEUED,
                    JobStatus.STARTING,
                    JobStatus.RUNNING,
                    JobStatus.PROCESSING_RESULTS,
                ]
            ),
        )
    )
    return {
        "security_posture": max(
            0, round(100 - sum(asset.risk_score for asset in assets) / max(1, len(assets)), 1)
        ),
        "exposure_score": round(
            sum(asset.exposure_score for asset in assets) / max(1, len(assets)), 1
        ),
        "assets": len(assets),
        "new_assets": sum(asset.lifecycle_status == "discovered" for asset in assets),
        "unmanaged_assets": sum(not asset.managed for asset in assets),
        "internet_exposed_assets": sum(asset.internet_exposed for asset in assets),
        "open_services": sum(service.state == "open" for service in services),
        "critical_findings": sum(
            str(finding.technical_severity) == "critical" and finding.status == "open"
            for finding in findings
        ),
        "known_exploited": sum(item.known_exploited for item in vulnerabilities),
        "coverage": round(sum(item.coverage_score for item in coverage) / max(1, len(coverage)), 1),
        "running_jobs": running_jobs or 0,
        "top_assets": sorted(
            [{"id": asset.id, "name": asset.name, "risk": asset.risk_score} for asset in assets],
            key=lambda item: cast(float, item["risk"]),
            reverse=True,
        )[:5],
    }


@router.get("/system-health")
async def system_health(
    _: User = Depends(require_permission("system_health.read")),
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()
    database_ok = bool(await db.scalar(select(func.count()).select_from(Asset)) is not None)
    redis_ok = False
    try:
        client = redis.from_url(settings.redis_url, socket_timeout=1)
        redis_ok = bool(await client.ping())
        await client.aclose()
    except (OSError, redis.RedisError):
        redis_ok = False
    latest_sync = await db.scalar(
        select(VulnerabilityFeedSync).order_by(VulnerabilityFeedSync.created_at.desc())
    )
    return {
        "status": "healthy" if database_ok and redis_ok else "degraded",
        "components": {
            "api": "healthy",
            "frontend": "unknown",
            "postgresql": "healthy" if database_ok else "unavailable",
            "redis": "healthy" if redis_ok else "unavailable",
            "workers": "unknown",
            "runners": "contract_only",
            "storage": "healthy" if settings.upload_dir.exists() else "unknown",
            "vulnerability_feeds": (latest_sync.status if latest_sync else "unknown"),
            "scheduler": "contract_only",
            "notifications": "healthy",
            "migrations": "0004",
            "version": "4.0.0-dev",
        },
    }
