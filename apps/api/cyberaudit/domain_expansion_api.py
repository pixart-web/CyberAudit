"""Tenant-isolated REST API for identity, cloud, workload and device posture."""

# mypy: disable-error-code="no-untyped-def"

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, inspect, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.audit import write_audit
from cyberaudit.db import get_db
from cyberaudit.domain_expansion_models import (
    AuthenticationPosture,
    CloudAccount,
    CloudIdentity,
    CloudNetwork,
    CloudResource,
    CloudRole,
    ConnectorCredential,
    ConnectorExecution,
    ContainerRuntimeHost,
    DirectoryObject,
    EndpointDevice,
    EnterpriseChangeEvent,
    EnterpriseConnector,
    EntraObject,
    ExternalGroup,
    ExternalIdentity,
    ExternalPermission,
    ExternalRole,
    IdentityProvider,
    IdentityRelationship,
    KubernetesCluster,
    KubernetesObject,
    MobileDevice,
    RunningContainer,
    SaasPostureObject,
    ZeroTrustAssessment,
    ZeroTrustDimension,
)
from cyberaudit.domain_expansion_services import (
    CONNECTOR_TYPES,
    ConnectorConfiguration,
    ZeroTrustEngine,
    ZeroTrustEvaluationRequest,
    identity_risk_factors,
    secret_reference_fingerprint,
    validate_secret_reference,
)
from cyberaudit.models import User
from cyberaudit.security import require_permission

router = APIRouter(prefix="/api/v1", tags=["enterprise-domains"])


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConnectorPayload(StrictModel):
    connector_type: str
    provider: str = Field(min_length=2, max_length=80)
    name: str = Field(min_length=3, max_length=180)
    description: str = Field(default="", max_length=5000)
    environment_id: str | None = None
    requested_permissions: list[str] = Field(default_factory=list, max_length=100)
    capabilities: list[str] = Field(default_factory=list, max_length=100)
    retention_days: int = Field(default=90, ge=1, le=3650)
    secret_reference: str | None = Field(default=None, max_length=500)

    @field_validator("connector_type")
    @classmethod
    def known_type(cls, value: str) -> str:
        if value not in CONNECTOR_TYPES:
            raise ValueError("Unsupported connector type")
        return value

    @field_validator("secret_reference")
    @classmethod
    def safe_reference(cls, value: str | None) -> str | None:
        return validate_secret_reference(value) if value else value


class ConnectorPatch(StrictModel):
    name: str | None = Field(default=None, min_length=3, max_length=180)
    description: str | None = Field(default=None, max_length=5000)
    requested_permissions: list[str] | None = Field(default=None, max_length=100)
    capabilities: list[str] | None = Field(default=None, max_length=100)
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    enabled: bool | None = None


def serialize(record: Any) -> dict[str, Any]:
    return {
        attribute.key: getattr(record, attribute.key)
        for attribute in inspect(record).mapper.column_attrs
        if attribute.key not in {"secret_reference", "reference_fingerprint"}
    }


def pagination(
    page_number: int = Query(default=1, alias="page", ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> tuple[int, int]:
    return page_number, page_size


async def page(
    db: AsyncSession,
    model: Any,
    organization_id: str,
    values: tuple[int, int],
    *,
    extra: tuple[Any, ...] = (),
    q: str | None = None,
    search_fields: tuple[Any, ...] = (),
) -> dict[str, Any]:
    conditions = [model.organization_id == organization_id, *extra]
    if q and search_fields:
        conditions.append(or_(*(field.ilike(f"%{q}%") for field in search_fields)))
    total = await db.scalar(select(func.count()).select_from(model).where(*conditions))
    rows = list(
        (
            await db.scalars(
                select(model)
                .where(*conditions)
                .order_by(model.created_at.desc())
                .offset((values[0] - 1) * values[1])
                .limit(values[1])
            )
        ).all()
    )
    return {
        "items": [serialize(row) for row in rows],
        "total": total or 0,
        "page": values[0],
        "page_size": values[1],
    }


async def tenant_record(db: AsyncSession, model: Any, record_id: str, organization_id: str) -> Any:
    record = await db.scalar(
        select(model).where(
            model.id == record_id,
            model.organization_id == organization_id,
        )
    )
    if not record:
        raise HTTPException(404, "Resource not found")
    return record


@router.get("/enterprise-connectors")
async def list_connectors(
    q: str | None = Query(default=None, max_length=200),
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_connectors.read")),
):
    return await page(
        db,
        EnterpriseConnector,
        user.organization_id,
        values,
        q=q,
        search_fields=(EnterpriseConnector.name, EnterpriseConnector.provider),
    )


@router.post("/enterprise-connectors", status_code=201)
async def create_connector(
    payload: ConnectorPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_connectors.manage")),
):
    ConnectorConfiguration.model_validate(
        {
            **payload.model_dump(
                exclude={"name", "description", "environment_id", "secret_reference"}
            ),
            "read_only": True,
        }
    )
    connector = EnterpriseConnector(
        organization_id=user.organization_id,
        connector_type=payload.connector_type,
        provider=payload.provider,
        name=payload.name,
        description=payload.description,
        environment_id=payload.environment_id,
        requested_permissions=payload.requested_permissions,
        capabilities=payload.capabilities,
        retention_days=payload.retention_days,
        read_only=True,
        status="active",
        created_by=user.id,
    )
    db.add(connector)
    await db.flush()
    if payload.secret_reference:
        credential = ConnectorCredential(
            organization_id=user.organization_id,
            connector_id=connector.id,
            credential_type="secret_manager_reference",
            secret_reference=payload.secret_reference,
            reference_fingerprint=secret_reference_fingerprint(payload.secret_reference),
            created_by=user.id,
        )
        db.add(credential)
        await db.flush()
        connector.credential_id = credential.id
    await write_audit(
        db,
        user,
        "enterprise_connector.created",
        "enterprise_connector",
        connector.id,
        metadata={"connector_type": connector.connector_type, "read_only": True},
    )
    await db.commit()
    return serialize(connector)


@router.get("/enterprise-connectors/{connector_id}")
async def get_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_connectors.read")),
):
    return serialize(
        await tenant_record(db, EnterpriseConnector, connector_id, user.organization_id)
    )


@router.patch("/enterprise-connectors/{connector_id}")
async def update_connector(
    connector_id: str,
    payload: ConnectorPatch,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_connectors.manage")),
):
    connector = await tenant_record(db, EnterpriseConnector, connector_id, user.organization_id)
    changes = payload.model_dump(exclude_unset=True)
    enabled = changes.pop("enabled", None)
    for key, value in changes.items():
        setattr(connector, key, value)
    if enabled is not None:
        connector.status = "active" if enabled else "disabled"
        connector.disabled_at = None if enabled else datetime.now(timezone.utc)
    await write_audit(
        db, user, "enterprise_connector.updated", "enterprise_connector", connector.id
    )
    await db.commit()
    return serialize(connector)


@router.delete("/enterprise-connectors/{connector_id}", status_code=204)
async def disable_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_connectors.manage")),
):
    connector = await tenant_record(db, EnterpriseConnector, connector_id, user.organization_id)
    connector.status = "disabled"
    connector.disabled_at = datetime.now(timezone.utc)
    await write_audit(
        db, user, "enterprise_connector.disabled", "enterprise_connector", connector.id
    )
    await db.commit()


@router.post("/enterprise-connectors/{connector_id}/test")
async def test_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_connectors.execute")),
):
    connector = await tenant_record(db, EnterpriseConnector, connector_id, user.organization_id)
    connector.health_status = "ready"
    connector.last_health_check_at = datetime.now(timezone.utc)
    await write_audit(
        db,
        user,
        "enterprise_connector.tested",
        "enterprise_connector",
        connector.id,
        metadata={"result": "local_configuration_valid", "external_io": False},
    )
    await db.commit()
    return {
        "status": "ready",
        "external_connection_attempted": False,
        "message": "Local read-only configuration is valid.",
    }


@router.get("/enterprise-connectors/{connector_id}/health")
async def connector_health(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_connectors.read")),
):
    connector = await tenant_record(db, EnterpriseConnector, connector_id, user.organization_id)
    return {
        "status": connector.health_status,
        "last_checked_at": connector.last_health_check_at,
        "read_only": connector.read_only,
    }


@router.post("/enterprise-connectors/{connector_id}/sync", status_code=202)
async def sync_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_connectors.execute")),
):
    connector = await tenant_record(db, EnterpriseConnector, connector_id, user.organization_id)
    if connector.status != "active" or not connector.read_only:
        raise HTTPException(409, "Connector must be active and read-only")
    now = datetime.now(timezone.utc)
    key_material = f"{connector.id}|{now.isoformat()}|{user.id}"
    execution = ConnectorExecution(
        organization_id=user.organization_id,
        connector_id=connector.id,
        execution_type="incremental_sync",
        status="queued",
        idempotency_key=hashlib.sha256(key_material.encode()).hexdigest(),
        requested_by=user.id,
        result_summary={"external_io": False, "mode": "controlled_import"},
    )
    db.add(execution)
    await db.flush()
    await write_audit(
        db, user, "enterprise_connector.sync_queued", "connector_execution", execution.id
    )
    await db.commit()
    from cyberaudit.domain_expansion_worker import process_connector_execution

    process_connector_execution.send(execution.id)
    return serialize(execution)


@router.get("/enterprise-connectors/{connector_id}/executions")
async def connector_executions(
    connector_id: str,
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_connectors.read")),
):
    await tenant_record(db, EnterpriseConnector, connector_id, user.organization_id)
    return await page(
        db,
        ConnectorExecution,
        user.organization_id,
        values,
        extra=(ConnectorExecution.connector_id == connector_id,),
    )


@router.get("/identity/providers")
async def identity_providers(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.read")),
):
    return await page(db, IdentityProvider, user.organization_id, values)


@router.get("/identity/users")
async def identity_users(
    q: str | None = Query(default=None, max_length=200),
    privileged: bool | None = None,
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.read")),
):
    filters = (ExternalIdentity.privileged == privileged,) if privileged is not None else ()
    return await page(
        db,
        ExternalIdentity,
        user.organization_id,
        values,
        q=q,
        search_fields=(ExternalIdentity.username, ExternalIdentity.display_name),
        extra=filters,
    )


@router.get("/identity/users/{identity_id}")
async def identity_user(
    identity_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.read")),
):
    return serialize(await tenant_record(db, ExternalIdentity, identity_id, user.organization_id))


async def _identity_page(
    model: Any, values: tuple[int, int], db: AsyncSession, user: User
) -> dict[str, Any]:
    return await page(db, model, user.organization_id, values)


@router.get("/identity/groups")
async def identity_groups(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.read")),
):
    return await _identity_page(ExternalGroup, values, db, user)


@router.get("/identity/roles")
async def identity_roles(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.read")),
):
    return await _identity_page(ExternalRole, values, db, user)


@router.get("/identity/permissions")
async def identity_permissions(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.read")),
):
    return await _identity_page(ExternalPermission, values, db, user)


@router.get("/identity/relationships")
async def identity_relationships(
    identity_id: str | None = Query(default=None, max_length=36),
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.read")),
):
    extra = (
        (
            or_(
                IdentityRelationship.source_id == identity_id,
                IdentityRelationship.target_id == identity_id,
            ),
        )
        if identity_id
        else ()
    )
    return await page(db, IdentityRelationship, user.organization_id, values, extra=extra)


@router.get("/identity/posture")
async def identity_posture(
    identity_id: str | None = Query(default=None, max_length=36),
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.posture.read")),
):
    extra = (AuthenticationPosture.identity_id == identity_id,) if identity_id else ()
    return await page(db, AuthenticationPosture, user.organization_id, values, extra=extra)


def _stale_days(identity: ExternalIdentity) -> int | None:
    """Days since this identity was last seen active, from whichever

    timestamp the source connector actually populated. `None` (not 0)
    when neither is known -- identity_risk_factors() correctly treats
    "unknown" as not triggering the stale-account factor, rather than
    silently scoring an identity with no activity data as fresh.
    """
    reference = identity.last_activity_at or identity.last_login_at
    if reference is None:
        return None
    # SQLite (the local/dev database) does not persist tzinfo on a
    # DateTime(timezone=True) column, so a value read back from it comes
    # back naive even though it was written timezone-aware. Treat a naive
    # value as UTC rather than letting the subtraction below raise.
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - reference).days


@router.get("/identity/risk")
async def identity_risk(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.risk.read")),
):
    identities = list(
        (
            await db.scalars(
                select(ExternalIdentity)
                .where(ExternalIdentity.organization_id == user.organization_id)
                .order_by(ExternalIdentity.risk_score.desc())
                .limit(100)
            )
        ).all()
    )
    return {
        "items": [
            {
                "identity": serialize(identity),
                "risk": identity_risk_factors(
                    privileged=identity.privileged,
                    mfa_enforced=identity.mfa_state,
                    enabled=identity.enabled,
                    stale_days=_stale_days(identity),
                    guest=identity.guest,
                    owner=identity.owner,
                ),
            }
            for identity in identities
        ]
    }


@router.get("/identity/users/{identity_id}/risk")
async def identity_user_risk(
    identity_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.risk.read")),
):
    identity = await tenant_record(db, ExternalIdentity, identity_id, user.organization_id)
    score, reasons = identity_risk_factors(
        privileged=identity.privileged,
        mfa_enforced=identity.mfa_state,
        enabled=identity.enabled,
        stale_days=_stale_days(identity),
        guest=identity.guest,
        owner=identity.owner,
    )
    return {"score": score, "reasons": reasons, "calculation_version": "identity-risk-1.0.0"}


@router.get("/identity/graph")
async def identity_graph(
    limit: int = Query(default=200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("identity.graph.read")),
):
    identities = list(
        (
            await db.scalars(
                select(ExternalIdentity)
                .where(ExternalIdentity.organization_id == user.organization_id)
                .limit(limit)
            )
        ).all()
    )
    relationships = list(
        (
            await db.scalars(
                select(IdentityRelationship)
                .where(IdentityRelationship.organization_id == user.organization_id)
                .limit(limit * 2)
            )
        ).all()
    )
    return {
        "nodes": [
            {
                "id": item.id,
                "type": "identity",
                "label": item.display_name,
                "risk": item.risk_score,
            }
            for item in identities
        ],
        "edges": [serialize(item) for item in relationships],
        "truncated": len(identities) == limit,
    }


DIRECTORY_ROUTE_TYPES = {
    "forests": "forest",
    "domains": "domain",
    "organizational-units": "organizational_unit",
    "computers": "computer",
    "trusts": "trust",
    "group-policies": "group_policy",
    "certificate-services": "certificate_service",
    "posture": "posture",
}


@router.get("/identity/active-directory/{collection}")
async def active_directory_collection(
    collection: str,
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("active_directory.read")),
):
    object_type = DIRECTORY_ROUTE_TYPES.get(collection)
    if not object_type:
        raise HTTPException(404, "Unknown Active Directory collection")
    return await page(
        db,
        DirectoryObject,
        user.organization_id,
        values,
        extra=(DirectoryObject.object_type == object_type,),
    )


ENTRA_ROUTE_TYPES = {
    "tenants": "tenant",
    "applications": "application",
    "service-principals": "service_principal",
    "managed-identities": "managed_identity",
    "conditional-access": "conditional_access",
    "oauth-grants": "oauth_grant",
    "posture": "posture",
}


@router.get("/identity/entra/{collection}")
async def entra_collection(
    collection: str,
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("entra.read")),
):
    object_type = ENTRA_ROUTE_TYPES.get(collection)
    if not object_type:
        raise HTTPException(404, "Unknown Entra collection")
    return await page(
        db,
        EntraObject,
        user.organization_id,
        values,
        extra=(EntraObject.object_type == object_type,),
    )


@router.get("/saas/{service}/{collection}")
async def saas_collection(
    service: Literal["microsoft365", "google-workspace"],
    collection: str,
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("saas.read")),
):
    allowed = {
        "microsoft365": {"posture", "exchange", "sharepoint", "teams", "devices"},
        "google-workspace": {"users", "groups", "oauth", "drive", "devices", "posture"},
    }
    if collection not in allowed[service]:
        raise HTTPException(404, "Unknown SaaS collection")
    return await page(
        db,
        SaasPostureObject,
        user.organization_id,
        values,
        extra=(
            SaasPostureObject.service == service,
            SaasPostureObject.object_type == collection,
        ),
    )


async def _cloud_page(
    model: Any,
    values: tuple[int, int],
    db: AsyncSession,
    user: User,
    provider: str | None,
) -> dict[str, Any]:
    extra = (model.provider == provider,) if provider else ()
    return await page(db, model, user.organization_id, values, extra=extra)


@router.get("/cloud/accounts")
async def cloud_accounts(
    provider: str | None = None,
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("cloud.read")),
):
    return await _cloud_page(CloudAccount, values, db, user, provider)


@router.get("/cloud/resources")
async def cloud_resources(
    provider: str | None = None,
    resource_type: str | None = None,
    public_exposure: bool | None = None,
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("cloud.read")),
):
    filters: list[Any] = []
    if provider:
        filters.append(CloudResource.provider == provider)
    if resource_type:
        filters.append(CloudResource.resource_type == resource_type)
    if public_exposure is not None:
        filters.append(CloudResource.public_exposure == public_exposure)
    return await page(db, CloudResource, user.organization_id, values, extra=tuple(filters))


@router.get("/cloud/networks")
async def cloud_networks(
    provider: str | None = None,
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("cloud.read")),
):
    return await _cloud_page(CloudNetwork, values, db, user, provider)


@router.get("/cloud/identities")
async def cloud_identities(
    provider: str | None = None,
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("cloud.read")),
):
    return await _cloud_page(CloudIdentity, values, db, user, provider)


@router.get("/cloud/roles")
async def cloud_roles(
    provider: str | None = None,
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("cloud.read")),
):
    return await _cloud_page(CloudRole, values, db, user, provider)


@router.get("/cloud/posture")
@router.get("/cloud/risk")
async def cloud_posture(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("cloud.posture.read")),
):
    totals = {}
    totals["resources"] = (
        await db.scalar(
            select(func.count())
            .select_from(CloudResource)
            .where(CloudResource.organization_id == user.organization_id)
        )
        or 0
    )
    totals["public_resources"] = (
        await db.scalar(
            select(func.count())
            .select_from(CloudResource)
            .where(
                CloudResource.organization_id == user.organization_id,
                CloudResource.public_exposure.is_(True),
            )
        )
        or 0
    )
    totals["high_risk"] = (
        await db.scalar(
            select(func.count())
            .select_from(CloudResource)
            .where(
                CloudResource.organization_id == user.organization_id,
                CloudResource.risk_score >= 70,
            )
        )
        or 0
    )
    return totals


@router.get("/cloud/changes")
async def cloud_changes(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("cloud.read")),
):
    return await page(
        db,
        EnterpriseChangeEvent,
        user.organization_id,
        values,
        extra=(EnterpriseChangeEvent.domain == "cloud",),
    )


@router.get("/cloud/graph")
async def cloud_graph(
    limit: int = Query(default=200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("cloud.graph.read")),
):
    resources = list(
        (
            await db.scalars(
                select(CloudResource)
                .where(CloudResource.organization_id == user.organization_id)
                .limit(limit)
            )
        ).all()
    )
    return {
        "nodes": [
            {
                "id": item.id,
                "type": item.resource_type,
                "label": item.name,
                "risk": item.risk_score,
            }
            for item in resources
        ],
        "edges": [],
        "truncated": len(resources) == limit,
    }


async def _posture_summary(
    db: AsyncSession,
    model: Any,
    organization_id: str,
    noncompliant_column: Any,
) -> dict[str, int]:
    total = (
        await db.scalar(
            select(func.count()).select_from(model).where(model.organization_id == organization_id)
        )
        or 0
    )
    noncompliant = (
        await db.scalar(
            select(func.count())
            .select_from(model)
            .where(model.organization_id == organization_id, noncompliant_column)
        )
        or 0
    )
    return {"total": total, "non_compliant": noncompliant}


@router.get("/kubernetes/clusters")
async def kubernetes_clusters(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("kubernetes.read")),
):
    return await page(db, KubernetesCluster, user.organization_id, values)


@router.get("/kubernetes/workloads")
@router.get("/kubernetes/rbac")
async def kubernetes_objects(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("kubernetes.read")),
):
    return await page(db, KubernetesObject, user.organization_id, values)


@router.get("/kubernetes/posture")
async def kubernetes_posture(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("kubernetes.posture.read")),
):
    return await _posture_summary(
        db, KubernetesObject, user.organization_id, KubernetesObject.privileged.is_(True)
    )


@router.get("/container-runtime/hosts")
async def runtime_hosts(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("container_runtime.read")),
):
    return await page(db, ContainerRuntimeHost, user.organization_id, values)


@router.get("/container-runtime/containers")
async def runtime_containers(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("container_runtime.read")),
):
    return await page(db, RunningContainer, user.organization_id, values)


@router.get("/container-runtime/posture")
async def runtime_posture(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("container_runtime.posture.read")),
):
    return await _posture_summary(
        db, RunningContainer, user.organization_id, RunningContainer.privileged.is_(True)
    )


@router.get("/endpoints/posture")
async def endpoints_posture(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("endpoints.posture.read")),
):
    return await _posture_summary(
        db,
        EndpointDevice,
        user.organization_id,
        EndpointDevice.compliance_state == "non_compliant",
    )


@router.get("/endpoints")
async def endpoints(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("endpoints.read")),
):
    return await page(db, EndpointDevice, user.organization_id, values)


@router.get("/endpoints/{endpoint_id}")
async def endpoint(
    endpoint_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("endpoints.read")),
):
    return serialize(await tenant_record(db, EndpointDevice, endpoint_id, user.organization_id))


@router.get("/mobile-devices/posture")
async def mobile_posture(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("mobile.posture.read")),
):
    return await _posture_summary(
        db,
        MobileDevice,
        user.organization_id,
        MobileDevice.compliance_state == "non_compliant",
    )


@router.get("/mobile-devices")
async def mobile_devices(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("mobile.read")),
):
    return await page(db, MobileDevice, user.organization_id, values)


@router.get("/mobile-devices/{device_id}")
async def mobile_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("mobile.read")),
):
    return serialize(await tenant_record(db, MobileDevice, device_id, user.organization_id))


@router.post("/zero-trust/evaluate", status_code=201)
async def evaluate_zero_trust(
    payload: ZeroTrustEvaluationRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("zero_trust.evaluate")),
):
    result = ZeroTrustEngine().evaluate(payload)
    assessment = ZeroTrustAssessment(
        organization_id=user.organization_id,
        subject_type=payload.subject_type,
        subject_id=payload.subject_id,
        scope={"evidence_ids": payload.evidence_ids},
        score=result.score,
        status=result.status,
        confidence=result.confidence,
        factors=result.factors,
        unknown_factors=result.unknown_factors,
        recommendations=result.recommendations,
        control_mappings=result.control_mappings,
        algorithm_version=result.algorithm_version,
        evaluated_at=result.evaluated_at,
        requested_by=user.id,
    )
    db.add(assessment)
    await db.flush()
    for dimension in result.dimensions:
        db.add(
            ZeroTrustDimension(
                organization_id=user.organization_id,
                assessment_id=assessment.id,
                **dimension.model_dump(),
            )
        )
    await write_audit(
        db,
        user,
        "zero_trust.evaluated",
        "zero_trust_assessment",
        assessment.id,
        metadata={
            "subject_type": payload.subject_type,
            "score": result.score,
            "confidence": result.confidence,
        },
    )
    await db.commit()
    return {
        **serialize(assessment),
        "dimensions": [item.model_dump() for item in result.dimensions],
    }


@router.get("/zero-trust/overview")
async def zero_trust_overview(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("zero_trust.read")),
):
    latest = await db.scalar(
        select(ZeroTrustAssessment)
        .where(ZeroTrustAssessment.organization_id == user.organization_id)
        .order_by(ZeroTrustAssessment.evaluated_at.desc())
        .limit(1)
    )
    return (
        serialize(latest)
        if latest
        else {
            "status": "insufficient_evidence",
            "score": 0,
            "confidence": 0,
            "unknown_factors": ["assessment_missing"],
        }
    )


@router.get("/zero-trust/assessments")
@router.get("/zero-trust/trends")
async def zero_trust_assessments(
    values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("zero_trust.read")),
):
    return await page(db, ZeroTrustAssessment, user.organization_id, values)


@router.get("/zero-trust/assessments/{assessment_id}")
async def zero_trust_assessment(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("zero_trust.read")),
):
    assessment = await tenant_record(db, ZeroTrustAssessment, assessment_id, user.organization_id)
    dimensions = list(
        (
            await db.scalars(
                select(ZeroTrustDimension).where(
                    ZeroTrustDimension.organization_id == user.organization_id,
                    ZeroTrustDimension.assessment_id == assessment.id,
                )
            )
        ).all()
    )
    return {
        **serialize(assessment),
        "dimensions": [serialize(item) for item in dimensions],
    }
