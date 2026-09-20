"""Phase 10.4.1 Cloud/Kubernetes Workspace: cross-tenant isolation for the

new single-item GETs (Cloud Account, Cloud Resource, Kubernetes Cluster,
Kubernetes Object) and the new `?account_id=`/`?cluster_id=` filters --
none of these previously existed, so this is genuinely new attack surface.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.db import get_db
from cyberaudit.domain_expansion_models import (
    CloudAccount,
    CloudResource,
    KubernetesCluster,
    KubernetesObject,
)
from cyberaudit.main import app
from cyberaudit.models import Organization, Permission, Role, User
from cyberaudit.security import current_user

ALL_PERMISSIONS = ["cloud.read", "kubernetes.read"]


async def _permission(db: AsyncSession, code: str) -> Permission:
    existing = await db.scalar(select(Permission).where(Permission.code == code))
    if existing:
        return existing
    permission = Permission(code=code, description=code)
    db.add(permission)
    await db.flush()
    return permission


async def _tenant(db: AsyncSession, suffix: str) -> tuple[Organization, User]:
    organization = Organization(name=f"Cloud Tenant {suffix}", slug=f"cloud-tenant-{suffix}")
    db.add(organization)
    await db.flush()
    role = Role(
        name=f"CloudOperator-{suffix}",
        permissions=[await _permission(db, code) for code in ALL_PERMISSIONS],
    )
    db.add(role)
    user = User(
        organization_id=organization.id,
        name=f"Cloud Operator {suffix}",
        email=f"cloud-operator-{suffix}@example.invalid",
        password_hash="not-used",  # noqa: S106
        status="active",
    )
    user.roles = [role]
    db.add(user)
    await db.flush()
    return organization, user


async def _request(db: AsyncSession, user: User, path: str) -> httpx.Response:
    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    async def override_user() -> User:
        return user

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[current_user] = override_user
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as client:
            return await client.get(path)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_cloud_account_detail_is_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "account-a")
    org_b, _ = await _tenant(db, "account-b")
    account_b = CloudAccount(
        organization_id=org_b.id,
        connector_id="connector-b",
        provider="aws",
        account_type="standard",
        external_id="ext-b-1",
        name="tenant-b-account",
    )
    db.add(account_b)
    await db.flush()

    response = await _request(db, user_a, f"/api/v1/cloud/accounts/{account_b.id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_cloud_resource_detail_and_account_id_filter_are_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "resource-a")
    org_b, _ = await _tenant(db, "resource-b")
    account_b = CloudAccount(
        organization_id=org_b.id,
        connector_id="connector-b",
        provider="aws",
        account_type="standard",
        external_id="ext-b-2",
        name="tenant-b-account-2",
    )
    db.add(account_b)
    await db.flush()
    resource_b = CloudResource(
        organization_id=org_b.id,
        connector_id="connector-b",
        account_id=account_b.id,
        provider="aws",
        external_id="ext-b-resource",
        resource_type="bucket",
        name="tenant-b-bucket",
        configuration_hash="a" * 64,
    )
    db.add(resource_b)
    await db.flush()

    detail = await _request(db, user_a, f"/api/v1/cloud/resources/{resource_b.id}")
    assert detail.status_code == 404

    listed = await _request(db, user_a, f"/api/v1/cloud/resources?account_id={account_b.id}")
    assert listed.status_code == 200
    assert listed.json()["items"] == []


@pytest.mark.asyncio
async def test_kubernetes_cluster_detail_and_workload_filter_are_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "k8s-a")
    org_b, _ = await _tenant(db, "k8s-b")
    cluster_b = KubernetesCluster(
        organization_id=org_b.id,
        connector_id="connector-b",
        external_id="cluster-b-1",
        name="tenant-b-cluster",
        provider="eks",
    )
    db.add(cluster_b)
    await db.flush()
    workload_b = KubernetesObject(
        organization_id=org_b.id,
        cluster_id=cluster_b.id,
        object_type="workload",
        external_id="workload-b-1",
        namespace="default",
        name="tenant-b-workload",
        configuration_hash="b" * 64,
    )
    db.add(workload_b)
    await db.flush()

    cluster_detail = await _request(db, user_a, f"/api/v1/kubernetes/clusters/{cluster_b.id}")
    workload_detail = await _request(db, user_a, f"/api/v1/kubernetes/workloads/{workload_b.id}")
    listed = await _request(db, user_a, f"/api/v1/kubernetes/workloads?cluster_id={cluster_b.id}")

    assert cluster_detail.status_code == 404
    assert workload_detail.status_code == 404
    assert listed.status_code == 200
    assert listed.json()["items"] == []
