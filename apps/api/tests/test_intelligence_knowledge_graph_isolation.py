"""Phase 10.4.1 Intelligence + Knowledge Graph Workspace: cross-tenant

isolation for the new single-item GETs (IOC/ThreatIndicator, Knowledge
Node).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.db import get_db
from cyberaudit.enterprise_models import KnowledgeEdge, KnowledgeNode, ThreatIndicator
from cyberaudit.main import app
from cyberaudit.models import Organization, Permission, Role, User
from cyberaudit.security import current_user

ALL_PERMISSIONS = ["threat_intel.read", "knowledge_graph.read"]


async def _permission(db: AsyncSession, code: str) -> Permission:
    existing = await db.scalar(select(Permission).where(Permission.code == code))
    if existing:
        return existing
    permission = Permission(code=code, description=code)
    db.add(permission)
    await db.flush()
    return permission


async def _tenant(db: AsyncSession, suffix: str) -> tuple[Organization, User]:
    organization = Organization(name=f"Intel Tenant {suffix}", slug=f"intel-tenant-{suffix}")
    db.add(organization)
    await db.flush()
    role = Role(
        name=f"IntelOperator-{suffix}",
        permissions=[await _permission(db, code) for code in ALL_PERMISSIONS],
    )
    db.add(role)
    user = User(
        organization_id=organization.id,
        name=f"Intel Operator {suffix}",
        email=f"intel-operator-{suffix}@example.invalid",
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
async def test_ioc_detail_is_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "ioc-a")
    org_b, _ = await _tenant(db, "ioc-b")
    indicator_b = ThreatIndicator(
        organization_id=org_b.id,
        indicator_type="ip",
        display_value="10.0.0.1",
        value_hash="a" * 64,
    )
    db.add(indicator_b)
    await db.flush()

    response = await _request(db, user_a, f"/api/v1/iocs/{indicator_b.id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_knowledge_node_detail_is_tenant_scoped_including_its_edges(db: AsyncSession):
    org_a, user_a = await _tenant(db, "kg-a")
    org_b, _ = await _tenant(db, "kg-b")
    node_b1 = KnowledgeNode(
        organization_id=org_b.id,
        node_type="finding",
        source_id="finding-b-1",
        label="tenant b node 1",
    )
    node_b2 = KnowledgeNode(
        organization_id=org_b.id, node_type="asset", source_id="asset-b-1", label="tenant b node 2"
    )
    db.add_all([node_b1, node_b2])
    await db.flush()
    db.add(
        KnowledgeEdge(
            organization_id=org_b.id,
            source_node_id=node_b1.id,
            target_node_id=node_b2.id,
            edge_type="affects",
        )
    )
    await db.flush()

    response = await _request(db, user_a, f"/api/v1/knowledge-nodes/{node_b1.id}")
    assert response.status_code == 404
