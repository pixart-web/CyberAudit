from __future__ import annotations

import inspect
import re
import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import HTTPException
from fastapi.params import Param
from fastapi.routing import APIRoute
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.db import get_db
from cyberaudit.execution_api import list_profiles
from cyberaudit.main import (
    app,
    change_engagement_status,
    create_asset,
    create_client,
    create_engagement,
    create_scope,
    create_target,
    create_user,
)
from cyberaudit.models import (
    Criticality,
    EngagementMode,
    EngagementStatus,
    Organization,
    Permission,
    Role,
    TargetType,
    User,
)
from cyberaudit.rls import set_tenant_context
from cyberaudit.schemas import (
    AssetCreate,
    ClientCreate,
    EngagementCreate,
    ScopeCreate,
    StateChange,
    TargetCreate,
    UserCreate,
)
from cyberaudit.security import current_user


def _api_routes() -> list[APIRoute]:
    routes: list[APIRoute] = []
    pending = list(app.routes)
    while pending:
        route = pending.pop()
        if isinstance(route, APIRoute):
            routes.append(route)
            continue
        nested_router = getattr(route, "original_router", None)
        if nested_router is not None:
            pending.extend(nested_router.routes)
    return routes


def _permission_codes() -> set[str]:
    codes: set[str] = set()
    for route in _api_routes():
        pending = list(route.dependant.dependencies)
        while pending:
            dependency = pending.pop()
            pending.extend(dependency.dependencies)
            call = dependency.call
            if getattr(call, "__qualname__", "") != "require_permission.<locals>.dependency":
                continue
            for cell in call.__closure__ or ():
                if isinstance(cell.cell_contents, str):
                    codes.add(cell.cell_contents)
    return codes


def _operator() -> User:
    role = Role(
        id=str(uuid.uuid4()),
        name="API contract operator",
        description="Test-only role exercising authenticated collection contracts",
    )
    role.permissions = [
        Permission(id=str(uuid.uuid4()), code=code, description="")
        for code in sorted(_permission_codes())
    ]
    user = User(
        id=str(uuid.uuid4()),
        organization_id=str(uuid.uuid4()),
        name="Contract Operator",
        email="contract-operator@example.invalid",
        password_hash="not-used",  # noqa: S106 -- inert test value
        status="active",
    )
    user.roles = [role]
    return user


@pytest.mark.asyncio
async def test_authenticated_get_routes_have_safe_empty_tenant_contract(
    db: AsyncSession,
) -> None:
    """GET APIs deny foreign identifiers and expose safe empty tenant collections."""

    operator = _operator()
    await set_tenant_context(db, operator.organization_id)

    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    async def override_user() -> User:
        return operator

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[current_user] = override_user
    paths = sorted(
        {
            route.path
            for route in _api_routes()
            if "GET" in route.methods and route.path.startswith("/api/v1/")
        }
    )
    excluded = {
        "/api/v1/auth/me",  # single-resource endpoint, covered by authentication tests
        "/api/v1/operations/health",  # exercises configured external dependencies
    }
    identifier = str(uuid.uuid4())

    def request_path(path: str) -> str:
        replacements = {
            "code": "unknown-adapter",
            "collection": "users",
            "service": "microsoft365",
        }
        result = path
        for parameter in re.findall(r"{([^}]+)}", path):
            result = result.replace(f"{{{parameter}}}", replacements.get(parameter, identifier))
        if result == "/api/v1/scope-targets":
            result = f"{result}?scope_id={identifier}"
        return result

    failures: list[str] = []
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as client:
            for path in paths:
                if path in excluded:
                    continue
                response = await client.get(request_path(path))
                static_route_failed = (
                    "{" not in path
                    and path != "/api/v1/scope-targets"
                    and response.status_code != 200
                )
                if (
                    static_route_failed
                    or response.status_code in {301, 302, 307, 308, 401, 403}
                    or response.status_code >= 500
                ):
                    failures.append(f"{path}: {response.status_code} {response.text[:200]}")
    finally:
        app.dependency_overrides.clear()

    assert not failures, "\n".join(failures)


@pytest.mark.asyncio
async def test_scan_profile_collection_is_tenant_scoped(db: AsyncSession) -> None:
    result = await list_profiles(
        q="",
        page_number=1,
        page_size=20,
        user=_operator(),
        db=db,
    )
    assert result == {"items": [], "total": 0, "page": 1, "page_size": 20}


@pytest.mark.asyncio
async def test_phase_one_crud_chain_preserves_tenant_ownership(db: AsyncSession) -> None:
    organization = Organization(name="Contract Tenant", slug="contract-tenant")
    db.add(organization)
    await db.flush()
    role = Role(name="Auditor", description="Contract role")
    actor = User(
        organization_id=organization.id,
        name="Contract Administrator",
        email="contract-admin@example.invalid",
        password_hash="not-used",  # noqa: S106 -- inert test value
        status="active",
    )
    db.add_all([role, actor])
    await db.flush()
    await set_tenant_context(db, organization.id)

    client = await create_client(
        ClientCreate(name="Contract Client", legal_name="Contract Client, Lda."),
        actor,
        db,
    )
    engagement = await create_engagement(
        EngagementCreate(
            client_id=client.id,
            name="Authorized Contract Assessment",
            code="CONTRACT-001",
            mode=EngagementMode.LABORATORY,
            owner_id=actor.id,
            risk_level=Criticality.MEDIUM,
        ),
        actor,
        db,
    )
    engagement = await change_engagement_status(
        engagement.id,
        StateChange(status=EngagementStatus.PENDING_AUTHORIZATION),
        actor,
        db,
    )
    scope = await create_scope(
        ScopeCreate(
            engagement_id=engagement.id,
            name="Private laboratory scope",
            allowed_techniques=["demo_assessment"],
        ),
        actor,
        db,
    )
    target = await create_target(
        TargetCreate(
            scope_id=scope.id,
            target_type=TargetType.CIDR,
            target_value="10.10.0.0/24",
        ),
        actor,
        db,
    )
    asset = await create_asset(
        AssetCreate(
            engagement_id=engagement.id,
            name="Synthetic host",
            asset_type="server",
            identifier="contract-host-01",
            ip_address="10.10.0.10",
        ),
        actor,
        db,
    )
    created_user = await create_user(
        UserCreate(
            name="Contract Auditor",
            email="contract-auditor@example.com",
            password="A-Unique-Contract-Password-2026!",  # noqa: S106 -- test credential
            role="Auditor",
        ),
        actor,
        db,
    )

    assert engagement.organization_id == organization.id
    assert scope.organization_id == organization.id
    assert target.normalized_value == "10.10.0.0/24"
    assert asset.organization_id == organization.id
    assert created_user.organization_id == organization.id


@pytest.mark.asyncio
async def test_get_handlers_enforce_empty_tenant_contract_directly(db: AsyncSession) -> None:
    """Exercise handler-level tenant filters independently from ASGI middleware."""

    operator = _operator()
    await set_tenant_context(db, operator.organization_id)
    identifier = str(uuid.uuid4())
    excluded = {
        "/api/v1/auth/me",
        "/api/v1/jobs/{job_id}/stream",
        "/api/v1/operations/health",
    }
    failures: list[str] = []
    for route in _api_routes():
        if (
            "GET" not in route.methods
            or not route.path.startswith("/api/v1/")
            or route.path in excluded
        ):
            continue
        kwargs: dict[str, object] = {}
        for parameter in inspect.signature(route.endpoint).parameters.values():
            if parameter.name == "db":
                kwargs[parameter.name] = db
            elif parameter.name == "user":
                kwargs[parameter.name] = operator
            elif parameter.name in {"pagination_values", "values"}:
                kwargs[parameter.name] = (1, 20)
            elif parameter.name == "collection":
                kwargs[parameter.name] = "users"
            elif parameter.name == "service":
                kwargs[parameter.name] = "microsoft365"
            elif parameter.name == "code":
                kwargs[parameter.name] = "unknown-adapter"
            elif parameter.default is not inspect.Parameter.empty:
                default = parameter.default
                kwargs[parameter.name] = default.default if isinstance(default, Param) else default
            else:
                kwargs[parameter.name] = identifier
        try:
            result = route.endpoint(**kwargs)
            if inspect.isawaitable(result):
                await result
        except HTTPException as exc:
            if exc.status_code not in {404, 422}:
                failures.append(f"{route.path}: unexpected HTTP {exc.status_code}")
        except Exception as exc:  # noqa: BLE001 -- aggregates contract failures
            failures.append(f"{route.path}: {type(exc).__name__}: {exc}")

    assert not failures, "\n".join(failures)
