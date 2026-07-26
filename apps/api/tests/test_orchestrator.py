from datetime import date, datetime, time, timedelta, timezone

import pytest

from cyberaudit.adapters import AdapterRegistry, DemoAssessmentAdapter
from cyberaudit.execution_schemas import JobCreate
from cyberaudit.models import (
    Approval,
    ApprovalStatus,
    AuthorizationDocument,
    Client,
    Criticality,
    Engagement,
    EngagementMode,
    EngagementStatus,
    Intensity,
    JobStatus,
    Organization,
    ScanProfile,
    Scope,
    ScopeTarget,
    TargetType,
    ToolAdapterDefinition,
    User,
)
from cyberaudit.orchestrator import (
    InvalidJobTransition,
    JobOrchestrator,
    transition_job,
    update_progress,
)
from cyberaudit.policy import ScopePolicyEngine
from cyberaudit.security import hash_password


async def domain(db, *, requires_approval: bool = False, adapter_enabled: bool = True):
    org = Organization(name="Tenant A", slug="tenant-a")
    db.add(org)
    await db.flush()
    user = User(
        organization_id=org.id,
        name="Auditor",
        email="auditor@example.test",
        password_hash=hash_password("TestPassword123!"),
    )
    db.add(user)
    await db.flush()
    client = Client(organization_id=org.id, name="Client A")
    db.add(client)
    await db.flush()
    engagement = Engagement(
        organization_id=org.id,
        client_id=client.id,
        name="Authorized",
        code="AUTH-1",
        mode=EngagementMode.CLIENT,
        status=EngagementStatus.ACTIVE,
        owner_id=user.id,
        risk_level=Criticality.MEDIUM,
    )
    db.add(engagement)
    await db.flush()
    scope = Scope(
        organization_id=org.id,
        engagement_id=engagement.id,
        name="Private",
        status="active",
        allowed_start_time=time(0),
        allowed_end_time=time(23, 59),
        timezone="UTC",
        maximum_intensity=Intensity.NORMAL,
        allowed_techniques=["asset-discovery"],
    )
    db.add(scope)
    await db.flush()
    db.add(
        ScopeTarget(
            scope_id=scope.id,
            target_type=TargetType.CIDR,
            target_value="10.20.0.0/24",
            normalized_value="10.20.0.0/24",
            allowed=True,
        )
    )
    db.add(
        AuthorizationDocument(
            organization_id=org.id,
            engagement_id=engagement.id,
            filename="authorization.pdf",
            storage_key=f"{org.id}.pdf",
            file_hash="0" * 64,
            status="valid",
            valid_from=date.today() - timedelta(days=1),
            valid_until=date.today() + timedelta(days=1),
            signed_by="Test",
            uploaded_by=user.id,
        )
    )
    metadata = DemoAssessmentAdapter().metadata()
    db.add(
        ToolAdapterDefinition(
            code=metadata.code,
            name=metadata.name,
            version=metadata.version,
            category=metadata.category,
            description=metadata.description,
            supported_target_types=[item.value for item in metadata.supported_target_types],
            supported_intensities=[item.value for item in metadata.supported_intensities],
            enabled=adapter_enabled,
        )
    )
    profile = ScanProfile(
        organization_id=org.id,
        name="Demo",
        category="simulation",
        adapter_code=metadata.code,
        target_types=[TargetType.IP.value],
        default_intensity=Intensity.NORMAL,
        maximum_intensity=Intensity.NORMAL,
        timeout_seconds=30,
        network_access=False,
        requires_approval=requires_approval,
        configuration_schema=metadata.configuration_schema,
        default_configuration={"scenario": "clean", "duration_seconds": 10, "finding_count": 0},
        created_by=user.id,
    )
    db.add(profile)
    await db.commit()
    return org, user, engagement, scope, profile


def payload(engagement, scope, profile, target="10.20.0.10"):
    return JobCreate(
        engagement_id=engagement.id,
        scope_id=scope.id,
        scan_profile_id=profile.id,
        target_type=TargetType.IP,
        target_value=target,
        technique="asset-discovery",
        intensity=Intensity.NORMAL,
        configuration={},
    )


@pytest.mark.asyncio
async def test_authorized_job_is_queued(db):
    _, user, engagement, scope, profile = await domain(db)
    queued: list[str] = []
    orchestrator = JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), queued.append)
    job = await orchestrator.create_job(db, user, payload(engagement, scope, profile))
    assert job.status == JobStatus.QUEUED
    assert job.progress == 10
    assert queued == [job.id]


@pytest.mark.asyncio
async def test_out_of_scope_job_is_denied_and_not_queued(db):
    _, user, engagement, scope, profile = await domain(db)
    queued: list[str] = []
    job = await JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), queued.append).create_job(
        db, user, payload(engagement, scope, profile, "10.21.0.1")
    )
    assert job.status == JobStatus.DENIED
    assert job.error_code == "POLICY_DENIED"
    assert queued == []


@pytest.mark.asyncio
async def test_profile_can_require_approval(db):
    _, user, engagement, scope, profile = await domain(db, requires_approval=True)
    queued: list[str] = []
    job = await JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), queued.append).create_job(
        db, user, payload(engagement, scope, profile)
    )
    assert job.status == JobStatus.PENDING_APPROVAL
    assert job.approval_id
    assert queued == []


@pytest.mark.asyncio
async def test_disabled_adapter_is_blocked(db):
    _, user, engagement, scope, profile = await domain(db, adapter_enabled=False)
    with pytest.raises(ValueError, match="disabled"):
        await JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), lambda _: None).create_job(
            db, user, payload(engagement, scope, profile)
        )


@pytest.mark.asyncio
async def test_invalid_transition_is_rejected(db):
    _, user, engagement, scope, profile = await domain(db)
    job = await JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), lambda _: None).create_job(
        db, user, payload(engagement, scope, profile)
    )
    with pytest.raises(InvalidJobTransition):
        await transition_job(db, job, JobStatus.COMPLETED, "invalid")


@pytest.mark.asyncio
async def test_progress_never_decreases(db):
    _, user, engagement, scope, profile = await domain(db)
    job = await JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), lambda _: None).create_job(
        db, user, payload(engagement, scope, profile)
    )
    await update_progress(db, job, 20, "forward")
    with pytest.raises(ValueError, match="decrease"):
        await update_progress(db, job, 19, "backward")


@pytest.mark.asyncio
async def test_approval_enqueues_job(db):
    _, user, engagement, scope, profile = await domain(db, requires_approval=True)
    queued: list[str] = []
    orchestrator = JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), queued.append)
    job = await orchestrator.create_job(db, user, payload(engagement, scope, profile))
    approval = await db.get(Approval, job.approval_id)
    assert approval
    approved = await orchestrator.approve(db, approval, user, "Reviewed")
    assert approved.status == JobStatus.QUEUED
    assert approval.status == ApprovalStatus.APPROVED
    assert queued == [job.id]


@pytest.mark.asyncio
async def test_rejected_approval_denies_job(db):
    _, user, engagement, scope, profile = await domain(db, requires_approval=True)
    orchestrator = JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), lambda _: None)
    job = await orchestrator.create_job(db, user, payload(engagement, scope, profile))
    approval = await db.get(Approval, job.approval_id)
    assert approval
    rejected = await orchestrator.reject(db, approval, user, "Risk not accepted")
    assert rejected.status == JobStatus.DENIED
    assert approval.status == ApprovalStatus.REJECTED


@pytest.mark.asyncio
async def test_expired_approval_cannot_enqueue(db):
    _, user, engagement, scope, profile = await domain(db, requires_approval=True)
    orchestrator = JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), lambda _: None)
    job = await orchestrator.create_job(db, user, payload(engagement, scope, profile))
    approval = await db.get(Approval, job.approval_id)
    assert approval
    approval.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    with pytest.raises(ValueError, match="expired"):
        await orchestrator.approve(db, approval, user, None)
    assert approval.status == ApprovalStatus.EXPIRED


@pytest.mark.asyncio
async def test_queued_job_can_be_cancelled(db):
    _, user, engagement, scope, profile = await domain(db)
    orchestrator = JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), lambda _: None)
    job = await orchestrator.create_job(db, user, payload(engagement, scope, profile))
    cancelled = await orchestrator.cancel(db, job, user)
    assert cancelled.status == JobStatus.CANCELLING


@pytest.mark.asyncio
async def test_other_tenant_cannot_cancel_job(db):
    _, user, engagement, scope, profile = await domain(db)
    orchestrator = JobOrchestrator(ScopePolicyEngine(), AdapterRegistry(), lambda _: None)
    job = await orchestrator.create_job(db, user, payload(engagement, scope, profile))
    other_org = Organization(name="Tenant B", slug="tenant-b")
    db.add(other_org)
    await db.flush()
    other_user = User(
        organization_id=other_org.id,
        name="Other",
        email="other@example.test",
        password_hash=hash_password("TestPassword123!"),
    )
    db.add(other_user)
    await db.flush()
    with pytest.raises(ValueError, match="not found"):
        await orchestrator.cancel(db, job, other_user)
