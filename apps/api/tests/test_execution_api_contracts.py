from __future__ import annotations

import pytest
from fastapi import HTTPException

from cyberaudit.execution_api import (
    adapter_health,
    create_profile,
    get_adapter,
    get_job,
    job_events,
    job_results,
    list_adapters,
    list_profiles,
    patch_profile,
    tenant_profile,
)
from cyberaudit.execution_schemas import ScanProfileCreate, ScanProfilePatch
from cyberaudit.models import (
    Client,
    Engagement,
    EngagementMode,
    EventType,
    Intensity,
    JobEvent,
    JobStatus,
    Organization,
    RawResult,
    ScanJob,
    Scope,
    TargetType,
    ToolAdapterDefinition,
    User,
)


@pytest.mark.asyncio
async def test_scan_profile_and_adapter_api_contracts_are_tenant_scoped(db) -> None:
    organization = Organization(name="Execution Tenant", slug="execution-tenant")
    db.add(organization)
    await db.flush()
    operator = User(
        organization_id=organization.id,
        name="Execution Operator",
        email="execution-operator@example.com",
        password_hash="not-used",  # noqa: S106 -- inert test value
        status="active",
    )
    db.add(operator)
    await db.flush()
    definition = ToolAdapterDefinition(
        code="cyberaudit.demo_assessment",
        name="Demo Assessment",
        version="1.0.0",
        category="demo",
        description="Safe deterministic assessment",
        supported_target_types=[TargetType.IP],
        supported_intensities=[Intensity.PASSIVE, Intensity.LOW, Intensity.NORMAL],
        requires_network=False,
        requires_approval=False,
        default_timeout=45,
        enabled=True,
        health_status="unknown",
        adapter_metadata={"simulated": True},
    )
    db.add(definition)
    await db.flush()

    profile = await create_profile(
        ScanProfileCreate(
            name="Safe demo profile",
            description="Controlled test profile",
            category="demo",
            adapter_code="cyberaudit.demo_assessment",
            target_types=[TargetType.IP],
            default_intensity=Intensity.LOW,
            maximum_intensity=Intensity.NORMAL,
            timeout_seconds=30,
            default_configuration={
                "scenario": "clean",
                "duration_seconds": 10,
                "finding_count": 0,
            },
        ),
        operator,
        db,
    )
    page = await list_profiles("demo", 1, 20, operator, db)
    assert page["total"] == 1
    assert page["items"][0].organization_id == organization.id
    assert (await tenant_profile(db, profile.id, organization.id)).id == profile.id
    with pytest.raises(HTTPException) as foreign:
        await tenant_profile(db, profile.id, "00000000-0000-4000-8000-000000000099")
    assert foreign.value.status_code == 404

    patched = await patch_profile(
        profile.id,
        ScanProfilePatch(
            description="Updated controlled profile",
            requires_approval=True,
            default_configuration={
                "scenario": "warning",
                "duration_seconds": 10,
                "finding_count": 1,
            },
        ),
        operator,
        db,
    )
    assert patched.requires_approval is True
    assert patched.default_configuration["scenario"] == "warning"

    adapters = await list_adapters(operator, db)
    demo = next(item for item in adapters if item["code"] == "cyberaudit.demo_assessment")
    assert demo["enabled"] is True
    assert (await get_adapter("cyberaudit.demo_assessment", operator)).code == demo["code"]
    with pytest.raises(HTTPException) as unknown:
        await get_adapter("user.supplied.adapter", operator)
    assert unknown.value.status_code == 404

    health = await adapter_health("cyberaudit.demo_assessment", operator, db)
    assert health.healthy is True
    await db.refresh(definition)
    assert definition.health_status == "online"
    invalid_payload = ScanProfileCreate(
        name="Invalid adapter profile",
        category="demo",
        adapter_code="user.supplied.adapter",
        target_types=[TargetType.IP],
        timeout_seconds=30,
    )
    with pytest.raises(HTTPException) as unknown_profile:
        await create_profile(invalid_payload, operator, db)
    assert unknown_profile.value.status_code == 422
    with pytest.raises(HTTPException) as invalid_configuration:
        await create_profile(
            invalid_payload.model_copy(
                update={
                    "adapter_code": "cyberaudit.demo_assessment",
                    "default_configuration": {"command": "not-allowed"},
                }
            ),
            operator,
            db,
        )
    assert invalid_configuration.value.status_code == 422
    with pytest.raises(HTTPException) as network_escalation:
        await create_profile(
            invalid_payload.model_copy(
                update={
                    "adapter_code": "cyberaudit.demo_assessment",
                    "network_access": True,
                    "default_configuration": {},
                }
            ),
            operator,
            db,
        )
    assert network_escalation.value.status_code == 422
    with pytest.raises(HTTPException) as unknown_health:
        await adapter_health("user.supplied.adapter", operator, db)
    assert unknown_health.value.status_code == 404

    client = Client(
        organization_id=organization.id,
        name="Execution Client",
        legal_name="Execution Client",
    )
    db.add(client)
    await db.flush()
    engagement = Engagement(
        organization_id=organization.id,
        client_id=client.id,
        name="Execution Engagement",
        code="EXEC-001",
        mode=EngagementMode.LABORATORY,
        owner_id=operator.id,
    )
    db.add(engagement)
    await db.flush()
    scope = Scope(
        organization_id=organization.id,
        engagement_id=engagement.id,
        name="Execution Scope",
    )
    db.add(scope)
    await db.flush()
    job = ScanJob(
        organization_id=organization.id,
        engagement_id=engagement.id,
        scope_id=scope.id,
        scan_profile_id=profile.id,
        adapter_code="cyberaudit.demo_assessment",
        target_type=TargetType.IP,
        target_value="10.20.0.10",
        normalized_target="10.20.0.10",
        technique="demo_assessment",
        intensity=Intensity.LOW,
        requested_by=operator.id,
        status=JobStatus.COMPLETED,
        progress=100,
        status_message="Synthetic completion",
        result_summary={"simulated": True},
    )
    db.add(job)
    await db.flush()
    db.add(
        JobEvent(
            organization_id=organization.id,
            job_id=job.id,
            event_type=EventType.CREATED,
            message="Synthetic event",
        )
    )
    await db.commit()

    assert (await get_job(job.id, operator, db)).id == job.id
    events = await job_events(job.id, operator, db)
    assert [event.message for event in events] == ["Synthetic event"]
    results = await job_results(job.id, operator, db)
    assert results["summary"] == {"simulated": True}
    assert results["findings"] == []
    assert results["raw_result"] is None
    raw_result = RawResult(
        organization_id=organization.id,
        job_id=job.id,
        adapter_code=job.adapter_code,
        format="application/json",
        content_hash="a" * 64,
        sanitized=True,
        size_bytes=2,
        untrusted_content="{}",
    )
    db.add(raw_result)
    await db.commit()
    results_with_raw = await job_results(job.id, operator, db)
    assert results_with_raw["raw_result"] == {
        "id": raw_result.id,
        "format": "application/json",
        "content_hash": "a" * 64,
        "size_bytes": 2,
        "sanitized": True,
        "untrusted": True,
    }
