import asyncio
from datetime import datetime, time, timedelta, timezone

from sqlalchemy import select

from cyberaudit.adapters import DemoAssessmentAdapter
from cyberaudit.db import SessionLocal
from cyberaudit.models import (
    Approval,
    ApprovalStatus,
    Criticality,
    Engagement,
    EngagementStatus,
    EventType,
    Finding,
    Intensity,
    JobEvent,
    JobPriority,
    JobStatus,
    Organization,
    Permission,
    Role,
    ScanJob,
    ScanProfile,
    Scope,
    TargetType,
    ToolAdapterDefinition,
    User,
)
from cyberaudit.security import hash_password

EXECUTION_PERMISSIONS = [
    "scan_profiles.read",
    "scan_profiles.manage",
    "adapters.read",
    "adapters.manage",
    "jobs.read",
    "jobs.create",
    "jobs.cancel",
    "jobs.retry",
    "approvals.read",
    "approvals.request",
    "approvals.review",
    "findings.read",
    "findings.manage",
]


async def seed_jobs() -> None:
    async with SessionLocal() as db:
        organization = await db.scalar(
            select(Organization).where(Organization.slug == "cyberaudit-demo")
        )
        user = await db.scalar(select(User).where(User.email == "admin@cyberaudit.local"))
        if not organization or not user:
            raise RuntimeError("Run the Phase 1 seed before seed-jobs")
        engagement = await db.scalar(
            select(Engagement).where(
                Engagement.organization_id == organization.id,
                Engagement.status == EngagementStatus.ACTIVE,
            )
        )
        if not engagement:
            raise RuntimeError("Run the Phase 1 seed before seed-jobs")
        scope = await db.scalar(
            select(Scope).where(
                Scope.organization_id == organization.id,
                Scope.engagement_id == engagement.id,
            )
        )
        if not scope:
            raise RuntimeError("Demo scope missing")
        scope.allowed_start_time = time(0, 0)
        scope.allowed_end_time = time(23, 59)
        roles = {
            role.name: role
            for role in (
                await db.scalars(
                    select(Role).where(Role.name.in_(["Administrator", "Auditor", "Reviewer"]))
                )
            ).all()
        }
        if "Administrator" not in roles:
            raise RuntimeError("Administrator role missing")
        role_permissions = {
            "Administrator": EXECUTION_PERMISSIONS,
            "Auditor": [
                "scan_profiles.read",
                "adapters.read",
                "jobs.read",
                "jobs.create",
                "jobs.cancel",
                "jobs.retry",
                "approvals.read",
                "approvals.request",
                "findings.read",
            ],
            "Reviewer": [
                "scan_profiles.read",
                "adapters.read",
                "jobs.read",
                "approvals.read",
                "approvals.review",
                "findings.read",
                "findings.manage",
            ],
        }
        for code in EXECUTION_PERMISSIONS:
            permission = await db.scalar(select(Permission).where(Permission.code == code))
            if not permission:
                permission = Permission(code=code, description=code.replace(".", " ").title())
                db.add(permission)
                await db.flush()
            for role_name, codes in role_permissions.items():
                role = roles.get(role_name)
                if role and code in codes and permission not in role.permissions:
                    role.permissions.append(permission)
        auditor = await db.scalar(select(User).where(User.email == "auditor@cyberaudit.local"))
        if not auditor and "Auditor" in roles:
            db.add(
                User(
                    organization_id=organization.id,
                    name="Auditor Demo",
                    email="auditor@cyberaudit.local",
                    password_hash=hash_password("ChangeMe123!"),
                    roles=[roles["Auditor"]],
                )
            )
        adapter = await db.scalar(
            select(ToolAdapterDefinition).where(
                ToolAdapterDefinition.code == "cyberaudit.demo_assessment"
            )
        )
        metadata = DemoAssessmentAdapter().metadata()
        if not adapter:
            adapter = ToolAdapterDefinition(
                code=metadata.code,
                name=metadata.name,
                version=metadata.version,
                category=metadata.category,
                description=metadata.description,
                supported_target_types=[item.value for item in metadata.supported_target_types],
                supported_intensities=[item.value for item in metadata.supported_intensities],
                requires_network=False,
                requires_approval=False,
                default_timeout=metadata.default_timeout,
                enabled=True,
                health_status="online",
                last_health_check_at=datetime.now(timezone.utc),
                adapter_metadata={"simulated": True},
            )
            db.add(adapter)
        profile = await db.scalar(
            select(ScanProfile).where(
                ScanProfile.organization_id == organization.id,
                ScanProfile.name == "Avaliação Segura de Demonstração",
            )
        )
        if not profile:
            profile = ScanProfile(
                organization_id=organization.id,
                name="Avaliação Segura de Demonstração",
                description="Simulação determinística, sem rede ou subprocessos.",
                category="simulation",
                adapter_code=metadata.code,
                target_types=[TargetType.IP.value, TargetType.CIDR.value],
                default_intensity=Intensity.NORMAL,
                maximum_intensity=Intensity.NORMAL,
                timeout_seconds=45,
                cpu_limit=0.5,
                memory_limit_mb=128,
                network_access=False,
                requires_approval=False,
                enabled=True,
                configuration_schema=metadata.configuration_schema,
                default_configuration={
                    "scenario": "mixed",
                    "duration_seconds": 10,
                    "finding_count": 3,
                },
                created_by=user.id,
            )
            db.add(profile)
            await db.flush()
        existing_job = await db.scalar(
            select(ScanJob).where(
                ScanJob.organization_id == organization.id,
                ScanJob.status == JobStatus.COMPLETED,
            )
        )
        if not existing_job:
            completed = ScanJob(
                organization_id=organization.id,
                engagement_id=engagement.id,
                scope_id=scope.id,
                scan_profile_id=profile.id,
                adapter_code=metadata.code,
                target_type=TargetType.IP,
                target_value="10.20.0.10",
                normalized_target="10.20.0.10",
                technique="asset-discovery",
                intensity=Intensity.NORMAL,
                configuration=profile.default_configuration,
                status=JobStatus.COMPLETED,
                priority=JobPriority.NORMAL,
                requested_by=user.id,
                approved_by=user.id,
                queued_at=datetime.now(timezone.utc) - timedelta(minutes=12),
                started_at=datetime.now(timezone.utc) - timedelta(minutes=11),
                completed_at=datetime.now(timezone.utc) - timedelta(minutes=10),
                progress=100,
                status_message="Avaliação simulada concluída",
                worker_id="seed-worker",
                result_summary={"simulated": True, "findings_created": 1},
            )
            running = ScanJob(
                organization_id=organization.id,
                engagement_id=engagement.id,
                scope_id=scope.id,
                scan_profile_id=profile.id,
                adapter_code=metadata.code,
                target_type=TargetType.IP,
                target_value="10.20.0.20",
                normalized_target="10.20.0.20",
                technique="configuration-review",
                intensity=Intensity.LOW,
                configuration=profile.default_configuration,
                status=JobStatus.RUNNING,
                priority=JobPriority.NORMAL,
                requested_by=user.id,
                progress=54,
                status_message="Execução simulada",
                worker_id="seed-worker",
            )
            pending = ScanJob(
                organization_id=organization.id,
                engagement_id=engagement.id,
                scope_id=scope.id,
                scan_profile_id=profile.id,
                adapter_code=metadata.code,
                target_type=TargetType.IP,
                target_value="10.20.0.30",
                normalized_target="10.20.0.30",
                technique="sensitive-demo",
                intensity=Intensity.ELEVATED,
                configuration=profile.default_configuration,
                status=JobStatus.PENDING_APPROVAL,
                priority=JobPriority.HIGH,
                requested_by=user.id,
                progress=5,
                status_message="A aguardar aprovação",
            )
            db.add_all([completed, running, pending])
            await db.flush()
            approval = Approval(
                organization_id=organization.id,
                engagement_id=engagement.id,
                job_id=pending.id,
                requested_by=user.id,
                approval_type="scan_job",
                reason="Cenário simulado de aprovação",
                risk_summary={"target": pending.target_value, "simulated": True},
                status=ApprovalStatus.PENDING,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            db.add(approval)
            await db.flush()
            pending.approval_id = approval.id
            for job in [completed, running, pending]:
                db.add(
                    JobEvent(
                        organization_id=organization.id,
                        job_id=job.id,
                        event_type=EventType.CREATED,
                        severity="info",
                        message="Evento simulado de seed",
                        event_metadata={"simulated": True},
                    )
                )
            db.add(
                Finding(
                    organization_id=organization.id,
                    engagement_id=engagement.id,
                    job_id=completed.id,
                    title="[SIMULADO] Autenticação multifator desativada",
                    description="Finding fictício criado pelo seed.",
                    category="identity",
                    technical_severity=Criticality.CRITICAL,
                    confidence="high",
                    status="open",
                    affected_component="10.20.0.10",
                    technical_impact="Simulado.",
                    business_impact="Sem impacto real.",
                    remediation_summary="Ativar MFA no cenário fictício.",
                    validation_steps=["Confirmar configuração simulada."],
                    source_adapter=metadata.code,
                    fingerprint="seed-" + "0" * 59,
                    evidence=[{"kind": "simulation", "simulated": True}],
                )
            )
        await db.commit()
        print("CyberAudit Phase 2 demo data created.")


if __name__ == "__main__":
    asyncio.run(seed_jobs())
