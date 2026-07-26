import asyncio
from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import select

from cyberaudit.db import Base, SessionLocal, engine
from cyberaudit.models import (
    Asset,
    AuditLog,
    AuthorizationDocument,
    Client,
    Criticality,
    Engagement,
    EngagementMode,
    EngagementStatus,
    Intensity,
    Organization,
    Permission,
    Role,
    Scope,
    ScopeTarget,
    TargetType,
    User,
)
from cyberaudit.security import hash_password

PERMISSIONS = [
    "organizations.read",
    "organizations.manage",
    "clients.read",
    "clients.manage",
    "engagements.read",
    "engagements.manage",
    "scopes.read",
    "scopes.manage",
    "assets.read",
    "assets.manage",
    "authorizations.read",
    "authorizations.manage",
    "jobs.read",
    "jobs.execute",
    "findings.read",
    "findings.manage",
    "reports.read",
    "reports.manage",
    "audit_logs.read",
    "users.manage",
    "roles.manage",
    "scan_profiles.read",
    "scan_profiles.manage",
    "adapters.read",
    "adapters.manage",
    "jobs.create",
    "jobs.cancel",
    "jobs.retry",
    "approvals.read",
    "approvals.request",
    "approvals.review",
]

ROLE_CODES = {
    "Administrator": PERMISSIONS,
    "Auditor": [
        "clients.read",
        "engagements.read",
        "engagements.manage",
        "scopes.read",
        "scopes.manage",
        "assets.read",
        "assets.manage",
        "authorizations.read",
        "authorizations.manage",
        "jobs.read",
        "jobs.execute",
        "findings.read",
        "findings.manage",
    ],
    "Reviewer": [
        "clients.read",
        "engagements.read",
        "scopes.read",
        "assets.read",
        "authorizations.read",
        "findings.read",
        "findings.manage",
        "reports.read",
        "reports.manage",
    ],
    "Client": ["engagements.read", "assets.read", "findings.read", "reports.read"],
}


async def seed() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        existing = await db.scalar(
            select(Organization).where(Organization.slug == "cyberaudit-demo")
        )
        if existing:
            print("Demo data already exists.")
            return
        org = Organization(name="CyberAudit Demo", slug="cyberaudit-demo")
        db.add(org)
        await db.flush()
        permission_objects = {
            code: Permission(code=code, description=code.replace(".", " ").title())
            for code in PERMISSIONS
        }
        db.add_all(permission_objects.values())
        roles = {}
        for name, codes in ROLE_CODES.items():
            role = Role(
                name=name,
                description=f"CyberAudit {name}",
                permissions=[permission_objects[code] for code in codes],
            )
            roles[name] = role
            db.add(role)
        admin = User(
            organization_id=org.id,
            name="Administrador Demo",
            email="admin@cyberaudit.local",
            password_hash=hash_password("ChangeMe123!"),
            roles=[roles["Administrator"]],
        )
        db.add(admin)
        await db.flush()
        client = Client(
            organization_id=org.id,
            name="ACME Corporation",
            legal_name="ACME Corporation Demo, Lda.",
            email="security@acme.invalid",
            status="active",
        )
        db.add(client)
        await db.flush()
        active = Engagement(
            organization_id=org.id,
            client_id=client.id,
            name="Avaliação de Superfície Interna",
            code="ACME-2026-01",
            description="Auditoria autorizada de demonstração.",
            mode=EngagementMode.CLIENT,
            status=EngagementStatus.ACTIVE,
            start_date=date.today() - timedelta(days=7),
            end_date=date.today() + timedelta(days=21),
            owner_id=admin.id,
            risk_level=Criticality.HIGH,
        )
        pending = Engagement(
            organization_id=org.id,
            client_id=client.id,
            name="Revisão Aplicacional Q3",
            code="ACME-2026-02",
            description="A aguardar autorização.",
            mode=EngagementMode.CLIENT,
            status=EngagementStatus.PENDING_AUTHORIZATION,
            start_date=date.today() + timedelta(days=14),
            end_date=date.today() + timedelta(days=35),
            owner_id=admin.id,
            risk_level=Criticality.MEDIUM,
        )
        db.add_all([active, pending])
        await db.flush()
        scope = Scope(
            organization_id=org.id,
            engagement_id=active.id,
            name="Rede privada ACME",
            status="active",
            allowed_start_time=time(0),
            allowed_end_time=time(23, 59),
            maximum_intensity=Intensity.NORMAL,
            allowed_techniques=["asset-discovery", "configuration-review"],
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
                engagement_id=active.id,
                filename="autorizacao-demo.pdf",
                storage_key="seed-placeholder.pdf",
                file_hash="0" * 64,
                status="valid",
                valid_from=date.today() - timedelta(days=10),
                valid_until=date.today() + timedelta(days=30),
                signed_by="Responsável ACME Demo",
                uploaded_by=admin.id,
            )
        )
        for index, (name, ip, criticality) in enumerate(
            [
                ("Identity Gateway", "10.20.0.10", Criticality.CRITICAL),
                ("API Interna", "10.20.0.20", Criticality.HIGH),
                ("Portal Web", "10.20.0.30", Criticality.HIGH),
                ("Servidor de Ficheiros", "10.20.0.40", Criticality.MEDIUM),
                ("Monitorização", "10.20.0.50", Criticality.LOW),
            ]
        ):
            db.add(
                Asset(
                    organization_id=org.id,
                    engagement_id=active.id,
                    name=name,
                    asset_type="host",
                    identifier=f"asset-{index + 1}",
                    hostname=name.lower().replace(" ", "-") + ".internal",
                    ip_address=ip,
                    criticality=criticality,
                    status="active",
                    first_seen_at=datetime.now(timezone.utc),
                    last_seen_at=datetime.now(timezone.utc),
                )
            )
        for action in [
            "auth.login",
            "engagement.created",
            "scope.created",
            "authorization.uploaded",
            "policy.evaluated",
        ]:
            db.add(
                AuditLog(
                    organization_id=org.id,
                    actor_id=admin.id,
                    action=action,
                    resource_type="demo",
                    result="success",
                    event_metadata={"seed": True},
                )
            )
        await db.commit()
        print("CyberAudit demo data created.")


if __name__ == "__main__":
    asyncio.run(seed())
