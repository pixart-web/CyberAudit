import asyncio
from datetime import date, time, timedelta

from sqlalchemy import select

from cyberaudit.adapters import AdapterRegistry
from cyberaudit.db import SessionLocal
from cyberaudit.models import (
    Client,
    Criticality,
    Engagement,
    EngagementMode,
    EngagementStatus,
    Intensity,
    Organization,
    Permission,
    Role,
    ScanProfile,
    Scope,
    ScopeTarget,
    TargetType,
    ToolAdapterDefinition,
    User,
)

PHASE3_PERMISSIONS = [
    "evidence.read",
    "evidence.download",
    "evidence.manage",
    "imports.read",
    "imports.create",
    "imports.confirm",
    "retests.read",
    "retests.create",
    "asset_observations.read",
    "asset_suggestions.review",
    "network_policies.read",
    "network_policies.manage",
]

ROLE_PERMISSIONS = {
    "Administrator": PHASE3_PERMISSIONS,
    "Auditor": [
        "evidence.read",
        "evidence.download",
        "imports.read",
        "imports.create",
        "imports.confirm",
        "retests.read",
        "retests.create",
        "asset_observations.read",
        "network_policies.read",
    ],
    "Reviewer": [
        "evidence.read",
        "evidence.download",
        "evidence.manage",
        "imports.read",
        "imports.confirm",
        "retests.read",
        "asset_observations.read",
        "asset_suggestions.review",
        "network_policies.read",
    ],
}

PROFILE_DATA = [
    (
        "Inventário básico",
        "asset_inventory",
        "cyberaudit.asset_inventory",
        [TargetType.IP, TargetType.DOMAIN, TargetType.HOSTNAME, TargetType.URL],
        Intensity.PASSIVE,
        20,
        {"sources": ["platform"]},
        "Consolidação local; sem descoberta de rede.",
    ),
    (
        "DNS seguro",
        "dns_assessment",
        "cyberaudit.dns_assessment",
        [TargetType.DOMAIN, TargetType.HOSTNAME],
        Intensity.PASSIVE,
        30,
        {
            "record_types": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"],
            "check_dnssec": True,
        },
        "Até 12 consultas DNS ao nome exato; sem enumeração.",
    ),
    (
        "TLS standard",
        "tls_assessment",
        "cyberaudit.tls_assessment",
        [TargetType.DOMAIN, TargetType.HOSTNAME, TargetType.URL],
        Intensity.PASSIVE,
        20,
        {"port": 443, "expiry_warning_days": 30},
        "Uma ligação TLS e recolha do certificado.",
    ),
    (
        "TLS detalhado",
        "tls_assessment",
        "cyberaudit.tls_assessment",
        [TargetType.DOMAIN, TargetType.HOSTNAME, TargetType.URL],
        Intensity.LOW,
        30,
        {"port": 443, "expiry_warning_days": 60},
        "Inspeção TLS limitada; sem downgrade ou enumeração de ciphers.",
    ),
    (
        "Headers HTTP",
        "http_security_headers",
        "cyberaudit.http_security_headers",
        [TargetType.URL, TargetType.DOMAIN, TargetType.HOSTNAME],
        Intensity.LOW,
        20,
        {"scheme": "https", "path": "/", "fallback_get": True},
        "HEAD e, se necessário, um GET limitado.",
    ),
    (
        "Tecnologias Web",
        "web_technology_detection",
        "cyberaudit.web_technology_detection",
        [TargetType.URL, TargetType.DOMAIN, TargetType.HOSTNAME],
        Intensity.PASSIVE,
        20,
        {"scheme": "https", "path": "/", "inspect_html": True},
        "Uma resposta pública limitada; sem crawling.",
    ),
    (
        "Configuração pública",
        "public_configuration",
        "cyberaudit.public_configuration",
        [TargetType.URL, TargetType.DOMAIN, TargetType.HOSTNAME],
        Intensity.LOW,
        20,
        {"scheme": "https", "endpoint": "/.well-known/security.txt"},
        "Um endpoint escolhido numa lista fechada.",
    ),
    (
        "Importação externa",
        "external_result_import",
        "cyberaudit.external_result_import",
        list(TargetType),
        Intensity.PASSIVE,
        20,
        {"import_id": "00000000-0000-0000-0000-000000000000"},
        "Parsing privado e sem execução; exige preview e confirmação.",
    ),
]


async def seed_phase3() -> None:
    async with SessionLocal() as db:
        organization = await db.scalar(
            select(Organization).where(Organization.slug == "cyberaudit-demo")
        )
        admin = await db.scalar(select(User).where(User.email == "admin@cyberaudit.local"))
        client = (
            await db.scalar(select(Client).where(Client.organization_id == organization.id))
            if organization
            else None
        )
        if not organization or not admin or not client:
            raise RuntimeError("Run Phase 1 and Phase 2 seeds first")
        roles = {
            role.name: role
            for role in (
                await db.scalars(select(Role).where(Role.name.in_(list(ROLE_PERMISSIONS))))
            ).all()
        }
        for code in PHASE3_PERMISSIONS:
            permission = await db.scalar(select(Permission).where(Permission.code == code))
            if not permission:
                permission = Permission(code=code, description=code.replace(".", " ").title())
                db.add(permission)
                await db.flush()
            for role_name, codes in ROLE_PERMISSIONS.items():
                role = roles.get(role_name)
                if role and code in codes and permission not in role.permissions:
                    role.permissions.append(permission)
        registry = AdapterRegistry()
        for metadata in registry.metadata():
            if metadata.code == "cyberaudit.demo_assessment":
                continue
            definition = await db.scalar(
                select(ToolAdapterDefinition).where(ToolAdapterDefinition.code == metadata.code)
            )
            if not definition:
                db.add(
                    ToolAdapterDefinition(
                        code=metadata.code,
                        name=metadata.name,
                        version=metadata.version,
                        category=metadata.category,
                        description=metadata.description,
                        supported_target_types=[
                            item.value for item in metadata.supported_target_types
                        ],
                        supported_intensities=[
                            item.value for item in metadata.supported_intensities
                        ],
                        requires_network=metadata.requires_network,
                        requires_approval=False,
                        default_timeout=metadata.default_timeout,
                        enabled=True,
                        health_status="online",
                        adapter_metadata={
                            "phase": 3,
                            "safe": True,
                            "configuration_schema": metadata.configuration_schema,
                        },
                    )
                )
        for (
            name,
            category,
            adapter_code,
            target_types,
            intensity,
            timeout,
            configuration,
            impact,
        ) in PROFILE_DATA:
            existing = await db.scalar(
                select(ScanProfile).where(
                    ScanProfile.organization_id == organization.id,
                    ScanProfile.name == name,
                )
            )
            if existing:
                continue
            metadata = registry.get(adapter_code).metadata()
            db.add(
                ScanProfile(
                    organization_id=organization.id,
                    name=name,
                    description=f"{metadata.description} Impacto: {impact}",
                    category=category,
                    adapter_code=adapter_code,
                    target_types=[item.value for item in target_types],
                    default_intensity=intensity,
                    maximum_intensity=Intensity.LOW,
                    timeout_seconds=timeout,
                    cpu_limit=0.5,
                    memory_limit_mb=256,
                    network_access=metadata.requires_network,
                    requires_approval=False,
                    enabled=True,
                    configuration_schema=metadata.configuration_schema,
                    default_configuration=configuration,
                    created_by=admin.id,
                )
            )
        laboratory = await db.scalar(
            select(Engagement).where(
                Engagement.organization_id == organization.id,
                Engagement.code == "LAB-PHASE3",
            )
        )
        scope: Scope | None
        if not laboratory:
            laboratory = Engagement(
                organization_id=organization.id,
                client_id=client.id,
                name="Laboratório Seguro Fase 3",
                code="LAB-PHASE3",
                description="Serviços locais controlados, sem destinos externos.",
                mode=EngagementMode.LABORATORY,
                status=EngagementStatus.ACTIVE,
                start_date=date.today() - timedelta(days=1),
                end_date=date.today() + timedelta(days=90),
                owner_id=admin.id,
                risk_level=Criticality.LOW,
            )
            db.add(laboratory)
            await db.flush()
            scope = Scope(
                organization_id=organization.id,
                engagement_id=laboratory.id,
                name="Serviços locais controlados",
                description="Loopback e endpoints Docker explicitamente registados.",
                status="active",
                allowed_start_time=time(0),
                allowed_end_time=time(23, 59),
                maximum_intensity=Intensity.LOW,
                allowed_techniques=[
                    "asset-inventory",
                    "dns-assessment",
                    "tls-assessment",
                    "http-security-headers",
                    "web-technology-detection",
                    "public-configuration",
                    "external-result-import",
                ],
            )
            db.add(scope)
            await db.flush()
            db.add_all(
                [
                    ScopeTarget(
                        scope_id=scope.id,
                        target_type=TargetType.HOSTNAME,
                        target_value="localhost",
                        normalized_value="localhost",
                        allowed=True,
                    ),
                    ScopeTarget(
                        scope_id=scope.id,
                        target_type=TargetType.IP,
                        target_value="127.0.0.1",
                        normalized_value="127.0.0.1",
                        allowed=True,
                    ),
                    ScopeTarget(
                        scope_id=scope.id,
                        target_type=TargetType.URL,
                        target_value="http://localhost:8080",
                        normalized_value="http://localhost:8080/",
                        allowed=True,
                    ),
                ]
            )
        else:
            scope = await db.scalar(
                select(Scope).where(
                    Scope.organization_id == organization.id,
                    Scope.engagement_id == laboratory.id,
                    Scope.name == "Serviços locais controlados",
                )
            )
            if scope:
                url_target = await db.scalar(
                    select(ScopeTarget).where(
                        ScopeTarget.scope_id == scope.id,
                        ScopeTarget.target_type == TargetType.URL,
                    )
                )
                if url_target:
                    url_target.normalized_value = "http://localhost:8080/"
        if scope:
            for path in ["/redirect-local", "/redirect-blocked", "/large", "/slow"]:
                value = f"http://localhost:8080{path}"
                exists = await db.scalar(
                    select(ScopeTarget).where(
                        ScopeTarget.scope_id == scope.id,
                        ScopeTarget.target_type == TargetType.URL,
                        ScopeTarget.normalized_value == value,
                    )
                )
                if not exists:
                    db.add(
                        ScopeTarget(
                            scope_id=scope.id,
                            target_type=TargetType.URL,
                            target_value=value,
                            normalized_value=value,
                            allowed=True,
                            notes="Endpoint controlado do laboratório Fase 3.",
                        )
                    )
        await db.commit()
        print("CyberAudit Phase 3 safe assessment data created.")


if __name__ == "__main__":
    asyncio.run(seed_phase3())
