"""Deterministic, synthetic Phase 5 AppSec demonstration data."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from cyberaudit.adapters import AdapterRegistry
from cyberaudit.db import SessionLocal
from cyberaudit.models import (
    Client,
    Engagement,
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
from cyberaudit.phase4_models import Environment
from cyberaudit.phase5_adapters import PHASE5_ADAPTERS
from cyberaudit.phase5_models import (
    ApiAsset,
    ApiEndpoint,
    ApplicationAsset,
    AppSecException,
    AppSecScore,
    CodeRepository,
    SbomComponent,
    SbomDependency,
    SecretObservation,
    SecurityGateEvaluation,
    SecurityGatePolicy,
    SoftwareBillOfMaterials,
    SoftwareRelease,
)

PHASE5_PERMISSIONS = [
    "applications.read",
    "applications.manage",
    "apis.read",
    "apis.manage",
    "api_specifications.import",
    "repositories.read",
    "repositories.manage",
    "releases.read",
    "releases.manage",
    "sboms.read",
    "sboms.import",
    "secrets.read",
    "secrets.review",
    "security_gates.read",
    "security_gates.manage",
    "security_gates.evaluate",
    "appsec_exceptions.read",
    "appsec_exceptions.request",
    "appsec_exceptions.review",
    "appsec_remediations.read",
    "appsec_remediations.manage",
    "appsec_risk.read",
]

ROLE_PERMISSIONS = {
    "Administrator": PHASE5_PERMISSIONS,
    "Auditor": [
        code
        for code in PHASE5_PERMISSIONS
        if not code.endswith(".review") and code != "security_gates.manage"
    ],
    "Reviewer": [
        "applications.read",
        "apis.read",
        "repositories.read",
        "releases.read",
        "sboms.read",
        "secrets.read",
        "secrets.review",
        "security_gates.read",
        "security_gates.evaluate",
        "appsec_exceptions.read",
        "appsec_exceptions.review",
        "appsec_remediations.read",
        "appsec_remediations.manage",
        "appsec_risk.read",
    ],
    "Client": [
        "applications.read",
        "apis.read",
        "repositories.read",
        "releases.read",
        "sboms.read",
        "security_gates.read",
        "appsec_exceptions.read",
        "appsec_remediations.read",
        "appsec_risk.read",
    ],
}


async def seed_phase5() -> None:
    async with SessionLocal() as db:
        organization = await db.scalar(
            select(Organization).where(Organization.slug == "cyberaudit-demo")
        )
        admin = await db.scalar(select(User).where(User.email == "admin@cyberaudit.local"))
        if not organization or not admin:
            raise RuntimeError("Run the Phase 1 seed first")
        client = await db.scalar(select(Client).where(Client.organization_id == organization.id))
        environment = await db.scalar(
            select(Environment).where(
                Environment.organization_id == organization.id,
                Environment.name == "CyberAudit Lab",
            )
        )
        if not client or not environment:
            raise RuntimeError("Run the Phase 4 seed first")
        laboratory = await db.scalar(
            select(Engagement).where(
                Engagement.organization_id == organization.id,
                Engagement.code == "LAB-PHASE3",
            )
        )
        scope = (
            await db.scalar(
                select(Scope).where(
                    Scope.organization_id == organization.id,
                    Scope.engagement_id == laboratory.id,
                )
            )
            if laboratory
            else None
        )
        if not laboratory or not scope:
            raise RuntimeError("Phase 3 laboratory scope is required")
        scope.allowed_techniques = sorted(
            set(scope.allowed_techniques)
            | {
                "web-inventory",
                "safe-api-assessment",
                "api-contract-analysis",
                "dependency-analysis",
                "secret-detection",
                "software-composition-analysis",
            }
        )
        if not await db.scalar(
            select(ScopeTarget).where(
                ScopeTarget.scope_id == scope.id,
                ScopeTarget.target_type == TargetType.URL,
                ScopeTarget.normalized_value == "http://127.0.0.1:8090/",
            )
        ):
            db.add(
                ScopeTarget(
                    scope_id=scope.id,
                    target_type=TargetType.URL,
                    target_value="http://127.0.0.1:8090/",
                    normalized_value="http://127.0.0.1:8090/",
                    allowed=True,
                    notes="Fixture AppSec estática e sintética em loopback.",
                )
            )

        roles = {
            role.name: role
            for role in (
                await db.scalars(select(Role).where(Role.name.in_(list(ROLE_PERMISSIONS))))
            ).all()
        }
        for code in PHASE5_PERMISSIONS:
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
        phase5_codes = {adapter.metadata().code for adapter in PHASE5_ADAPTERS}
        for metadata in registry.metadata():
            if not metadata.code.startswith("cyberaudit.") or metadata.code in {
                "cyberaudit.demo_assessment"
            }:
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
                        requires_approval=metadata.requires_approval,
                        default_timeout=metadata.default_timeout,
                        enabled=True,
                        health_status="online",
                        last_health_check_at=datetime.now(timezone.utc),
                        adapter_metadata={
                            "phase": 5 if metadata.code in phase5_codes else 4,
                            "safe": True,
                        },
                    )
                )

        profile_specs = [
            (
                "Inventário Web Passivo",
                "cyberaudit.web_inventory",
                "web_inventory",
                [TargetType.URL.value],
                True,
                {"maximum_pages": 1, "maximum_depth": 0, "include_well_known": False},
            ),
            (
                "Revisão de Contrato API",
                "cyberaudit.api_contract_analysis",
                "api_contract",
                [TargetType.REPOSITORY.value],
                False,
                {"declared_controls": {"specification_reviewed": True}},
            ),
            (
                "Deteção Segura de Segredos",
                "cyberaudit.secret_detection",
                "secret_detection",
                [TargetType.REPOSITORY.value],
                False,
                {
                    "filename": "synthetic-demo.env",
                    "content": "DEMO_VALUE=not-a-real-secret",
                },
            ),
            (
                "Análise CycloneDX Offline",
                "cyberaudit.software_composition_analysis",
                "software_composition",
                [TargetType.REPOSITORY.value],
                False,
                {
                    "filename": "bom.json",
                    "content": (
                        '{"bomFormat":"CycloneDX","specVersion":"1.5",'
                        '"components":[],"dependencies":[]}'
                    ),
                },
            ),
        ]
        for name, code, category, target_types, network, configuration in profile_specs:
            if not await db.scalar(
                select(ScanProfile).where(
                    ScanProfile.organization_id == organization.id,
                    ScanProfile.name == name,
                )
            ):
                metadata = registry.get(code).metadata()
                db.add(
                    ScanProfile(
                        organization_id=organization.id,
                        name=name,
                        description=metadata.description,
                        category=category,
                        adapter_code=code,
                        target_types=target_types,
                        default_intensity=Intensity.PASSIVE,
                        maximum_intensity=Intensity.LOW,
                        timeout_seconds=metadata.default_timeout,
                        cpu_limit=0.5,
                        memory_limit_mb=256,
                        network_access=network,
                        requires_approval=False,
                        enabled=True,
                        configuration_schema=metadata.configuration_schema,
                        default_configuration=configuration,
                        created_by=admin.id,
                    )
                )

        application = await db.scalar(
            select(ApplicationAsset).where(
                ApplicationAsset.organization_id == organization.id,
                ApplicationAsset.name == "ACME Customer Portal",
            )
        )
        if not application:
            application = ApplicationAsset(
                organization_id=organization.id,
                client_id=client.id,
                environment_id=environment.id,
                name="ACME Customer Portal",
                description="Aplicação sintética usada exclusivamente no laboratório local.",
                application_type="web",
                architecture_type="modular_monolith",
                lifecycle_status="production",
                internet_exposed=False,
                internal_only=True,
                base_urls=["http://127.0.0.1:8090"],
                repository_urls=["https://example.invalid/acme/customer-portal"],
                owners=["ACME Demo Team"],
                technical_owner="Application Security Demo",
                business_owner="ACME Demo",
                data_classification="synthetic",
                business_criticality="high",
                authentication_type="oidc",
                authorization_model="rbac",
                technology_stack=[
                    {"name": "FastAPI", "type": "backend"},
                    {"name": "Next.js", "type": "frontend"},
                ],
                risk_score=31,
                exposure_score=12,
                appsec_score=82,
                confidence=0.9,
                source="phase5_demo_seed",
                last_assessed_at=datetime.now(timezone.utc),
                tags=["phase5", "synthetic", "local-only"],
                application_metadata={"simulated": True},
            )
            db.add(application)
            await db.flush()
        application.base_urls = ["http://127.0.0.1:8090"]

        api = await db.scalar(
            select(ApiAsset).where(
                ApiAsset.organization_id == organization.id,
                ApiAsset.application_id == application.id,
                ApiAsset.name == "ACME Demo API",
            )
        )
        if not api:
            api = ApiAsset(
                organization_id=organization.id,
                application_id=application.id,
                environment_id=environment.id,
                name="ACME Demo API",
                description="API sintética sem credenciais reais.",
                api_type="rest",
                visibility="local",
                base_url="http://127.0.0.1:8090/api",
                version="1.0.0",
                specification_type="openapi_3_1",
                authentication_type="bearer_demo",
                authorization_model="rbac",
                data_classification="synthetic",
                business_criticality="high",
                owner="Application Security Demo",
                lifecycle_status="production",
                risk_score=28,
                exposure_score=10,
                confidence=0.95,
                source="phase5_demo_seed",
                tags=["synthetic", "local-only"],
                api_metadata={"simulated": True},
            )
            db.add(api)
            await db.flush()
        api.base_url = "http://127.0.0.1:8090/api"
        if not await db.scalar(
            select(ApiEndpoint).where(
                ApiEndpoint.organization_id == organization.id,
                ApiEndpoint.api_id == api.id,
                ApiEndpoint.method == "GET",
                ApiEndpoint.normalized_path == "/customers/{id}",
            )
        ):
            db.add(
                ApiEndpoint(
                    organization_id=organization.id,
                    api_id=api.id,
                    method="GET",
                    path_template="/customers/{customerId}",
                    normalized_path="/customers/{id}",
                    operation_id="getDemoCustomer",
                    summary="Obter cliente sintético",
                    authentication_required=True,
                    authorization_required=True,
                    parameters=[
                        {
                            "name": "customerId",
                            "in": "path",
                            "schema": {"type": "string"},
                        }
                    ],
                    tags=["customers"],
                    sensitive=True,
                    data_categories=["synthetic"],
                    exposure="local",
                    source="phase5_demo_seed",
                    confidence=1,
                )
            )

        repository = await db.scalar(
            select(CodeRepository).where(
                CodeRepository.organization_id == organization.id,
                CodeRepository.repository_identifier == "acme/customer-portal-demo",
            )
        )
        if not repository:
            repository = CodeRepository(
                organization_id=organization.id,
                application_id=application.id,
                provider="demo",
                repository_identifier="acme/customer-portal-demo",
                repository_url="https://example.invalid/acme/customer-portal-demo",
                name="customer-portal-demo",
                default_branch="main",
                visibility="private",
                owner_team="Application Security Demo",
                language_summary={"TypeScript": 60, "Python": 40},
                risk_score=24,
                security_posture=84,
                integration_status="synthetic",
            )
            db.add(repository)
            await db.flush()

        sbom = await db.scalar(
            select(SoftwareBillOfMaterials).where(
                SoftwareBillOfMaterials.organization_id == organization.id,
                SoftwareBillOfMaterials.document_hash
                == hashlib.sha256(b"phase5-synthetic-sbom").hexdigest(),
            )
        )
        if not sbom:
            sbom = SoftwareBillOfMaterials(
                organization_id=organization.id,
                application_id=application.id,
                repository_id=repository.id,
                format="cyclonedx_json",
                specification_version="1.5",
                serial_number="urn:uuid:00000000-0000-4000-8000-000000000005",
                document_hash=hashlib.sha256(b"phase5-synthetic-sbom").hexdigest(),
                component_count=2,
                dependency_count=1,
                direct_dependency_count=1,
                transitive_dependency_count=1,
                generated_by="phase5_demo_seed",
                generated_at=datetime.now(timezone.utc),
                imported=True,
                validated=True,
                validation_errors=[],
            )
            db.add(sbom)
            await db.flush()
            direct = SbomComponent(
                sbom_id=sbom.id,
                component_type="library",
                name="demo-web-framework",
                version="5.0.0",
                purl="pkg:npm/demo-web-framework@5.0.0",
                licenses=["MIT"],
                direct_dependency=True,
                properties={"simulated": True},
            )
            transitive = SbomComponent(
                sbom_id=sbom.id,
                component_type="library",
                name="demo-utility",
                version="2.1.0",
                purl="pkg:npm/demo-utility@2.1.0",
                licenses=["Apache-2.0"],
                direct_dependency=False,
                properties={"simulated": True},
            )
            db.add_all([direct, transitive])
            await db.flush()
            db.add(
                SbomDependency(
                    sbom_id=sbom.id,
                    source_component_id=direct.id,
                    target_component_id=transitive.id,
                )
            )

        release = await db.scalar(
            select(SoftwareRelease).where(
                SoftwareRelease.organization_id == organization.id,
                SoftwareRelease.application_id == application.id,
                SoftwareRelease.version == "2026.07-demo",
            )
        )
        if not release:
            release = SoftwareRelease(
                organization_id=organization.id,
                application_id=application.id,
                repository_id=repository.id,
                version="2026.07-demo",
                commit_hash="0" * 40,
                branch="main",
                tag="v2026.07-demo",
                build_id="demo-build-5",
                artifact_identifier="cyberaudit/acme-portal:demo",
                artifact_hash=hashlib.sha256(b"synthetic-artifact").hexdigest(),
                sbom_id=sbom.id,
                environment_id=environment.id,
                released_at=datetime.now(timezone.utc) - timedelta(days=1),
                status="deployed",
                signed=True,
                signature_verified=True,
                provenance_available=True,
                provenance_verified=True,
            )
            db.add(release)
            await db.flush()
            sbom.release_id = release.id

        secret = await db.scalar(
            select(SecretObservation).where(
                SecretObservation.organization_id == organization.id,
                SecretObservation.repository_id == repository.id,
                SecretObservation.fingerprint
                == hashlib.sha256(b"synthetic-revoked-demo-value").hexdigest(),
            )
        )
        if not secret:
            synthetic_observation_type = "demo_" + "token"
            db.add(
                SecretObservation(
                    organization_id=organization.id,
                    repository_id=repository.id,
                    application_id=application.id,
                    secret_type=synthetic_observation_type,
                    fingerprint=hashlib.sha256(b"synthetic-revoked-demo-value").hexdigest(),
                    location="fixtures/synthetic.env:3",
                    length=28,
                    masked_prefix="dem…",
                    status="revoked_demo",
                    confidence=1,
                    branch="main",
                    evidence={"simulated": True, "raw_value_stored": False},
                )
            )

        score = await db.scalar(
            select(AppSecScore).where(
                AppSecScore.organization_id == organization.id,
                AppSecScore.entity_type == "application",
                AppSecScore.entity_id == application.id,
                AppSecScore.formula_version == "appsec-score-1.0",
            )
        )
        if not score:
            db.add(
                AppSecScore(
                    organization_id=organization.id,
                    entity_type="application",
                    entity_id=application.id,
                    score=82,
                    previous_score=76,
                    confidence=0.9,
                    positive_factors=[
                        {"factor": "validated_sbom", "weight": 10},
                        {"factor": "verified_provenance", "weight": 8},
                    ],
                    negative_factors=[],
                    targets={"minimum": 75},
                    formula_version="appsec-score-1.0",
                )
            )

        gate = await db.scalar(
            select(SecurityGatePolicy).where(
                SecurityGatePolicy.organization_id == organization.id,
                SecurityGatePolicy.name == "Produção — baseline AppSec",
            )
        )
        if not gate:
            gate = SecurityGatePolicy(
                organization_id=organization.id,
                name="Produção — baseline AppSec",
                description="Gate demonstrativo para artefactos sintéticos.",
                scope_selector={"tags": ["phase5"]},
                applies_to="release",
                environment="production",
                minimum_appsec_score=75,
                maximum_critical_findings=0,
                maximum_high_findings=0,
                block_known_exploited=True,
                block_confirmed_secrets=True,
                block_unsigned_artifacts=True,
                require_sbom=True,
                require_sast=False,
                require_sca=True,
                require_iac_scan=False,
                require_container_scan=False,
                maximum_scan_age=30,
                exceptions_allowed=True,
                approval_required=False,
                enabled=True,
            )
            db.add(gate)
            await db.flush()
        if not await db.scalar(
            select(SecurityGateEvaluation).where(
                SecurityGateEvaluation.organization_id == organization.id,
                SecurityGateEvaluation.policy_id == gate.id,
                SecurityGateEvaluation.release_id == release.id,
            )
        ):
            db.add(
                SecurityGateEvaluation(
                    organization_id=organization.id,
                    policy_id=gate.id,
                    application_id=application.id,
                    release_id=release.id,
                    result="passed",
                    reasons=[],
                    expires_at=datetime.now(timezone.utc) + timedelta(days=7),
                )
            )
        if not await db.scalar(
            select(AppSecException).where(
                AppSecException.organization_id == organization.id,
                AppSecException.application_id == application.id,
                AppSecException.exception_type == "synthetic_demo",
            )
        ):
            db.add(
                AppSecException(
                    organization_id=organization.id,
                    application_id=application.id,
                    release_id=release.id,
                    exception_type="synthetic_demo",
                    reason="Demonstração do fluxo de revisão sem risco real.",
                    business_justification="Validar a interface e o audit trail da Fase 5.",
                    compensating_controls=["Ambiente local", "Dados sintéticos"],
                    requested_by=admin.id,
                    status="pending",
                    expires_at=datetime.now(timezone.utc) + timedelta(days=14),
                    review_date=datetime.now(timezone.utc) + timedelta(days=7),
                )
            )
        await db.commit()


if __name__ == "__main__":
    asyncio.run(seed_phase5())
