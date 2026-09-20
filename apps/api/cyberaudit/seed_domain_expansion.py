"""Synthetic, idempotent seed for enterprise identity and cloud domains."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from cyberaudit import enterprise_models, phase4_models  # noqa: F401
from cyberaudit.db import SessionLocal
from cyberaudit.domain_expansion_models import (
    AuthenticationPosture,
    CloudAccount,
    CloudResource,
    ConnectorCredential,
    DirectoryObject,
    EndpointDevice,
    EnterpriseConnector,
    EntraObject,
    ExternalIdentity,
    IdentityProvider,
    KubernetesCluster,
    KubernetesObject,
    MobileDevice,
    SaasPostureObject,
    ZeroTrustAssessment,
    ZeroTrustDimension,
)
from cyberaudit.domain_expansion_services import (
    ZeroTrustEngine,
    ZeroTrustEvaluationRequest,
    secret_reference_fingerprint,
    stable_snapshot,
)
from cyberaudit.enterprise_models import KnowledgeEdge, KnowledgeNode
from cyberaudit.models import Organization, Permission, Role, User

DOMAIN_PERMISSIONS = [
    "enterprise_connectors.read",
    "enterprise_connectors.manage",
    "enterprise_connectors.execute",
    "enterprise_credentials.manage",
    "identity.read",
    "identity.posture.read",
    "identity.risk.read",
    "identity.graph.read",
    "active_directory.read",
    "entra.read",
    "saas.read",
    "cloud.read",
    "cloud.posture.read",
    "cloud.risk.read",
    "cloud.graph.read",
    "kubernetes.read",
    "kubernetes.posture.read",
    "container_runtime.read",
    "container_runtime.posture.read",
    "endpoints.read",
    "endpoints.posture.read",
    "mobile.read",
    "mobile.posture.read",
    "zero_trust.read",
    "zero_trust.evaluate",
    "enterprise_exports.create",
]


async def _permissions(db: Any) -> None:
    permission_records: dict[str, Permission] = {}
    for code in DOMAIN_PERMISSIONS:
        permission = await db.scalar(select(Permission).where(Permission.code == code))
        if not permission:
            permission = Permission(code=code, description=code.replace(".", " ").title())
            db.add(permission)
            await db.flush()
        permission_records[code] = permission
    roles = list(
        (
            await db.scalars(
                select(Role).where(
                    Role.name.in_(["Administrator", "Auditor", "Reviewer", "Client"])
                )
            )
        ).all()
    )
    for role in roles:
        allowed = DOMAIN_PERMISSIONS
        if role.name == "Auditor":
            allowed = [
                code
                for code in DOMAIN_PERMISSIONS
                if code not in {"enterprise_credentials.manage", "enterprise_exports.create"}
            ]
        elif role.name == "Reviewer":
            allowed = [
                code
                for code in DOMAIN_PERMISSIONS
                if code.endswith(".read") or code in {"zero_trust.read"}
            ]
        elif role.name == "Client":
            allowed = [
                "identity.posture.read",
                "cloud.posture.read",
                "zero_trust.read",
            ]
        current = {permission.code for permission in role.permissions}
        for code in allowed:
            if code not in current:
                role.permissions.append(permission_records[code])


async def _connector(
    db: Any,
    organization: Organization,
    user: User,
    connector_type: str,
    provider: str,
) -> EnterpriseConnector:
    name = f"[DEMO] {provider.title()} read-only"
    connector = await db.scalar(
        select(EnterpriseConnector).where(
            EnterpriseConnector.organization_id == organization.id,
            EnterpriseConnector.name == name,
        )
    )
    if connector:
        return connector
    connector = EnterpriseConnector(
        organization_id=organization.id,
        connector_type=connector_type,
        provider=provider,
        name=name,
        description="Synthetic connector. No external connection or customer data.",
        requested_permissions=["inventory.read", "posture.read"],
        detected_permissions=["inventory.read", "posture.read"],
        read_only=True,
        status="active",
        capabilities=["inventory", "posture", "incremental_sync"],
        health_status="ready",
        last_health_check_at=datetime.now(timezone.utc),
        connector_metadata={"demo_data": True, "external_io": False},
        created_by=user.id,
    )
    db.add(connector)
    await db.flush()
    reference = f"development://demo-{connector_type}"
    credential = ConnectorCredential(
        organization_id=organization.id,
        connector_id=connector.id,
        credential_type="development_reference",
        secret_reference=reference,
        reference_fingerprint=secret_reference_fingerprint(reference),
        created_by=user.id,
    )
    db.add(credential)
    await db.flush()
    connector.credential_id = credential.id
    return connector


async def _node(
    db: Any,
    organization_id: str,
    node_type: str,
    source_id: str,
    label: str,
    facts: dict[str, Any],
) -> KnowledgeNode:
    node = await db.scalar(
        select(KnowledgeNode).where(
            KnowledgeNode.organization_id == organization_id,
            KnowledgeNode.node_type == node_type,
            KnowledgeNode.source_id == source_id,
        )
    )
    if node:
        return node
    node = KnowledgeNode(
        organization_id=organization_id,
        node_type=node_type,
        source_id=source_id,
        label=label,
        facts={**facts, "demo_data": True},
        source_references=[f"{node_type}:{source_id}"],
        confidence=1,
    )
    db.add(node)
    await db.flush()
    return node


async def seed() -> None:
    async with SessionLocal() as db:
        organization = await db.scalar(
            select(Organization).where(Organization.slug == "cyberaudit-demo")
        )
        user = await db.scalar(select(User).where(User.email == "admin@cyberaudit.local"))
        if not organization or not user:
            raise RuntimeError("Run the base and enterprise seeds first")
        await _permissions(db)

        connectors = {
            connector_type: await _connector(db, organization, user, connector_type, provider)
            for connector_type, provider in [
                ("active_directory", "active-directory"),
                ("entra_id", "entra"),
                ("microsoft_365", "microsoft365"),
                ("google_workspace", "google-workspace"),
                ("aws", "aws"),
                ("azure", "azure"),
                ("gcp", "gcp"),
                ("kubernetes", "kubernetes"),
                ("container_runtime", "container-runtime"),
                ("endpoint", "endpoint-management"),
                ("mobile", "mobile-management"),
            ]
        }
        provider = await db.scalar(
            select(IdentityProvider).where(
                IdentityProvider.organization_id == organization.id,
                IdentityProvider.tenant_identifier == "demo-tenant",
            )
        )
        if not provider:
            provider = IdentityProvider(
                organization_id=organization.id,
                connector_id=connectors["entra_id"].id,
                provider_type="entra_id",
                name="[DEMO] CyberAudit Identity",
                tenant_identifier="demo-tenant",
                domain="cyberaudit.example",
                provider_metadata={"demo_data": True},
            )
            db.add(provider)
            await db.flush()

        identities: list[ExternalIdentity] = []
        identity_specs = [
            ("demo-admin", "Demo Administrator", True, False, False, None, "false", 92),
            (
                "demo-guest",
                "Historical Guest",
                False,
                True,
                False,
                "Demo Collaboration",
                "unknown",
                58,
            ),
            (
                "demo-service",
                "Unowned Demo Service Principal",
                True,
                False,
                True,
                None,
                "not_applicable",
                82,
            ),
        ]
        for (
            external_id,
            name,
            privileged,
            guest,
            service_account,
            owner,
            mfa,
            risk,
        ) in identity_specs:
            identity = await db.scalar(
                select(ExternalIdentity).where(
                    ExternalIdentity.organization_id == organization.id,
                    ExternalIdentity.provider_id == provider.id,
                    ExternalIdentity.external_id == external_id,
                )
            )
            if not identity:
                identity = ExternalIdentity(
                    organization_id=organization.id,
                    provider_id=provider.id,
                    external_id=external_id,
                    identity_type="service_principal" if service_account else "user",
                    username=f"{external_id}@cyberaudit.example",
                    display_name=f"[DEMO] {name}",
                    email=None if service_account else f"{external_id}@cyberaudit.example",
                    privileged=privileged,
                    guest=guest,
                    service_account=service_account,
                    owner=owner,
                    mfa_state=mfa,
                    authentication_methods=[] if mfa == "false" else ["unknown"],
                    risk_state="high" if risk >= 70 else "medium",
                    risk_score=risk,
                    source_metadata={"demo_data": True},
                    demo_data=True,
                    last_activity_at=datetime.now(timezone.utc)
                    - timedelta(days=180 if guest else 2),
                )
                db.add(identity)
                await db.flush()
            identities.append(identity)
            posture = await db.scalar(
                select(AuthenticationPosture).where(
                    AuthenticationPosture.organization_id == organization.id,
                    AuthenticationPosture.identity_id == identity.id,
                )
            )
            if not posture:
                db.add(
                    AuthenticationPosture(
                        organization_id=organization.id,
                        identity_id=identity.id,
                        mfa_registered=mfa,
                        mfa_available=mfa,
                        mfa_required=mfa,
                        mfa_enforced=mfa,
                        mfa_observed="unknown",
                        posture_score=15 if mfa == "false" else 45,
                        confidence=0.8,
                        unknown_factors=["mfa_observed"],
                    )
                )

        directory_specs = [
            ("forest", "forest-demo", "[DEMO] cyberaudit.example"),
            ("domain", "domain-demo", "[DEMO] cyberaudit.example"),
            ("trust", "trust-demo", "[DEMO] Lab forest trust"),
            ("group_policy", "gpo-demo", "[DEMO] Workstation baseline"),
            ("certificate_service", "ca-demo", "[DEMO] Enterprise CA"),
            ("posture", "posture-demo", "[DEMO] AD posture"),
        ]
        for object_type, external_id, name in directory_specs:
            exists = await db.scalar(
                select(DirectoryObject).where(
                    DirectoryObject.organization_id == organization.id,
                    DirectoryObject.provider_id == provider.id,
                    DirectoryObject.object_type == object_type,
                    DirectoryObject.external_id == external_id,
                )
            )
            if not exists:
                _, digest = stable_snapshot({"object_type": object_type, "demo": True})
                db.add(
                    DirectoryObject(
                        organization_id=organization.id,
                        provider_id=provider.id,
                        object_type=object_type,
                        external_id=external_id,
                        name=name,
                        configuration_hash=digest,
                        posture={"demo_data": True, "read_only": True},
                        demo_data=True,
                    )
                )

        entra_specs = [
            ("tenant", "tenant-demo", "[DEMO] CyberAudit tenant", 20),
            ("application", "oauth-app-demo", "[DEMO] High privilege OAuth app", 88),
            (
                "service_principal",
                "sp-demo",
                "[DEMO] Service principal without owner",
                82,
            ),
            (
                "conditional_access",
                "ca-policy-demo",
                "[DEMO] Partial MFA policy",
                72,
            ),
            ("oauth_grant", "grant-demo", "[DEMO] Directory read/write grant", 90),
            ("posture", "entra-posture-demo", "[DEMO] Entra posture", 70),
        ]
        for object_type, external_id, name, risk in entra_specs:
            exists = await db.scalar(
                select(EntraObject).where(
                    EntraObject.organization_id == organization.id,
                    EntraObject.provider_id == provider.id,
                    EntraObject.object_type == object_type,
                    EntraObject.external_id == external_id,
                )
            )
            if not exists:
                _, digest = stable_snapshot({"external_id": external_id, "risk": risk})
                db.add(
                    EntraObject(
                        organization_id=organization.id,
                        provider_id=provider.id,
                        object_type=object_type,
                        external_id=external_id,
                        name=name,
                        owner=None if "without owner" in name else "Demo Security",
                        risk_score=risk,
                        configuration_hash=digest,
                        posture={"demo_data": True, "high_privilege": risk >= 80},
                        demo_data=True,
                    )
                )

        for service_name, connector_key, object_types in [
            (
                "microsoft365",
                "microsoft_365",
                ["posture", "exchange", "sharepoint", "teams", "devices"],
            ),
            (
                "google-workspace",
                "google_workspace",
                ["users", "groups", "oauth", "drive", "devices", "posture"],
            ),
        ]:
            for object_type in object_types:
                external_id = f"{service_name}-{object_type}-demo"
                exists = await db.scalar(
                    select(SaasPostureObject).where(
                        SaasPostureObject.organization_id == organization.id,
                        SaasPostureObject.connector_id == connectors[connector_key].id,
                        SaasPostureObject.service == service_name,
                        SaasPostureObject.object_type == object_type,
                        SaasPostureObject.external_id == external_id,
                    )
                )
                if not exists:
                    _, digest = stable_snapshot({"service": service_name, "type": object_type})
                    db.add(
                        SaasPostureObject(
                            organization_id=organization.id,
                            connector_id=connectors[connector_key].id,
                            service=service_name,
                            object_type=object_type,
                            external_id=external_id,
                            name=f"[DEMO] {service_name} {object_type}",
                            status="requires_review",
                            posture={"demo_data": True, "read_only": True},
                            configuration_hash=digest,
                            demo_data=True,
                        )
                    )

        resources: list[CloudResource] = []
        cloud_specs = {
            "aws": ("123456789012-demo", "bucket", "Public demo bucket"),
            "azure": ("subscription-demo", "key_vault", "Public demo Key Vault"),
            "gcp": ("project-demo", "storage_bucket", "Public demo storage"),
        }
        for cloud, (account_external_id, resource_type, resource_name) in cloud_specs.items():
            account = await db.scalar(
                select(CloudAccount).where(
                    CloudAccount.organization_id == organization.id,
                    CloudAccount.provider == cloud,
                    CloudAccount.external_id == account_external_id,
                )
            )
            if not account:
                account = CloudAccount(
                    organization_id=organization.id,
                    connector_id=connectors[cloud].id,
                    provider=cloud,
                    account_type="account",
                    external_id=account_external_id,
                    name=f"[DEMO] {cloud.upper()} environment",
                    environment="laboratory",
                    owner="Demo Cloud Team",
                    criticality="high",
                    risk_score=85,
                    tags={"demo_data": "true"},
                    demo_data=True,
                )
                db.add(account)
                await db.flush()
            resource_external_id = f"{cloud}:{resource_type}:demo"
            resource = await db.scalar(
                select(CloudResource).where(
                    CloudResource.organization_id == organization.id,
                    CloudResource.provider == cloud,
                    CloudResource.external_id == resource_external_id,
                )
            )
            if not resource:
                configuration, digest = stable_snapshot(
                    {
                        "public_access": True,
                        "encryption": False,
                        "logging": False,
                        "demo_data": True,
                    }
                )
                resource = CloudResource(
                    organization_id=organization.id,
                    connector_id=connectors[cloud].id,
                    account_id=account.id,
                    provider=cloud,
                    external_id=resource_external_id,
                    resource_type=resource_type,
                    name=f"[DEMO] {resource_name}",
                    region="demo-region-1",
                    environment="laboratory",
                    criticality="high",
                    public_exposure=True,
                    owner="Demo Cloud Team",
                    risk_score=90,
                    tags={"demo_data": "true"},
                    configuration_hash=digest,
                    configuration=configuration,
                    source_metadata={"demo_data": True},
                    demo_data=True,
                )
                db.add(resource)
                await db.flush()
            resources.append(resource)

        cluster = await db.scalar(
            select(KubernetesCluster).where(
                KubernetesCluster.organization_id == organization.id,
                KubernetesCluster.external_id == "cluster-demo",
            )
        )
        if not cluster:
            cluster = KubernetesCluster(
                organization_id=organization.id,
                connector_id=connectors["kubernetes"].id,
                external_id="cluster-demo",
                name="[DEMO] Enterprise laboratory cluster",
                provider="demo",
                version="1.31-demo",
                environment="laboratory",
                public_endpoint=False,
                audit_logging="true",
                risk_score=75,
                posture={"demo_data": True},
                demo_data=True,
            )
            db.add(cluster)
            await db.flush()
        workload = await db.scalar(
            select(KubernetesObject).where(
                KubernetesObject.organization_id == organization.id,
                KubernetesObject.cluster_id == cluster.id,
                KubernetesObject.object_type == "workload",
                KubernetesObject.namespace == "demo",
                KubernetesObject.external_id == "privileged-workload-demo",
            )
        )
        if not workload:
            _, digest = stable_snapshot({"privileged": True, "cluster_admin": True})
            workload = KubernetesObject(
                organization_id=organization.id,
                cluster_id=cluster.id,
                object_type="workload",
                external_id="privileged-workload-demo",
                namespace="demo",
                name="[DEMO] Privileged workload",
                labels={"demo_data": "true"},
                annotations={},
                configuration_hash=digest,
                posture={"cluster_admin": True, "demo_data": True},
                privileged=True,
                risk_score=92,
                demo_data=True,
            )
            db.add(workload)
            await db.flush()

        endpoint = await db.scalar(
            select(EndpointDevice).where(
                EndpointDevice.organization_id == organization.id,
                EndpointDevice.connector_id == connectors["endpoint"].id,
                EndpointDevice.external_id == "endpoint-demo",
            )
        )
        if not endpoint:
            endpoint = EndpointDevice(
                organization_id=organization.id,
                connector_id=connectors["endpoint"].id,
                external_id="endpoint-demo",
                hostname="demo-endpoint",
                platform="windows",
                os_name="Demo OS",
                os_version="2026.1",
                owner="Demo User",
                managed="true",
                compliance_state="non_compliant",
                encryption_state="false",
                firewall_state="true",
                edr_state="true",
                patch_state="outdated",
                risk_score=78,
                posture={"demo_data": True},
                demo_data=True,
            )
            db.add(endpoint)
        mobile = await db.scalar(
            select(MobileDevice).where(
                MobileDevice.organization_id == organization.id,
                MobileDevice.connector_id == connectors["mobile"].id,
                MobileDevice.external_id == "mobile-demo",
            )
        )
        if not mobile:
            mobile = MobileDevice(
                organization_id=organization.id,
                connector_id=connectors["mobile"].id,
                external_id="mobile-demo",
                name="[DEMO] Non-compliant mobile",
                platform="android",
                os_version="15-demo",
                owner="Demo User",
                managed="true",
                compliance_state="non_compliant",
                encryption_state="true",
                integrity_state="unknown",
                screen_lock_state="false",
                unknown_sources_allowed="true",
                risk_score=74,
                posture={"demo_data": True},
                demo_data=True,
            )
            db.add(mobile)

        assessment = await db.scalar(
            select(ZeroTrustAssessment).where(
                ZeroTrustAssessment.organization_id == organization.id,
                ZeroTrustAssessment.demo_data.is_(True),
            )
        )
        if not assessment:
            evaluation = ZeroTrustEngine().evaluate(
                ZeroTrustEvaluationRequest(
                    subject_type="organization",
                    facts={
                        "identity": {"mfa_enforced": False, "least_privilege": False},
                        "device": {"managed": True, "compliant": False},
                        "session": {"continuous_evaluation": None},
                        "application": {"oauth_governed": False},
                        "network": {"segmented": True},
                        "workload": {"least_privilege": False},
                        "data": {"classified": None},
                        "control": {"monitored": True},
                    },
                )
            )
            assessment = ZeroTrustAssessment(
                organization_id=organization.id,
                subject_type="organization",
                scope={"demo_data": True},
                score=evaluation.score,
                status=evaluation.status,
                confidence=evaluation.confidence,
                factors=evaluation.factors,
                unknown_factors=evaluation.unknown_factors,
                recommendations=evaluation.recommendations,
                control_mappings=evaluation.control_mappings,
                evaluated_at=evaluation.evaluated_at,
                requested_by=user.id,
                demo_data=True,
            )
            db.add(assessment)
            await db.flush()
            for dimension in evaluation.dimensions:
                db.add(
                    ZeroTrustDimension(
                        organization_id=organization.id,
                        assessment_id=assessment.id,
                        **dimension.model_dump(),
                    )
                )

        identity_node = await _node(
            db,
            organization.id,
            "identity",
            identities[0].id,
            identities[0].display_name,
            {"risk": identities[0].risk_score, "privileged": True},
        )
        resource_node = await _node(
            db,
            organization.id,
            "cloud_resource",
            resources[0].id,
            resources[0].name,
            {"risk": resources[0].risk_score, "public": True},
        )
        edge = await db.scalar(
            select(KnowledgeEdge).where(
                KnowledgeEdge.organization_id == organization.id,
                KnowledgeEdge.source_node_id == identity_node.id,
                KnowledgeEdge.edge_type == "can_access",
                KnowledgeEdge.target_node_id == resource_node.id,
            )
        )
        if not edge:
            db.add(
                KnowledgeEdge(
                    organization_id=organization.id,
                    source_node_id=identity_node.id,
                    target_node_id=resource_node.id,
                    edge_type="can_access",
                    facts={"path_type": "possible", "demo_data": True},
                    source_references=[
                        f"identity:{identities[0].id}",
                        f"cloud_resource:{resources[0].id}",
                    ],
                    confidence=0.85,
                    inferred=True,
                )
            )
        await db.commit()


if __name__ == "__main__":
    asyncio.run(seed())
