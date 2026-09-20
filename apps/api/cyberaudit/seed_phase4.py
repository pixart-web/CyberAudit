"""Deterministic Phase 4 CyberAudit OS demonstration data."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from cyberaudit.adapters import AdapterRegistry
from cyberaudit.db import SessionLocal
from cyberaudit.models import (
    Asset,
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
from cyberaudit.phase4_models import (
    AssessmentCoverage,
    AssessmentSchedule,
    AssetChange,
    AssetRelationship,
    DiscoveryPolicy,
    Environment,
    ExposureScore,
    IPAddress,
    Network,
    NetworkZone,
    Notification,
    Service,
    SoftwareInstance,
    SoftwareProduct,
    VulnerabilityFeed,
)
from cyberaudit.phase4_worker import DEMO_FEED
from cyberaudit.risk_engine import ContextualRiskEngine, RiskContext
from cyberaudit.vulnerability_intelligence import VulnerabilityIntelligenceService

PHASE4_PERMISSIONS = [
    "environments.read",
    "environments.manage",
    "network_zones.read",
    "network_zones.manage",
    "networks.read",
    "networks.manage",
    "discovery_policies.read",
    "discovery_policies.manage",
    "asset_changes.read",
    "services.read",
    "software.read",
    "vulnerabilities.read",
    "vulnerabilities.manage",
    "vulnerability_matches.review",
    "vulnerability_feeds.read",
    "vulnerability_feeds.manage",
    "vulnerability_feeds.sync",
    "attack_paths.read",
    "attack_paths.analyze",
    "attack_paths.review",
    "risk.read",
    "risk.manage",
    "risk_scenarios.create",
    "coverage.read",
    "assessment_schedules.read",
    "assessment_schedules.manage",
    "notifications.read",
    "system_health.read",
]

ROLE_PERMISSIONS = {
    "Administrator": PHASE4_PERMISSIONS,
    "Auditor": [
        "environments.read",
        "network_zones.read",
        "networks.read",
        "discovery_policies.read",
        "asset_changes.read",
        "services.read",
        "software.read",
        "vulnerabilities.read",
        "attack_paths.read",
        "attack_paths.analyze",
        "risk.read",
        "risk_scenarios.create",
        "coverage.read",
        "assessment_schedules.read",
        "assessment_schedules.manage",
        "notifications.read",
        "system_health.read",
    ],
    "Reviewer": [
        "environments.read",
        "network_zones.read",
        "networks.read",
        "asset_changes.read",
        "services.read",
        "software.read",
        "vulnerabilities.read",
        "vulnerability_matches.review",
        "vulnerability_feeds.read",
        "attack_paths.read",
        "attack_paths.review",
        "risk.read",
        "coverage.read",
        "notifications.read",
        "system_health.read",
    ],
    "Client": [
        "environments.read",
        "network_zones.read",
        "networks.read",
        "services.read",
        "vulnerabilities.read",
        "attack_paths.read",
        "risk.read",
        "coverage.read",
        "notifications.read",
    ],
}

PROFILE_DATA = [
    (
        "Descoberta de hosts mínima",
        "host_discovery",
        "cyberaudit.host_discovery",
        [TargetType.IP, TargetType.CIDR],
        {"probe_profile": "minimal", "maximum_hosts": 8},
        120,
        False,
    ),
    (
        "Portas essenciais",
        "port_discovery",
        "cyberaudit.port_discovery",
        [TargetType.IP],
        {"profile": "minimal", "maximum_ports": 3},
        90,
        False,
    ),
    (
        "Serviços standard",
        "service_identification",
        "cyberaudit.service_identification",
        [TargetType.IP],
        {"profile": "standard"},
        120,
        False,
    ),
    (
        "Identificação OS conservadora",
        "os_identification",
        "cyberaudit.os_identification",
        [TargetType.IP, TargetType.HOSTNAME],
        {},
        30,
        False,
    ),
    (
        "Exposição contextual",
        "exposure_assessment",
        "cyberaudit.exposure_assessment",
        [TargetType.IP, TargetType.HOSTNAME, TargetType.URL],
        {},
        30,
        False,
    ),
    (
        "Correlação de vulnerabilidades",
        "vulnerability_correlation",
        "cyberaudit.vulnerability_correlation",
        [TargetType.IP, TargetType.HOSTNAME],
        {},
        60,
        False,
    ),
]


async def seed_phase4() -> None:
    async with SessionLocal() as db:
        organization = await db.scalar(
            select(Organization).where(Organization.slug == "cyberaudit-demo")
        )
        admin = await db.scalar(select(User).where(User.email == "admin@cyberaudit.local"))
        if not organization or not admin:
            raise RuntimeError("Run Phase 1 through Phase 3 seeds first")
        client = await db.scalar(select(Client).where(Client.organization_id == organization.id))
        if not client:
            raise RuntimeError("Run Phase 1 through Phase 3 seeds first")
        roles = {
            role.name: role
            for role in (
                await db.scalars(select(Role).where(Role.name.in_(list(ROLE_PERMISSIONS))))
            ).all()
        }
        for code in PHASE4_PERMISSIONS:
            permission = await db.scalar(select(Permission).where(Permission.code == code))
            if not permission:
                permission = Permission(code=code, description=code.replace(".", " ").title())
                db.add(permission)
                await db.flush()
            for role_name, codes in ROLE_PERMISSIONS.items():
                role = roles.get(role_name)
                if role and code in codes and permission not in role.permissions:
                    role.permissions.append(permission)
        laboratory = await db.scalar(
            select(Engagement).where(
                Engagement.organization_id == organization.id,
                Engagement.code == "LAB-PHASE3",
            )
        )
        if not laboratory:
            raise RuntimeError("Run Phase 3 seed first")
        scope = await db.scalar(
            select(Scope).where(
                Scope.organization_id == organization.id,
                Scope.engagement_id == laboratory.id,
            )
        )
        if not scope:
            raise RuntimeError("Phase 3 laboratory scope missing")
        techniques = {
            "host-discovery",
            "port-discovery",
            "service-identification",
            "os-identification",
            "exposure-assessment",
            "vulnerability-correlation",
        }
        scope.allowed_techniques = sorted(set(scope.allowed_techniques) | techniques)
        existing_cidr = await db.scalar(
            select(ScopeTarget).where(
                ScopeTarget.scope_id == scope.id,
                ScopeTarget.target_type == TargetType.CIDR,
                ScopeTarget.normalized_value == "127.0.0.0/30",
            )
        )
        if not existing_cidr:
            db.add(
                ScopeTarget(
                    scope_id=scope.id,
                    target_type=TargetType.CIDR,
                    target_value="127.0.0.0/30",
                    normalized_value="127.0.0.0/30",
                    allowed=True,
                    notes="Rede loopback controlada do laboratório Fase 4.",
                )
            )
        environment = await db.scalar(
            select(Environment).where(
                Environment.organization_id == organization.id,
                Environment.name == "CyberAudit Lab",
            )
        )
        if not environment:
            environment = Environment(
                organization_id=organization.id,
                client_id=client.id,
                name="CyberAudit Lab",
                description="Ambiente integralmente local e controlado.",
                environment_type="laboratory",
                criticality="medium",
                exposure="local",
                data_classification="synthetic",
                owner="CyberAudit Demo",
                business_owner="CyberAudit Demo",
                technical_owner="CyberAudit Demo",
                tags=["phase4", "local", "simulated"],
                environment_metadata={"simulated": True},
            )
            db.add(environment)
            await db.flush()
        policy = await db.scalar(
            select(DiscoveryPolicy).where(
                DiscoveryPolicy.organization_id == organization.id,
                DiscoveryPolicy.name == "Laboratório limitado",
            )
        )
        if not policy:
            policy = DiscoveryPolicy(
                organization_id=organization.id,
                name="Laboratório limitado",
                description="TCP connect apenas, máximo 8 hosts e 16 portas.",
                allowed_target_types=["ip", "cidr"],
                maximum_hosts=8,
                maximum_ports=16,
                maximum_packets_per_second=10,
                maximum_concurrent_hosts=2,
                maximum_concurrent_ports=4,
                host_timeout=2,
                total_timeout=120,
                permitted_protocols=["tcp"],
                permitted_ports=[22, 25, 80, 443, 5432, 8080, 8443],
                forbidden_ports=[],
                allow_icmp=False,
                allow_tcp_discovery=True,
                allow_udp_discovery=False,
                allow_service_detection=True,
                allow_os_detection=False,
                require_approval=False,
                active_hours={"start": "00:00", "end": "23:59"},
                excluded_targets=[],
                created_by=admin.id,
            )
            db.add(policy)
            await db.flush()
        zones: dict[str, NetworkZone] = {}
        for name, zone_type, exposure, internet_access in [
            ("Lab DMZ", "dmz", "local", False),
            ("Lab Internal", "internal", "internal", False),
            ("Lab Restricted", "restricted", "restricted", False),
        ]:
            zone = await db.scalar(
                select(NetworkZone).where(
                    NetworkZone.organization_id == organization.id,
                    NetworkZone.environment_id == environment.id,
                    NetworkZone.name == name,
                )
            )
            if not zone:
                zone = NetworkZone(
                    organization_id=organization.id,
                    environment_id=environment.id,
                    name=name,
                    description="Zona simulada do laboratório.",
                    zone_type=zone_type,
                    trust_level="controlled",
                    exposure=exposure,
                    internet_access=internet_access,
                    criticality="medium",
                    tags=["simulated"],
                )
                db.add(zone)
                await db.flush()
            zones[name] = zone
        network = await db.scalar(
            select(Network).where(
                Network.organization_id == organization.id,
                Network.cidr == "127.0.0.0/30",
            )
        )
        if not network:
            network = Network(
                organization_id=organization.id,
                environment_id=environment.id,
                network_zone_id=zones["Lab DMZ"].id,
                name="Loopback Lab",
                cidr="127.0.0.0/30",
                ip_version=4,
                description="Rede local explicitamente autorizada.",
                owner="CyberAudit Demo",
                scan_allowed=True,
                discovery_policy_id=policy.id,
                tags=["loopback", "phase4"],
            )
            db.add(network)
            await db.flush()
        assets = list(
            (await db.scalars(select(Asset).where(Asset.organization_id == organization.id))).all()
        )
        for index, asset in enumerate(assets):
            asset.environment_id = environment.id
            asset.network_zone_id = zones["Lab DMZ"].id if index == 0 else zones["Lab Internal"].id
            asset.primary_ip = asset.ip_address
            asset.lifecycle_status = "active"
            asset.managed = index != 4
            asset.business_criticality = asset.criticality.value
            asset.data_classification = "internal"
            asset.confidence = 0.9
            asset.source = "phase4_demo_seed"
            asset.internet_exposed = index == 0
            asset.exposure_score = 82 if index == 0 else 24
            result = ContextualRiskEngine().calculate(
                RiskContext(
                    asset_criticality={"low": 20, "medium": 50, "high": 75, "critical": 95}[
                        asset.criticality.value
                    ],
                    exposure=asset.exposure_score,
                    reachability=90 if asset.internet_exposed else 30,
                    vulnerability_severity=70 if index == 0 else 35,
                    vulnerability_confidence=90,
                    asset_owner=bool(asset.owner),
                    evidence_quality=85,
                )
            )
            asset.risk_score = result.overall_risk_score
            score = await db.scalar(
                select(ExposureScore).where(
                    ExposureScore.organization_id == organization.id,
                    ExposureScore.entity_type == "asset",
                    ExposureScore.entity_id == asset.id,
                )
            )
            if not score:
                db.add(
                    ExposureScore(
                        organization_id=organization.id,
                        entity_type="asset",
                        entity_id=asset.id,
                        score=asset.exposure_score,
                        previous_score=max(0, asset.exposure_score - 7),
                        factors=[
                            {
                                "factor": "internet_exposed",
                                "value": asset.internet_exposed,
                            }
                        ],
                        recommendations=["Rever exposição e propriedade do ativo."],
                        calculation_version="exposure-1.0",
                    )
                )
        await db.flush()
        if assets:
            lab_ip = await db.scalar(
                select(IPAddress).where(
                    IPAddress.organization_id == organization.id,
                    IPAddress.address == "127.0.0.1",
                )
            )
            if not lab_ip:
                lab_ip = IPAddress(
                    organization_id=organization.id,
                    address="127.0.0.1",
                    version=4,
                    scope_type="loopback",
                    public=False,
                    private=True,
                    reserved=False,
                    network_id=network.id,
                    asset_id=assets[0].id,
                    source="phase4_demo_seed",
                    confidence=1,
                )
                db.add(lab_ip)
                await db.flush()
            for port, name, encrypted in [
                (8080, "http-alt", False),
                (8443, "https-alt", True),
            ]:
                service = await db.scalar(
                    select(Service).where(
                        Service.organization_id == organization.id,
                        Service.asset_id == assets[0].id,
                        Service.port == port,
                    )
                )
                if not service:
                    db.add(
                        Service(
                            organization_id=organization.id,
                            asset_id=assets[0].id,
                            ip_address_id=lab_ip.id,
                            port=port,
                            transport_protocol="tcp",
                            application_protocol="https" if encrypted else "http",
                            service_name=name,
                            product="CyberAudit Lab Service",
                            version="1.0-demo",
                            encrypted=encrypted,
                            exposure="local",
                            state="open",
                            confidence=1,
                            fingerprint_method="seed",
                            source_adapter="cyberaudit.demo_assessment",
                        )
                    )
            for source, target, relation in [
                (0, 1, "depends_on"),
                (1, 2, "serves"),
                (2, 3, "depends_on"),
            ]:
                if len(assets) <= max(source, target):
                    continue
                existing = await db.scalar(
                    select(AssetRelationship).where(
                        AssetRelationship.organization_id == organization.id,
                        AssetRelationship.source_asset_id == assets[source].id,
                        AssetRelationship.target_asset_id == assets[target].id,
                        AssetRelationship.relationship_type == relation,
                    )
                )
                if not existing:
                    db.add(
                        AssetRelationship(
                            organization_id=organization.id,
                            source_asset_id=assets[source].id,
                            target_asset_id=assets[target].id,
                            relationship_type=relation,
                            direction="directed",
                            confidence=0.85,
                            source="phase4_demo_seed",
                            reviewed=True,
                        )
                    )
            for asset_index, asset in enumerate(assets):
                for category in ["inventory", "ports", "services", "vulnerabilities"]:
                    existing = await db.scalar(
                        select(AssessmentCoverage).where(
                            AssessmentCoverage.organization_id == organization.id,
                            AssessmentCoverage.engagement_id == laboratory.id,
                            AssessmentCoverage.asset_id == asset.id,
                            AssessmentCoverage.assessment_category == category,
                        )
                    )
                    if not existing:
                        db.add(
                            AssessmentCoverage(
                                organization_id=organization.id,
                                engagement_id=laboratory.id,
                                asset_id=asset.id,
                                assessment_category=category,
                                last_assessed_at=datetime.now(timezone.utc)
                                - timedelta(days=asset_index * 3),
                                assessment_depth="standard",
                                status="covered" if category != "vulnerabilities" else "partial",
                                result="observed",
                                confidence=0.85,
                                next_recommended_at=datetime.now(timezone.utc) + timedelta(days=30),
                                coverage_score=100 if category != "vulnerabilities" else 60,
                            )
                        )
        product = await db.scalar(
            select(SoftwareProduct).where(
                SoftwareProduct.normalized_name == "cyberaudit-demo/orion-service"
            )
        )
        if not product:
            product = SoftwareProduct(
                vendor="CyberAudit Demo",
                product="Orion Service",
                normalized_name="cyberaudit-demo/orion-service",
                ecosystem="generic",
                cpe="cpe:2.3:a:cyberaudit_demo:orion_service:*:*:*:*:*:*:*:*",
                aliases=["orion demo"],
                product_metadata={"simulated": True},
            )
            db.add(product)
            await db.flush()
        if assets:
            instance = await db.scalar(
                select(SoftwareInstance).where(
                    SoftwareInstance.organization_id == organization.id,
                    SoftwareInstance.asset_id == assets[0].id,
                    SoftwareInstance.software_product_id == product.id,
                )
            )
            if not instance:
                instance = SoftwareInstance(
                    organization_id=organization.id,
                    asset_id=assets[0].id,
                    software_product_id=product.id,
                    version="2.1",
                    source="phase4_demo_seed",
                    confidence=1,
                    active=True,
                )
                db.add(instance)
        feed = await db.scalar(
            select(VulnerabilityFeed).where(VulnerabilityFeed.name == "CyberAudit Demo Feed")
        )
        if not feed:
            feed = VulnerabilityFeed(
                name="CyberAudit Demo Feed",
                provider="CyberAudit Demo",
                source_identifier="embedded://phase4-demo",
                feed_type="normalized_json",
                enabled=True,
                synchronization_interval=86400,
                signature_verified=True,
            )
            db.add(feed)
            await db.flush()
        await VulnerabilityIntelligenceService(db).import_feed_bytes(
            feed, __import__("json").dumps(DEMO_FEED, sort_keys=True).encode()
        )
        await db.flush()
        if assets:
            await VulnerabilityIntelligenceService(db).correlate_asset(
                organization.id, assets[0].id
            )
            db.add(
                AssetChange(
                    organization_id=organization.id,
                    asset_id=assets[0].id,
                    change_type="service_opened",
                    field_name="port",
                    previous_value=None,
                    current_value={"port": 8080, "transport": "tcp"},
                    severity="medium",
                )
            )
        registry = AdapterRegistry()
        for adapter_code in [item[2] for item in PROFILE_DATA]:
            metadata = registry.get(adapter_code).metadata()
            definition = await db.scalar(
                select(ToolAdapterDefinition).where(ToolAdapterDefinition.code == adapter_code)
            )
            if not definition:
                definition = ToolAdapterDefinition(
                    code=metadata.code,
                    name=metadata.name,
                    version=metadata.version,
                    category=metadata.category,
                    description=metadata.description,
                    supported_target_types=[item.value for item in metadata.supported_target_types],
                    supported_intensities=[item.value for item in metadata.supported_intensities],
                    requires_network=metadata.requires_network,
                    requires_approval=metadata.requires_approval,
                    default_timeout=metadata.default_timeout,
                    enabled=True,
                    health_status="online",
                    adapter_metadata={},
                )
                db.add(definition)
            definition.adapter_metadata = {
                "phase": 4,
                "safe": True,
                "no_exploitation": True,
                "configuration_schema": metadata.configuration_schema,
            }
        for (
            name,
            category,
            adapter_code,
            target_types,
            configuration,
            timeout,
            approval,
        ) in PROFILE_DATA:
            profile = await db.scalar(
                select(ScanProfile).where(
                    ScanProfile.organization_id == organization.id,
                    ScanProfile.name == name,
                )
            )
            if not profile:
                metadata = registry.get(adapter_code).metadata()
                db.add(
                    ScanProfile(
                        organization_id=organization.id,
                        name=name,
                        description=metadata.description,
                        category=category,
                        adapter_code=adapter_code,
                        target_types=[item.value for item in target_types],
                        default_intensity=Intensity.LOW,
                        maximum_intensity=Intensity.LOW,
                        timeout_seconds=timeout,
                        cpu_limit=0.5,
                        memory_limit_mb=256,
                        network_access=metadata.requires_network,
                        requires_approval=approval,
                        enabled=True,
                        configuration_schema=metadata.configuration_schema,
                        default_configuration=configuration,
                        created_by=admin.id,
                    )
                )
        schedule = await db.scalar(
            select(AssessmentSchedule).where(AssessmentSchedule.organization_id == organization.id)
        )
        inventory_profile = await db.scalar(
            select(ScanProfile).where(
                ScanProfile.organization_id == organization.id,
                ScanProfile.adapter_code == "cyberaudit.asset_inventory",
            )
        )
        if not schedule and inventory_profile and assets:
            db.add(
                AssessmentSchedule(
                    organization_id=organization.id,
                    engagement_id=laboratory.id,
                    scan_profile_id=inventory_profile.id,
                    target_selector={"asset_ids": [assets[0].id]},
                    recurrence="weekly",
                    timezone="Europe/Lisbon",
                    active_window={"start": "08:00", "end": "18:00"},
                    maximum_duration=1800,
                    approval_policy="inherit",
                    enabled=False,
                    next_run_at=datetime.now(timezone.utc) + timedelta(days=7),
                    created_by=admin.id,
                )
            )
        if not await db.scalar(
            select(Notification).where(
                Notification.organization_id == organization.id,
                Notification.event_type == "new_exposure",
            )
        ):
            db.add(
                Notification(
                    organization_id=organization.id,
                    event_type="new_exposure",
                    severity="high",
                    title="Nova exposição de demonstração",
                    message="Serviço local 8080 observado no laboratório controlado.",
                    resource_type="asset",
                    resource_id=assets[0].id if assets else None,
                    notification_metadata={"simulated": True},
                )
            )
        await db.commit()
        print("CyberAudit Phase 4 OS demo data created.")


if __name__ == "__main__":
    asyncio.run(seed_phase4())
