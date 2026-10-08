"""Deterministic, clearly synthetic demo tenant: "Northstar Industries (DEMO)".

Everything here is demonstration material. It is NOT a claim of real discovery:
names carry a [DEMO] marker, findings are flagged ``simulated`` and unverified,
and the tenant lives in a dedicated demo database (see admin_cli.demo_database_guard).
Idempotent: re-running when the tenant exists changes nothing.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.admin_api import ensure_rbac
from cyberaudit.engagement_models import Report, ReportSection
from cyberaudit.enterprise_models import (
    ControlAssessment,
    EnterpriseRisk,
    GrcEvidenceLink,
    Incident,
    IncidentTimelineEntry,
    KnowledgeEdge,
    KnowledgeNode,
    UnifiedControl,
)
from cyberaudit.models import (
    Asset,
    AuthorizationDocument,
    Client,
    Criticality,
    Engagement,
    EngagementMode,
    EngagementStatus,
    Evidence,
    Finding,
    Intensity,
    JobStatus,
    Organization,
    Role,
    ScanJob,
    ScanProfile,
    Scope,
    ScopeTarget,
    TargetType,
    User,
)
from cyberaudit.phase4_models import AssetRelationship
from cyberaudit.provisioning import provision_assessment_catalog
from cyberaudit.security import hash_password

SLUG = "northstar-demo"
TAG = "[DEMO]"

ASSETS = [
    # name, type, ip, criticality, risk, internet_exposed
    ("Identity Gateway", "host", "10.40.0.10", Criticality.CRITICAL, 71.0, True),
    ("Domain Controller DC01", "host", "10.40.1.5", Criticality.CRITICAL, 64.0, False),
    ("ERP Database", "database", "10.40.2.20", Criticality.HIGH, 52.0, False),
    ("Customer Portal", "web_application", "10.40.3.30", Criticality.HIGH, 58.0, True),
    ("VPN Gateway", "network_device", "10.40.0.2", Criticality.HIGH, 46.0, True),
    ("Backup Server", "host", "10.40.4.40", Criticality.MEDIUM, 33.0, False),
    ("File Server FS02", "host", "10.40.4.50", Criticality.MEDIUM, 29.0, False),
    ("Public Storage Bucket", "cloud_resource", "n/a", Criticality.MEDIUM, 41.0, True),
]
FINDINGS = [
    # title, severity, asset index, category, remediation
    (
        "MFA not enforced on identity gateway administrators",
        Criticality.CRITICAL,
        0,
        "identity",
        "Enforce phishing-resistant MFA for all administrative sign-ins.",
    ),
    (
        "Domain admin group contains an unowned service account",
        Criticality.HIGH,
        1,
        "identity",
        "Assign an owner, rotate the secret and remove unnecessary privileges.",
    ),
    (
        "Customer portal accepts TLS 1.0",
        Criticality.HIGH,
        3,
        "tls",
        "Disable TLS 1.0/1.1; require TLS 1.2 or later.",
    ),
    (
        "VPN gateway management interface reachable from the internet",
        Criticality.HIGH,
        4,
        "exposure",
        "Restrict management access to a dedicated admin network.",
    ),
    (
        "ERP database backups are not encrypted at rest",
        Criticality.MEDIUM,
        2,
        "data-protection",
        "Enable backup encryption and manage keys centrally.",
    ),
    (
        "Backup server missing the last three OS security updates",
        Criticality.MEDIUM,
        5,
        "patching",
        "Apply pending updates within the agreed maintenance window.",
    ),
    (
        "Storage bucket allows public listing",
        Criticality.MEDIUM,
        7,
        "cloud",
        "Disable public listing; use signed URLs for intended sharing.",
    ),
    (
        "File server shares readable by 'Everyone'",
        Criticality.MEDIUM,
        6,
        "access-control",
        "Replace broad ACLs with role-based groups.",
    ),
    (
        "HTTP security headers incomplete on the customer portal",
        Criticality.LOW,
        3,
        "web",
        "Add HSTS, CSP and X-Content-Type-Options.",
    ),
]


def _risk(
    reference: str,
    title: str,
    likelihood: float,
    impact: float,
    control_eff: float,
    asset_id: str | None,
    org: str,
) -> EnterpriseRisk:
    inherent = likelihood * impact
    return EnterpriseRisk(
        organization_id=org,
        reference=reference,
        title=f"{TAG} {title}",
        description="Synthetic risk for demonstration.",
        risk_type="cyber",
        category="identity",
        likelihood=likelihood,
        impact=impact,
        inherent_score=inherent,
        control_effectiveness=control_eff,
        residual_score=round(inherent * (1 - control_eff), 1),
        asset_id=asset_id,
        treatment_strategy="mitigate",
    )


async def seed_northstar(db: AsyncSession, admin_password: str) -> str:
    """Create the demo tenant; returns the organization id (existing id if already present)."""
    existing = await db.scalar(select(Organization).where(Organization.slug == SLUG))
    if existing:
        return existing.id
    await ensure_rbac(db)
    roles = {r.name: r for r in (await db.scalars(select(Role))).all()}
    now = datetime.now(timezone.utc)

    org = Organization(name=f"Northstar Industries {TAG}", slug=SLUG)
    db.add(org)
    await db.flush()
    pw = hash_password(admin_password)
    admin = User(
        organization_id=org.id,
        name="Ana Costa (DEMO)",
        email="ana.costa@northstar-demo.example.com",
        password_hash=pw,
        roles=[roles["Administrator"]],
    )
    analyst = User(
        organization_id=org.id,
        name="Rui Mendes (DEMO)",
        email="rui.mendes@northstar-demo.example.com",
        password_hash=pw,
        roles=[roles["Security Analyst"]],
    )
    viewer = User(
        organization_id=org.id,
        name="Inês Faria (DEMO)",
        email="ines.faria@northstar-demo.example.com",
        password_hash=pw,
        roles=[roles["Read-only Viewer"]],
    )
    db.add_all([admin, analyst, viewer])
    await db.flush()
    await provision_assessment_catalog(db, org.id, admin.id)

    client = Client(
        organization_id=org.id,
        name=f"Northstar Industries {TAG}",
        legal_name="Northstar Industries, S.A. (fictional)",
        email="ciso@northstar-demo.example.com",
    )
    db.add(client)
    await db.flush()
    eng = Engagement(
        organization_id=org.id,
        client_id=client.id,
        name=f"Enterprise Security Assessment {TAG}",
        code="NORTHSTAR-DEMO-01",
        description="Synthetic engagement used for product demonstrations.",
        mode=EngagementMode.CLIENT,
        status=EngagementStatus.ACTIVE,
        start_date=date.today() - timedelta(days=10),
        end_date=date.today() + timedelta(days=20),
        owner_id=admin.id,
        risk_level=Criticality.HIGH,
    )
    db.add(eng)
    await db.flush()
    scope = Scope(
        organization_id=org.id,
        engagement_id=eng.id,
        name="Northstar corporate network (DEMO)",
        status="active",
    )
    db.add(scope)
    await db.flush()
    db.add(
        ScopeTarget(
            scope_id=scope.id,
            target_type=TargetType.CIDR,
            target_value="10.40.0.0/16",
            normalized_value="10.40.0.0/16",
            notes="Synthetic range (RFC1918)",
        )
    )
    db.add(
        AuthorizationDocument(
            organization_id=org.id,
            engagement_id=eng.id,
            filename="demo-authorization.pdf",
            storage_key="demo/none",
            file_hash="0" * 64,
            valid_from=date.today() - timedelta(days=15),
            valid_until=date.today() + timedelta(days=60),
            signed_by="Northstar CISO (fictional)",
            uploaded_by=admin.id,
        )
    )

    assets: list[Asset] = []
    for name, kind, ip, crit, asset_risk, exposed in ASSETS:
        asset = Asset(
            organization_id=org.id,
            engagement_id=eng.id,
            name=name,
            asset_type=kind,
            identifier=name.lower().replace(" ", "-"),
            ip_address=None if ip == "n/a" else ip,
            criticality=crit,
            risk_score=asset_risk,
            exposure_score=70.0 if exposed else 25.0,
            internet_exposed=exposed,
            owner="Northstar IT (fictional)",
        )
        assets.append(asset)
    db.add_all(assets)
    await db.flush()
    for src, dst, rel in [
        (0, 1, "authenticates_against"),
        (3, 2, "depends_on"),
        (4, 0, "connects_to"),
        (5, 2, "backs_up"),
        (6, 1, "joined_to"),
    ]:
        db.add(
            AssetRelationship(
                organization_id=org.id,
                source_asset_id=assets[src].id,
                target_asset_id=assets[dst].id,
                relationship_type=rel,
                source="demo_seed",
            )
        )

    profile = await db.scalar(
        select(ScanProfile).where(
            ScanProfile.organization_id == org.id,
            ScanProfile.adapter_code == "cyberaudit.external_result_import",
        )
    )
    assert profile is not None
    job = ScanJob(
        organization_id=org.id,
        engagement_id=eng.id,
        scope_id=scope.id,
        scan_profile_id=profile.id,
        adapter_code=profile.adapter_code,
        target_type=TargetType.CIDR,
        target_value="10.40.0.0/16",
        normalized_target="10.40.0.0/16",
        technique="external-import",
        intensity=Intensity.PASSIVE,
        status=JobStatus.COMPLETED,
        requested_by=analyst.id,
        progress=100,
        status_message="Synthetic demonstration data (not a real scan)",
        result_summary={"simulated": True},
        started_at=now - timedelta(hours=3),
        completed_at=now - timedelta(hours=2),
    )
    db.add(job)
    await db.flush()

    findings: list[Finding] = []
    for index, (title, severity, asset_index, category, fix) in enumerate(FINDINGS):
        findings.append(
            Finding(
                organization_id=org.id,
                engagement_id=eng.id,
                job_id=job.id,
                asset_id=assets[asset_index].id,
                title=f"{TAG} {title}",
                description=f"Synthetic finding for demonstration: {title.lower()}.",
                category=category,
                technical_severity=severity,
                confidence="medium",
                status="open",
                affected_component=assets[asset_index].name,
                technical_impact="Illustrative impact (synthetic).",
                business_impact="Illustrative business impact (synthetic).",
                remediation_summary=fix,
                validation_steps=["Confirm the change in a re-test."],
                source_adapter=profile.adapter_code,
                fingerprint=f"northstar-demo-{index:02d}".ljust(64, "0"),
                simulated=True,
                imported=False,
                verification_status="unverified",
            )
        )
    db.add_all(findings)
    await db.flush()

    evidence = [
        Evidence(
            organization_id=org.id,
            engagement_id=eng.id,
            job_id=job.id,
            evidence_type="configuration_excerpt",
            title=f"{TAG} Identity gateway admin policy export",
            content_hash="a" * 64,
            collected_by_adapter="demo_seed",
            description="Synthetic excerpt showing MFA disabled for the admin role.",
        ),
        Evidence(
            organization_id=org.id,
            engagement_id=eng.id,
            job_id=job.id,
            evidence_type="log_excerpt",
            title=f"{TAG} Repeated failed sign-ins (synthetic)",
            content_hash="b" * 64,
            collected_by_adapter="demo_seed",
            description="Synthetic log lines for the incident timeline.",
        ),
    ]
    db.add_all(evidence)
    await db.flush()

    incident = Incident(
        organization_id=org.id,
        reference="INC-NS-DEMO-001",
        title=f"{TAG} Suspicious admin sign-in burst on Identity Gateway",
        description="Synthetic incident used for the SOC walkthrough.",
        severity="high",
        status="investigating",
        category="identity",
        detected_at=now - timedelta(hours=5),
        business_impact="Potential administrative account compromise (synthetic).",
        risk_score=7.5,
    )
    db.add(incident)
    await db.flush()
    for offset, title in [
        (5, "Burst of failed administrator sign-ins"),
        (4, "Successful sign-in from new network"),
        (3, "Analyst opened investigation"),
    ]:
        db.add(
            IncidentTimelineEntry(
                organization_id=org.id,
                incident_id=incident.id,
                entry_type="note",
                occurred_at=now - timedelta(hours=offset),
                title=f"{TAG} {title}",
                source="demo_seed",
                created_by=analyst.id,
            )
        )

    control = UnifiedControl(
        organization_id=org.id,
        code="NS-IAM-01",
        title=f"{TAG} Multi-factor authentication for privileged access",
        description="MFA for all privileged identities.",
        domain="Identity and Access Management",
        implementation_status="partially_implemented",
        maturity_level=2,
        status="approved",
    )
    control2 = UnifiedControl(
        organization_id=org.id,
        code="NS-DP-02",
        title=f"{TAG} Encrypted backups",
        description="Backups encrypted at rest.",
        domain="Data Protection",
        implementation_status="not_implemented",
        maturity_level=1,
        status="approved",
    )
    db.add_all([control, control2])
    await db.flush()
    db.add(
        ControlAssessment(
            organization_id=org.id,
            control_id=control.id,
            assessor_id=analyst.id,
            status="completed",
            result="partially_effective",
            effectiveness=0.4,
            tested_at=now - timedelta(days=2),
            notes="MFA enforced for staff, not for gateway administrators (synthetic).",
        )
    )
    db.add(
        ControlAssessment(
            organization_id=org.id,
            control_id=control2.id,
            assessor_id=analyst.id,
            status="completed",
            result="ineffective",
            effectiveness=0.1,
            tested_at=now - timedelta(days=2),
            notes="Backups not encrypted (synthetic).",
        )
    )
    db.add(
        GrcEvidenceLink(
            organization_id=org.id,
            evidence_id=evidence[0].id,
            subject_type="control",
            subject_id=control.id,
            purpose="Shows the MFA gap (synthetic)",
        )
    )
    db.add(
        GrcEvidenceLink(
            organization_id=org.id,
            evidence_id=evidence[1].id,
            subject_type="incident",
            subject_id=incident.id,
            purpose="Timeline support (synthetic)",
        )
    )

    risk = _risk(
        "RISK-NS-001",
        "Administrative account takeover via missing MFA",
        4,
        5,
        0.4,
        assets[0].id,
        org.id,
    )
    risk2 = _risk(
        "RISK-NS-002",
        "Loss of recoverability from unencrypted backups",
        3,
        4,
        0.1,
        assets[5].id,
        org.id,
    )
    db.add_all([risk, risk2])
    await db.flush()

    # Knowledge graph projection so contextual Cyber AI has grounded, tenant-scoped sources.
    nodes = {}
    for node_type, source_id, label, facts in [
        (
            "incident",
            incident.id,
            incident.title,
            {"severity": "high", "status": "investigating", "simulated": True},
        ),
        ("risk", risk.id, risk.title, {"residual_score": risk.residual_score, "simulated": True}),
        (
            "control",
            control.id,
            control.title,
            {
                "implementation_status": "partially_implemented",
                "assessment": "partially_effective",
                "simulated": True,
            },
        ),
        (
            "asset",
            assets[0].id,
            assets[0].name,
            {"criticality": "critical", "internet_exposed": True, "simulated": True},
        ),
    ]:
        node = KnowledgeNode(
            organization_id=org.id,
            node_type=node_type,
            source_id=source_id,
            label=label,
            facts=facts,
            source_references=[f"{node_type}:{source_id}"],
            confidence=1,
        )
        db.add(node)
        nodes[node_type] = node
    await db.flush()
    for a, b, edge in [
        ("incident", "asset", "affects"),
        ("risk", "control", "mitigated_by"),
        ("incident", "risk", "informs"),
    ]:
        db.add(
            KnowledgeEdge(
                organization_id=org.id,
                source_node_id=nodes[a].id,
                target_node_id=nodes[b].id,
                edge_type=edge,
                facts={"basis": "synthetic_demo"},
                source_references=[],
                confidence=0.8,
            )
        )

    report = Report(
        organization_id=org.id,
        engagement_id=eng.id,
        report_type="executive_summary",
        title=f"Executive Summary — Northstar {TAG}",
        generated_by=admin.id,
        status="draft",
    )
    db.add(report)
    await db.flush()
    for position, finding in enumerate(findings):
        db.add(
            ReportSection(
                report_id=report.id,
                position=position,
                heading=finding.title,
                content_type="finding",
                body=finding.description,
                source_references=[finding.id],
            )
        )
    db.add(
        ReportSection(
            report_id=report.id,
            position=len(findings),
            heading="Analyst conclusion",
            content_type="analyst_conclusion",
            body="Identity hardening (MFA, privileged account hygiene) is the highest-value remediation. All content in this report is synthetic demonstration data.",
        )
    )
    await db.commit()
    return org.id
