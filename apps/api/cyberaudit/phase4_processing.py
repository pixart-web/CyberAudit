"""Normalize Phase 4 adapter observations into the living inventory."""

from __future__ import annotations

import ipaddress
import json
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.models import AssetSuggestion, Evidence, ScanJob, utcnow
from cyberaudit.phase4_models import (
    AssessmentCoverage,
    AssetChange,
    IPAddress,
    Service,
)


async def process_phase4_observations(
    db: AsyncSession,
    job: ScanJob,
    evidence_rows: list[Evidence],
) -> dict[str, int]:
    created = {"suggestions": 0, "services": 0, "changes": 0}
    for evidence in evidence_rows:
        if not evidence.sanitized_content:
            continue
        try:
            payload = json.loads(evidence.sanitized_content)
        except json.JSONDecodeError:
            continue
        if evidence.evidence_type == "host_discovery":
            for address in payload.get("active_hosts", []):
                db.add(
                    AssetSuggestion(
                        organization_id=job.organization_id,
                        engagement_id=job.engagement_id,
                        asset_id=None,
                        job_id=job.id,
                        suggestion_type="host_discovered",
                        proposed_value={
                            "primary_ip": str(address),
                            "identifier": str(address),
                            "asset_type": "unknown",
                            "lifecycle_status": "discovered",
                            "source": job.adapter_code,
                        },
                        reason=(
                            "Resposta TCP observada dentro do CIDR autorizado; "
                            "requer revisão humana antes de criar o ativo."
                        ),
                    )
                )
                created["suggestions"] += 1
        if evidence.evidence_type in {"port_discovery", "service_identification"} and job.asset_id:
            observations = payload.get("observations", payload.get("services", []))
            address = ipaddress.ip_address(job.normalized_target)
            ip_row = await db.scalar(
                select(IPAddress).where(
                    IPAddress.organization_id == job.organization_id,
                    IPAddress.address == str(address),
                )
            )
            if not ip_row:
                ip_row = IPAddress(
                    organization_id=job.organization_id,
                    address=str(address),
                    version=address.version,
                    scope_type="private" if address.is_private else "public",
                    public=not address.is_private,
                    private=address.is_private,
                    reserved=address.is_reserved,
                    asset_id=job.asset_id,
                    source=job.adapter_code,
                    confidence=0.95,
                )
                db.add(ip_row)
                await db.flush()
            for item in observations:
                if item.get("state") != "open":
                    continue
                port = int(item["port"])
                service = await db.scalar(
                    select(Service).where(
                        Service.organization_id == job.organization_id,
                        Service.asset_id == job.asset_id,
                        Service.ip_address_id == ip_row.id,
                        Service.port == port,
                        Service.transport_protocol == "tcp",
                    )
                )
                if not service:
                    service = Service(
                        organization_id=job.organization_id,
                        asset_id=job.asset_id,
                        ip_address_id=ip_row.id,
                        port=port,
                        transport_protocol="tcp",
                        application_protocol=item.get("service_name"),
                        service_name=item.get("service_name"),
                        product=item.get("product"),
                        version=item.get("version"),
                        encrypted=port in {443, 465, 636, 993, 995, 8443},
                        exposure="internet" if ip_row.public else "internal",
                        state="open",
                        confidence=float(
                            item.get("identification_confidence", item.get("confidence", 0.8))
                        ),
                        fingerprint_method=item.get("method", "tcp_connect"),
                        source_adapter=job.adapter_code,
                    )
                    db.add(service)
                    db.add(
                        AssetChange(
                            organization_id=job.organization_id,
                            asset_id=job.asset_id,
                            change_type="service_opened",
                            field_name="port",
                            previous_value=None,
                            current_value={"port": port, "transport": "tcp"},
                            source_job_id=job.id,
                            evidence_id=evidence.id,
                            severity="medium",
                        )
                    )
                    created["services"] += 1
                    created["changes"] += 1
                else:
                    service.last_seen_at = utcnow()
                    service.state = "open"
        category = {
            "host_discovery": "discovery",
            "port_discovery": "ports",
            "service_identification": "services",
            "os_identification": "operating_system",
            "exposure_assessment": "configuration",
            "vulnerability_correlation": "vulnerabilities",
        }.get(evidence.evidence_type)
        if category and job.asset_id:
            coverage = await db.scalar(
                select(AssessmentCoverage).where(
                    AssessmentCoverage.organization_id == job.organization_id,
                    AssessmentCoverage.engagement_id == job.engagement_id,
                    AssessmentCoverage.asset_id == job.asset_id,
                    AssessmentCoverage.assessment_category == category,
                )
            )
            if not coverage:
                coverage = AssessmentCoverage(
                    organization_id=job.organization_id,
                    engagement_id=job.engagement_id,
                    asset_id=job.asset_id,
                    assessment_category=category,
                )
                db.add(coverage)
            coverage.last_assessed_at = utcnow()
            coverage.next_recommended_at = utcnow() + timedelta(days=30)
            coverage.assessment_depth = "standard"
            coverage.status = "covered"
            coverage.result = "observed"
            coverage.confidence = 0.8
            coverage.coverage_score = 100
    return created
