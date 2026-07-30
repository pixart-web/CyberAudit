import asyncio
import hashlib
import ipaddress
import json
import socket
from datetime import datetime, timezone

import dramatiq
from sqlalchemy import select

from cyberaudit.adapters import (
    AdapterExecutionContext,
    AdapterRegistry,
    AdapterRequest,
    NormalizedTarget,
    finding_fingerprint,
    sanitize_raw_output,
)
from cyberaudit.db import SessionLocal
from cyberaudit.evidence import EvidenceSanitizer
from cyberaudit.models import (
    Approval,
    ApprovalStatus,
    Asset,
    AssetObservation,
    AssetSuggestion,
    Engagement,
    EngagementMode,
    EventType,
    Evidence,
    EvidenceSensitivity,
    Finding,
    FindingEvidence,
    JobEvent,
    JobStatus,
    RawResult,
    Retest,
    RetestStatus,
    ScanJob,
    ScanProfile,
    ScopeTarget,
    User,
    utcnow,
)
from cyberaudit.network_security import NetworkPolicyViolation, build_network_policy
from cyberaudit.observability import (
    asset_suggestions,
    evidence_redactions,
    findings_created,
    findings_deduplicated,
    jobs_cancelled,
    jobs_completed,
    jobs_failed,
    jobs_timed_out,
    ssrf_blocks,
    structured_event,
)
from cyberaudit.orchestrator import approval_is_expired, transition_job, update_progress
from cyberaudit.phase4_processing import process_phase4_observations
from cyberaudit.policy import ScopePolicyEngine
from cyberaudit.queue import broker as _configured_broker  # noqa: F401
from cyberaudit.rls import set_tenant_context_from_resource
from cyberaudit.schemas import PolicyRequest

registry = AdapterRegistry()
policy_engine = ScopePolicyEngine()


@dramatiq.actor(queue_name="cyberaudit.jobs", max_retries=0, time_limit=3_900_000)
def execute_scan_job(job_id: str) -> None:
    asyncio.run(run_job(job_id))


async def run_job(job_id: str) -> None:
    async with SessionLocal() as db:
        if db.get_bind().dialect.name == "postgresql":
            if not await set_tenant_context_from_resource(db, "scan_job", job_id):
                return
        job = await db.get(ScanJob, job_id)
        if not job or job.status not in {JobStatus.QUEUED, JobStatus.CANCELLING}:
            return
        if job.status == JobStatus.CANCELLING:
            await transition_job(db, job, JobStatus.CANCELLED, "Cancelado antes de iniciar")
            await db.commit()
            return
        job.worker_id = f"{socket.gethostname()}:{job_id[:8]}"
        await transition_job(db, job, JobStatus.STARTING, "Worker atribuído")
        await update_progress(db, job, 15, "Worker atribuído")
        await db.commit()
        user = await db.get(User, job.requested_by)
        profile = await db.get(ScanProfile, job.scan_profile_id)
        if not user or not profile or not profile.enabled:
            await fail_job(db, job, "WORKER_CONTEXT_INVALID", "Utilizador ou perfil indisponível")
            return
        approval_id = job.approval_id
        if approval_id:
            approval = await db.get(Approval, approval_id)
            if (
                not approval
                or approval.status != ApprovalStatus.APPROVED
                or approval_is_expired(approval.expires_at)
            ):
                await fail_job(db, job, "APPROVAL_INVALID", "Aprovação ausente ou expirada")
                return
        policy = await policy_engine.evaluate(
            db,
            PolicyRequest(
                organization_id=job.organization_id,
                engagement_id=job.engagement_id,
                operator_id=job.requested_by,
                target_type=job.target_type,
                target_value=job.normalized_target,
                technique=job.technique,
                requested_intensity=job.intensity,
                requested_at=datetime.now(timezone.utc),
                approval_id=job.approval_id,
            ),
        )
        db.add(
            JobEvent(
                organization_id=job.organization_id,
                job_id=job.id,
                event_type=EventType.POLICY_EVALUATED,
                severity="error" if policy.decision == "denied" else "info",
                message=f"Revalidação de política: {policy.decision}",
                event_metadata=policy.model_dump(mode="json"),
            )
        )
        if policy.decision == "denied":
            await fail_job(
                db,
                job,
                "FAILED_POLICY_REVALIDATION",
                "; ".join(policy.reasons),
            )
            return
        adapter = registry.get(job.adapter_code)
        config_validation = await adapter.validate_configuration(job.configuration)
        target = NormalizedTarget(target_type=job.target_type, value=job.normalized_target)
        target_validation = await adapter.validate_target(target)
        if not config_validation.valid or not target_validation.valid:
            await fail_job(
                db,
                job,
                "WORKER_VALIDATION_FAILED",
                "; ".join(config_validation.errors + target_validation.errors),
            )
            return
        await transition_job(db, job, JobStatus.RUNNING, "Execução autorizada iniciada")
        retest = await db.scalar(select(Retest).where(Retest.retest_job_id == job.id))
        if retest:
            retest.status = RetestStatus.RUNNING
        await update_progress(db, job, 20, "Adaptador iniciado")
        job.timeout_at = utcnow() + __import__("datetime").timedelta(
            seconds=profile.timeout_seconds
        )
        await db.commit()

        async def progress(value: int, message: str) -> None:
            await db.refresh(job)
            await update_progress(db, job, value, message)
            await db.commit()

        async def cancelled() -> bool:
            await db.refresh(job)
            return job.status == JobStatus.CANCELLING

        context = AdapterExecutionContext(
            execution_id=job.id,
            request=AdapterRequest(
                target=target,
                technique=job.technique,
                intensity=job.intensity,
                configuration=job.configuration,
            ),
            progress_callback=progress,
            cancellation_check=cancelled,
        )
        adapter_metadata = adapter.metadata()
        if adapter_metadata.requires_network:
            engagement = await db.get(Engagement, job.engagement_id)
            scope_targets = list(
                (
                    await db.scalars(
                        select(ScopeTarget).where(
                            ScopeTarget.scope_id == job.scope_id,
                            ScopeTarget.allowed.is_(True),
                        )
                    )
                ).all()
            )
            allowed_destinations = [item.normalized_value for item in scope_targets]
            laboratory = bool(engagement and engagement.mode == EngagementMode.LABORATORY)
            permits_private = laboratory or any(
                _scope_value_is_private(value) for value in allowed_destinations
            )
            network_policy = build_network_policy(
                category=profile.category,
                profile_timeout=profile.timeout_seconds,
                laboratory_mode=laboratory,
            ).model_copy(update={"allow_private_addresses": permits_private})
            context.network_policy = network_policy
            context.allowed_destinations = allowed_destinations
        try:
            result = await asyncio.wait_for(
                adapter.execute(context),
                timeout=profile.timeout_seconds,
            )
        except TimeoutError:
            await transition_job(db, job, JobStatus.TIMED_OUT, "Timeout de execução")
            job.error_code = "EXECUTION_TIMEOUT"
            job.error_message = "O adaptador excedeu o timeout do perfil"
            jobs_timed_out.labels(adapter_code=job.adapter_code).inc()
            await db.commit()
            return
        except asyncio.CancelledError:
            await db.refresh(job)
            if job.status != JobStatus.CANCELLING:
                await transition_job(db, job, JobStatus.CANCELLING, "Cancelamento cooperativo")
            await transition_job(db, job, JobStatus.CANCELLED, "Cancelamento concluído")
            await db.commit()
            return
        except (NetworkPolicyViolation, ValueError, OSError) as exc:
            if isinstance(exc, NetworkPolicyViolation):
                ssrf_blocks.labels(reason=str(exc)).inc()
            await fail_job(db, job, "ADAPTER_SAFETY_BLOCK", str(exc))
            return
        if result.summary.status == "cancelled":
            await db.refresh(job)
            if job.status != JobStatus.CANCELLING:
                await transition_job(db, job, JobStatus.CANCELLING, "Adaptador a terminar")
            await transition_job(db, job, JobStatus.CANCELLED, "Cancelamento concluído")
            jobs_cancelled.labels(adapter_code=job.adapter_code).inc()
            await db.commit()
            return
        if result.summary.status == "failure":
            await fail_job(db, job, "ADAPTER_FAILURE", result.summary.message)
            return
        await transition_job(db, job, JobStatus.PROCESSING_RESULTS, "A processar resultados")
        await update_progress(db, job, 85, "Output recebido")
        raw, sanitized = sanitize_raw_output(result.raw_output)
        db.add(
            RawResult(
                organization_id=job.organization_id,
                job_id=job.id,
                adapter_code=job.adapter_code,
                format="application/json",
                content_hash=hashlib.sha256(raw).hexdigest(),
                sanitized=sanitized,
                size_bytes=len(raw),
                untrusted_content=raw.decode(errors="replace"),
            )
        )
        parsed = await adapter.parse_output(raw)
        await update_progress(db, job, 90, "A normalizar findings")
        if job.asset_id:
            asset = await db.get(Asset, job.asset_id)
            if asset and asset.organization_id == job.organization_id:
                asset.last_seen_at = utcnow()
        persisted_evidence: list[Evidence] = []
        sanitizer = EvidenceSanitizer()
        for normalized_evidence in parsed.evidence:
            sanitized_evidence = sanitizer.sanitize_text(normalized_evidence.content)
            evidence_row = Evidence(
                organization_id=job.organization_id,
                engagement_id=job.engagement_id,
                job_id=job.id,
                evidence_type=normalized_evidence.kind,
                title=normalized_evidence.summary,
                description="Evidência sanitizada recolhida por avaliação autorizada.",
                content_hash=sanitized_evidence.content_hash,
                mime_type=normalized_evidence.mime_type,
                size_bytes=sanitized_evidence.size_bytes,
                sensitivity=EvidenceSensitivity(normalized_evidence.sensitivity),
                redacted=sanitized_evidence.redacted
                or bool(normalized_evidence.metadata.get("redacted")),
                collected_by_adapter=job.adapter_code,
                evidence_metadata={
                    **normalized_evidence.metadata,
                    "simulated": normalized_evidence.simulated,
                    "untrusted": True,
                },
                sanitized_content=sanitized_evidence.content,
            )
            db.add(evidence_row)
            if evidence_row.redacted:
                evidence_redactions.inc()
            await db.flush()
            persisted_evidence.append(evidence_row)
            if normalized_evidence.kind == "structured_data":
                db.add(
                    AssetObservation(
                        organization_id=job.organization_id,
                        engagement_id=job.engagement_id,
                        asset_id=job.asset_id,
                        job_id=job.id,
                        observation_type=profile.category,
                        value={"evidence_id": evidence_row.id},
                        source_adapter=job.adapter_code,
                        confidence="medium",
                    )
                )
                if profile.category == "asset_inventory":
                    try:
                        inventory = json.loads(sanitized_evidence.content)
                    except json.JSONDecodeError:
                        inventory = {}
                    for address in inventory.get("resolved_ips", []):
                        db.add(
                            AssetSuggestion(
                                organization_id=job.organization_id,
                                engagement_id=job.engagement_id,
                                asset_id=job.asset_id,
                                job_id=job.id,
                                suggestion_type="observed_ip",
                                proposed_value={"ip_address": str(address)},
                                reason="IP observado por resolução autorizada; requer revisão.",
                            )
                        )
                        asset_suggestions.labels(result="created").inc()
        created = 0
        deduplicated = 0
        observed_fingerprints: set[str] = set()
        for normalized in parsed.findings:
            fingerprint = finding_fingerprint(
                job.organization_id,
                job.engagement_id,
                job.asset_id,
                normalized,
                job.adapter_code,
            )
            observed_fingerprints.add(fingerprint)
            existing = await db.scalar(
                select(Finding).where(
                    Finding.organization_id == job.organization_id,
                    Finding.fingerprint == fingerprint,
                )
            )
            evidence = [item.model_dump() for item in normalized.evidence]
            if existing:
                existing.last_seen_at = utcnow()
                existing.job_id = job.id
                existing.evidence = [*existing.evidence, *evidence]
                for evidence_row in persisted_evidence:
                    db.add(
                        FindingEvidence(
                            finding_id=existing.id,
                            evidence_id=evidence_row.id,
                            job_id=job.id,
                        )
                    )
                deduplicated += 1
                continue
            finding = Finding(
                organization_id=job.organization_id,
                engagement_id=job.engagement_id,
                asset_id=job.asset_id,
                job_id=job.id,
                title=normalized.title,
                description=normalized.description,
                category=normalized.category,
                technical_severity=normalized.severity,
                confidence=normalized.confidence,
                affected_component=normalized.affected_component,
                affected_version=normalized.affected_version,
                technical_impact=normalized.technical_impact,
                business_impact=normalized.business_impact,
                remediation_summary=normalized.remediation,
                validation_steps=normalized.validation_steps,
                source_adapter=job.adapter_code,
                fingerprint=fingerprint,
                evidence=evidence,
                recommendation_type=normalized.recommendation_type,
                remediation_effort=normalized.remediation_effort,
                remediation_priority=normalized.remediation_priority,
                standards=normalized.standards,
                references=normalized.references,
                observed_value=normalized.observed_value,
                expected_value=normalized.expected_value,
                location=normalized.logical_location,
                reproducibility=normalized.reproducibility,
                imported=normalized.imported,
                simulated=normalized.simulated,
                verification_status=normalized.verification_status,
            )
            db.add(finding)
            await db.flush()
            db.add(
                JobEvent(
                    organization_id=job.organization_id,
                    job_id=job.id,
                    event_type=EventType.FINDING_CREATED,
                    severity="info",
                    message="Finding normalizado criado",
                    event_metadata={
                        "finding_id": finding.id,
                        "simulated": normalized.simulated,
                        "imported": normalized.imported,
                    },
                )
            )
            for evidence_row in persisted_evidence:
                db.add(
                    FindingEvidence(
                        finding_id=finding.id,
                        evidence_id=evidence_row.id,
                        job_id=job.id,
                    )
                )
            created += 1
        phase4_inventory = await process_phase4_observations(db, job, persisted_evidence)
        job.result_summary = {
            "simulated": parsed.summary.simulated,
            "findings_created": created,
            "findings_deduplicated": deduplicated,
            "evidence_created": len(persisted_evidence),
            "inventory_updates": phase4_inventory,
            "warnings": [warning.model_dump() for warning in parsed.warnings],
            "network": (
                {
                    "maximum_requests": context.network_policy.maximum_requests,
                    "maximum_response_bytes": context.network_policy.maximum_response_bytes,
                    "maximum_redirects": context.network_policy.maximum_redirects,
                    "allowed_ports": list(context.network_policy.allowed_ports),
                }
                if context.network_policy
                else None
            ),
        }
        if retest:
            original_finding = await db.get(Finding, retest.finding_id)
            if not original_finding:
                retest.status = RetestStatus.INCONCLUSIVE
                retest.result = "original_finding_missing"
            elif original_finding.fingerprint in observed_fingerprints:
                retest.status = RetestStatus.FAILED
                retest.result = "finding_still_observed"
            elif parsed.summary.status in {"success", "warning"}:
                retest.status = RetestStatus.PASSED
                retest.result = "finding_not_observed"
                original_finding.verification_status = "confirmed"
                original_finding.status = "remediated"
            else:
                retest.status = RetestStatus.INCONCLUSIVE
                retest.result = "assessment_inconclusive"
            retest.completed_at = utcnow()
        findings_created.labels(adapter_code=job.adapter_code).inc(created)
        findings_deduplicated.labels(adapter_code=job.adapter_code).inc(deduplicated)
        terminal = JobStatus.COMPLETED_WITH_WARNINGS if parsed.warnings else JobStatus.COMPLETED
        await transition_job(db, job, terminal, parsed.summary.message)
        await update_progress(db, job, 100, "Concluído")
        jobs_completed.labels(adapter_code=job.adapter_code).inc()
        structured_event(
            "job_completed",
            organization_id=job.organization_id,
            engagement_id=job.engagement_id,
            job_id=job.id,
            worker_id=job.worker_id,
            adapter_code=job.adapter_code,
            result=terminal.value,
        )
        await db.commit()


async def fail_job(db, job: ScanJob, code: str, message: str) -> None:
    await transition_job(db, job, JobStatus.FAILED, message)
    job.error_code = code
    job.error_message = message
    jobs_failed.labels(adapter_code=job.adapter_code, code=code).inc()
    structured_event(
        "job_failed",
        organization_id=job.organization_id,
        engagement_id=job.engagement_id,
        job_id=job.id,
        worker_id=job.worker_id,
        adapter_code=job.adapter_code,
        result=code,
    )
    await db.commit()


def _scope_value_is_private(value: str) -> bool:
    candidate = value.strip()
    try:
        if "/" in candidate:
            return ipaddress.ip_network(candidate, strict=False).is_private
        return ipaddress.ip_address(candidate).is_private
    except ValueError:
        return False
