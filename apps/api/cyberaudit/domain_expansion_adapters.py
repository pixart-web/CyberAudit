"""Closed registry of safe enterprise posture adapter definitions.

Phase 6.2 adapters are fixture/import-only. They perform no network, filesystem
or process activity; provider SDK collectors can replace them behind the same
interface after a separate security review.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cyberaudit.adapters import (
    AdapterExecutionContext,
    AdapterExecutionResult,
    AdapterExecutionSummary,
    AdapterMetadata,
    AdapterRequest,
    ExecutionEstimate,
    HealthCheckResult,
    NormalizedEvidence,
    NormalizedTarget,
    ParsedAdapterOutput,
    ToolAdapter,
    ValidationResult,
)
from cyberaudit.models import Intensity, TargetType

ADAPTER_CODES = (
    "cyberaudit.active_directory.inventory",
    "cyberaudit.active_directory.posture",
    "cyberaudit.active_directory.trusts",
    "cyberaudit.active_directory.group_policy",
    "cyberaudit.active_directory.delegation",
    "cyberaudit.active_directory.kerberos_posture",
    "cyberaudit.active_directory.dns_posture",
    "cyberaudit.active_directory.certificate_services",
    "cyberaudit.entra.inventory",
    "cyberaudit.entra.identity_posture",
    "cyberaudit.entra.privileged_roles",
    "cyberaudit.entra.applications",
    "cyberaudit.entra.oauth_permissions",
    "cyberaudit.entra.conditional_access",
    "cyberaudit.entra.devices",
    "cyberaudit.entra.external_identities",
    "cyberaudit.microsoft365.inventory",
    "cyberaudit.microsoft365.exchange_posture",
    "cyberaudit.microsoft365.sharepoint_posture",
    "cyberaudit.microsoft365.onedrive_posture",
    "cyberaudit.microsoft365.teams_posture",
    "cyberaudit.microsoft365.defender_posture",
    "cyberaudit.microsoft365.purview_posture",
    "cyberaudit.microsoft365.intune_posture",
    "cyberaudit.google_workspace.inventory",
    "cyberaudit.google_workspace.identity_posture",
    "cyberaudit.google_workspace.oauth_posture",
    "cyberaudit.google_workspace.gmail_posture",
    "cyberaudit.google_workspace.drive_posture",
    "cyberaudit.google_workspace.access_context",
    "cyberaudit.google_workspace.device_posture",
    "cyberaudit.aws.inventory",
    "cyberaudit.aws.iam_posture",
    "cyberaudit.aws.network_posture",
    "cyberaudit.aws.storage_posture",
    "cyberaudit.aws.logging_posture",
    "cyberaudit.aws.compute_posture",
    "cyberaudit.aws.container_posture",
    "cyberaudit.aws.security_services",
    "cyberaudit.azure.inventory",
    "cyberaudit.azure.rbac_posture",
    "cyberaudit.azure.network_posture",
    "cyberaudit.azure.storage_posture",
    "cyberaudit.azure.compute_posture",
    "cyberaudit.azure.logging_posture",
    "cyberaudit.azure.key_vault_posture",
    "cyberaudit.azure.aks_posture",
    "cyberaudit.azure.defender_posture",
    "cyberaudit.gcp.inventory",
    "cyberaudit.gcp.iam_posture",
    "cyberaudit.gcp.network_posture",
    "cyberaudit.gcp.storage_posture",
    "cyberaudit.gcp.compute_posture",
    "cyberaudit.gcp.logging_posture",
    "cyberaudit.gcp.gke_posture",
    "cyberaudit.gcp.security_services",
    "cyberaudit.kubernetes.inventory",
    "cyberaudit.kubernetes.rbac_posture",
    "cyberaudit.kubernetes.workload_posture",
    "cyberaudit.kubernetes.network_posture",
    "cyberaudit.kubernetes.control_plane_posture",
    "cyberaudit.kubernetes.secret_metadata",
    "cyberaudit.kubernetes.admission_posture",
    "cyberaudit.container_runtime.inventory",
    "cyberaudit.container_runtime.posture",
    "cyberaudit.container_runtime.images",
    "cyberaudit.container_runtime.network",
    "cyberaudit.container_runtime.security_profiles",
)


class EnterpriseImportConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: Literal["empty", "demo"] = "empty"
    record_count: int = Field(default=0, ge=0, le=1000)


class EnterpriseReadOnlyAdapter(ToolAdapter):
    def __init__(self, code: str) -> None:
        if code not in ADAPTER_CODES:
            raise ValueError("Adapter code is not part of the reviewed registry")
        self.code = code
        self._cancelled: set[str] = set()

    def metadata(self) -> AdapterMetadata:
        domain = self.code.split(".")[1]
        return AdapterMetadata(
            code=self.code,
            name=self.code.removeprefix("cyberaudit.")
            .replace("_", " ")
            .replace(".", " · ")
            .title(),
            version="0.1.0",
            category=f"{domain}_posture",
            description=(
                "Read-only enterprise posture adapter. Current implementation accepts "
                "controlled demo metadata and performs no external I/O."
            ),
            supported_target_types=list(TargetType),
            supported_intensities=[Intensity.PASSIVE],
            requires_network=False,
            requires_approval=False,
            default_timeout=30,
            configuration_schema=EnterpriseImportConfiguration.model_json_schema(),
        )

    async def validate_configuration(self, configuration: dict[str, Any]) -> ValidationResult:
        try:
            EnterpriseImportConfiguration.model_validate(configuration)
        except ValueError as exc:
            return ValidationResult(valid=False, errors=[str(exc)])
        return ValidationResult(valid=True)

    async def validate_target(self, target: NormalizedTarget) -> ValidationResult:
        return ValidationResult(
            valid=bool(target.value),
            errors=[] if target.value else ["Target identifier is required"],
        )

    async def estimate(self, request: AdapterRequest) -> ExecutionEstimate:
        EnterpriseImportConfiguration.model_validate(request.configuration)
        return ExecutionEstimate(
            duration_seconds=1,
            risk="none",
            summary="Local deterministic posture import; no external connection is made.",
        )

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        configuration = EnterpriseImportConfiguration.model_validate(context.request.configuration)
        await context.progress_callback(60, "Validating controlled enterprise dataset")
        cancelled = context.execution_id in self._cancelled or await context.cancellation_check()
        summary = AdapterExecutionSummary(
            status="cancelled" if cancelled else "success",
            message=(
                "Enterprise import cancelled."
                if cancelled
                else "Read-only enterprise posture import completed."
            ),
        )
        payload = {
            "adapter_code": self.code,
            "simulated": True,
            "record_count": configuration.record_count,
            "target": context.request.target.value,
            "summary": summary.model_dump(),
        }
        return AdapterExecutionResult(
            execution_id=context.execution_id,
            raw_output=json.dumps(payload, sort_keys=True).encode(),
            summary=summary,
        )

    async def cancel(self, execution_id: str) -> None:
        self._cancelled.add(execution_id)

    async def parse_output(self, raw_output: bytes) -> ParsedAdapterOutput:
        payload = json.loads(raw_output.decode())
        return ParsedAdapterOutput(
            evidence=[
                NormalizedEvidence(
                    kind="enterprise_posture_import",
                    summary="Controlled read-only enterprise posture import",
                    content=json.dumps(
                        {
                            "adapter_code": payload["adapter_code"],
                            "record_count": payload["record_count"],
                            "simulated": True,
                        },
                        sort_keys=True,
                    ),
                    simulated=True,
                )
            ],
            summary=AdapterExecutionSummary.model_validate(payload["summary"]),
        )

    async def health_check(self) -> HealthCheckResult:
        return HealthCheckResult(
            healthy=True,
            message="Registered in safe fixture/import-only mode; external I/O disabled.",
            checked_at=datetime.now(timezone.utc),
        )


DOMAIN_EXPANSION_ADAPTERS: list[ToolAdapter] = [
    EnterpriseReadOnlyAdapter(code) for code in ADAPTER_CODES
]
