"""Allowlisted Phase 5 adapters; no package manager, shell or mutable HTTP method exists."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, ClassVar, Literal
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from cyberaudit.adapters import (
    AdapterExecutionContext,
    AdapterExecutionResult,
    AdapterExecutionSummary,
    AdapterMetadata,
    AdapterRequest,
    AdapterWarning,
    ExecutionEstimate,
    HealthCheckResult,
    NormalizedEvidence,
    NormalizedTarget,
    ParsedAdapterOutput,
    ToolAdapter,
    ValidationResult,
)
from cyberaudit.appsec_services import (
    detect_secrets,
    parse_api_specification,
    parse_cyclonedx_json,
    parse_dependency_manifest,
)
from cyberaudit.evidence import EvidenceSanitizer
from cyberaudit.models import Intensity, TargetType
from cyberaudit.network_security import NetworkPolicyViolation, SecureHttpClient


class ClosedConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WebInventoryConfig(ClosedConfig):
    maximum_pages: int = Field(default=1, ge=1, le=20)
    maximum_depth: int = Field(default=0, ge=0, le=2)
    include_well_known: bool = False


class DocumentConfig(ClosedConfig):
    filename: str = Field(max_length=255)
    content: str = Field(max_length=1_000_000)


class PostureConfig(ClosedConfig):
    declared_controls: dict[str, bool | str | int | float | None] = Field(default_factory=dict)


class SafeApiConfig(ClosedConfig):
    method: Literal["GET", "HEAD"] = "HEAD"


class BasePhase5Adapter(ToolAdapter):
    code: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[str]
    description: ClassVar[str]
    configuration_model: ClassVar[type[BaseModel]]
    target_types: ClassVar[list[TargetType]] = [TargetType.REPOSITORY]
    requires_network: ClassVar[bool] = False

    def metadata(self) -> AdapterMetadata:
        return AdapterMetadata(
            code=self.code,
            name=self.name,
            version="1.0.0",
            category=self.category,
            description=self.description,
            supported_target_types=self.target_types,
            supported_intensities=[Intensity.PASSIVE, Intensity.LOW],
            requires_network=self.requires_network,
            requires_approval=False,
            default_timeout=60,
            configuration_schema=self.configuration_model.model_json_schema(),
        )

    async def validate_configuration(self, configuration: dict[str, Any]) -> ValidationResult:
        try:
            self.configuration_model.model_validate(configuration)
        except ValueError as exc:
            return ValidationResult(valid=False, errors=[str(exc)])
        return ValidationResult(valid=True)

    async def validate_target(self, target: NormalizedTarget) -> ValidationResult:
        return ValidationResult(
            valid=target.target_type in self.target_types,
            errors=[] if target.target_type in self.target_types else ["unsupported_target_type"],
        )

    async def estimate(self, request: AdapterRequest) -> ExecutionEstimate:
        return ExecutionEstimate(
            duration_seconds=30,
            risk="low" if self.requires_network else "none",
            summary="Análise limitada, read-only, sem scripts, instalação ou métodos mutáveis.",
        )

    async def cancel(self, execution_id: str) -> None:
        return None

    async def parse_output(self, raw_output: bytes) -> ParsedAdapterOutput:
        return ParsedAdapterOutput.model_validate_json(raw_output)

    async def health_check(self) -> HealthCheckResult:
        return HealthCheckResult(
            healthy=True,
            message="Adapter allowlisted; health check não lê código nem contacta alvos.",
            checked_at=datetime.now(timezone.utc),
        )

    def result(
        self,
        context: AdapterExecutionContext,
        evidence: list[NormalizedEvidence],
        warnings: list[AdapterWarning] | None = None,
    ) -> AdapterExecutionResult:
        summary = AdapterExecutionSummary(
            status="warning" if warnings else "success",
            message=f"{self.name} concluído dentro dos limites.",
            simulated=False,
        )
        output = ParsedAdapterOutput(evidence=evidence, warnings=warnings or [], summary=summary)
        return AdapterExecutionResult(
            execution_id=context.execution_id,
            raw_output=output.model_dump_json().encode(),
            summary=summary,
        )


class WebInventoryAdapter(BasePhase5Adapter):
    code = "cyberaudit.web_inventory"
    name = "Web Inventory Passive"
    category = "web_inventory"
    description = "Um GET autorizado, links internos limitados e sem submissão de formulários."
    configuration_model = WebInventoryConfig
    target_types = [TargetType.URL]
    requires_network = True

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        if not context.network_policy:
            raise NetworkPolicyViolation("network_policy_missing")
        config = WebInventoryConfig.model_validate(context.request.configuration)
        response = await SecureHttpClient(
            context.network_policy, context.allowed_destinations
        ).request(
            context.request.target.value,
            method="GET",
            cancellation_check=context.cancellation_check,
        )
        text = response.body.decode("utf-8", errors="replace")
        origin = urlsplit(context.request.target.value)
        links: list[str] = []
        for raw in re.findall(r"""(?:href|src)=["']([^"'#]+)""", text, re.I)[:200]:
            candidate = urljoin(context.request.target.value, raw)
            parsed = urlsplit(candidate)
            if parsed.hostname == origin.hostname and candidate not in links:
                links.append(candidate)
        forms = len(re.findall(r"<form\b", text, re.I))
        sanitizer = EvidenceSanitizer()
        sanitized_headers = sanitizer.sanitize_headers(response.headers)
        await context.progress_callback(80, "Inventário web público recolhido")
        return self.result(
            context,
            [
                NormalizedEvidence(
                    kind="web_inventory",
                    summary="Estrutura web pública sanitizada",
                    content=json.dumps(
                        {
                            "url": context.request.target.value,
                            "status": response.status_code,
                            "links": links[: config.maximum_pages * 10],
                            "forms_observed": forms,
                            "forms_submitted": 0,
                            "headers": json.loads(sanitized_headers.content),
                            "bytes_received": response.bytes_received,
                            "limitations": [
                                "JavaScript não executado",
                                "Formulários não submetidos",
                                "Links externos ignorados",
                            ],
                        },
                        sort_keys=True,
                    ),
                    simulated=False,
                    metadata={"redacted": sanitized_headers.redacted},
                )
            ],
        )


class ApiSpecificationAdapter(BasePhase5Adapter):
    code = "cyberaudit.api_specification_import"
    name = "API Specification Import"
    category = "api_specification_import"
    description = "Parser JSON fechado; referências externas bloqueadas."
    configuration_model = DocumentConfig

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = DocumentConfig.model_validate(context.request.configuration)
        preview = parse_api_specification(config.content.encode())
        await context.progress_callback(80, "Contrato API normalizado")
        return self.result(
            context,
            [
                NormalizedEvidence(
                    kind="api_contract",
                    summary="Preview seguro do contrato API",
                    content=preview.model_dump_json(),
                    simulated=False,
                )
            ],
        )


class DependencyAnalysisAdapter(BasePhase5Adapter):
    code = "cyberaudit.dependency_analysis"
    name = "Dependency Inventory"
    category = "dependencies"
    description = "Interpreta lockfiles sem instalar packages nem executar scripts."
    configuration_model = DocumentConfig

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = DocumentConfig.model_validate(context.request.configuration)
        dependencies = parse_dependency_manifest(config.filename, config.content.encode())
        await context.progress_callback(80, "Dependências normalizadas")
        return self.result(
            context,
            [
                NormalizedEvidence(
                    kind="dependency_inventory",
                    summary="Dependências declaradas",
                    content=json.dumps({"dependencies": dependencies}, sort_keys=True),
                    simulated=False,
                )
            ],
        )


class SecretDetectionAdapter(BasePhase5Adapter):
    code = "cyberaudit.secret_detection"
    name = "Secret Detection"
    category = "secrets"
    description = "Deteta padrões e guarda apenas fingerprints e máscaras."
    configuration_model = DocumentConfig

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = DocumentConfig.model_validate(context.request.configuration)
        candidates = detect_secrets(config.content, config.filename)
        sanitized = [
            {
                "secret_type": item.secret_type,
                "fingerprint": item.fingerprint,
                "location": item.location,
                "length": item.length,
                "masked_prefix": item.masked_prefix,
                "confidence": item.confidence,
                "validated_externally": False,
            }
            for item in candidates
        ]
        await context.progress_callback(80, "Candidatos a segredo sanitizados")
        return self.result(
            context,
            [
                NormalizedEvidence(
                    kind="secret_candidates",
                    summary="Candidatos a segredo sem valores",
                    content=json.dumps({"candidates": sanitized}, sort_keys=True),
                    simulated=False,
                    sensitivity="restricted",
                    metadata={"redacted": True},
                )
            ],
        )


class SbomAnalysisAdapter(BasePhase5Adapter):
    code = "cyberaudit.software_composition_analysis"
    name = "Software Composition Analysis"
    category = "sca"
    description = "Normaliza CycloneDX e prepara correlação local, sem rede."
    configuration_model = DocumentConfig

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = DocumentConfig.model_validate(context.request.configuration)
        preview = parse_cyclonedx_json(config.content.encode())
        await context.progress_callback(80, "SBOM validada")
        return self.result(
            context,
            [
                NormalizedEvidence(
                    kind="sbom",
                    summary="SBOM normalizada",
                    content=preview.model_dump_json(),
                    simulated=False,
                )
            ],
        )


class PostureAdapter(BasePhase5Adapter):
    configuration_model = PostureConfig

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = PostureConfig.model_validate(context.request.configuration)
        await context.progress_callback(80, f"{self.name} analisado")
        return self.result(
            context,
            [
                NormalizedEvidence(
                    kind=self.category,
                    summary=f"{self.name} — configuração declarada",
                    content=json.dumps(
                        {
                            "declared_controls": config.declared_controls,
                            "active_testing": False,
                            "commands_executed": 0,
                            "credentials_validated": False,
                        },
                        sort_keys=True,
                    ),
                    simulated=False,
                )
            ],
        )


def posture_adapter(
    class_name: str, code: str, name: str, category: str, description: str
) -> type[PostureAdapter]:
    return type(
        class_name,
        (PostureAdapter,),
        {"code": code, "name": name, "category": category, "description": description},
    )


ApiContractAnalysisAdapter = posture_adapter(
    "ApiContractAnalysisAdapter",
    "cyberaudit.api_contract_analysis",
    "API Contract Review",
    "api_contract",
    "Analisa apenas o contrato persistido.",
)


class SafeApiAssessmentAdapter(BasePhase5Adapter):
    code = "cyberaudit.safe_api_assessment"
    name = "API Safe Runtime Check"
    category = "api_runtime"
    description = "Um GET/HEAD autorizado, sem payloads, fuzzing ou métodos mutáveis."
    configuration_model = SafeApiConfig
    target_types = [TargetType.URL]
    requires_network = True

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        if not context.network_policy:
            raise NetworkPolicyViolation("network_policy_missing")
        config = SafeApiConfig.model_validate(context.request.configuration)
        response = await SecureHttpClient(
            context.network_policy, context.allowed_destinations
        ).request(
            context.request.target.value,
            method=config.method,
            cancellation_check=context.cancellation_check,
        )
        headers = EvidenceSanitizer().sanitize_headers(response.headers)
        await context.progress_callback(80, "Resposta API segura recolhida")
        return self.result(
            context,
            [
                NormalizedEvidence(
                    kind="api_runtime",
                    summary="Resposta API segura e sanitizada",
                    content=json.dumps(
                        {
                            "method": config.method,
                            "status": response.status_code,
                            "headers": json.loads(headers.content),
                            "bytes_received": response.bytes_received,
                            "body_retained": False,
                            "mutating_methods_available": False,
                        },
                        sort_keys=True,
                    ),
                    simulated=False,
                    metadata={"redacted": headers.redacted},
                )
            ],
        )


AuthenticationPostureAdapter = posture_adapter(
    "AuthenticationPostureAdapter",
    "cyberaudit.authentication_posture",
    "Authentication Posture Review",
    "authentication",
    "Revê controlos declarados sem testar credenciais.",
)
AuthenticationPostureAdapter.target_types = [TargetType.URL]
SessionSecurityAdapter = posture_adapter(
    "SessionSecurityAdapter",
    "cyberaudit.session_security",
    "Session Security Review",
    "session",
    "Revê atributos sanitizados sem guardar cookies ou tokens.",
)
SessionSecurityAdapter.target_types = [TargetType.URL]
CorsAssessmentAdapter = posture_adapter(
    "CorsAssessmentAdapter",
    "cyberaudit.cors_assessment",
    "CORS Review",
    "cors",
    "Analisa configuração declarada e origins sintéticas.",
)
CorsAssessmentAdapter.target_types = [TargetType.URL]
SastAdapter = posture_adapter(
    "SastAdapter",
    "cyberaudit.sast_analysis",
    "SAST Baseline",
    "sast",
    "Contrato sandboxed; nenhuma ferramenta externa é executada nesta fase.",
)
IacAdapter = posture_adapter(
    "IacAdapter",
    "cyberaudit.iac_security",
    "IaC Baseline",
    "iac",
    "Análise read-only de representação importada.",
)
ContainerAdapter = posture_adapter(
    "ContainerAdapter",
    "cyberaudit.container_image_analysis",
    "Container Image Baseline",
    "container",
    "Analisa metadados; nunca executa imagens nem monta Docker socket.",
)
CicdAdapter = posture_adapter(
    "CicdAdapter",
    "cyberaudit.cicd_posture",
    "CI/CD Posture Review",
    "cicd",
    "Revê configuração importada sem modificar pipelines.",
)

PHASE5_ADAPTERS: list[ToolAdapter] = [
    WebInventoryAdapter(),
    ApiSpecificationAdapter(),
    ApiContractAnalysisAdapter(),
    SafeApiAssessmentAdapter(),
    AuthenticationPostureAdapter(),
    SessionSecurityAdapter(),
    CorsAssessmentAdapter(),
    DependencyAnalysisAdapter(),
    SbomAnalysisAdapter(),
    SecretDetectionAdapter(),
    SastAdapter(),
    IacAdapter(),
    ContainerAdapter(),
    CicdAdapter(),
]
