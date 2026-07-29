import asyncio
import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cyberaudit.models import Criticality, Intensity, TargetType
from cyberaudit.network_security import NetworkExecutionPolicy


class AdapterMetadata(BaseModel):
    code: str
    name: str
    version: str
    category: str
    description: str
    supported_target_types: list[TargetType]
    supported_intensities: list[Intensity]
    requires_network: bool
    requires_approval: bool
    default_timeout: int
    configuration_schema: dict[str, Any]


class ValidationResult(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)


class NormalizedTarget(BaseModel):
    target_type: TargetType
    value: str


class AdapterRequest(BaseModel):
    target: NormalizedTarget
    technique: str
    intensity: Intensity
    configuration: dict[str, Any]


class ExecutionEstimate(BaseModel):
    duration_seconds: int
    risk: Literal["none", "low", "medium", "high"]
    summary: str


class NormalizedEvidence(BaseModel):
    kind: str
    summary: str
    content: str
    simulated: bool = True
    mime_type: str = "application/json"
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizedFinding(BaseModel):
    title: str
    description: str
    category: str
    severity: Criticality
    confidence: Literal["low", "medium", "high"]
    affected_component: str
    affected_version: str | None = None
    technical_impact: str
    business_impact: str
    remediation: str
    validation_steps: list[str]
    evidence: list[NormalizedEvidence]
    references: list[str] = Field(default_factory=list)
    source_identifier: str
    logical_location: str
    simulated: bool = True
    recommendation_type: str = "configuration"
    remediation_effort: Literal["trivial", "low", "medium", "high"] = "low"
    remediation_priority: Literal["low", "normal", "high", "urgent"] = "normal"
    standards: list[dict[str, str]] = Field(default_factory=list)
    observed_value: str | None = None
    expected_value: str | None = None
    reproducibility: Literal["unknown", "intermittent", "consistent"] = "consistent"
    imported: bool = False
    verification_status: Literal["unverified", "observed", "confirmed"] = "observed"


class AdapterWarning(BaseModel):
    code: str
    message: str


class AdapterExecutionSummary(BaseModel):
    status: Literal["success", "warning", "failure", "timeout", "cancelled"]
    message: str
    simulated: bool = True


class ParsedAdapterOutput(BaseModel):
    findings: list[NormalizedFinding] = Field(default_factory=list)
    evidence: list[NormalizedEvidence] = Field(default_factory=list)
    warnings: list[AdapterWarning] = Field(default_factory=list)
    summary: AdapterExecutionSummary


class AdapterExecutionResult(BaseModel):
    execution_id: str
    raw_output: bytes
    summary: AdapterExecutionSummary


ProgressCallback = Callable[[int, str], Awaitable[None]]
CancellationCheck = Callable[[], Awaitable[bool]]


class AdapterExecutionContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    execution_id: str
    request: AdapterRequest
    progress_callback: ProgressCallback
    cancellation_check: CancellationCheck
    network_policy: NetworkExecutionPolicy | None = None
    allowed_destinations: list[str] = Field(default_factory=list)


class HealthCheckResult(BaseModel):
    healthy: bool
    message: str
    checked_at: datetime


class ExecutionSandboxConfig(BaseModel):
    read_only_filesystem: bool = True
    container_image: str | None = None
    container_image_digest: str | None = None
    read_only_root_filesystem: bool = True
    drop_all_capabilities: bool = True
    allowed_capabilities: list[str] = Field(default_factory=list)
    no_new_privileges: bool = True
    seccomp_profile: str = "runtime/default"
    apparmor_profile: str | None = None
    user_namespace: bool = True
    run_as_user: int = Field(default=65532, ge=1000)
    run_as_group: int = Field(default=65532, ge=1000)
    temporary_directory: str = "isolated://ephemeral"
    tmpfs_size_mb: int = Field(default=64, ge=16, le=512)
    cpu_limit: float = Field(default=1.0, gt=0, le=4)
    cpu_quota: int = Field(default=100000, ge=1000, le=400000)
    cpu_shares: int = Field(default=256, ge=2, le=1024)
    memory_limit_mb: int = Field(default=256, ge=64, le=2048)
    swap_limit_mb: int = Field(default=0, ge=0, le=2048)
    process_limit: int = Field(default=1, ge=1, le=32)
    maximum_open_files: int = Field(default=256, ge=32, le=4096)
    network_mode: Literal["none", "restricted"] = "none"
    network_namespace: bool = True
    allowed_destinations: list[str] = Field(default_factory=list)
    allowed_protocols: list[Literal["tcp", "udp", "icmp"]] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    dns_policy: Literal["none", "pinned", "internal-only"] = "none"
    timeout: int = Field(default=60, ge=1, le=3600)
    environment_allowlist: list[str] = Field(default_factory=list)
    mounted_inputs: list[str] = Field(default_factory=list)
    mounted_outputs: list[str] = Field(default_factory=list)
    execution_timeout: int = Field(default=60, ge=1, le=3600)
    termination_grace_period: int = Field(default=5, ge=1, le=30)

    @property
    def maximum_processes(self) -> int:
        return self.process_limit

    @property
    def memory_limit(self) -> int:
        return self.memory_limit_mb


class ToolAdapter(ABC):
    @abstractmethod
    def metadata(self) -> AdapterMetadata: ...

    @abstractmethod
    async def validate_configuration(self, configuration: dict[str, Any]) -> ValidationResult: ...

    @abstractmethod
    async def validate_target(self, target: NormalizedTarget) -> ValidationResult: ...

    @abstractmethod
    async def estimate(self, request: AdapterRequest) -> ExecutionEstimate: ...

    @abstractmethod
    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult: ...

    @abstractmethod
    async def cancel(self, execution_id: str) -> None: ...

    @abstractmethod
    async def parse_output(self, raw_output: bytes) -> ParsedAdapterOutput: ...

    @abstractmethod
    async def health_check(self) -> HealthCheckResult: ...


class DemoConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: Literal["clean", "low_risk", "mixed", "critical", "warning", "failure", "timeout"] = (
        "mixed"
    )
    duration_seconds: int = Field(default=10, ge=10, le=30)
    finding_count: int = Field(default=3, ge=0, le=6)


DEMO_FINDINGS = [
    (
        "demo.outdated-service",
        "Serviço de demonstração desatualizado",
        "software",
        Criticality.HIGH,
    ),
    ("demo.weak-password", "Política de password fraca", "identity", Criticality.MEDIUM),
    ("demo.mfa-disabled", "Autenticação multifator desativada", "identity", Criticality.CRITICAL),
    (
        "demo.certificate-expiry",
        "Certificado de demonstração próximo da expiração",
        "crypto",
        Criticality.LOW,
    ),
    ("demo.exposed-config", "Configuração fictícia exposta", "configuration", Criticality.HIGH),
    (
        "demo.stale-device",
        "Dispositivo de demonstração sem atualização recente",
        "patching",
        Criticality.MEDIUM,
    ),
]


class DemoAssessmentAdapter(ToolAdapter):
    def __init__(self) -> None:
        self._cancelled: set[str] = set()

    def metadata(self) -> AdapterMetadata:
        return AdapterMetadata(
            code="cyberaudit.demo_assessment",
            name="Demo Assessment",
            version="1.0.0",
            category="simulation",
            description="Adaptador determinístico e totalmente simulado; não comunica com o alvo.",
            supported_target_types=list(TargetType),
            supported_intensities=[Intensity.PASSIVE, Intensity.LOW, Intensity.NORMAL],
            requires_network=False,
            requires_approval=False,
            default_timeout=45,
            configuration_schema=DemoConfiguration.model_json_schema(),
        )

    async def validate_configuration(self, configuration: dict[str, Any]) -> ValidationResult:
        try:
            DemoConfiguration.model_validate(configuration)
            return ValidationResult(valid=True)
        except ValueError as exc:
            return ValidationResult(valid=False, errors=[str(exc)])

    async def validate_target(self, target: NormalizedTarget) -> ValidationResult:
        return ValidationResult(
            valid=bool(target.value), errors=[] if target.value else ["empty target"]
        )

    async def estimate(self, request: AdapterRequest) -> ExecutionEstimate:
        config = DemoConfiguration.model_validate(request.configuration)
        return ExecutionEstimate(
            duration_seconds=config.duration_seconds,
            risk="none",
            summary="Simulação local sem rede, processos externos ou acesso ao sistema de ficheiros.",
        )

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = DemoConfiguration.model_validate(context.request.configuration)
        steps = max(config.duration_seconds * 2, 1)
        for step in range(steps):
            if context.execution_id in self._cancelled or await context.cancellation_check():
                summary = AdapterExecutionSummary(
                    status="cancelled", message="Simulação cancelada."
                )
                return self._result(context, config, summary)
            if config.scenario == "timeout":
                await asyncio.sleep(0.5)
                await context.progress_callback(
                    min(79, 20 + step * 60 // steps), "A simular timeout"
                )
                continue
            await asyncio.sleep(0.5)
            await context.progress_callback(
                min(80, 20 + (step + 1) * 60 // steps), "Avaliação simulada"
            )
        if config.scenario == "failure":
            summary = AdapterExecutionSummary(
                status="failure", message="Falha simulada controlada."
            )
        elif config.scenario == "warning":
            summary = AdapterExecutionSummary(
                status="warning", message="Concluído com aviso simulado."
            )
        else:
            summary = AdapterExecutionSummary(
                status="success", message="Avaliação simulada concluída."
            )
        return self._result(context, config, summary)

    def _result(
        self,
        context: AdapterExecutionContext,
        config: DemoConfiguration,
        summary: AdapterExecutionSummary,
    ) -> AdapterExecutionResult:
        payload = {
            "simulated": True,
            "scenario": config.scenario,
            "finding_count": config.finding_count,
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
        scenario = payload["scenario"]
        count = int(payload["finding_count"])
        selected = DEMO_FINDINGS[:count]
        if scenario == "clean":
            selected = []
        elif scenario == "low_risk":
            selected = [item for item in DEMO_FINDINGS if item[3] == Criticality.LOW][:count]
        elif scenario == "critical":
            selected = [DEMO_FINDINGS[2]]
        findings = [
            NormalizedFinding(
                title=f"[SIMULADO] {title}",
                description="Resultado fictício gerado pelo adaptador seguro de demonstração.",
                category=category,
                severity=severity,
                confidence="high",
                affected_component=payload["target"],
                technical_impact="Impacto técnico exclusivamente demonstrativo.",
                business_impact="Sem impacto real; este finding é simulado.",
                remediation="Rever a configuração fictícia no ambiente de demonstração.",
                validation_steps=["Confirmar que o cenário de demonstração foi removido."],
                evidence=[
                    NormalizedEvidence(
                        kind="simulation",
                        summary="Evidência simulada",
                        content=f"Fonte determinística: {source}",
                    )
                ],
                source_identifier=source,
                logical_location=payload["target"],
            )
            for source, title, category, severity in selected
        ]
        warnings = (
            [AdapterWarning(code="DEMO_WARNING", message="Aviso simulado controlado.")]
            if scenario == "warning"
            else []
        )
        return ParsedAdapterOutput(
            findings=findings,
            warnings=warnings,
            summary=AdapterExecutionSummary.model_validate(payload["summary"]),
        )

    async def health_check(self) -> HealthCheckResult:
        return HealthCheckResult(
            healthy=True,
            message="Adaptador de demonstração disponível; rede e subprocessos desativados.",
            checked_at=datetime.now(timezone.utc),
        )


class AdapterRegistry:
    def __init__(self, adapters: list[ToolAdapter] | None = None) -> None:
        self._adapters: dict[str, ToolAdapter] = {}
        if adapters is None:
            from cyberaudit.phase3_adapters import REAL_ADAPTERS
            from cyberaudit.phase4_adapters import PHASE4_ADAPTERS
            from cyberaudit.phase5_adapters import PHASE5_ADAPTERS

            adapters = [
                DemoAssessmentAdapter(),
                *REAL_ADAPTERS,
                *PHASE4_ADAPTERS,
                *PHASE5_ADAPTERS,
            ]
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: ToolAdapter) -> None:
        code = adapter.metadata().code
        if code in self._adapters:
            raise ValueError(f"Duplicate adapter code: {code}")
        self._adapters[code] = adapter

    def get(self, code: str) -> ToolAdapter:
        try:
            return self._adapters[code]
        except KeyError as exc:
            raise LookupError(f"Unknown adapter: {code}") from exc

    def metadata(self) -> list[AdapterMetadata]:
        return [adapter.metadata() for adapter in self._adapters.values()]

    async def health_check(self, code: str) -> HealthCheckResult:
        return await self.get(code).health_check()


def finding_fingerprint(
    organization_id: str,
    engagement_id: str,
    asset_id: str | None,
    finding: NormalizedFinding,
    adapter_code: str,
) -> str:
    components = [
        organization_id,
        engagement_id,
        asset_id or "",
        finding.category,
        finding.affected_component,
        finding.source_identifier,
        finding.logical_location,
        adapter_code,
    ]
    return hashlib.sha256("\x1f".join(components).encode()).hexdigest()


def sanitize_raw_output(raw: bytes, limit: int = 1_048_576) -> tuple[bytes, bool]:
    if len(raw) > limit:
        raise ValueError("Raw output exceeds maximum size")
    text = raw.decode("utf-8", errors="replace")
    for key in ("password", "token", "secret", "authorization", "api_key"):
        import re

        text = re.sub(
            rf'(?i)("{key}"\s*:\s*")[^"]*(")',
            r"\1[REDACTED]\2",
            text,
        )
    return text.encode(), True
