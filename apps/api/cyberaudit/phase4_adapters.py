"""Closed, low-impact adapters for controlled network and exposure assessment."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, ClassVar, Literal, cast

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
from cyberaudit.discovery import (
    PORT_PROFILES,
    BoundedNetworkDiscovery,
    CalculatedDiscoveryPolicy,
    bounded_hosts,
)
from cyberaudit.evidence import EvidenceSanitizer
from cyberaudit.models import Intensity, TargetType
from cyberaudit.network_security import NetworkPolicyViolation


class HostDiscoveryConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    probe_profile: Literal["minimal", "standard"] = "minimal"
    maximum_hosts: int = Field(default=32, ge=1, le=64)


class PortDiscoveryConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: Literal["minimal", "standard", "extended"] = "minimal"
    maximum_ports: int = Field(default=16, ge=1, le=32)


class ServiceIdentificationConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: Literal["minimal", "standard"] = "minimal"


class EmptyConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _result(
    context: AdapterExecutionContext,
    evidence: list[NormalizedEvidence],
    message: str,
    warnings: list[dict[str, str]] | None = None,
) -> AdapterExecutionResult:
    summary = AdapterExecutionSummary(
        status="warning" if warnings else "success",
        message=message,
        simulated=False,
    )
    payload = {
        "findings": [],
        "evidence": [item.model_dump(mode="json") for item in evidence],
        "warnings": warnings or [],
        "summary": summary.model_dump(mode="json"),
    }
    return AdapterExecutionResult(
        execution_id=context.execution_id,
        raw_output=json.dumps(payload, ensure_ascii=False, sort_keys=True).encode(),
        summary=summary,
    )


def _evidence(kind: str, summary: str, payload: Any) -> NormalizedEvidence:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    sanitized = EvidenceSanitizer().sanitize_text(text)
    return NormalizedEvidence(
        kind=kind,
        summary=summary,
        content=sanitized.content,
        simulated=False,
        metadata={"redacted": sanitized.redacted, "observation_only": True},
    )


def _target_is_allowed(target: str, allowed: list[str]) -> bool:
    try:
        candidate = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    for value in allowed:
        try:
            permitted = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if candidate.version == permitted.version and candidate.subnet_of(cast(Any, permitted)):
            return True
    return False


class ClosedPhase4Adapter(ToolAdapter):
    configuration_model: ClassVar[type[BaseModel]]
    adapter_code: ClassVar[str]
    adapter_name: ClassVar[str]
    description: ClassVar[str]
    category: ClassVar[str]
    target_types: ClassVar[list[TargetType]]
    requires_network: ClassVar[bool] = False
    default_timeout: ClassVar[int] = 120

    def metadata(self) -> AdapterMetadata:
        return AdapterMetadata(
            code=self.adapter_code,
            name=self.adapter_name,
            version="1.0.0",
            category=self.category,
            description=self.description,
            supported_target_types=self.target_types,
            supported_intensities=[Intensity.PASSIVE, Intensity.LOW],
            requires_network=self.requires_network,
            requires_approval=self.adapter_code == "cyberaudit.port_discovery",
            default_timeout=self.default_timeout,
            configuration_schema=self.configuration_model.model_json_schema(),
        )

    async def validate_configuration(self, configuration: dict[str, Any]) -> ValidationResult:
        try:
            self.configuration_model.model_validate(configuration)
        except ValueError as exc:
            return ValidationResult(valid=False, errors=[str(exc)])
        return ValidationResult(valid=True)

    async def validate_target(self, target: NormalizedTarget) -> ValidationResult:
        if target.target_type not in self.target_types:
            return ValidationResult(valid=False, errors=["unsupported_target_type"])
        if target.target_type in {TargetType.IP, TargetType.CIDR}:
            try:
                ipaddress.ip_network(target.value, strict=False)
            except ValueError:
                return ValidationResult(valid=False, errors=["invalid_network_target"])
        return ValidationResult(valid=True)

    async def estimate(self, request: AdapterRequest) -> ExecutionEstimate:
        return ExecutionEstimate(
            duration_seconds=self.default_timeout,
            risk="low" if self.requires_network else "none",
            summary=(
                "Observação limitada, sem stealth, autenticação, exploração, UDP ou comandos."
            ),
        )

    async def cancel(self, execution_id: str) -> None:
        return None

    async def parse_output(self, raw_output: bytes) -> ParsedAdapterOutput:
        return ParsedAdapterOutput.model_validate_json(raw_output)

    async def health_check(self) -> HealthCheckResult:
        return HealthCheckResult(
            healthy=True,
            message="Adaptador allowlisted carregado; health check não contacta destinos.",
            checked_at=datetime.now(timezone.utc),
        )


class HostDiscoveryAdapter(ClosedPhase4Adapter):
    configuration_model = HostDiscoveryConfiguration
    adapter_code = "cyberaudit.host_discovery"
    adapter_name = "Descoberta controlada de hosts"
    description = "TCP connect limitado a CIDR autorizado; gera apenas sugestões."
    category = "host_discovery"
    target_types = [TargetType.IP, TargetType.CIDR]
    requires_network = True

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        if not context.network_policy or not _target_is_allowed(
            context.request.target.value, context.allowed_destinations
        ):
            raise NetworkPolicyViolation("target_outside_calculated_scope")
        config = HostDiscoveryConfiguration.model_validate(context.request.configuration)
        ports = [
            port
            for port in PORT_PROFILES[config.probe_profile]
            if port in context.network_policy.allowed_ports
        ]
        if not ports:
            raise NetworkPolicyViolation("no_profile_ports_permitted_by_backend")
        policy = CalculatedDiscoveryPolicy(
            maximum_hosts=config.maximum_hosts,
            maximum_ports=len(ports),
            permitted_ports=ports,
            total_timeout=min(context.network_policy.total_timeout, self.default_timeout),
            host_timeout=min(context.network_policy.connect_timeout, 3),
            packets_per_second=int(min(context.network_policy.maximum_requests_per_second, 20)),
        )
        target = context.request.target.value
        hosts = (
            [str(ipaddress.ip_address(target))]
            if context.request.target.target_type == TargetType.IP
            else bounded_hosts(target, policy)
        )
        observations = await BoundedNetworkDiscovery(policy).scan(
            hosts, ports, context.cancellation_check, context.progress_callback
        )
        active_hosts = sorted({item["host"] for item in observations if item["state"] == "open"})
        return _result(
            context,
            [
                _evidence(
                    "host_discovery",
                    "Hosts potencialmente ativos por TCP connect controlado",
                    {
                        "active_hosts": active_hosts,
                        "probes": observations,
                        "limitations": [
                            "Ausência de resposta não confirma host inativo",
                            "Sem ICMP, ARP, UDP, raw packets ou expansão do CIDR",
                        ],
                    },
                )
            ],
            f"{len(active_hosts)} host(s) potencialmente ativo(s) observados",
        )


class PortDiscoveryAdapter(ClosedPhase4Adapter):
    configuration_model: ClassVar[type[BaseModel]] = PortDiscoveryConfiguration
    adapter_code = "cyberaudit.port_discovery"
    adapter_name = "Descoberta controlada de portas"
    description = "TCP connect com listas internas fechadas e limites backend."
    category = "port_discovery"
    target_types = [TargetType.IP]
    requires_network = True

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        if not context.network_policy or not _target_is_allowed(
            context.request.target.value, context.allowed_destinations
        ):
            raise NetworkPolicyViolation("target_outside_calculated_scope")
        config = PortDiscoveryConfiguration.model_validate(context.request.configuration)
        profile_ports = [
            port
            for port in PORT_PROFILES[config.profile]
            if port in context.network_policy.allowed_ports
        ]
        ports = profile_ports[: config.maximum_ports]
        if not ports:
            raise NetworkPolicyViolation("no_profile_ports_permitted_by_backend")
        policy = CalculatedDiscoveryPolicy(
            maximum_hosts=1,
            maximum_ports=config.maximum_ports,
            permitted_ports=ports,
            total_timeout=min(context.network_policy.total_timeout, self.default_timeout),
            host_timeout=min(context.network_policy.connect_timeout, 3),
            packets_per_second=int(min(context.network_policy.maximum_requests_per_second, 20)),
        )
        observations = await BoundedNetworkDiscovery(policy).scan(
            [context.request.target.value],
            ports,
            context.cancellation_check,
            context.progress_callback,
        )
        return _result(
            context,
            [
                _evidence(
                    "port_discovery",
                    "Estados de portas por TCP connect",
                    {
                        "observations": observations,
                        "profile": config.profile,
                        "limitations": [
                            "Sem UDP, stealth, evasão, flooding, decoys ou raw packets"
                        ],
                    },
                )
            ],
            f"{sum(item['state'] == 'open' for item in observations)} porta(s) aberta(s)",
        )


class ServiceIdentificationAdapter(PortDiscoveryAdapter):
    configuration_model: ClassVar[type[BaseModel]] = ServiceIdentificationConfiguration
    adapter_code = "cyberaudit.service_identification"
    adapter_name = "Identificação segura de serviços"
    description = "Classificação conservadora por porta e observação mínima, sem autenticação."
    category = "service_identification"

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = ServiceIdentificationConfiguration.model_validate(context.request.configuration)
        port_config = PortDiscoveryConfiguration(
            profile=config.profile, maximum_ports=len(PORT_PROFILES[config.profile])
        )
        forwarded = context.model_copy(
            update={
                "request": context.request.model_copy(
                    update={"configuration": port_config.model_dump()}
                )
            }
        )
        base = await super().execute(forwarded)
        payload = json.loads(base.raw_output)
        observations = json.loads(payload["evidence"][0]["content"])["observations"]
        names = {
            21: "ftp",
            22: "ssh",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            389: "ldap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            3389: "rdp",
            5432: "postgresql",
            8080: "http-alt",
            8443: "https-alt",
        }
        services = [
            {
                **item,
                "service_name": names.get(item["port"], "unknown"),
                "product": None,
                "version": None,
                "identification_confidence": 0.55,
                "fact": "porta acessível",
                "inference": "protocolo provável pela porta; não confirmado",
            }
            for item in observations
            if item["state"] == "open"
        ]
        return _result(
            context,
            [_evidence("service_identification", "Serviços prováveis", {"services": services})],
            f"{len(services)} serviço(s) provável(is); versões não inferidas",
        )


class OfflineObservationAdapter(ClosedPhase4Adapter):
    configuration_model = EmptyConfiguration
    target_types = [TargetType.IP, TargetType.HOSTNAME, TargetType.DOMAIN, TargetType.URL]
    requires_network = False

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        return _result(
            context,
            [
                _evidence(
                    self.category,
                    self.adapter_name,
                    {
                        "target": context.request.target.value,
                        "status": "insufficient_information",
                        "confidence": 0,
                        "limitations": [
                            "Análise usa apenas dados persistidos e não contacta o alvo",
                            "Sem evidência suficiente não é produzida conclusão",
                        ],
                    },
                )
            ],
            "Observação concluída sem inferências não suportadas",
        )


class SafeOsIdentificationAdapter(OfflineObservationAdapter):
    adapter_code = "cyberaudit.os_identification"
    adapter_name = "Identificação conservadora de sistema operativo"
    description = "Produz unknown quando os sinais persistidos são insuficientes."
    category = "os_identification"


class ExposureAssessmentAdapter(OfflineObservationAdapter):
    adapter_code = "cyberaudit.exposure_assessment"
    adapter_name = "Avaliação contextual de exposição"
    description = "Analisa dados persistidos sem assumir vulnerabilidade por porta aberta."
    category = "exposure_assessment"


class VulnerabilityCorrelationAdapter(OfflineObservationAdapter):
    adapter_code = "cyberaudit.vulnerability_correlation"
    adapter_name = "Correlação conservadora de vulnerabilidades"
    description = "Não contacta o alvo; matching exato é processado pelo serviço interno."
    category = "vulnerability_correlation"


PHASE4_ADAPTERS: list[ToolAdapter] = [
    HostDiscoveryAdapter(),
    PortDiscoveryAdapter(),
    ServiceIdentificationAdapter(),
    SafeOsIdentificationAdapter(),
    ExposureAssessmentAdapter(),
    VulnerabilityCorrelationAdapter(),
]
