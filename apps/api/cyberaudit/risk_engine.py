"""Deterministic and explainable contextual risk calculations."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class RiskContext(BaseModel):
    asset_criticality: float = Field(default=50, ge=0, le=100)
    business_service_criticality: float = Field(default=50, ge=0, le=100)
    data_classification: float = Field(default=40, ge=0, le=100)
    exposure: float = Field(default=30, ge=0, le=100)
    reachability: float = Field(default=30, ge=0, le=100)
    vulnerability_severity: float = Field(default=0, ge=0, le=100)
    vulnerability_confidence: float = Field(default=50, ge=0, le=100)
    known_exploited: bool = False
    exploit_availability: bool = False
    patch_availability: bool = False
    compensating_controls: float = Field(default=0, ge=0, le=100)
    asset_owner: bool = True
    environment: str = "unknown"
    network_zone: str = "unknown"
    age_days: int = Field(default=0, ge=0, le=3650)
    recurrence: int = Field(default=0, ge=0, le=100)
    evidence_quality: float = Field(default=50, ge=0, le=100)
    remediation_status: str = "open"
    accepted_risk: bool = False


class RiskResult(BaseModel):
    technical_score: float
    exposure_score: float
    exploitability_score: float
    business_impact_score: float
    confidence_score: float
    remediation_urgency_score: float
    overall_risk_score: float
    risk_level: Literal["informational", "low", "medium", "high", "critical"]
    explanation: str
    contributing_factors: list[str]
    reducing_factors: list[str]
    calculation_version: str = "risk-2.0.0"


def _level(score: float) -> Literal["informational", "low", "medium", "high", "critical"]:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"


class ContextualRiskEngine:
    """Versioned weighted model; every factor is visible and deterministic."""

    version = "risk-2.0.0"

    def calculate(self, context: RiskContext) -> RiskResult:
        technical = round(context.vulnerability_severity * 0.75 + context.recurrence * 0.25, 2)
        exposure = round(context.exposure * 0.6 + context.reachability * 0.4, 2)
        exploitability = min(
            100.0,
            context.vulnerability_severity * 0.35
            + (30 if context.known_exploited else 0)
            + (20 if context.exploit_availability else 0),
        )
        business = round(
            context.asset_criticality * 0.4
            + context.business_service_criticality * 0.4
            + context.data_classification * 0.2,
            2,
        )
        confidence = round(
            context.vulnerability_confidence * 0.6 + context.evidence_quality * 0.4, 2
        )
        urgency = min(
            100.0,
            technical * 0.35
            + exposure * 0.3
            + exploitability * 0.25
            + (10 if context.patch_availability else 0),
        )
        base = technical * 0.25 + exposure * 0.2 + exploitability * 0.2 + business * 0.35
        confidence_adjustment = 0.55 + (confidence / 100) * 0.45
        control_reduction = context.compensating_controls * 0.35
        ownership_penalty = 5 if not context.asset_owner else 0
        age_penalty = min(8.0, context.age_days / 365)
        score = max(
            0.0,
            min(
                100.0,
                base * confidence_adjustment - control_reduction + ownership_penalty + age_penalty,
            ),
        )
        reducing: list[str] = []
        contributing: list[str] = []
        if context.known_exploited:
            contributing.append("Vulnerabilidade incluída num catálogo de exploração conhecida")
        if context.exposure >= 70:
            contributing.append("Exposição elevada")
        if context.asset_criticality >= 70:
            contributing.append("Ativo crítico")
        if not context.asset_owner:
            contributing.append("Ativo sem proprietário")
        if context.patch_availability:
            contributing.append("Correção disponível aumenta a urgência de remediação")
        if context.compensating_controls:
            reducing.append("Controlos compensatórios observados")
        if context.accepted_risk:
            reducing.append("Risco aceite; o score inerente não é ocultado")
        if confidence < 50:
            reducing.append("Confiança limitada reduz o score até validação")
        score = round(score, 2)
        return RiskResult(
            technical_score=technical,
            exposure_score=exposure,
            exploitability_score=round(exploitability, 2),
            business_impact_score=business,
            confidence_score=confidence,
            remediation_urgency_score=round(urgency, 2),
            overall_risk_score=score,
            risk_level=_level(score),
            explanation=(
                f"Score {score:.1f}/100 calculado por {self.version} a partir de risco técnico, "
                "exposição, explorabilidade, impacto empresarial, confiança e controlos."
            ),
            contributing_factors=contributing,
            reducing_factors=reducing,
        )

    def simulate(
        self,
        baseline: list[RiskResult],
        removed_indexes: set[int],
        exposure_reduction: float = 0,
    ) -> dict[str, Any]:
        current = sum(result.overall_risk_score for result in baseline)
        projected = sum(
            max(0.0, result.overall_risk_score - exposure_reduction)
            for index, result in enumerate(baseline)
            if index not in removed_indexes
        )
        reduction = max(0.0, current - projected)
        percentage = 0.0 if current == 0 else round(reduction / current * 100, 2)
        return {
            "baseline_risk": round(current, 2),
            "projected_risk": round(projected, 2),
            "absolute_reduction": round(reduction, 2),
            "percentage_reduction": percentage,
            "language": "estimativa",
            "calculation_version": self.version,
        }
