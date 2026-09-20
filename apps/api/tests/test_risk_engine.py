from cyberaudit.risk_engine import ContextualRiskEngine, RiskContext


def test_risk_engine_is_deterministic_and_explainable():
    engine = ContextualRiskEngine()
    context = RiskContext(
        asset_criticality=95,
        business_service_criticality=90,
        data_classification=80,
        exposure=90,
        reachability=90,
        vulnerability_severity=90,
        vulnerability_confidence=95,
        known_exploited=True,
        exploit_availability=True,
        patch_availability=True,
        evidence_quality=95,
    )
    first = engine.calculate(context)
    second = engine.calculate(context)
    assert first == second
    assert first.overall_risk_score >= 80
    assert first.risk_level == "critical"
    assert first.calculation_version == "risk-2.0.0"
    assert first.contributing_factors


def test_controls_reduce_but_do_not_hide_inherent_risk():
    engine = ContextualRiskEngine()
    baseline = engine.calculate(
        RiskContext(vulnerability_severity=80, exposure=80, reachability=80)
    )
    controlled = engine.calculate(
        RiskContext(
            vulnerability_severity=80,
            exposure=80,
            reachability=80,
            compensating_controls=80,
            accepted_risk=True,
        )
    )
    assert controlled.overall_risk_score < baseline.overall_risk_score
    assert controlled.overall_risk_score >= 0
    assert any("aceite" in factor for factor in controlled.reducing_factors)


def test_risk_simulation_is_projection_only():
    engine = ContextualRiskEngine()
    rows = [
        engine.calculate(RiskContext(vulnerability_severity=80)),
        engine.calculate(RiskContext(vulnerability_severity=40)),
    ]
    before = [row.model_copy() for row in rows]
    result = engine.simulate(rows, {0})
    assert result["projected_risk"] < result["baseline_risk"]
    assert result["language"] == "estimativa"
    assert rows == before
