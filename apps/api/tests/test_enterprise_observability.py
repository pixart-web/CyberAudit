from cyberaudit import enterprise_observability as metrics


def test_enterprise_observability_registers_expected_low_cardinality_metrics():
    """Metrics modules must import cleanly and expose stable, low-cardinality names.

    Prometheus raises at import time on duplicate metric names, so importing
    the module and asserting its label sets is a real regression check, not a
    smoke test: it fails if a metric is renamed, its labels change shape, or a
    collision with another module's metric is introduced.
    """
    assert metrics.security_events_ingested._labelnames == ("source", "event_type")
    assert metrics.detections_created._labelnames == ("severity",)
    assert metrics.incidents_created._labelnames == ("severity",)
    assert metrics.grc_workflows._labelnames == ("workflow", "result")
    assert metrics.ai_requests._labelnames == ("service", "provider", "result")
    assert metrics.enterprise_operation_duration._labelnames == ("module", "operation")
    assert metrics.enterprise_connector_sync._labelnames == ("connector_type", "result")
    assert metrics.enterprise_connector_sync_duration._labelnames == ("connector_type",)
    assert metrics.enterprise_connector_records._labelnames == ("domain",)
    assert metrics.enterprise_inventory._labelnames == ("domain", "posture")
    assert metrics.enterprise_risk_evaluations._labelnames == ("domain", "result")
    assert metrics.enterprise_graph_projection._labelnames == ("domain", "result")
    assert metrics.enterprise_change_events._labelnames == ("domain", "severity")
    assert metrics.zero_trust_score._labelnames == ("subject_type",)
