import pytest

from cyberaudit.enterprise_services import SUPPORTED_FRAMEWORKS, calculate_residual_risk


def test_all_required_frameworks_are_supported():
    assert {
        "ISO27001",
        "ISO27002",
        "NIS2",
        "DORA",
        "PCI-DSS",
        "CIS",
        "NIST-CSF",
        "NIST-800-53",
        "SOC2",
        "GDPR",
    } == set(SUPPORTED_FRAMEWORKS)


def test_residual_risk_is_deterministic():
    inherent, residual = calculate_residual_risk(4, 5, 0.6)
    assert inherent == 20
    assert residual == 8


@pytest.mark.parametrize(
    ("likelihood", "impact", "effectiveness"),
    [(0, 1, 0), (1, 6, 0), (1, 1, -0.1), (1, 1, 1.1)],
)
def test_residual_risk_rejects_invalid_ranges(likelihood, impact, effectiveness):
    with pytest.raises(ValueError):
        calculate_residual_risk(likelihood, impact, effectiveness)
