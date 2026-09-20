import pytest

from cyberaudit.enterprise_models import KnowledgeNode
from cyberaudit.enterprise_services import AiQuestion, DeterministicGroundedProvider


@pytest.mark.asyncio
async def test_ai_answer_has_sources_confidence_and_limitations():
    source = KnowledgeNode(
        id="node-1",
        organization_id="org-1",
        node_type="finding",
        source_id="finding-1",
        label="Synthetic finding",
        facts={"severity": "high"},
        source_references=["finding:finding-1"],
        confidence=0.8,
    )
    answer = await DeterministicGroundedProvider().answer(
        AiQuestion(service="explanation", question="Explica este finding"),
        [source],
    )
    assert answer.citations[0]["source_id"] == "finding-1"
    assert answer.facts
    assert answer.inferences == []
    assert answer.confidence == 0.8
    assert answer.limitations
    assert len(answer.reproducibility_key) == 64


@pytest.mark.asyncio
async def test_ai_refuses_to_invent_without_sources():
    answer = await DeterministicGroundedProvider().answer(
        AiQuestion(service="executive", question="Qual é o risco atual?"),
        [],
    )
    assert answer.confidence == 0
    assert answer.citations == []
    assert "Não existem fontes" in answer.response
