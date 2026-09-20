import pytest

from cyberaudit.asset_graph import (
    AttackPathAnalysisService,
    CyberAssetGraphService,
    PostgreSQLAssetGraphRepository,
)
from cyberaudit.models import Asset, Criticality
from cyberaudit.phase4_models import AssetRelationship


def asset(organization_id: str, name: str, exposed: bool, criticality: str) -> Asset:
    return Asset(
        organization_id=organization_id,
        engagement_id="engagement",
        name=name,
        asset_type="server",
        identifier=f"{organization_id}-{name}",
        criticality=Criticality.HIGH,
        status="active",
        internet_exposed=exposed,
        business_criticality=criticality,
        risk_score=80 if criticality == "critical" else 40,
    )


@pytest.mark.asyncio
async def test_graph_and_attack_paths_are_tenant_isolated(db):
    entry = asset("org-a", "Internet API", True, "high")
    target = asset("org-a", "Critical DB", False, "critical")
    foreign = asset("org-b", "Other tenant", True, "critical")
    db.add_all([entry, target, foreign])
    await db.flush()
    relation = AssetRelationship(
        organization_id="org-a",
        source_asset_id=entry.id,
        target_asset_id=target.id,
        relationship_type="depends_on",
        direction="directed",
        confidence=0.9,
        source="test",
        reviewed=True,
    )
    db.add(relation)
    await db.flush()
    graph = await CyberAssetGraphService(PostgreSQLAssetGraphRepository(db)).graph("org-a")
    assert {node["id"] for node in graph["nodes"]} == {entry.id, target.id}
    paths = await AttackPathAnalysisService(db).analyze("org-a")
    assert len(paths) == 1
    assert paths[0].status == "candidate"
    assert paths[0].entry_asset_id == entry.id
    assert paths[0].target_asset_id == target.id


@pytest.mark.asyncio
async def test_attack_path_cycle_is_bounded(db):
    first = asset("org-a", "A", True, "high")
    second = asset("org-a", "B", False, "critical")
    db.add_all([first, second])
    await db.flush()
    db.add_all(
        [
            AssetRelationship(
                organization_id="org-a",
                source_asset_id=first.id,
                target_asset_id=second.id,
                relationship_type="connected_to",
                direction="directed",
                confidence=0.8,
                source="test",
            ),
            AssetRelationship(
                organization_id="org-a",
                source_asset_id=second.id,
                target_asset_id=first.id,
                relationship_type="connected_to",
                direction="directed",
                confidence=0.8,
                source="test",
            ),
        ]
    )
    await db.flush()
    paths = await AttackPathAnalysisService(db).analyze("org-a", max_depth=3)
    assert len(paths) == 1
