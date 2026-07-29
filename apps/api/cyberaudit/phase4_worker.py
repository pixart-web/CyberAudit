"""Dedicated low-priority worker actors for vulnerability intelligence."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import dramatiq

from cyberaudit.db import SessionLocal
from cyberaudit.phase4_models import VulnerabilityFeed
from cyberaudit.queue import broker as _configured_broker  # noqa: F401
from cyberaudit.vulnerability_intelligence import VulnerabilityIntelligenceService

DEMO_FEED = {
    "provider": "CyberAudit Demo",
    "generated_at": "2026-01-15T00:00:00Z",
    "vulnerabilities": [
        {
            "external_id": "CVE-2026-10001",
            "title": "[SIMULADO] Serviço Orion anterior a 2.4",
            "description": "Registo fictício para validar correlação sem alegar vulnerabilidade real.",
            "severity": "high",
            "cvss_v3": 8.1,
            "cwes": ["CWE-20"],
            "references": ["https://example.invalid/advisories/CVE-2026-10001"],
            "affected_products": [
                {
                    "normalized_name": "cyberaudit-demo/orion-service",
                    "cpe": "cpe:2.3:a:cyberaudit_demo:orion_service:*:*:*:*:*:*:*:*",
                    "introduced": "1.0",
                    "fixed": "2.4",
                }
            ],
            "known_exploited": True,
            "ransomware_associated": False,
            "patch_available": True,
        },
        {
            "external_id": "OSV-DEMO-2026-2",
            "title": "[SIMULADO] Biblioteca Atlas anterior a 4.1",
            "description": "Exemplo OSV fictício e explicitamente simulado.",
            "severity": "medium",
            "affected_products": [
                {
                    "normalized_name": "cyberaudit-demo/atlas",
                    "purl": "pkg:generic/cyberaudit-demo/atlas",
                    "introduced": "3.0",
                    "fixed": "4.1",
                }
            ],
        },
    ],
}


@dramatiq.actor(queue_name="cyberaudit.feeds", max_retries=1, time_limit=120_000)
def sync_vulnerability_feed(feed_id: str) -> None:
    asyncio.run(_sync(feed_id))


async def _sync(feed_id: str) -> None:
    async with SessionLocal() as db:
        feed = await db.get(VulnerabilityFeed, feed_id)
        if not feed or not feed.enabled:
            return
        if feed.source_identifier != "embedded://phase4-demo":
            feed.last_error = "connector_not_approved"
            feed.last_sync_completed_at = datetime.now(timezone.utc)
            await db.commit()
            return
        content = json.dumps(DEMO_FEED, sort_keys=True).encode()
        try:
            await VulnerabilityIntelligenceService(db).import_feed_bytes(feed, content)
            await db.commit()
        except ValueError as exc:
            feed.last_error = str(exc)
            feed.last_sync_completed_at = datetime.now(timezone.utc)
            await db.commit()
