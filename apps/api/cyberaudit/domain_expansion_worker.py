"""Safe workers for controlled enterprise inventory imports."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import dramatiq

from cyberaudit.db import SessionLocal
from cyberaudit.domain_expansion_models import ConnectorExecution, EnterpriseConnector
from cyberaudit.queue import broker as _configured_broker  # noqa: F401
from cyberaudit.rls import set_tenant_context_from_resource


def connector_execution_allowed(
    execution: ConnectorExecution, connector: EnterpriseConnector | None
) -> bool:
    return bool(
        connector
        and connector.organization_id == execution.organization_id
        and connector.status == "active"
        and connector.read_only
    )


@dramatiq.actor(queue_name="cyberaudit.connectors", max_retries=2, time_limit=120_000)
def process_connector_execution(execution_id: str) -> None:
    asyncio.run(_process_connector_execution(execution_id))


async def _process_connector_execution(execution_id: str) -> None:
    """Validate persisted state again and process only controlled local metadata."""
    async with SessionLocal() as db:
        if db.get_bind().dialect.name == "postgresql":
            if not await set_tenant_context_from_resource(db, "connector_execution", execution_id):
                return
        execution = await db.get(ConnectorExecution, execution_id)
        if not execution:
            return
        connector = await db.get(EnterpriseConnector, execution.connector_id)
        if not connector_execution_allowed(execution, connector):
            execution.status = "failed"
            execution.error_code = "CONNECTOR_REVALIDATION_FAILED"
            execution.error_message = "Connector is unavailable, cross-tenant or not read-only"
            execution.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return
        assert connector is not None
        execution.status = "running"
        execution.started_at = datetime.now(timezone.utc)
        execution.worker_id = "safe-enterprise-import-worker"
        await db.flush()
        # Provider network collection is deliberately disabled in this phase.
        execution.status = "completed"
        execution.records_processed = 0
        execution.result_summary = {
            "external_io": False,
            "records_processed": 0,
            "message": "Controlled import queue verified; no external collection configured.",
        }
        execution.completed_at = datetime.now(timezone.utc)
        connector.last_synced_at = execution.completed_at
        connector.health_status = "ready"
        await db.commit()
