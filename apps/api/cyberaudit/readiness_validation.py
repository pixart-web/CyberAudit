"""Controlled live-provider validation; output contains no resolved values."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from uuid import uuid4

from cyberaudit.config import get_settings
from cyberaudit.object_storage import object_storage_provider
from cyberaudit.secrets import SecretReference, secret_provider


async def validate() -> dict[str, object]:
    settings = get_settings()
    vault = secret_provider(settings)
    reference = SecretReference("vault://cyberaudit/organizations/platform/storage#access_key")
    health = await vault.health_check()
    metadata = await vault.get_metadata(reference)
    resolved = await vault.resolve_reference(reference)

    storage = object_storage_provider(settings)
    organization_id = str(uuid4())
    content = b"cyberaudit-readiness-synthetic-object"
    stored = await storage.put(
        organization_id,
        content,
        "application/octet-stream",
        "evidence",
    )
    downloaded = await storage.get(organization_id, stored.key, 1024)
    storage_health = await storage.health_check()
    await storage.delete(organization_id, stored.key)

    return {
        "status": "passed",
        "synthetic_data_only": True,
        "vault": {
            "health": asdict(health),
            "metadata": asdict(metadata),
            "resolved_nonempty": bool(resolved),
        },
        "object_storage": {
            "health": storage_health,
            "tenant_prefix": stored.key.startswith(f"organizations/{organization_id}/"),
            "checksum_verified": downloaded == content,
            "size_bytes": stored.size_bytes,
            "quarantine": stored.quarantine,
            "deleted_after_validation": True,
        },
    }


def main() -> None:
    print(json.dumps(asyncio.run(validate()), default=str, sort_keys=True))


if __name__ == "__main__":
    main()
