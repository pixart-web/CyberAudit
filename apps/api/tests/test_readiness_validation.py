from datetime import datetime, timezone

import pytest

from cyberaudit import readiness_validation
from cyberaudit.object_storage import ObjectMetadata, ObjectStorageProvider
from cyberaudit.secrets import SecretHealth, SecretMetadata, SecretProvider


class FakeSecretProvider(SecretProvider):
    scheme = "vault://"

    def validate_reference(self, reference):
        return None

    async def resolve_reference(self, reference):
        return "synthetic-resolved-value"

    async def rotate_reference(self, reference):
        raise NotImplementedError

    async def get_metadata(self, reference):
        return SecretMetadata("vault", reference.uri, True)

    async def health_check(self):
        return SecretHealth(True, "vault", "synthetic vault is healthy", datetime.now(timezone.utc))


class FakeObjectStorageProvider(ObjectStorageProvider):
    def __init__(self):
        self._store: dict[str, bytes] = {}

    async def put(self, organization_id, content, content_type, object_type):
        key = f"organizations/{organization_id}/{object_type}/synthetic-object"
        self._store[key] = content
        return ObjectMetadata(
            key=key,
            content_hash="synthetic-hash",
            size_bytes=len(content),
            content_type=content_type,
            quarantine=False,
        )

    async def get(self, organization_id, key, maximum_bytes):
        return self._store[key]

    async def delete(self, organization_id, key):
        self._store.pop(key, None)

    async def health_check(self):
        return {"healthy": True, "provider": "fake"}


@pytest.mark.asyncio
async def test_validate_assembles_a_synthetic_only_result(monkeypatch):
    monkeypatch.setattr(
        readiness_validation, "secret_provider", lambda settings: FakeSecretProvider()
    )
    monkeypatch.setattr(
        readiness_validation,
        "object_storage_provider",
        lambda settings: FakeObjectStorageProvider(),
    )

    result = await readiness_validation.validate()

    assert result["status"] == "passed"
    assert result["synthetic_data_only"] is True
    assert result["vault"]["resolved_nonempty"] is True
    assert result["vault"]["health"]["healthy"] is True
    assert result["object_storage"]["tenant_prefix"] is True
    assert result["object_storage"]["checksum_verified"] is True
    assert result["object_storage"]["deleted_after_validation"] is True


@pytest.mark.asyncio
async def test_validate_surfaces_a_checksum_mismatch(monkeypatch):
    class MismatchingStorage(FakeObjectStorageProvider):
        async def get(self, organization_id, key, maximum_bytes):
            return b"tampered"

    monkeypatch.setattr(
        readiness_validation, "secret_provider", lambda settings: FakeSecretProvider()
    )
    monkeypatch.setattr(
        readiness_validation, "object_storage_provider", lambda settings: MismatchingStorage()
    )

    result = await readiness_validation.validate()

    assert result["object_storage"]["checksum_verified"] is False
