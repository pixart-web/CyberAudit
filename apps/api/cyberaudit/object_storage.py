"""Tenant-safe object storage and upload inspection."""

from __future__ import annotations

import hashlib
import secrets
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class ObjectMetadata:
    key: str
    content_hash: str
    size_bytes: int
    content_type: str
    quarantine: bool


class ObjectStorageProvider(ABC):
    @abstractmethod
    async def put(
        self, organization_id: str, content: bytes, content_type: str, object_type: str
    ) -> ObjectMetadata: ...

    @abstractmethod
    async def get(self, organization_id: str, key: str, maximum_bytes: int) -> bytes: ...

    @abstractmethod
    async def delete(self, organization_id: str, key: str) -> None: ...

    @abstractmethod
    async def health_check(self) -> dict[str, object]: ...


def inspect_upload(
    content: bytes,
    *,
    filename: str,
    content_type: str,
    allowed_types: set[str],
    maximum_bytes: int,
) -> None:
    if not content or len(content) > maximum_bytes:
        raise ValueError("Upload is empty or exceeds its size limit")
    safe_name = Path(filename).name
    if safe_name != filename or safe_name.count(".") > 2:
        raise ValueError("Unsafe filename or double extension")
    if content_type not in allowed_types:
        raise ValueError("Content type is not allowed")
    if content.startswith(b"PK\x03\x04"):
        with zipfile.ZipFile(BytesIO(content)) as archive:
            if len(archive.infolist()) > 1000:
                raise ValueError("Archive contains too many entries")
            expanded = sum(item.file_size for item in archive.infolist())
            if expanded > maximum_bytes * 10:
                raise ValueError("Archive expansion ratio is unsafe")
            for item in archive.infolist():
                path = Path(item.filename)
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("Archive contains an unsafe path")


class FilesystemObjectStorage(ObjectStorageProvider):
    def __init__(self, root: Path, environment: str) -> None:
        if environment not in {"development", "test", "demo"}:
            raise ValueError("Filesystem object storage is development-only")
        self.root = root.resolve()

    def _path(self, organization_id: str, key: str) -> Path:
        if not organization_id.replace("-", "").isalnum() or Path(key).name != key:
            raise ValueError("Unsafe tenant or object key")
        path = (self.root / organization_id / key).resolve()
        if self.root not in path.parents:
            raise ValueError("Unsafe storage path")
        return path

    async def put(
        self, organization_id: str, content: bytes, content_type: str, object_type: str
    ) -> ObjectMetadata:
        suffix = {
            "application/pdf": ".pdf",
            "application/json": ".json",
            "text/csv": ".csv",
        }.get(content_type, ".bin")
        key = f"{secrets.token_hex(24)}{suffix}"
        path = self._path(organization_id, key)
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_bytes(content)
        path.chmod(0o600)
        return ObjectMetadata(
            key,
            hashlib.sha256(content).hexdigest(),
            len(content),
            content_type,
            quarantine=True,
        )

    async def get(self, organization_id: str, key: str, maximum_bytes: int) -> bytes:
        path = self._path(organization_id, key)
        if not path.is_file() or path.stat().st_size > maximum_bytes:
            raise ValueError("Object is unavailable or exceeds the read limit")
        return path.read_bytes()

    async def delete(self, organization_id: str, key: str) -> None:
        path = self._path(organization_id, key)
        if path.is_file():
            path.unlink()

    async def health_check(self) -> dict[str, object]:
        return {"healthy": True, "provider": "filesystem", "production_ready": False}


class ExternalObjectStorage(ObjectStorageProvider):
    def __init__(self, provider: Literal["s3", "azure", "gcs"], bucket: str) -> None:
        self.provider = provider
        self.bucket = bucket

    async def put(
        self, organization_id: str, content: bytes, content_type: str, object_type: str
    ) -> ObjectMetadata:
        raise RuntimeError("External object storage SDK integration is not configured")

    async def get(self, organization_id: str, key: str, maximum_bytes: int) -> bytes:
        raise RuntimeError("External object storage SDK integration is not configured")

    async def delete(self, organization_id: str, key: str) -> None:
        raise RuntimeError("External deletion requires an approved lifecycle workflow")

    async def health_check(self) -> dict[str, object]:
        return {
            "healthy": False,
            "provider": self.provider,
            "bucket_configured": bool(self.bucket),
        }
