"""Tenant-safe object storage and upload inspection."""

from __future__ import annotations

import hashlib
import secrets
import zipfile
from abc import ABC, abstractmethod
from asyncio import to_thread
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlparse
from uuid import UUID

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from cyberaudit.config import Settings, get_settings


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

    async def create_download_url(
        self, organization_id: str, key: str, expires_seconds: int = 300
    ) -> str:
        raise NotImplementedError("Signed downloads are unavailable for this provider")


class S3Client(Protocol):
    def put_object(self, **kwargs: Any) -> Any: ...

    def get_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def delete_object(self, **kwargs: Any) -> Any: ...

    def generate_presigned_url(self, *args: Any, **kwargs: Any) -> str: ...

    def head_bucket(self, **kwargs: Any) -> Any: ...


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


class S3ObjectStorage(ObjectStorageProvider):
    """S3-compatible storage using workload identity and tenant-owned opaque keys."""

    _object_types = {
        "authorization",
        "evidence",
        "raw-result",
        "report",
        "import",
        "export",
        "backup",
    }

    def __init__(
        self,
        bucket: str,
        region: str,
        endpoint: str | None = None,
        *,
        environment: str = "production",
        client: S3Client | None = None,
    ) -> None:
        if not bucket or len(bucket) > 63:
            raise ValueError("A valid object storage bucket is required")
        if endpoint:
            parsed = urlparse(endpoint)
            local_test = environment in {"development", "test", "demo"} and parsed.hostname in {
                "localhost",
                "127.0.0.1",
                "::1",
            }
            if not parsed.netloc or (parsed.scheme != "https" and not local_test):
                raise ValueError("Object storage endpoint must use HTTPS")
        self.bucket = bucket
        self.region = region
        self.endpoint = endpoint
        self.client = client or cast(
            S3Client,
            boto3.client(
                "s3",
                region_name=region,
                endpoint_url=endpoint,
                config=Config(
                    connect_timeout=3,
                    read_timeout=10,
                    retries={"max_attempts": 2, "mode": "standard"},
                    signature_version="s3v4",
                ),
            ),
        )

    @staticmethod
    def _tenant(organization_id: str) -> str:
        try:
            return str(UUID(organization_id))
        except ValueError as exc:
            raise ValueError("Invalid organization identifier") from exc

    def _validate_key(self, organization_id: str, key: str) -> str:
        tenant = self._tenant(organization_id)
        prefix = f"organizations/{tenant}/"
        if not key.startswith(prefix) or len(key) > 500 or ".." in key.split("/") or "\\" in key:
            raise ValueError("Object key is outside the tenant partition")
        return key

    async def put(
        self, organization_id: str, content: bytes, content_type: str, object_type: str
    ) -> ObjectMetadata:
        tenant = self._tenant(organization_id)
        if object_type not in self._object_types:
            raise ValueError("Object type is not allowlisted")
        if not content:
            raise ValueError("Cannot store an empty object")
        content_hash = hashlib.sha256(content).hexdigest()
        key = f"organizations/{tenant}/{object_type}/{secrets.token_hex(24)}"
        await to_thread(
            self.client.put_object,
            Bucket=self.bucket,
            Key=key,
            Body=content,
            ContentLength=len(content),
            ContentType=content_type,
            Metadata={
                "sha256": content_hash,
                "organization-id": tenant,
                "trust": "untrusted",
            },
            ServerSideEncryption="AES256",
            Tagging="quarantine=true",
        )
        return ObjectMetadata(key, content_hash, len(content), content_type, quarantine=True)

    async def get(self, organization_id: str, key: str, maximum_bytes: int) -> bytes:
        validated_key = self._validate_key(organization_id, key)
        response = await to_thread(
            self.client.get_object,
            Bucket=self.bucket,
            Key=validated_key,
        )
        size = int(response.get("ContentLength", 0))
        if size < 0 or size > maximum_bytes:
            response["Body"].close()
            raise ValueError("Object exceeds the read limit")
        content = await to_thread(response["Body"].read, maximum_bytes + 1)
        response["Body"].close()
        if len(content) > maximum_bytes:
            raise ValueError("Object exceeds the read limit")
        expected_hash = response.get("Metadata", {}).get("sha256")
        if expected_hash and not secrets.compare_digest(
            expected_hash, hashlib.sha256(content).hexdigest()
        ):
            raise ValueError("Object checksum validation failed")
        return bytes(content)

    async def delete(self, organization_id: str, key: str) -> None:
        validated_key = self._validate_key(organization_id, key)
        await to_thread(
            self.client.delete_object,
            Bucket=self.bucket,
            Key=validated_key,
        )

    async def create_download_url(
        self, organization_id: str, key: str, expires_seconds: int = 300
    ) -> str:
        validated_key = self._validate_key(organization_id, key)
        if not 60 <= expires_seconds <= 900:
            raise ValueError("Signed URL expiry must be between 60 and 900 seconds")
        return str(
            await to_thread(
                self.client.generate_presigned_url,
                "get_object",
                Params={"Bucket": self.bucket, "Key": validated_key},
                ExpiresIn=expires_seconds,
            )
        )

    async def health_check(self) -> dict[str, object]:
        try:
            await to_thread(self.client.head_bucket, Bucket=self.bucket)
        except (BotoCoreError, ClientError):
            return {
                "healthy": False,
                "provider": "s3",
                "bucket_configured": True,
            }
        return {
            "healthy": True,
            "provider": "s3",
            "bucket_configured": True,
            "workload_identity": True,
        }


def object_storage_provider(settings: Settings | None = None) -> ObjectStorageProvider:
    config = settings or get_settings()
    if config.object_storage_provider == "filesystem":
        return FilesystemObjectStorage(config.upload_dir, config.environment)
    if config.object_storage_provider == "s3":
        if not config.object_storage_bucket:
            raise ValueError("S3 object storage bucket is required")
        return S3ObjectStorage(
            config.object_storage_bucket,
            config.object_storage_region,
            config.object_storage_endpoint,
            environment=config.environment,
        )
    return ExternalObjectStorage(
        config.object_storage_provider,
        config.object_storage_bucket or "",
    )
