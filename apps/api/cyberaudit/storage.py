import hashlib
import secrets
from pathlib import Path

from fastapi import UploadFile

from cyberaudit.config import get_settings


class LocalStorage:
    async def save_pdf(self, upload: UploadFile) -> tuple[str, str, int]:
        settings = get_settings()
        if Path(upload.filename or "").suffix.lower() != ".pdf":
            raise ValueError("Only PDF files are accepted")
        if upload.content_type != "application/pdf":
            raise ValueError("Invalid PDF MIME type")
        content = await upload.read(settings.max_upload_bytes + 1)
        if len(content) > settings.max_upload_bytes:
            raise ValueError("File too large")
        if not content.startswith(b"%PDF-"):
            raise ValueError("Invalid PDF signature")
        settings.upload_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = f"{secrets.token_hex(24)}.pdf"
        destination = (settings.upload_dir / key).resolve()
        if settings.upload_dir.resolve() not in destination.parents:
            raise ValueError("Unsafe storage path")
        destination.write_bytes(content)
        destination.chmod(0o600)
        return key, hashlib.sha256(content).hexdigest(), len(content)

    async def save_private_file(
        self,
        upload: UploadFile,
        *,
        allowed_extensions: set[str],
        allowed_mime_types: set[str],
        maximum_bytes: int,
    ) -> tuple[str, str, int]:
        suffix = Path(upload.filename or "").suffix.lower()
        if suffix not in allowed_extensions:
            raise ValueError("File extension is not allowed")
        if upload.content_type not in allowed_mime_types:
            raise ValueError("File MIME type is not allowed")
        content = await upload.read(maximum_bytes + 1)
        if len(content) > maximum_bytes:
            raise ValueError("File too large")
        if not content:
            raise ValueError("File is empty")
        settings = get_settings()
        settings.upload_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = f"{secrets.token_hex(24)}{suffix}"
        destination = (settings.upload_dir / key).resolve()
        if settings.upload_dir.resolve() not in destination.parents:
            raise ValueError("Unsafe storage path")
        destination.write_bytes(content)
        destination.chmod(0o600)
        return key, hashlib.sha256(content).hexdigest(), len(content)

    def read_private_file(self, key: str, maximum_bytes: int) -> bytes:
        settings = get_settings()
        if Path(key).name != key:
            raise ValueError("Unsafe storage key")
        source = (settings.upload_dir / key).resolve()
        if settings.upload_dir.resolve() not in source.parents:
            raise ValueError("Unsafe storage path")
        if not source.is_file():
            raise ValueError("Stored file not found")
        if source.stat().st_size > maximum_bytes:
            raise ValueError("Stored file exceeds maximum size")
        return source.read_bytes()
