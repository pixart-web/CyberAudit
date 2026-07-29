from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        secrets_dir=Path("/run/secrets") if Path("/run/secrets").is_dir() else None,
        extra="ignore",
    )
    environment: Literal[
        "development", "test", "demo", "staging", "production", "on_premises", "ha"
    ] = "development"
    database_url: str = "sqlite+aiosqlite:///./cyberaudit.db"
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str = "development-only-secret-change-me-32chars"
    encryption_key: str = "development-only-encryption-key-change-me"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    upload_dir: Path = Path("./uploads")
    max_upload_bytes: int = 10 * 1024 * 1024
    app_origin: str = "http://localhost:3000"
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "testserver"]
    debug: bool = False
    trusted_proxy: bool = False
    require_https: bool = False
    secure_cookies: bool = False
    authentication_mode: Literal["local", "oidc", "hybrid"] = "local"
    local_auth_enabled: bool = True
    oidc_enabled: bool = False
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret_reference: str | None = None
    oidc_redirect_uri: str | None = None
    oidc_scopes: list[str] = ["openid", "profile", "email", "groups"]
    oidc_allowed_domains: list[str] = []
    oidc_required_group: str | None = None
    oidc_jit_enabled: bool = False
    oidc_default_role: str = "Client"
    mfa_required: bool = False
    session_idle_minutes: int = Field(default=30, ge=5, le=1440)
    session_absolute_hours: int = Field(default=12, ge=1, le=168)
    maximum_sessions_per_user: int = Field(default=5, ge=1, le=50)
    secret_provider: Literal[
        "environment", "vault", "aws", "azure", "gcp", "kubernetes", "docker"
    ] = "environment"
    object_storage_provider: Literal["filesystem", "s3", "azure", "gcs"] = "filesystem"
    object_storage_bucket: str | None = None
    object_storage_endpoint: str | None = None
    connector_mode: Literal["fixture", "import", "live_read_only"] = "fixture"
    runner_type: Literal["local_restricted", "docker_ephemeral", "kubernetes_job"] = (
        "local_restricted"
    )
    telemetry_enabled: bool = False
    license_provider: Literal["community", "signed_offline", "online"] = "community"
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_pool_overflow: int = Field(default=10, ge=0, le=100)
    database_statement_timeout_ms: int = Field(default=30_000, ge=1000, le=300_000)
    request_max_bytes: int = Field(default=12 * 1024 * 1024, ge=1024)

    @property
    def production_like(self) -> bool:
        return self.environment in {"staging", "production", "on_premises", "ha"}

    @model_validator(mode="after")
    def reject_insecure_production(self) -> "Settings":
        if not self.production_like:
            return self
        errors: list[str] = []
        if "sqlite" in self.database_url:
            errors.append("SQLite is not allowed")
        if (
            self.jwt_secret.startswith(("development-", "replace-", "change-", "example-"))
            or len(self.jwt_secret) < 32
        ):
            errors.append("JWT_SECRET must be a non-default value of at least 32 characters")
        if (
            self.encryption_key.startswith(("development-", "replace-", "change-", "example-"))
            or len(self.encryption_key) < 32
        ):
            errors.append("ENCRYPTION_KEY must be a non-default value")
        if self.debug:
            errors.append("debug must be disabled")
        if "*" in self.allowed_hosts:
            errors.append("wildcard allowed hosts are forbidden")
        if not self.require_https or not self.secure_cookies:
            errors.append("HTTPS and secure cookies are required")
        if urlparse(self.app_origin).scheme != "https":
            errors.append("APP_ORIGIN must use HTTPS")
        if self.authentication_mode == "local" or not self.oidc_enabled:
            errors.append("OIDC must be enabled")
        if self.local_auth_enabled:
            errors.append("local authentication must be explicitly disabled")
        if not all([self.oidc_issuer, self.oidc_client_id, self.oidc_redirect_uri]):
            errors.append("OIDC issuer, client ID and redirect URI are required")
        if self.oidc_issuer and urlparse(self.oidc_issuer).scheme != "https":
            errors.append("OIDC issuer must use HTTPS")
        if self.oidc_redirect_uri and urlparse(self.oidc_redirect_uri).scheme != "https":
            errors.append("OIDC redirect URI must use HTTPS")
        if self.secret_provider == "environment":
            errors.append("environment secret provider is development-only")
        if self.object_storage_provider == "filesystem":
            errors.append("external object storage is required")
        if self.connector_mode == "fixture":
            errors.append("fixture connectors cannot be represented as production connections")
        if self.runner_type == "local_restricted":
            errors.append("production requires an ephemeral runner")
        if self.redis_url.startswith("redis://") and "localhost" not in self.redis_url:
            errors.append("Redis TLS is required")
        if errors:
            raise ValueError("Unsafe production configuration: " + "; ".join(errors))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
