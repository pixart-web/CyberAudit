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
    oidc_max_groups: int = Field(default=100, ge=1, le=500)
    oidc_require_verified_email: bool = True
    oidc_group_role_mapping: dict[str, str] = {
        "CyberAudit-Viewer": "Client",
        "CyberAudit-Analyst": "Auditor",
        "CyberAudit-Admin": "Administrator",
    }
    oidc_jit_enabled: bool = False
    oidc_default_role: str = "Client"
    mfa_required: bool = False
    webauthn_enabled: bool = False
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "CyberAudit"
    webauthn_origins: list[str] = ["http://localhost:3000"]
    webauthn_require_user_verification: bool = True
    webauthn_challenge_ttl_seconds: int = Field(default=300, ge=60, le=600)
    rls_required: bool = False
    session_idle_minutes: int = Field(default=30, ge=5, le=1440)
    session_absolute_hours: int = Field(default=12, ge=1, le=168)
    maximum_sessions_per_user: int = Field(default=5, ge=1, le=50)
    secret_provider: Literal[
        "environment", "vault", "aws", "azure", "gcp", "kubernetes", "docker"
    ] = "environment"
    object_storage_provider: Literal["filesystem", "s3", "azure", "gcs"] = "filesystem"
    object_storage_bucket: str | None = None
    object_storage_endpoint: str | None = None
    object_storage_region: str = "us-east-1"
    vault_address: str | None = None
    vault_namespace: str | None = None
    vault_token_file: Path = Path("/var/run/secrets/vault/token")
    connector_mode: Literal["fixture", "import", "live_read_only"] = "fixture"
    runner_type: Literal["local_restricted", "docker_ephemeral", "kubernetes_job"] = (
        "local_restricted"
    )
    runner_controller_url: str | None = None
    runner_token_file: Path = Path("/var/run/secrets/cyberaudit/runner-token")
    telemetry_enabled: bool = False
    license_provider: Literal["community", "signed_offline", "online"] = "community"
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_pool_overflow: int = Field(default=10, ge=0, le=100)
    database_use_null_pool: bool = False
    database_statement_timeout_ms: int = Field(default=30_000, ge=1000, le=300_000)
    database_runtime_role: str | None = None
    request_max_bytes: int = Field(default=12 * 1024 * 1024, ge=1024)
    readiness_evidence_manifest: Path | None = None
    # Sovereign AI runtime: disabled by default so core functionality never
    # depends on a running local model. An administrator opts in to a
    # specific local, self-hosted backend; no commercial AI API is supported.
    ai_runtime_backend: Literal["disabled", "ollama"] = "disabled"
    ai_runtime_base_url: str = "http://127.0.0.1:11434"
    ai_runtime_timeout_seconds: float = Field(default=30.0, ge=1, le=300)
    ai_runtime_embedding_model: str | None = None

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
        if not self.webauthn_enabled or not self.mfa_required:
            errors.append("WebAuthn and MFA are required")
        if not self.rls_required:
            errors.append("PostgreSQL RLS enforcement is required")
        if self.rls_required and self.database_runtime_role != "cyberaudit_runtime":
            errors.append("database runtime role must be cyberaudit_runtime")
        if not all([self.oidc_issuer, self.oidc_client_id, self.oidc_redirect_uri]):
            errors.append("OIDC issuer, client ID and redirect URI are required")
        if self.oidc_issuer and urlparse(self.oidc_issuer).scheme != "https":
            errors.append("OIDC issuer must use HTTPS")
        if self.oidc_redirect_uri and urlparse(self.oidc_redirect_uri).scheme != "https":
            errors.append("OIDC redirect URI must use HTTPS")
        if not self.webauthn_rp_id or not self.webauthn_origins:
            errors.append("WebAuthn RP ID and trusted origins are required")
        if any(urlparse(origin).scheme != "https" for origin in self.webauthn_origins):
            errors.append("WebAuthn origins must use HTTPS")
        if self.secret_provider == "environment":
            errors.append("environment secret provider is development-only")
        if self.secret_provider == "vault" and (
            not self.vault_address or urlparse(self.vault_address).scheme != "https"
        ):
            errors.append("Vault requires an HTTPS address")
        if self.object_storage_provider == "filesystem":
            errors.append("external object storage is required")
        if self.object_storage_provider == "s3" and not self.object_storage_bucket:
            errors.append("S3-compatible storage requires a bucket")
        if (
            self.object_storage_endpoint
            and urlparse(self.object_storage_endpoint).scheme != "https"
        ):
            errors.append("object storage endpoint must use HTTPS")
        if self.connector_mode == "fixture":
            errors.append("fixture connectors cannot be represented as production connections")
        if self.runner_type == "local_restricted":
            errors.append("production requires an ephemeral runner")
        if self.runner_type != "local_restricted" and (
            not self.runner_controller_url or urlparse(self.runner_controller_url).scheme != "https"
        ):
            errors.append("ephemeral runner requires an HTTPS controller")
        if self.redis_url.startswith("redis://") and "localhost" not in self.redis_url:
            errors.append("Redis TLS is required")
        if errors:
            raise ValueError("Unsafe production configuration: " + "; ".join(errors))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
