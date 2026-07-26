from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    environment: str = "development"
    database_url: str = "sqlite+aiosqlite:///./cyberaudit.db"
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str = "development-only-secret-change-me-32chars"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    upload_dir: Path = Path("./uploads")
    max_upload_bytes: int = 10 * 1024 * 1024
    app_origin: str = "http://localhost:3000"


@lru_cache
def get_settings() -> Settings:
    return Settings()
