from collections.abc import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from cyberaudit.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine_options: dict[str, object] = {"pool_pre_ping": True}
if settings.database_url.startswith("postgresql"):
    engine_options.update(
        {
            "pool_size": settings.database_pool_size,
            "max_overflow": settings.database_pool_overflow,
            "pool_recycle": 1800,
            "connect_args": {
                "server_settings": {
                    "application_name": "cyberaudit-api",
                    "statement_timeout": str(settings.database_statement_timeout_ms),
                }
            },
        }
    )
engine = create_async_engine(settings.database_url, **engine_options)
if settings.database_url.startswith("postgresql") and settings.database_runtime_role:
    if settings.database_runtime_role != "cyberaudit_runtime":
        raise ValueError("Unsupported database runtime role")

    @event.listens_for(engine.sync_engine, "connect")
    def assume_runtime_role(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SET ROLE cyberaudit_runtime")
        finally:
            cursor.close()


SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session
