from collections.abc import AsyncIterator

from sqlalchemy import event, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Session, SessionTransaction
from sqlalchemy.pool import NullPool

from cyberaudit.config import get_settings


class Base(DeclarativeBase):
    pass


class TenantSession(Session):
    """Synchronous session backing the tenant-aware async session."""


class TenantAsyncSession(AsyncSession):
    sync_session_class = TenantSession


settings = get_settings()
engine_options: dict[str, object] = {"pool_pre_ping": True}
if settings.database_url.startswith("postgresql"):
    engine_options["connect_args"] = {
        "server_settings": {
            "application_name": "cyberaudit-api",
            "statement_timeout": str(settings.database_statement_timeout_ms),
        }
    }
    if settings.database_use_null_pool:
        engine_options["poolclass"] = NullPool
    else:
        engine_options.update(
            {
                "pool_size": settings.database_pool_size,
                "max_overflow": settings.database_pool_overflow,
                "pool_recycle": 1800,
            }
        )
engine = create_async_engine(settings.database_url, **engine_options)
if settings.database_url.startswith("postgresql") and settings.database_runtime_role:
    if settings.database_runtime_role != "cyberaudit_runtime":
        raise ValueError("Unsupported database runtime role")

    @event.listens_for(engine.sync_engine, "checkout")
    def assume_runtime_role(
        dbapi_connection: object,
        _connection_record: object,
        _connection_proxy: object,
    ) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SET ROLE cyberaudit_runtime")
        finally:
            cursor.close()


@event.listens_for(TenantSession, "after_begin")
def restore_transaction_tenant_context(
    session: Session, _transaction: SessionTransaction, connection: Connection
) -> None:
    """Restore validated tenant context after commit starts a new transaction."""

    organization_id = session.info.get("organization_id")
    if organization_id and connection.dialect.name == "postgresql":
        connection.execute(
            text("SELECT set_config('app.current_organization_id', :organization_id, true)"),
            {"organization_id": organization_id},
        )


SessionLocal = async_sessionmaker(
    engine,
    class_=TenantAsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session
