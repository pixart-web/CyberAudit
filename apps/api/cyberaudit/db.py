from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from cyberaudit.config import get_settings


class Base(DeclarativeBase):
    pass


engine = create_async_engine(
    get_settings().database_url,
    pool_pre_ping=True,
    poolclass=NullPool,
)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session
