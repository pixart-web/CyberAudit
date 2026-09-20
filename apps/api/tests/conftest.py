from collections.abc import AsyncIterator

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from cyberaudit import (
    ai_runtime_models,  # noqa: F401
    domain_expansion_models,  # noqa: F401
    enterprise_models,  # noqa: F401
    hardening_models,  # noqa: F401
    phase4_models,  # noqa: F401
    phase5_models,  # noqa: F401
)
from cyberaudit.db import Base


@pytest_asyncio.fixture
async def db() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture
async def worker_session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """A SessionLocal-style factory backed by one shared in-memory database.

    Worker actors (readiness_dlq, enterprise_worker, ...) open their own
    sessions via a module-level ``SessionLocal`` rather than an injected
    fixture, so exercising them requires a factory that yields independent
    sessions which all see the same in-memory schema and rows.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()
