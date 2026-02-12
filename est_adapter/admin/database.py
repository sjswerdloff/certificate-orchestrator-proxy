"""Database configuration and session management for admin API."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import AsyncAdaptedQueuePool

from est_adapter.admin.models.base import Base

# Module-level dictionary to store engines and session makers per database URL
_engines = {}
_session_makers = {}


async def init_database(database_url: str) -> None:
    """Initialize database and create tables if they don't exist.

    Args:
        database_url: SQLAlchemy database URL
    """
    global _engines, _session_makers

    if database_url not in _engines:
        _engines[database_url] = create_async_engine(
            database_url,
            echo=False,
            poolclass=AsyncAdaptedQueuePool,
        )

    if database_url not in _session_makers:
        _session_makers[database_url] = async_sessionmaker(
            _engines[database_url],
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    async with _engines[database_url].begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_async_session(database_url: str) -> AsyncGenerator[AsyncSession, None]:
    """Get an async database session.

    Args:
        database_url: SQLAlchemy database URL

    Yields:
        AsyncSession: Database session
    """
    global _engines, _session_makers

    if database_url not in _engines:
        _engines[database_url] = create_async_engine(
            database_url,
            echo=False,
            poolclass=AsyncAdaptedQueuePool,
        )

    if database_url not in _session_makers:
        _session_makers[database_url] = async_sessionmaker(
            _engines[database_url],
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    async with _session_makers[database_url]() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
