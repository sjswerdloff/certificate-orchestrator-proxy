"""Database configuration and session management for EST Adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from est_adapter.admin.models import Base

# Module-level engine and session maker for reuse
_engine = None
_session_maker = None


def get_async_engine(database_url: str = "sqlite+aiosqlite:///:memory:"):
    """Create an async SQLAlchemy engine.

    Args:
        database_url: Database connection URL (default: SQLite in-memory)

    Returns:
        Async SQLAlchemy engine
    """
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            database_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False,
        )
    return _engine


def get_async_session_maker(database_url: str = "sqlite+aiosqlite:///:memory:"):
    """Create an async session maker.

    Args:
        database_url: Database connection URL (default: SQLite in-memory)

    Returns:
        Async session maker
    """
    global _session_maker
    if _session_maker is None:
        engine = get_async_engine(database_url)
        _session_maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return _session_maker


async def get_async_session(database_url: str = "sqlite+aiosqlite:///:memory:"):
    """Get an async database session.

    Args:
        database_url: Database connection URL (default: SQLite in-memory)

    Returns:
        Async database session
    """
    session_maker = get_async_session_maker(database_url)
    async with session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_database(database_url: str = "sqlite+aiosqlite:///:memory:"):
    """Initialize the database with all tables.

    Args:
        database_url: Database connection URL (default: SQLite in-memory)
    """
    engine = get_async_engine(database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
