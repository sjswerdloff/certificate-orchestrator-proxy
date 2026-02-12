"""Database configuration and session management for admin API.

Lifecycle
---------
Engines and session makers are cached per database URL in module-level
dictionaries. This avoids creating new engines on every request but
requires explicit cleanup when the application shuts down or between
tests.

Production usage::

    # In FastAPI lifespan:
    async with lifespan(app):
        await init_database(url)
        yield
        await close_database(url)  # or close_all_databases()

Testing usage::

    # In a pytest fixture, reset state before each test to ensure
    # isolation. See close_all_databases() for details.

    @pytest.fixture(autouse=True)
    async def _reset_db():
        await close_all_databases()
        yield
        await close_all_databases()
"""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import AsyncAdaptedQueuePool, StaticPool

from est_adapter.admin.models.base import Base

_engines: dict = {}
_session_makers: dict = {}


def _pool_class_for_url(database_url: str) -> type:
    """Select the appropriate connection pool class for a database URL.

    In-memory SQLite databases require StaticPool to keep a single
    connection alive for the lifetime of the engine (otherwise each
    connection gets a separate empty database). All other URLs use the
    default async queue pool.
    """
    if ":memory:" in database_url:
        return StaticPool
    return AsyncAdaptedQueuePool


async def init_database(database_url: str) -> None:
    """Initialize database engine, session maker, and create tables.

    Safe to call multiple times with the same URL - the engine is
    created only once and subsequent calls just ensure tables exist.

    Args:
        database_url: SQLAlchemy async database URL.
    """
    if database_url not in _engines:
        _engines[database_url] = create_async_engine(
            database_url,
            echo=False,
            poolclass=_pool_class_for_url(database_url),
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


async def close_database(database_url: str) -> None:
    """Dispose engine and remove cached state for a single database URL.

    Call this during application shutdown or test teardown to release
    connection pool resources and ensure the next init_database() call
    creates a fresh engine.
    """
    engine = _engines.pop(database_url, None)
    _session_makers.pop(database_url, None)
    if engine is not None:
        await engine.dispose()


async def close_all_databases() -> None:
    """Dispose all cached engines and clear module-level state.

    Primarily useful in test fixtures to guarantee isolation between
    tests. Each test that calls init_database() after this gets a
    completely fresh engine, session maker, and (for in-memory SQLite)
    a fresh database.
    """
    for engine in _engines.values():
        await engine.dispose()
    _engines.clear()
    _session_makers.clear()


async def get_async_session(database_url: str) -> AsyncGenerator[AsyncSession, None]:
    """Get an async database session.

    If the engine for this URL has not been initialized, it will be
    created on the fly. Prefer calling init_database() at startup
    instead to catch configuration errors early.

    Args:
        database_url: SQLAlchemy async database URL.

    Yields:
        AsyncSession: Database session that auto-commits on success
        and rolls back on exception.
    """
    if database_url not in _engines:
        _engines[database_url] = create_async_engine(
            database_url,
            echo=False,
            poolclass=_pool_class_for_url(database_url),
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
