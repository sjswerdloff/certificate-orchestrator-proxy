"""Dependencies for admin API."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.database import get_async_session
from est_adapter.config import load_config_from_env


async def get_database_session() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session with the configured database URL.

    Yields:
        AsyncSession: Database session
    """
    settings = load_config_from_env()
    if not settings.admin.database.url:
        raise ValueError("Database URL not configured")  # noqa: TRY003

    async for session in get_async_session(settings.admin.database.url):
        yield session
