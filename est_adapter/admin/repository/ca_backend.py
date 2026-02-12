"""Repository for CABackend model."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import select

from est_adapter.admin.models import CABackend

from .base import BaseRepository


class CABackendRepository(BaseRepository[CABackend]):
    """Repository for CABackend model with SQLite-compatible async operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the repository with a database session."""
        super().__init__(session, CABackend)

    async def get_by_name(self, name: str) -> CABackend | None:
        """Get a CA backend by its unique name.

        Args:
            name: Name of the CA backend

        Returns:
            The CA backend if found, None otherwise
        """
        result = await self.session.execute(select(self.model).where(self.model.name == name))
        return result.scalar_one_or_none()

    async def get_enabled_backends(self) -> list[CABackend]:
        """Get all enabled CA backends.

        Returns:
            List of enabled CA backends
        """
        result = await self.session.execute(select(self.model).where(self.model.is_enabled))
        return list(result.scalars().all())

    async def get_backends_by_type(self, backend_type: str) -> list[CABackend]:
        """Get CA backends by type.

        Args:
            backend_type: Type of CA backend (e.g., 'self_signed', 'acme', 'scep')

        Returns:
            List of CA backends of the specified type
        """
        result = await self.session.execute(select(self.model).where(self.model.type == backend_type))
        return list(result.scalars().all())

    async def update_config(
        self,
        record_id: UUID,
        config: dict[str, Any],
    ) -> CABackend | None:
        """Update the configuration of a CA backend.

        Args:
            record_id: UUID of the CA backend
            config: New configuration dictionary

        Returns:
            The updated CA backend if found, None otherwise
        """
        return await self.update(record_id, config=config)

    async def toggle_enabled(self, record_id: UUID, enabled: bool) -> CABackend | None:
        """Enable or disable a CA backend.

        Args:
            record_id: UUID of the CA backend
            enabled: Whether to enable or disable the backend

        Returns:
            The updated CA backend if found, None otherwise
        """
        return await self.update(record_id, is_enabled=enabled)
