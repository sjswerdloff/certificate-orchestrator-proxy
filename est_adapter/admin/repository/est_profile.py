"""Repository for ESTProfile model."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import select

from est_adapter.admin.models import ESTProfile

from .base import BaseRepository


class ESTProfileRepository(BaseRepository[ESTProfile]):
    """Repository for ESTProfile model with SQLite-compatible async operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the repository with a database session."""
        super().__init__(session, ESTProfile)

    async def get_by_name(self, name: str) -> ESTProfile | None:
        """Get an EST profile by its unique name.

        Args:
            name: Name of the EST profile

        Returns:
            The EST profile if found, None otherwise
        """
        result = await self.session.execute(select(self.model).where(self.model.name == name))
        return result.scalar_one_or_none()

    async def get_enabled_profiles(self) -> list[ESTProfile]:
        """Get all enabled EST profiles.

        Returns:
            List of enabled EST profiles
        """
        result = await self.session.execute(select(self.model).where(self.model.is_enabled))
        return list(result.scalars().all())

    async def get_profiles_by_ca_backend(self, ca_backend_id: UUID) -> list[ESTProfile]:
        """Get EST profiles by CA backend.

        Args:
            ca_backend_id: UUID of the CA backend

        Returns:
            List of EST profiles using the specified CA backend
        """
        result = await self.session.execute(select(self.model).where(self.model.ca_backend_id == ca_backend_id))
        return list(result.scalars().all())

    async def update_allowed_subjects(
        self,
        record_id: UUID,
        allowed_subjects: list[str] | None,
    ) -> ESTProfile | None:
        """Update the allowed subjects for an EST profile.

        Args:
            record_id: UUID of the EST profile
            allowed_subjects: List of allowed subject DNs or None to clear

        Returns:
            The updated EST profile if found, None otherwise
        """
        return await self.update(record_id, allowed_subjects=allowed_subjects)

    async def update_validation_rules(
        self,
        record_id: UUID,
        validation_rules: dict[str, Any] | None,
    ) -> ESTProfile | None:
        """Update the validation rules for an EST profile.

        Args:
            record_id: UUID of the EST profile
            validation_rules: Dictionary of validation rules or None to clear

        Returns:
            The updated EST profile if found, None otherwise
        """
        return await self.update(record_id, validation_rules=validation_rules)

    async def toggle_enabled(self, record_id: UUID, enabled: bool) -> ESTProfile | None:
        """Enable or disable an EST profile.

        Args:
            record_id: UUID of the EST profile
            enabled: Whether to enable or disable the profile

        Returns:
            The updated EST profile if found, None otherwise
        """
        return await self.update(record_id, is_enabled=enabled)
