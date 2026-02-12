"""Repository for EnrollmentEvent model."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.sql import func

from est_adapter.admin.models import EnrollmentEvent

from .base import BaseRepository


class EnrollmentEventRepository(BaseRepository[EnrollmentEvent]):
    """Repository for EnrollmentEvent model with SQLite-compatible async operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the repository with a database session."""
        super().__init__(session, EnrollmentEvent)

    async def get_by_profile(self, profile_id: UUID, skip: int = 0, limit: int = 100) -> list[EnrollmentEvent]:
        """Get enrollment events for a specific EST profile.

        Args:
            profile_id: UUID of the EST profile
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return

        Returns:
            List of enrollment events for the specified profile
        """
        query = (
            select(self.model)
            .where(self.model.profile_id == profile_id)
            .order_by(self.model.created_at.desc())
            .offset(skip)
            .limit(limit)
        )

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_by_status(self, status: str, skip: int = 0, limit: int = 100) -> list[EnrollmentEvent]:
        """Get enrollment events by status.

        Args:
            status: Status of the enrollment events (e.g., 'pending', 'approved', 'rejected', 'error')
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return

        Returns:
            List of enrollment events with the specified status
        """
        query = (
            select(self.model)
            .where(self.model.status == status)
            .order_by(self.model.created_at.desc())
            .offset(skip)
            .limit(limit)
        )

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_by_device(self, device_id: str, skip: int = 0, limit: int = 100) -> list[EnrollmentEvent]:
        """Get enrollment events for a specific device.

        Args:
            device_id: Device identifier
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return

        Returns:
            List of enrollment events for the specified device
        """
        query = (
            select(self.model)
            .where(self.model.device_id == device_id)
            .order_by(self.model.created_at.desc())
            .offset(skip)
            .limit(limit)
        )

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_by_correlation_id(self, correlation_id: str) -> EnrollmentEvent | None:
        """Get an enrollment event by its correlation ID.

        Args:
            correlation_id: Correlation ID of the enrollment event

        Returns:
            The enrollment event if found, None otherwise
        """
        result = await self.session.execute(select(self.model).where(self.model.correlation_id == correlation_id))
        return result.scalar_one_or_none()

    async def get_recent(
        self,
        hours: int = 24,
        skip: int = 0,
        limit: int = 100,
    ) -> list[EnrollmentEvent]:
        """Get recent enrollment events within a time window.

        Args:
            hours: Number of hours to look back
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return

        Returns:
            List of recent enrollment events
        """
        cutoff = datetime.now(UTC) - timedelta(hours=hours)

        query = (
            select(self.model)
            .where(self.model.created_at >= cutoff)
            .order_by(self.model.created_at.desc())
            .offset(skip)
            .limit(limit)
        )

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def update_status(
        self,
        record_id: UUID,
        status: str,
        error_message: str | None = None,
    ) -> EnrollmentEvent | None:
        """Update the status of an enrollment event.

        Args:
            record_id: UUID of the enrollment event
            status: New status
            error_message: Optional error message for failed events

        Returns:
            The updated enrollment event if found, None otherwise
        """
        return await self.update(record_id, status=status, error_message=error_message)

    async def count_by_status(self, status: str) -> int:
        """Count enrollment events by status.

        Args:
            status: Status to count

        Returns:
            Number of enrollment events with the specified status
        """
        query = select(func.count()).where(self.model.status == status)
        result = await self.session.execute(query)
        return result.scalar_one()

    async def count_by_profile(self, profile_id: UUID) -> int:
        """Count enrollment events for a specific profile.

        Args:
            profile_id: UUID of the EST profile

        Returns:
            Number of enrollment events for the specified profile
        """
        query = select(func.count()).where(self.model.profile_id == profile_id)
        result = await self.session.execute(query)
        return result.scalar_one()
