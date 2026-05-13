"""Base repository with common CRUD operations for SQLAlchemy 2.0+ async API."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import DeclarativeBase

from sqlalchemy import func, select

ModelType = TypeVar("ModelType", bound="DeclarativeBase")


class BaseRepository(Generic[ModelType]):
    """Base repository class providing common CRUD operations.

    This class is designed to work with SQLAlchemy 2.0+ async API and is
    SQLite-compatible. It provides a consistent interface for database
    operations across all entity types.

    Args:
        session: AsyncSession instance for database operations
        model: SQLAlchemy model class
    """

    def __init__(self, session: AsyncSession, model: type[ModelType]) -> None:
        """Initialize the repository with a database session and model."""
        self.session = session
        self.model = model

    async def get_by_id(self, record_id: UUID) -> ModelType | None:
        """Get a single record by its ID.

        Args:
            record_id: UUID of the record to retrieve

        Returns:
            The record if found, None otherwise
        """
        result = await self.session.execute(select(self.model).where(self.model.id == record_id))  # type: ignore[attr-defined]
        return result.scalar_one_or_none()

    async def get_all(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
    ) -> list[ModelType]:
        """Get multiple records with pagination and optional filters.

        Args:
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return
            filters: Optional dictionary of field-value pairs to filter by

        Returns:
            List of matching records
        """
        query = select(self.model)

        # Apply filters if provided
        if filters:
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.where(getattr(self.model, field) == value)

        # Apply pagination
        query = query.offset(skip).limit(limit)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def create(self, **kwargs: Any) -> ModelType:
        """Create a new record.

        Args:
            **kwargs: Field values for the new record

        Returns:
            The newly created record
        """
        instance = self.model(**kwargs)
        self.session.add(instance)
        await self.session.flush()
        await self.session.refresh(instance)
        await self.session.commit()
        return instance

    async def update(self, record_id: UUID, **kwargs: Any) -> ModelType | None:
        """Update an existing record.

        Args:
            record_id: UUID of the record to update
            **kwargs: Field values to update

        Returns:
            The updated record if found, None otherwise
        """
        instance = await self.get_by_id(record_id)
        if not instance:
            return None

        for field, value in kwargs.items():
            if hasattr(instance, field):
                setattr(instance, field, value)

        await self.session.flush()
        await self.session.refresh(instance)
        await self.session.commit()
        return instance

    async def delete(self, record_id: UUID) -> bool:
        """Delete a record by its ID.

        Args:
            record_id: UUID of the record to delete

        Returns:
            True if deleted successfully, False if record not found
        """
        instance = await self.get_by_id(record_id)
        if not instance:
            return False

        await self.session.delete(instance)
        await self.session.flush()
        await self.session.commit()
        return True

    async def count(self, filters: dict[str, Any] | None = None) -> int:
        """Count records with optional filters.

        Args:
            filters: Optional dictionary of field-value pairs to filter by

        Returns:
            Number of matching records
        """
        query = select(func.count()).select_from(self.model)

        # Apply filters if provided
        if filters:
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.where(getattr(self.model, field) == value)

        result = await self.session.execute(query)
        return result.scalar_one()
