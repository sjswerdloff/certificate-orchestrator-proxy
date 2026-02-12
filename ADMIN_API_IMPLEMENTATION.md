# Admin API Implementation Guide

## Overview

This document provides detailed technical implementation guidance for adding admin REST API to certificate-orchestrator-proxy. The implementation follows Python best practices and integrates with the existing FastAPI architecture.

## Project Structure

```
certificate-orchestrator-proxy/
├── est_adapter/
│   ├── admin/                    # New admin module
│   │   ├── __init__.py
│   │   ├── api/                 # REST API endpoints
│   │   │   ├── __init__.py
│   │   │   ├── ca_backends.py
│   │   │   ├── est_profiles.py
│   │   │   ├── enrollment_events.py
│   │   │   └── status.py
│   │   ├── models/              # Database models
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   ├── ca_backend.py
│   │   │   ├── est_profile.py
│   │   │   └── enrollment_event.py
│   │   ├── schemas/             # Pydantic schemas
│   │   │   ├── __init__.py
│   │   │   ├── ca_backend.py
│   │   │   ├── est_profile.py
│   │   │   ├── enrollment_event.py
│   │   │   └── common.py
│   │   ├── repository/          # Database repository layer
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   ├── ca_backend.py
│   │   │   ├── est_profile.py
│   │   │   └── enrollment_event.py
│   │   ├── database/            # Database connection
│   │   │   ├── __init__.py
│   │   │   └── session.py
│   │   └── auth/                # API authentication
│   │       ├── __init__.py
│   │       ├── api_key.py
│   │       └── dependencies.py
│   ├── config.py                # Enhanced configuration
│   └── main.py                  # Updated main entry point
├── migrations/                  # Alembic migrations
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
├── alembic.ini
└── config.yaml.example          # Updated configuration example
```

## 1. Database Layer Implementation

### 1.1 Database Models

**File: `est_adapter/admin/models/base.py`**
```python
"""Base database model with common fields."""
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    """Base class for all database models."""

    type_annotation_map = {
        UUID: UUID,
        datetime: DateTime(timezone=True),
    }

    # Common fields for all models
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to dictionary."""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def __repr__(self) -> str:
        """String representation."""
        return f"<{self.__class__.__name__}(id={self.id})>"
```

**File: `est_adapter/admin/models/ca_backend.py`**
```python
"""CA Backend database model."""
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import Boolean, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class CABackend(Base):
    """Certificate Authority backend configuration."""

    __tablename__ = "ca_backends"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'self_signed', 'acme', 'scep'
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    est_profiles: Mapped[list["ESTProfile"]] = mapped_column(
        back_populates="ca_backend", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<CABackend(name='{self.name}', type='{self.type}')>"
```

**File: `est_adapter/admin/models/est_profile.py`**
```python
"""EST Profile database model."""
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .ca_backend import CABackend


class ESTProfile(Base):
    """EST endpoint profile configuration."""

    __tablename__ = "est_profiles"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    ca_backend_id: Mapped[UUID] = mapped_column(ForeignKey("ca_backends.id"), nullable=False)
    allowed_subjects: Mapped[Optional[list[str]]] = mapped_column(JSONB)
    validation_rules: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    ca_backend: Mapped[CABackend] = mapped_column(
        back_populates="est_profiles", lazy="joined"
    )
    enrollment_events: Mapped[list["EnrollmentEvent"]] = mapped_column(
        back_populates="profile", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<ESTProfile(name='{self.name}', ca_backend_id='{self.ca_backend_id}')>"
```

**File: `est_adapter/admin/models/enrollment_event.py`**
```python
"""Enrollment Event database model."""
from typing import Optional
from uuid import UUID

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .est_profile import ESTProfile


class EnrollmentEvent(Base):
    """Certificate enrollment event log."""

    __tablename__ = "enrollment_events"

    profile_id: Mapped[UUID] = mapped_column(ForeignKey("est_profiles.id"), nullable=False)
    device_id: Mapped[Optional[str]] = mapped_column(String(255))
    subject_dn: Mapped[Optional[str]] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # 'pending', 'approved', 'rejected', 'error'
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 compatible
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    request_id: Mapped[Optional[str]] = mapped_column(String(255))
    correlation_id: Mapped[Optional[str]] = mapped_column(String(255))

    # Relationships
    profile: Mapped[ESTProfile] = mapped_column(
        back_populates="enrollment_events", lazy="joined"
    )

    def __repr__(self) -> str:
        return f"<EnrollmentEvent(profile_id='{self.profile_id}', status='{self.status}')>"
```

### 1.2 Database Session Management

**File: `est_adapter/admin/database/session.py`**
```python
"""Database session management."""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import AsyncAdaptedQueuePool

from est_adapter.config import Settings


class DatabaseSessionManager:
    """Manages database sessions and connections."""

    def __init__(self, settings: Settings):
        """Initialize database session manager."""
        self.settings = settings
        self.engine = None
        self.session_factory = None

    async def initialize(self) -> None:
        """Initialize database engine and session factory."""
        if self.settings.admin.database.url is None:
            return

        # Create async engine
        self.engine = create_async_engine(
            self.settings.admin.database.url,
            echo=False,
            poolclass=AsyncAdaptedQueuePool,
            pool_size=self.settings.admin.database.pool_size,
            max_overflow=self.settings.admin.database.max_overflow,
        )

        # Create session factory
        self.session_factory = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    async def close(self) -> None:
        """Close database engine."""
        if self.engine:
            await self.engine.dispose()

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session."""
        if self.session_factory is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()


# Global instance
db_manager: DatabaseSessionManager | None = None


def get_db_manager() -> DatabaseSessionManager:
    """Get the global database manager instance."""
    if db_manager is None:
        raise RuntimeError("Database manager not initialized")
    return db_manager


def initialize_database(settings: Settings) -> None:
    """Initialize the global database manager."""
    global db_manager
    db_manager = DatabaseSessionManager(settings)
```

### 1.3 Repository Layer

**File: `est_adapter/admin/repository/base.py`**
```python
"""Base repository with common CRUD operations."""
from typing import Any, Generic, TypeVar
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from est_adapter.admin.models.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """Base repository with common CRUD operations."""

    def __init__(self, session: AsyncSession, model: type[ModelType]):
        """Initialize repository."""
        self.session = session
        self.model = model

    async def get_by_id(self, id: UUID) -> ModelType | None:
        """Get entity by ID."""
        return await self.session.get(self.model, id)

    async def get_all(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
    ) -> list[ModelType]:
        """Get all entities with pagination and filters."""
        query: Select = select(self.model).offset(skip).limit(limit)

        if filters:
            for key, value in filters.items():
                if hasattr(self.model, key):
                    column = getattr(self.model, key)
                    query = query.where(column == value)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def create(self, **kwargs: Any) -> ModelType:
        """Create a new entity."""
        entity = self.model(**kwargs)
        self.session.add(entity)
        await self.session.flush()
        await self.session.refresh(entity)
        return entity

    async def update(self, id: UUID, **kwargs: Any) -> ModelType | None:
        """Update an existing entity."""
        entity = await self.get_by_id(id)
        if entity is None:
            return None

        for key, value in kwargs.items():
            if hasattr(entity, key):
                setattr(entity, key, value)

        await self.session.flush()
        await self.session.refresh(entity)
        return entity

    async def delete(self, id: UUID) -> bool:
        """Delete an entity by ID."""
        entity = await self.get_by_id(id)
        if entity is None:
            return False

        await self.session.delete(entity)
        await self.session.flush()
        return True

    async def count(self, filters: dict[str, Any] | None = None) -> int:
        """Count entities with optional filters."""
        query: Select = select(self.model)

        if filters:
            for key, value in filters.items():
                if hasattr(self.model, key):
                    column = getattr(self.model, key)
                    query = query.where(column == value)

        result = await self.session.execute(query)
        return len(list(result.scalars().all()))
```

**File: `est_adapter/admin/repository/ca_backend.py`**
```python
"""CA Backend repository."""
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.models.ca_backend import CABackend
from .base import BaseRepository


class CABackendRepository(BaseRepository[CABackend]):
    """Repository for CA Backend operations."""

    def __init__(self, session: AsyncSession):
        """Initialize CA Backend repository."""
        super().__init__(session, CABackend)

    async def get_by_name(self, name: str) -> CABackend | None:
        """Get CA Backend by name."""
        from sqlalchemy import select

        query = select(self.model).where(self.model.name == name)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_enabled(self) -> list[CABackend]:
        """Get all enabled CA Backends."""
        from sqlalchemy import select

        query = select(self.model).where(self.model.is_enabled == True)
        result = await self.session.execute(query)
        return list(result.scalars().all())
```

**File: `est_adapter/admin/repository/est_profile.py`**
```python
"""EST Profile repository."""
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.models.est_profile import ESTProfile
from .base import BaseRepository


class ESTProfileRepository(BaseRepository[ESTProfile]):
    """Repository for EST Profile operations."""

    def __init__(self, session: AsyncSession):
        """Initialize EST Profile repository."""
        super().__init__(session, ESTProfile)

    async def get_by_name(self, name: str) -> ESTProfile | None:
        """Get EST Profile by name."""
        from sqlalchemy import select

        query = select(self.model).where(self.model.name == name)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_ca_backend(self, ca_backend_id: UUID) -> list[ESTProfile]:
        """Get EST Profiles by CA Backend ID."""
        from sqlalchemy import select

        query = select(self.model).where(self.model.ca_backend_id == ca_backend_id)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_enabled(self) -> list[ESTProfile]:
        """Get all enabled EST Profiles."""
        from sqlalchemy import select

        query = select(self.model).where(self.model.is_enabled == True)
        result = await self.session.execute(query)
        return list(result.scalars().all())
```

**File: `est_adapter/admin/repository/enrollment_event.py`**
```python
"""Enrollment Event repository."""
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.models.enrollment_event import EnrollmentEvent
from .base import BaseRepository


class EnrollmentEventRepository(BaseRepository[EnrollmentEvent]):
    """Repository for Enrollment Event operations."""

    def __init__(self, session: AsyncSession):
        """Initialize Enrollment Event repository."""
        super().__init__(session, EnrollmentEvent)

    async def get_by_profile(self, profile_id: UUID, skip: int = 0, limit: int = 100) -> list[EnrollmentEvent]:
        """Get enrollment events by profile ID."""
        from sqlalchemy import select

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
        """Get enrollment events by status."""
        from sqlalchemy import select

        query = (
            select(self.model)
            .where(self.model.status == status)
            .order_by(self.model.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_recent(
        self,
        hours: int = 24,
        skip: int = 0,
        limit: int = 100,
    ) -> list[EnrollmentEvent]:
        """Get recent enrollment events."""
        from sqlalchemy import select
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(hours=hours)

        query = (
            select(self.model)
            .where(self.model.created_at >= cutoff)
            .order_by(self.model.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def search(
        self,
        query: str,
        skip: int = 0,
        limit: int = 100,
    ) -> list[EnrollmentEvent]:
        """Search enrollment events by device ID, subject DN, or error message."""
        from sqlalchemy import select

        search_filter = or_(
            self.model.device_id.ilike(f"%{query}%"),
            self.model.subject_dn.ilike(f"%{query}%"),
            self.model.error_message.ilike(f"%{query}%"),
        )

        stmt = (
            select(self.model)
            .where(search_filter)
            .order_by(self.model.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
```

## 2. Pydantic Schemas

### 2.1 Common Schemas

**File: `est_adapter/admin/schemas/common.py`**
```python
"""Common Pydantic schemas."""
from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class BaseSchema(BaseModel):
    """Base schema with common configuration."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        extra="forbid",
    )


class PaginatedResponse(BaseSchema, Generic[BaseSchema]):
    """Paginated response schema."""

    data: list[BaseSchema]
    pagination: dict[str, Any]


class ErrorResponse(BaseSchema):
    """Error response schema."""

    error: dict[str, Any]


class HealthResponse(BaseSchema):
    """Health check response schema."""

    status: str
    version: str
    timestamp: datetime
```

### 2.2 CA Backend Schemas

**File: `est_adapter/admin/schemas/ca_backend.py`**
```python
"""CA Backend Pydantic schemas."""
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from .common import BaseSchema


class CABackendBase(BaseSchema):
    """Base CA Backend schema."""

    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., pattern=r"^(self_signed|acme|scep)$")
    config: dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool = True
    description: Optional[str] = None

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate CA backend type."""
        valid_types = ["self_signed", "acme", "scep"]
        if v not in valid_types:
            raise ValueError(f"Invalid CA backend type: {v}. Must be one of: {valid_types}")
        return v


class CABackendCreate(CABackendBase):
    """Schema for creating a CA Backend."""

    pass


class CABackendUpdate(BaseSchema):
    """Schema for updating a CA Backend."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    type: Optional[str] = Field(None, pattern=r"^(self_signed|acme|scep)$")
    config: Optional[dict[str, Any]] = None
    is_enabled: Optional[bool] = None
    description: Optional[str] = None

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: Optional[str]) -> Optional[str]:
        """Validate CA backend type."""
        if v is None:
            return v
        valid_types = ["self_signed", "acme", "scep"]
        if v not in valid_types:
            raise ValueError(f"Invalid CA backend type: {v}. Must be one of: {valid_types}")
        return v


class CABackendResponse(CABackendBase):
    """Schema for CA Backend response."""

    id: UUID
    created_at: datetime
    updated_at: datetime
```

### 2.3 EST Profile Schemas

**File: `est_adapter/admin/schemas/est_profile.py`**
```python
"""EST Profile Pydantic schemas."""
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from .common import BaseSchema


class ESTProfileBase(BaseSchema):
    """Base EST Profile schema."""

    name: str = Field(..., min_length=1, max_length=255)
    ca_backend_id: UUID
    allowed_subjects: Optional[list[str]] = None
    validation_rules: Optional[dict[str, Any]] = None
    is_enabled: bool = True
    description: Optional[str] = None


class ESTProfileCreate(ESTProfileBase):
    """Schema for creating an EST Profile."""

    pass


class ESTProfileUpdate(BaseSchema):
    """Schema for updating an EST Profile."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    ca_backend_id: Optional[UUID] = None
    allowed_subjects: Optional[list[str]] = None
    validation_rules: Optional[dict[str, Any]] = None
    is_enabled: Optional[bool] = None
    description: Optional[str] = None


class ESTProfileResponse(ESTProfileBase):
    """Schema for EST Profile response."""

    id: UUID
    created_at: datetime
    updated_at: datetime
    ca_backend_name: Optional[str] = None  # For convenience
```

### 2.4 Enrollment Event Schemas

**File: `est_adapter/admin/schemas/enrollment_event.py`**
```python
"""Enrollment Event Pydantic schemas."""
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from .common import BaseSchema


class EnrollmentEventBase(BaseSchema):
    """Base Enrollment Event schema."""

    profile_id: UUID
    device_id: Optional[str] = None
    subject_dn: Optional[str] = None
    status: str = Field(..., pattern=r"^(pending|approved|rejected|error)$")
    error_message: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None


class EnrollmentEventCreate(EnrollmentEventBase):
    """Schema for creating an Enrollment Event."""

    pass


class EnrollmentEventResponse(EnrollmentEventBase):
    """Schema for Enrollment Event response."""

    id: UUID
    created_at: datetime
    updated_at: datetime
    profile_name: Optional[str] = None  # For convenience


class EnrollmentEventFilter(BaseSchema):
    """Schema for filtering enrollment events."""

    profile_id: Optional[UUID] = None
    status: Optional[str] = None
    device_id: Optional[str] = None
    subject_dn: Optional[str] = None
    hours: Optional[int] = 24
    skip: int = 0
    limit: int = 100
    search: Optional[str] = None
```

## 3. API Endpoints

### 3.1 CA Backend Endpoints

**File: `est_adapter/admin/api/ca_backends.py`**
```python
"""CA Backend API endpoints."""
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.database.session import get_db_manager
from est_adapter.admin.repository.ca_backend import CABackendRepository
from est_adapter.admin.schemas.ca_backend import (
    CABackendCreate,
    CABackendResponse,
    CABackendUpdate,
)
from est_adapter.admin.schemas.common import ErrorResponse

router = APIRouter(prefix="/ca-backends", tags=["CA Backends"])


async def get_ca_backend_repository(
    session: AsyncSession = Depends(get_db_manager().get_session),
) -> CABackendRepository:
    """Dependency to get CA Backend repository."""
    return CABackendRepository(session)


@router.get(
    "/",
    response_model=list[CABackendResponse],
    status_code=status.HTTP_200_OK,
    summary="List CA Backends",
    description="Retrieve a list of all CA Backend configurations.",
)
async def list_ca_backends(
    repository: CABackendRepository = Depends(get_ca_backend_repository),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of items to return"),
) -> list[CABackendResponse]:
    """List all CA Backends with optional filtering."""
    filters = {}
    if enabled is not None:
        filters["is_enabled"] = enabled

    backends = await repository.get_all(skip=skip, limit=limit, filters=filters)
    return [CABackendResponse.model_validate(b) for b in backends]


@router.post(
    "/",
    response_model=CABackendResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create CA Backend",
    description="Create a new CA Backend configuration.",
)
async def create_ca_backend(
    ca_backend: CABackendCreate,
    repository: CABackendRepository = Depends(get_ca_backend_repository),
) -> CABackendResponse:
    """Create a new CA Backend."""
    # Check if name already exists
    existing = await repository.get_by_name(ca_backend.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"CA Backend with name '{ca_backend.name}' already exists",
        )

    # Create the CA Backend
    created = await repository.create(
        name=ca_backend.name,
        type=ca_backend.type,
        config=ca_backend.config,
        is_enabled=ca_backend.is_enabled,
        description=ca_backend.description,
    )

    return CABackendResponse.model_validate(created)


@router.get(
    "/{id}",
    response_model=CABackendResponse,
    status_code=status.HTTP_200_OK,
    summary="Get CA Backend",
    description="Retrieve a specific CA Backend by ID.",
)
async def get_ca_backend(
    id: UUID,
    repository: CABackendRepository = Depends(get_ca_backend_repository),
) -> CABackendResponse:
    """Get a CA Backend by ID."""
    ca_backend = await repository.get_by_id(id)
    if ca_backend is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CA Backend with ID '{id}' not found",
        )

    return CABackendResponse.model_validate(ca_backend)


@router.put(
    "/{id}",
    response_model=CABackendResponse,
    status_code=status.HTTP_200_OK,
    summary="Update CA Backend",
    description="Update an existing CA Backend configuration.",
)
async def update_ca_backend(
    id: UUID,
    ca_backend: CABackendUpdate,
    repository: CABackendRepository = Depends(get_ca_backend_repository),
) -> CABackendResponse:
    """Update a CA Backend."""
    # Check if CA Backend exists
    existing = await repository.get_by_id(id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CA Backend with ID '{id}' not found",
        )

    # Check if name is being changed and already exists
    if ca_backend.name and ca_backend.name != existing.name:
        name_exists = await repository.get_by_name(ca_backend.name)
        if name_exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"CA Backend with name '{ca_backend.name}' already exists",
            )

    # Update the CA Backend
    update_data = ca_backend.model_dump(exclude_unset=True)
    updated = await repository.update(id, **update_data)

    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update CA Backend",
        )

    return CABackendResponse.model_validate(updated)


@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete CA Backend",
    description="Delete a CA Backend configuration.",
)
async def delete_ca_backend(
    id: UUID,
    repository: CABackendRepository = Depends(get_ca_backend_repository),
) -> None:
    """Delete a CA Backend."""
    # Check if CA Backend exists
    existing = await repository.get_by_id(id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CA Backend with ID '{id}' not found",
        )

    # Check if CA Backend is in use by any EST profiles
    # (This would require checking EST profile repository)
    # For now, we'll allow deletion

    deleted = await repository.delete(id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete CA Backend",
        )
```

### 3.2 EST Profile Endpoints

**File: `est_adapter/admin/api/est_profiles.py`**
```python
"""EST Profile API endpoints."""
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.database.session import get_db_manager
from est_adapter.admin.repository.ca_backend import CABackendRepository
from est_adapter.admin.repository.est_profile import ESTProfileRepository
from est_adapter.admin.schemas.common import ErrorResponse
from est_adapter.admin.schemas.est_profile import (
    ESTProfileCreate,
    ESTProfileResponse,
    ESTProfileUpdate,
)

router = APIRouter(prefix="/est-profiles", tags=["EST Profiles"])


async def get_est_profile_repository(
    session: AsyncSession = Depends(get_db_manager().get_session),
) -> ESTProfileRepository:
    """Dependency to get EST Profile repository."""
    return ESTProfileRepository(session)


async def get_ca_backend_repository(
    session: AsyncSession = Depends(get_db_manager().get_session),
) -> CABackendRepository:
    """Dependency to get CA Backend repository."""
    return CABackendRepository(session)


@router.get(
    "/",
    response_model=list[ESTProfileResponse],
    status_code=status.HTTP_200_OK,
    summary="List EST Profiles",
    description="Retrieve a list of all EST Profile configurations.",
)
async def list_est_profiles(
    repository: ESTProfileRepository = Depends(get_est_profile_repository),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    ca_backend_id: Optional[UUID] = Query(None, description="Filter by CA Backend ID"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of items to return"),
) -> list[ESTProfileResponse]:
    """List all EST Profiles with optional filtering."""
    filters = {}
    if enabled is not None:
        filters["is_enabled"] = enabled
    if ca_backend_id is not None:
        filters["ca_backend_id"] = ca_backend_id

    profiles = await repository.get_all(skip=skip, limit=limit, filters=filters)
    return [ESTProfileResponse.model_validate(p) for p in profiles]


@router.post(
    "/",
    response_model=ESTProfileResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create EST Profile",
    description="Create a new EST Profile configuration.",
)
async def create_est_profile(
    est_profile: ESTProfileCreate,
    repository: ESTProfileRepository = Depends(get_est_profile_repository),
    ca_backend_repo: CABackendRepository = Depends(get_ca_backend_repository),
) -> ESTProfileResponse:
    """Create a new EST Profile."""
    # Check if name already exists
    existing = await repository.get_by_name(est_profile.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"EST Profile with name '{est_profile.name}' already exists",
        )

    # Check if CA Backend exists
    ca_backend = await ca_backend_repo.get_by_id(est_profile.ca_backend_id)
    if ca_backend is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CA Backend with ID '{est_profile.ca_backend_id}' not found",
        )

    # Create the EST Profile
    created = await repository.create(
        name=est_profile.name,
        ca_backend_id=est_profile.ca_backend_id,
        allowed_subjects=est_profile.allowed_subjects,
        validation_rules=est_profile.validation_rules,
        is_enabled=est_profile.is_enabled,
        description=est_profile.description,
    )

    return ESTProfileResponse.model_validate(created)


@router.get(
    "/{id}",
    response_model=ESTProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Get EST Profile",
    description="Retrieve a specific EST Profile by ID.",
)
async def get_est_profile(
    id: UUID,
    repository: ESTProfileRepository = Depends(get_est_profile_repository),
) -> ESTProfileResponse:
    """Get an EST Profile by ID."""
    est_profile = await repository.get_by_id(id)
    if est_profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"EST Profile with ID '{id}' not found",
        )

    return ESTProfileResponse.model_validate(est_profile)


@router.put(
    "/{id}",
    response_model=ESTProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Update EST Profile",
    description="Update an existing EST Profile configuration.",
)
async def update_est_profile(
    id: UUID,
    est_profile: ESTProfileUpdate,
    repository: ESTProfileRepository = Depends(get_est_profile_repository),
    ca_backend_repo: CABackendRepository = Depends(get_ca_backend_repository),
) -> ESTProfileResponse:
    """Update an EST Profile."""
    # Check if EST Profile exists
    existing = await repository.get_by_id(id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"EST Profile with ID '{id}' not found",
        )

    # Check if name is being changed and already exists
    if est_profile.name and est_profile.name != existing.name:
        name_exists = await repository.get_by_name(est_profile.name)
        if name_exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"EST Profile with name '{est_profile.name}' already exists",
            )

    # Check if CA Backend exists (if being changed)
    if est_profile.ca_backend_id and est_profile.ca_backend_id != existing.ca_backend_id:
        ca_backend = await ca_backend_repo.get_by_id(est_profile.ca_backend_id)
        if ca_backend is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA Backend with ID '{est_profile.ca_backend_id}' not found",
            )

    # Update the EST Profile
    update_data = est_profile.model_dump(exclude_unset=True)
    updated = await repository.update(id, **update_data)

    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update EST Profile",
        )

    return ESTProfileResponse.model_validate(updated)


@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete EST Profile",
    description="Delete an EST Profile configuration.",
)
async def delete_est_profile(
    id: UUID,
    repository: ESTProfileRepository = Depends(get_est_profile_repository),
) -> None:
    """Delete an EST Profile."""
    # Check if EST Profile exists
    existing = await repository.get_by_id(id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"EST Profile with ID '{id}' not found",
        )

    # Check if EST Profile is in use by any enrollment events
    # (This would require checking enrollment event repository)
    # For now, we'll allow deletion

    deleted = await repository.delete(id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete EST Profile",
        )
```

### 3.3 Enrollment Event Endpoints

**File: `est_adapter/admin/api/enrollment_events.py`**
```python
"""Enrollment Event API endpoints."""
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.database.session import get_db_manager
from est_adapter.admin.repository.enrollment_event import EnrollmentEventRepository
from est_adapter.admin.repository.est_profile import ESTProfileRepository
from est_adapter.admin.schemas.common import ErrorResponse
from est_adapter.admin.schemas.enrollment_event import (
    EnrollmentEventFilter,
    EnrollmentEventResponse,
)

router = APIRouter(prefix="/enrollment-events", tags=["Enrollment Events"])


async def get_enrollment_event_repository(
    session: AsyncSession = Depends(get_db_manager().get_session),
) -> EnrollmentEventRepository:
    """Dependency to get Enrollment Event repository."""
    return EnrollmentEventRepository(session)


async def get_est_profile_repository(
    session: AsyncSession = Depends(get_db_manager().get_session),
) -> ESTProfileRepository:
    """Dependency to get EST Profile repository."""
    return ESTProfileRepository(session)


@router.get(
    "/",
    response_model=list[EnrollmentEventResponse],
    status_code=status.HTTP_200_OK,
    summary="List Enrollment Events",
    description="Retrieve a list of enrollment events with filtering and pagination.",
)
async def list_enrollment_events(
    repository: EnrollmentEventRepository = Depends(get_enrollment_event_repository),
    profile_id: Optional[UUID] = Query(None, description="Filter by EST Profile ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    device_id: Optional[str] = Query(None, description="Filter by device ID"),
    hours: int = Query(24, ge=1, le=720, description="Time window in hours"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of items to return"),
) -> list[EnrollmentEventResponse]:
    """List enrollment events with filtering."""
    events = await repository.get_recent(hours=hours, skip=skip, limit=limit)
    return [EnrollmentEventResponse.model_validate(e) for e in events]


@router.get(
    "/search",
    response_model=list[EnrollmentEventResponse],
    status_code=status.HTTP_200_OK,
    summary="Search Enrollment Events",
    description="Search enrollment events by device ID, subject DN, or error message.",
)
async def search_enrollment_events(
    query: str = Query(..., min_length=1, description="Search query"),
    repository: EnrollmentEventRepository = Depends(get_enrollment_event_repository),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of items to return"),
) -> list[EnrollmentEventResponse]:
    """Search enrollment events."""
    events = await repository.search(query=query, skip=skip, limit=limit)
    return [EnrollmentEventResponse.model_validate(e) for e in events]


@router.get(
    "/{id}",
    response_model=EnrollmentEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Enrollment Event",
    description="Retrieve a specific enrollment event by ID.",
)
async def get_enrollment_event(
    id: UUID,
    repository: EnrollmentEventRepository = Depends(get_enrollment_event_repository),
) -> EnrollmentEventResponse:
    """Get an enrollment event by ID."""
    event = await repository.get_by_id(id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Enrollment Event with ID '{id}' not found",
        )

    return EnrollmentEventResponse.model_validate(event)


@router.get(
    "/stats",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get Enrollment Statistics",
    description="Get statistics about enrollment events.",
)
async def get_enrollment_stats(
    repository: EnrollmentEventRepository = Depends(get_enrollment_event_repository),
    hours: int = Query(24, ge=1, le=720, description="Time window in hours"),
) -> dict[str, Any]:
    """Get enrollment statistics."""
    events = await repository.get_recent(hours=hours)
    
    stats = {
        "total_events": len(events),
        "by_status": {},
        "by_profile": {},
        "time_window_hours": hours,
    }
    
    for event in events:
        # Count by status
        status = event.status
        stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
        
        # Count by profile
        profile_name = event.profile.name if event.profile else "unknown"
        stats["by_profile"][profile_name] = stats["by_profile"].get(profile_name, 0) + 1
    
    return stats
```

### 3.4 Status Endpoints

**File: `est_adapter/admin/api/status.py`**
```python
"""Status and health check endpoints."""
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.database.session import get_db_manager
from est_adapter.admin.schemas.common import HealthResponse
from est_adapter import __version__

router = APIRouter(prefix="/status", tags=["Status"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health Check",
    description="Check the health of the admin API.",
)
async def health_check(
    session: AsyncSession = Depends(get_db_manager().get_session),
) -> HealthResponse:
    """Check the health of the admin API."""
    # Check database connectivity
    try:
        await session.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "disconnected"

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        version=__version__,
        timestamp=datetime.utcnow(),
    )


@router.get(
    "/metrics",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get Metrics",
    description="Get system metrics.",
)
async def get_metrics(
    session: AsyncSession = Depends(get_db_manager().get_session),
) -> dict[str, Any]:
    """Get system metrics."""
    # Get database metrics
    try:
        # Count tables
        result = await session.execute(text("""
            SELECT COUNT(*) as table_count
            FROM information_schema.tables
            WHERE table_schema = 'public'
        """))
        table_count = result.scalar() or 0

        # Get row counts
        result = await session.execute(text("""
            SELECT 
                'ca_backends' as table_name,
                COUNT(*) as row_count
            FROM ca_backends
            UNION ALL
            SELECT 
                'est_profiles' as table_name,
                COUNT(*) as row_count
            FROM est_profiles
            UNION ALL
            SELECT 
                'enrollment_events' as table_name,
                COUNT(*) as row_count
            FROM enrollment_events
        """))
        row_counts = {row[0]: row[1] for row in result.fetchall()}
    except Exception:
        table_count = 0
        row_counts = {}

    return {
        "database": {
            "connected": True,
            "table_count": table_count,
            "row_counts": row_counts,
        },
        "version": __version__,
        "timestamp": datetime.utcnow().isoformat(),
    }
```

## 4. Enhanced Configuration

### 4.1 Updated Configuration Schema

**File: `est_adapter/config.py`** (additions)
```python
# Add to existing config.py

class AdminAPIConfig(BaseModel):
    """Admin API configuration."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    port: Annotated[int, Field(ge=1, le=65535)] = 8080
    host: str = "0.0.0.0"
    auth: "AdminAuthConfig" | None = None


class AdminWebConfig(BaseModel):
    """Admin Web UI configuration."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    port: Annotated[int, Field(ge=1, le=65535)] = 8501
    host: str = "0.0.0.0"
    auth: "AdminAuthConfig" | None = None


class AdminAuthConfig(BaseModel):
    """Admin authentication configuration."""

    model_config = ConfigDict(frozen=True)

    method: str = "api_key"  # api_key, jwt, or none
    api_keys: list["APIKeyConfig"] = []
    jwt_secret: str | None = None
    jwt_algorithm: str = "HS256"


class APIKeyConfig(BaseModel):
    """API key configuration."""

    model_config = ConfigDict(frozen=True)

    name: str
    key: str


class DatabaseConfig(BaseModel):
    """Database configuration."""

    model_config = ConfigDict(frozen=True)

    url: str | None = None
    pool_size: int = 10
    max_overflow: int = 20


class AdminConfig(BaseModel):
    """Admin configuration (API + Web UI)."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    api: AdminAPIConfig = AdminAPIConfig()
    web: AdminWebConfig = AdminWebConfig()
    database: DatabaseConfig = DatabaseConfig()


class Settings(BaseModel):
    """Root configuration model for EST Adapter."""

    model_config = ConfigDict(frozen=True)

    server: ServerConfig = ServerConfig()
    ca: CAConfig = CAConfig()
    auth: AuthConfig = AuthConfig()
    validation: ValidationConfig = ValidationConfig()
    audit: AuditConfig = AuditConfig()
    admin: AdminConfig = AdminConfig()  # New admin configuration
```

### 4.2 Updated Configuration Example

**File: `config.yaml.example`** (additions)
```yaml
# Add to existing config.yaml.example

# Admin API and Web UI configuration
admin:
  enabled: true
  
  # Admin REST API configuration
  api:
    enabled: true
    port: 8080
    host: "0.0.0.0"
    auth:
      method: "api_key"  # api_key, jwt, or none
      api_keys:
        - name: "admin"
          key: "your-api-key-here"
  
  # Admin Web UI configuration
  web:
    enabled: true
    port: 8501
    host: "0.0.0.0"
    auth:
      method: "basic"  # basic, oauth2, or none
      users:
        - username: "admin"
          password_hash: "$2b$12$..."  # bcrypt hash
  
  # Database configuration
  database:
    url: "postgresql+asyncpg://user:pass@localhost:5432/est_adapter"
    pool_size: 10
    max_overflow: 20

# Enhanced EST configuration with rate limiting
est:
  endpoints:
    cacerts:
      enabled: true
      rate_limit: 100  # requests per minute
    simpleenroll:
      enabled: true
      rate_limit: 30   # requests per minute
    simplereenroll:
      enabled: true
      rate_limit: 30   # requests per minute
```

## 5. Updated Main Entry Point

**File: `est_adapter/main.py`** (additions)
```python
# Add to existing main.py

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from est_adapter.admin.database.session import initialize_database
from est_adapter.admin.api.ca_backends import router as ca_backends_router
from est_adapter.admin.api.est_profiles import router as est_profiles_router
from est_adapter.admin.api.enrollment_events import router as enrollment_events_router
from est_adapter.admin.api.status import router as status_router

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    # ... existing code ...

    # Initialize database if admin is enabled
    if settings.admin.enabled and settings.admin.database.url:
        initialize_database(settings)

    # ... existing code ...

    # Add admin API routes if enabled
    if settings.admin.enabled and settings.admin.api.enabled:
        app.include_router(ca_backends_router, prefix="/api/v1")
        app.include_router(est_profiles_router, prefix="/api/v1")
        app.include_router(enrollment_events_router, prefix="/api/v1")
        app.include_router(status_router, prefix="/api/v1")

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return app
```

## 6. Docker Compose Setup

**File: `docker-compose.yml`**
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: est_adapter
      POSTGRES_USER: est_adapter
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U est_adapter"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  est-adapter:
    build: .
    environment:
      EST_ADAPTER_CONFIG: /app/config.yaml
      DB_PASSWORD: ${DB_PASSWORD}
    ports:
      - "8443:8443"  # EST endpoints
      - "8080:8080"  # Admin API
      - "8501:8501"  # Web UI
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./ca_data:/app/ca_data
      - ./logs:/app/logs
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    profiles:
      - "full"  # Run all services
      - "api"   # Run only API (no web UI)

  admin-web:
    build: .
    command: streamlit run est_adapter/admin/web/app.py --server.port 8501 --server.address 0.0.0.0
    environment:
      EST_ADAPTER_CONFIG: /app/config.yaml
      DB_PASSWORD: ${DB_PASSWORD}
    ports:
      - "8501:8501"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    depends_on:
      postgres:
        condition: service_healthy
      est-adapter:
        condition: service_started
    profiles:
      - "web"  # Run only web UI

volumes:
  postgres_data:
```

## 7. Migration Scripts

### 7.1 Alembic Configuration

**File: `alembic.ini`**
```ini
[alembic]
script_location = migrations
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = postgresql+asyncpg://user:pass@localhost:5432/est_adapter

[post_write_hooks]
hooks = ruff
ruff.type = exec
ruff.executable = ruff
ruff.options = --fix REVISION_SCRIPT_FILENAME
```

**File: `migrations/env.py`**
```python
"""Alembic environment configuration."""
import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from est_adapter.admin.models.base import Base
from est_adapter.config import load_config_from_env

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def get_url() -> str:
    """Get database URL from configuration."""
    settings = load_config_from_env()
    if settings.admin.database.url:
        return settings.admin.database.url
    return config.get_main_option("sqlalchemy.url")


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    """Run migrations with the given connection."""
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    url = get_url()
    connectable = create_async_engine(url)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
```

### 7.2 Initial Migration

**File: `migrations/versions/001_initial_migration.py`**
```python
"""Initial migration for admin API."""
from typing import Any, Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: str = None
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    # Create ca_backends table
    op.create_table(
        "ca_backends",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("type", sa.String(length=50), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, default=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    # Create est_profiles table
    op.create_table(
        "est_profiles",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("ca_backend_id", sa.UUID(), nullable=False),
        sa.Column("allowed_subjects", postgresql.JSONB(), nullable=True),
        sa.Column("validation_rules", postgresql.JSONB(), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, default=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["ca_backend_id"], ["ca_backends.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    # Create enrollment_events table
    op.create_table(
        "enrollment_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("profile_id", sa.UUID(), nullable=False),
        sa.Column("device_id", sa.String(length=255), nullable=True),
        sa.Column("subject_dn", sa.String(length=500), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("request_id", sa.String(length=255), nullable=True),
        sa.Column("correlation_id", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["profile_id"], ["est_profiles.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create indexes for performance
    op.create_index(
        "idx_enrollment_events_profile_id",
        "enrollment_events",
        ["profile_id"],
    )
    op.create_index(
        "idx_enrollment_events_status",
        "enrollment_events",
        ["status"],
    )
    op.create_index(
        "idx_enrollment_events_created_at",
        "enrollment_events",
        ["created_at"],
    )
    op.create_index(
        "idx_enrollment_events_device_id",
        "enrollment_events",
        ["device_id"],
    )


def downgrade() -> None:
    """Downgrade database schema."""
    # Drop indexes
    op.drop_index("idx_enrollment_events_device_id", table_name="enrollment_events")
    op.drop_index("idx_enrollment_events_created_at", table_name="enrollment_events")
    op.drop_index("idx_enrollment_events_status", table_name="enrollment_events")
    op.drop_index("idx_enrollment_events_profile_id", table_name="enrollment_events")

    # Drop tables
    op.drop_table("enrollment_events")
    op.drop_table("est_profiles")
    op.drop_table("ca_backends")
```

## 8. Updated Dependencies

**File: `pyproject.toml`** (additions)
```toml
[project.optional-dependencies]
admin = [
    "sqlalchemy>=2.0.0",
    "alembic>=1.13.0",
    "asyncpg>=0.30.0",  # PostgreSQL async driver
    "redis>=5.0.0",
    "slowapi>=0.1.9",
    "python-multipart>=0.0.6",
    "python-jose[cryptography]>=3.3.0",
    "streamlit>=1.30.0",
    "streamlit-authenticator>=0.2.0",
    "plotly>=5.18.0",
    "pandas>=2.1.0",
]

dev-admin = [
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=6.0.0",
    "httpx>=0.28.0",
    "factory-boy>=3.3.0",
    "faker>=24.0.0",
]
```

## 9. Implementation Checklist

### Phase 1: Database Layer
- [ ] Add SQLAlchemy and Alembic to dependencies
- [ ] Create database models
- [ ] Set up Alembic migrations
- [ ] Create repository layer
- [ ] Add database connection management
- [ ] Write unit tests for database layer

### Phase 2: Admin REST API
- [ ] Create API models and DTOs
- [ ] Implement CA backend management endpoints
- [ ] Implement EST profile management endpoints
- [ ] Implement enrollment event endpoints
- [ ] Add API authentication (API keys)
- [ ] Add rate limiting
- [ ] Generate OpenAPI specifications
- [ ] Write integration tests for API

### Phase 3: Integration
- [ ] Integrate database with existing EST endpoints
- [ ] Add enrollment event logging to EST endpoints
- [ ] Update configuration loading
- [ ] Update main entry point
- [ ] Create Docker Compose setup
- [ ] Write end-to-end tests

### Phase 4: Documentation
- [ ] Update README with new features
- [ ] Create API documentation
- [ ] Create deployment guides
- [ ] Add monitoring and metrics
- [ ] Prepare for production deployment

## 10. Testing Strategy

### Unit Tests
```python
# Example test for CA Backend repository
@pytest.mark.unit
async def test_create_ca_backend(session: AsyncSession):
    repository = CABackendRepository(session)
    
    ca_backend = await repository.create(
        name="test-ca",
        type="self_signed",
        config={"subject": "CN=Test CA"},
        is_enabled=True,
    )
    
    assert ca_backend.id is not None
    assert ca_backend.name == "test-ca"
    assert ca_backend.type == "self_signed"
```

### Integration Tests
```python
# Example test for CA Backend API
@pytest.mark.integration
async def test_create_ca_backend_api(client: AsyncClient):
    response = await client.post(
        "/api/v1/ca-backends",
        json={
            "name": "test-ca",
            "type": "self_signed",
            "config": {"subject": "CN=Test CA"},
        },
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "test-ca"
    assert "id" in data
```

### End-to-End Tests
```python
# Example test for full workflow
@pytest.mark.integration
async def test_full_enrollment_workflow(client: AsyncClient):
    # 1. Create CA Backend
    ca_response = await client.post(
        "/api/v1/ca-backends",
        json={
            "name": "test-ca",
            "type": "self_signed",
            "config": {"subject": "CN=Test CA"},
        },
    )
    ca_data = ca_response.json()
    
    # 2. Create EST Profile
    profile_response = await client.post(
        "/api/v1/est-profiles",
        json={
            "name": "test-profile",
            "ca_backend_id": ca_data["id"],
        },
    )
    profile_data = profile_response.json()
    
    # 3. Enroll certificate via EST endpoint
    # (This would involve generating a CSR and calling the EST endpoint)
    
    # 4. Check enrollment event
    events_response = await client.get(
        f"/api/v1/enrollment-events?profile_id={profile_data['id']}",
    )
    events_data = events_response.json()
    
    assert len(events_data) > 0
    assert events_data[0]["status"] == "approved"
```

## 11. Security Considerations

### API Authentication
- **API Keys**: Simple, stateless, recommended for MVP
- **JWT Tokens**: More secure, requires OAuth2 infrastructure
- **mTLS**: For internal services

### Rate Limiting
- Use `slowapi` middleware
- Store rate limit data in Redis
- Configure per-endpoint limits

### Input Validation
- All API inputs validated with Pydantic
- SQL injection prevention with SQLAlchemy
- XSS prevention in web UI

### CORS Configuration
- Configure allowed origins appropriately
- Use environment variables for production

## 12. Performance Considerations

### Database
- Use connection pooling
- Create appropriate indexes
- Use async database driver
- Implement query optimization

### API
- Use pagination for large datasets
- Implement caching for frequently accessed data
- Use async operations for I/O-bound operations

### Web UI
- Use Streamlit caching features
- Implement lazy loading for large datasets
- Use pagination for data tables

## 13. Deployment Strategy

### Development
```bash
# Install dependencies
uv sync --extra admin --extra dev-admin

# Run migrations
alembic upgrade head

# Start services
docker-compose --profile full up -d

# Run tests
uv run pytest
```

### Production
```bash
# Build Docker image
docker build -t est-adapter:latest .

# Run with Docker Compose
docker-compose --profile full up -d

# Monitor logs
docker-compose logs -f est-adapter
```

## 14. Monitoring and Logging

### Metrics
- API request/response times
- Database query times
- Enrollment event statistics
- Error rates

### Logging
- Structured logging with Loguru
- Request/response logging
- Error tracking
- Audit logging for compliance

## 15. Conclusion

This implementation guide provides a comprehensive plan for adding admin API and web UI to certificate-orchestrator-proxy. The solution is modular, scalable, and maintains alignment with the existing Python/FastAPI architecture.

**Key Benefits:**
1. **Python Native**: Uses existing Python ecosystem
2. **Modular Design**: Can be implemented incrementally
3. **Production Ready**: Includes Docker orchestration and monitoring
4. **Healthcare Focused**: Maintains medical-grade audit logging
5. **Feature Parity**: Brings certificate-orchestrator-proxy closer to RTSec.Kryptonian

**Next Steps:**
1. Review and approve this implementation guide
2. Create implementation tickets
3. Start Phase 1: Database Layer
4. Regular progress reviews and adjustments

---
**Document Version**: 1.0
**Date**: 2026-02-12
**Author**: Xander (AI assistant)
**Status**: Implementation Guide