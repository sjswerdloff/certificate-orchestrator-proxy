"""Common Pydantic schemas for admin API."""

from datetime import UTC, datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class BaseSchema(BaseModel):
    """Base schema with common configuration."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


class PaginatedResponse(BaseSchema, Generic[T]):
    """Generic paginated response schema."""

    items: list[T] = Field(..., description="List of items in the current page")
    total: int = Field(..., description="Total number of items across all pages")
    page: int = Field(..., description="Current page number (1-indexed)")
    per_page: int = Field(..., description="Number of items per page")
    total_pages: int = Field(..., description="Total number of pages")


class ErrorResponse(BaseSchema):
    """Error response schema."""

    detail: str = Field(..., description="Error message")
    error_code: str | None = Field(None, description="Optional error code for categorization")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC), description="Timestamp of the error")


class HealthResponse(BaseSchema):
    """Health check response schema."""

    status: str = Field(..., description="Health status (healthy, degraded, unhealthy)")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC), description="Timestamp of health check")
    version: str | None = Field(None, description="Service version")
    uptime_seconds: float | None = Field(None, description="Service uptime in seconds")
    database: str | None = Field(None, description="Database connection status")
    ca_backends: int | None = Field(None, description="Number of configured CA backends")
    est_profiles: int | None = Field(None, description="Number of configured EST profiles")
