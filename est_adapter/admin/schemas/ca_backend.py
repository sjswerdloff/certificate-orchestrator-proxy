"""Pydantic schemas for CA Backend admin API."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .common import BaseSchema


class CABackendBase(BaseSchema):
    """Base schema for CA Backend with common fields."""

    name: str = Field(
        ...,
        description="Unique name for the CA backend",
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z0-9_-]+$",
    )
    type: str = Field(
        ...,
        description="Type of CA backend (self_signed, acme, scep)",
        min_length=1,
        max_length=50,
    )
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Configuration dictionary for the CA backend",
    )
    is_enabled: bool = Field(
        default=True,
        description="Whether the CA backend is enabled for use",
    )
    description: str | None = Field(
        None,
        description="Optional description of the CA backend",
        max_length=1000,
    )

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate that the type is one of the supported values."""
        valid_types = {"self_signed", "acme", "scep"}
        if v not in valid_types:
            raise ValueError(f"Type must be one of: {', '.join(valid_types)}")
        return v


class CABackendCreate(CABackendBase):
    """Schema for creating a new CA Backend."""

    pass


class CABackendUpdate(BaseSchema):
    """Schema for updating an existing CA Backend."""

    name: str | None = Field(
        None,
        description="Updated unique name for the CA backend",
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z0-9_-]+$",
    )
    type: str | None = Field(
        None,
        description="Updated type of CA backend (self_signed, acme, scep)",
        min_length=1,
        max_length=50,
    )
    config: dict[str, Any] | None = Field(
        None,
        description="Updated configuration dictionary for the CA backend",
    )
    is_enabled: bool | None = Field(
        None,
        description="Updated enabled status for the CA backend",
    )
    description: str | None = Field(
        None,
        description="Updated optional description of the CA backend",
        max_length=1000,
    )

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str | None) -> str | None:
        """Validate that the type is one of the supported values."""
        if v is None:
            return v
        valid_types = {"self_signed", "acme", "scep"}
        if v not in valid_types:
            raise ValueError(f"Type must be one of: {', '.join(valid_types)}")
        return v


class CABackendResponse(CABackendBase):
    """Schema for CA Backend response."""

    id: UUID = Field(..., description="Unique identifier for the CA backend")
    created_at: datetime = Field(..., description="Timestamp when the CA backend was created")
    updated_at: datetime = Field(..., description="Timestamp when the CA backend was last updated")
    est_profiles_count: int | None = Field(
        None,
        description="Number of EST profiles using this CA backend",
    )

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )
