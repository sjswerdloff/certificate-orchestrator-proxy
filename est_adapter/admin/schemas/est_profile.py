"""Pydantic schemas for EST Profile admin API."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .common import BaseSchema


class ESTProfileBase(BaseSchema):
    """Base schema for EST Profile with common fields."""

    name: str = Field(
        ...,
        description="Unique name for the EST profile",
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z0-9_-]+$",
    )
    ca_backend_id: UUID = Field(
        ...,
        description="UUID of the CA backend this profile uses",
    )
    allowed_subjects: list[str] | None = Field(
        None,
        description="List of allowed subject DNs (distinguished names) for enrollment",
        max_length=100,
    )
    validation_rules: dict[str, Any] | None = Field(
        None,
        description="Validation rules for certificate requests",
    )
    is_enabled: bool = Field(
        default=True,
        description="Whether the EST profile is enabled for use",
    )
    description: str | None = Field(
        None,
        description="Optional description of the EST profile",
        max_length=1000,
    )

    @field_validator("allowed_subjects")
    @classmethod
    def validate_allowed_subjects(cls, v: list[str] | None) -> list[str] | None:
        """Validate that allowed_subjects doesn't exceed maximum length."""
        if v is None:
            return v
        if len(v) > 100:
            raise ValueError("allowed_subjects cannot contain more than 100 entries")
        return v


class ESTProfileCreate(ESTProfileBase):
    """Schema for creating a new EST Profile."""

    pass


class ESTProfileUpdate(BaseSchema):
    """Schema for updating an existing EST Profile."""

    name: str | None = Field(
        None,
        description="Updated unique name for the EST profile",
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z0-9_-]+$",
    )
    ca_backend_id: UUID | None = Field(
        None,
        description="Updated UUID of the CA backend this profile uses",
    )
    allowed_subjects: list[str] | None = Field(
        None,
        description="Updated list of allowed subject DNs for enrollment",
        max_length=100,
    )
    validation_rules: dict[str, Any] | None = Field(
        None,
        description="Updated validation rules for certificate requests",
    )
    is_enabled: bool | None = Field(
        None,
        description="Updated enabled status for the EST profile",
    )
    description: str | None = Field(
        None,
        description="Updated optional description of the EST profile",
        max_length=1000,
    )

    @field_validator("allowed_subjects")
    @classmethod
    def validate_allowed_subjects(cls, v: list[str] | None) -> list[str] | None:
        """Validate that allowed_subjects doesn't exceed maximum length."""
        if v is None:
            return v
        if len(v) > 100:
            raise ValueError("allowed_subjects cannot contain more than 100 entries")
        return v


class ESTProfileResponse(ESTProfileBase):
    """Schema for EST Profile response."""

    id: UUID = Field(..., description="Unique identifier for the EST profile")
    created_at: datetime = Field(..., description="Timestamp when the EST profile was created")
    updated_at: datetime = Field(..., description="Timestamp when the EST profile was last updated")
    enrollment_events_count: int | None = Field(
        None,
        description="Number of enrollment events for this profile",
    )

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )
