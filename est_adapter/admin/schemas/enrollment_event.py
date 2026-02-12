"""Pydantic schemas for Enrollment Event admin API."""

import re
from datetime import datetime
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator

from .common import BaseSchema


class EnrollmentEventBase(BaseSchema):
    """Base schema for Enrollment Event with common fields."""

    profile_id: UUID = Field(
        ...,
        description="UUID of the EST profile associated with this event",
    )
    device_id: str | None = Field(
        None,
        description="Device identifier (e.g., serial number, MAC address)",
        max_length=255,
    )
    subject_dn: str | None = Field(
        None,
        description="Subject Distinguished Name of the certificate request",
        max_length=500,
    )
    status: str = Field(
        ...,
        description="Status of the enrollment event (pending, approved, rejected, error)",
        min_length=1,
        max_length=50,
    )
    error_message: str | None = Field(
        None,
        description="Error message if status is 'error'",
    )
    ip_address: str | None = Field(
        None,
        description="IP address of the requesting client (IPv4 or IPv6)",
        max_length=45,
    )
    user_agent: str | None = Field(
        None,
        description="User agent string from the HTTP request",
    )
    request_id: str | None = Field(
        None,
        description="Unique request identifier for tracking",
        max_length=255,
    )
    correlation_id: str | None = Field(
        None,
        description="Correlation ID for linking related events",
        max_length=255,
    )

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Validate that the status is one of the supported values."""
        valid_statuses = {"pending", "approved", "rejected", "error"}
        if v not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")
        return v

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, v: str | None) -> str | None:
        """Validate IP address format (basic validation)."""
        if v is None:
            return v
        # Basic validation for IPv4 and IPv6
        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"

        if not (re.match(ipv4_pattern, v) or re.match(ipv6_pattern, v)):
            raise ValueError("Invalid IP address format")
        return v


class EnrollmentEventCreate(EnrollmentEventBase):
    """Schema for creating a new Enrollment Event."""


class EnrollmentEventResponse(EnrollmentEventBase):
    """Schema for Enrollment Event response."""

    id: UUID = Field(..., description="Unique identifier for the enrollment event")
    created_at: datetime = Field(..., description="Timestamp when the event was created")
    updated_at: datetime = Field(..., description="Timestamp when the event was last updated")

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


class EnrollmentEventFilter(BaseSchema):
    """Schema for filtering enrollment events."""

    profile_id: UUID | None = Field(
        None,
        description="Filter by EST profile ID",
    )
    device_id: str | None = Field(
        None,
        description="Filter by device ID (partial match)",
        max_length=255,
    )
    status: str | None = Field(
        None,
        description="Filter by status (pending, approved, rejected, error)",
        max_length=50,
    )
    subject_dn: str | None = Field(
        None,
        description="Filter by subject DN (partial match)",
        max_length=500,
    )
    ip_address: str | None = Field(
        None,
        description="Filter by IP address",
        max_length=45,
    )
    request_id: str | None = Field(
        None,
        description="Filter by request ID (partial match)",
        max_length=255,
    )
    correlation_id: str | None = Field(
        None,
        description="Filter by correlation ID (partial match)",
        max_length=255,
    )
    start_date: datetime | None = Field(
        None,
        description="Filter events created after this timestamp",
    )
    end_date: datetime | None = Field(
        None,
        description="Filter events created before this timestamp",
    )

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str | None) -> str | None:
        """Validate that the status is one of the supported values."""
        if v is None:
            return v
        valid_statuses = {"pending", "approved", "rejected", "error"}
        if v not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")
        return v

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, v: str | None) -> str | None:
        """Validate IP address format (basic validation)."""
        if v is None:
            return v
        # Basic validation for IPv4 and IPv6
        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"

        if not (re.match(ipv4_pattern, v) or re.match(ipv6_pattern, v)):
            raise ValueError("Invalid IP address format")
        return v
