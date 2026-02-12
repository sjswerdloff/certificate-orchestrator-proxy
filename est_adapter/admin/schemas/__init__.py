"""Pydantic schemas for admin API."""

from .common import BaseSchema, ErrorResponse, HealthResponse, PaginatedResponse
from .ca_backend import (
    CABackendBase,
    CABackendCreate,
    CABackendResponse,
    CABackendUpdate,
)
from .enrollment_event import (
    EnrollmentEventBase,
    EnrollmentEventCreate,
    EnrollmentEventFilter,
    EnrollmentEventResponse,
)
from .est_profile import (
    ESTProfileBase,
    ESTProfileCreate,
    ESTProfileResponse,
    ESTProfileUpdate,
)

__all__ = [
    # Common schemas
    "BaseSchema",
    "PaginatedResponse",
    "ErrorResponse",
    "HealthResponse",
    # CA Backend schemas
    "CABackendBase",
    "CABackendCreate",
    "CABackendUpdate",
    "CABackendResponse",
    # EST Profile schemas
    "ESTProfileBase",
    "ESTProfileCreate",
    "ESTProfileUpdate",
    "ESTProfileResponse",
    # Enrollment Event schemas
    "EnrollmentEventBase",
    "EnrollmentEventCreate",
    "EnrollmentEventResponse",
    "EnrollmentEventFilter",
]
