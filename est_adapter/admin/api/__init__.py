"""Admin API endpoints for certificate-orchestrator-proxy."""

from .ca_backends import router as ca_backends_router
from .enrollment_events import router as enrollment_events_router
from .est_profiles import router as est_profiles_router
from .status import router as status_router

__all__ = [
    "ca_backends_router",
    "enrollment_events_router",
    "est_profiles_router",
    "status_router",
]
