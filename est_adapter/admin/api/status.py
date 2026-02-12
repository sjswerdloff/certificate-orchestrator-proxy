"""Status and health check endpoints for admin API."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.dependencies import get_database_session
from est_adapter.admin.repository import (
    CABackendRepository,
    EnrollmentEventRepository,
    ESTProfileRepository,
)
from est_adapter.admin.schemas.common import HealthResponse

router = APIRouter(prefix="/api/v1/status", tags=["status"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health check endpoint",
    description="Check the health status of the service and its dependencies",
)
async def health_check(
    session: AsyncSession = Depends(get_database_session),
) -> HealthResponse:
    """Check the health status of the service.

    Returns:
        HealthResponse: Health status including database connectivity and resource counts
    """
    try:
        # Initialize repositories
        ca_backend_repo = CABackendRepository(session)
        est_profile_repo = ESTProfileRepository(session)

        # Check database connectivity by attempting to count records
        ca_backends_count = await ca_backend_repo.count()
        est_profiles_count = await est_profile_repo.count()

        return HealthResponse(
            status="healthy",
            timestamp=datetime.now(UTC),
            version="0.1.0",
            uptime_seconds=None,
            database="connected",
            ca_backends=ca_backends_count,
            est_profiles=est_profiles_count,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Health check failed: {e!s}",
        ) from e


@router.get(
    "/metrics",
    status_code=status.HTTP_200_OK,
    summary="System metrics endpoint",
    description="Get system metrics and statistics",
)
async def metrics(
    session: AsyncSession = Depends(get_database_session),
) -> dict[str, int]:
    """Get system metrics and statistics.

    Returns:
        dict: System metrics including counts of various resources
    """
    try:
        # Initialize repositories
        ca_backend_repo = CABackendRepository(session)
        est_profile_repo = ESTProfileRepository(session)
        enrollment_event_repo = EnrollmentEventRepository(session)

        # Get counts
        ca_backends_count = await ca_backend_repo.count()
        est_profiles_count = await est_profile_repo.count()
        enrollment_events_count = await enrollment_event_repo.count()

        # Get counts by status
        pending_count = await enrollment_event_repo.count_by_status("pending")
        approved_count = await enrollment_event_repo.count_by_status("approved")
        rejected_count = await enrollment_event_repo.count_by_status("rejected")
        error_count = await enrollment_event_repo.count_by_status("error")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Metrics retrieval failed: {e!s}",
        ) from e

    return {
        "ca_backends": ca_backends_count,
        "est_profiles": est_profiles_count,
        "enrollment_events": enrollment_events_count,
        "enrollment_events_pending": pending_count,
        "enrollment_events_approved": approved_count,
        "enrollment_events_rejected": rejected_count,
        "enrollment_events_error": error_count,
    }
