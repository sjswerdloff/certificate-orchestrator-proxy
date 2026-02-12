"""Enrollment Event admin API endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.dependencies import get_database_session
from est_adapter.admin.repository import EnrollmentEventRepository
from est_adapter.admin.schemas.common import PaginatedResponse
from est_adapter.admin.schemas.enrollment_event import (
    EnrollmentEventResponse,
)

router = APIRouter(prefix="/api/v1/enrollment-events", tags=["enrollment-events"])


@router.get(
    "",
    response_model=PaginatedResponse[EnrollmentEventResponse],
    status_code=status.HTTP_200_OK,
    summary="List enrollment events",
    description="Get a paginated list of all enrollment events",
)
async def list_enrollment_events(
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    session: AsyncSession = Depends(get_database_session),
) -> PaginatedResponse[EnrollmentEventResponse]:
    """List all enrollment events with pagination.

    Args:
        skip: Number of records to skip for pagination
        limit: Maximum number of records to return
        session: Database session

    Returns:
        PaginatedResponse: Paginated list of enrollment events
    """
    try:
        repo = EnrollmentEventRepository(session)

        # Get total count for pagination
        total_count = await repo.count()

        # Get paginated results
        enrollment_events = await repo.get_all(skip=skip, limit=limit)

        # Calculate pagination metadata
        total_pages = (total_count + limit - 1) // limit if total_count > 0 else 1
        current_page = (skip // limit) + 1 if limit > 0 else 1

        return PaginatedResponse(
            items=[EnrollmentEventResponse.model_validate(ee) for ee in enrollment_events],
            total=total_count,
            page=current_page,
            per_page=limit,
            total_pages=total_pages,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve enrollment events: {e!s}",
        ) from e


@router.get(
    "/search",
    response_model=PaginatedResponse[EnrollmentEventResponse],
    status_code=status.HTTP_200_OK,
    summary="Search enrollment events",
    description="Search enrollment events with filters",
)
async def search_enrollment_events(
    profile_id: UUID | None = Query(None, description="Filter by EST profile ID"),
    device_id: str | None = Query(None, description="Filter by device ID (partial match)"),
    status_filter: str | None = Query(None, description="Filter by status (pending, approved, rejected, error)"),
    subject_dn: str | None = Query(None, description="Filter by subject DN (partial match)"),
    ip_address: str | None = Query(None, description="Filter by IP address"),
    request_id: str | None = Query(None, description="Filter by request ID (partial match)"),
    correlation_id: str | None = Query(None, description="Filter by correlation ID (partial match)"),
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    session: AsyncSession = Depends(get_database_session),
) -> PaginatedResponse[EnrollmentEventResponse]:
    """Search enrollment events with filters.

    Args:
        profile_id: Filter by EST profile ID
        device_id: Filter by device ID (partial match)
        status_filter: Filter by status
        subject_dn: Filter by subject DN (partial match)
        ip_address: Filter by IP address
        request_id: Filter by request ID (partial match)
        correlation_id: Filter by correlation ID (partial match)
        skip: Number of records to skip for pagination
        limit: Maximum number of records to return
        session: Database session

    Returns:
        PaginatedResponse: Paginated list of matching enrollment events
    """
    try:
        repo = EnrollmentEventRepository(session)

        # Build filters dictionary
        filters: dict[str, str | UUID] = {}
        if profile_id:
            filters["profile_id"] = profile_id
        if device_id:
            filters["device_id"] = device_id
        if status_filter:
            filters["status"] = status_filter
        if subject_dn:
            filters["subject_dn"] = subject_dn
        if ip_address:
            filters["ip_address"] = ip_address
        if request_id:
            filters["request_id"] = request_id
        if correlation_id:
            filters["correlation_id"] = correlation_id

        # Get total count for pagination
        total_count = await repo.count(filters=filters)

        # Get paginated results
        enrollment_events = await repo.get_all(skip=skip, limit=limit, filters=filters)

        # Calculate pagination metadata
        total_pages = (total_count + limit - 1) // limit if total_count > 0 else 1
        current_page = (skip // limit) + 1 if limit > 0 else 1

        return PaginatedResponse(
            items=[EnrollmentEventResponse.model_validate(ee) for ee in enrollment_events],
            total=total_count,
            page=current_page,
            per_page=limit,
            total_pages=total_pages,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to search enrollment events: {e!s}",
        ) from e


@router.get(
    "/stats",
    status_code=status.HTTP_200_OK,
    summary="Get enrollment statistics",
    description="Get statistics about enrollment events",
)
async def get_enrollment_stats(
    session: AsyncSession = Depends(get_database_session),
) -> dict[str, int]:
    """Get enrollment statistics.

    Returns:
        dict: Statistics about enrollment events
    """
    try:
        repo = EnrollmentEventRepository(session)

        # Get counts by status
        pending_count = await repo.count_by_status("pending")
        approved_count = await repo.count_by_status("approved")
        rejected_count = await repo.count_by_status("rejected")
        error_count = await repo.count_by_status("error")

        # Get total count
        total_count = await repo.count()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve enrollment statistics: {e!s}",
        ) from e

    return {
        "total": total_count,
        "pending": pending_count,
        "approved": approved_count,
        "rejected": rejected_count,
        "error": error_count,
    }


@router.get(
    "/{enrollment_event_id}",
    response_model=EnrollmentEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Get enrollment event",
    description="Get a specific enrollment event by ID",
)
async def get_enrollment_event(
    enrollment_event_id: UUID,
    session: AsyncSession = Depends(get_database_session),
) -> EnrollmentEventResponse:
    """Get a specific enrollment event by ID.

    Args:
        enrollment_event_id: UUID of the enrollment event
        session: Database session

    Returns:
        EnrollmentEventResponse: Enrollment event details
    """
    try:
        repo = EnrollmentEventRepository(session)
        enrollment_event = await repo.get_by_id(enrollment_event_id)

        if not enrollment_event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Enrollment event with ID '{enrollment_event_id}' not found",
            )

        return EnrollmentEventResponse.model_validate(enrollment_event)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve enrollment event: {e!s}",
        ) from e
