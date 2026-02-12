"""EST Profile admin API endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.dependencies import get_database_session
from est_adapter.admin.repository import CABackendRepository, ESTProfileRepository
from est_adapter.admin.schemas.common import PaginatedResponse
from est_adapter.admin.schemas.est_profile import (
    ESTProfileCreate,
    ESTProfileResponse,
    ESTProfileUpdate,
)

router = APIRouter(prefix="/api/v1/est-profiles", tags=["est-profiles"])


@router.get(
    "",
    response_model=PaginatedResponse[ESTProfileResponse],
    status_code=status.HTTP_200_OK,
    summary="List EST profiles",
    description="Get a paginated list of all EST profiles",
)
async def list_est_profiles(
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    session: AsyncSession = Depends(get_database_session),
) -> PaginatedResponse[ESTProfileResponse]:
    """List all EST profiles with pagination.

    Args:
        skip: Number of records to skip for pagination
        limit: Maximum number of records to return
        session: Database session

    Returns:
        PaginatedResponse: Paginated list of EST profiles
    """
    try:
        repo = ESTProfileRepository(session)

        # Get total count for pagination
        total_count = await repo.count()

        # Get paginated results
        est_profiles = await repo.get_all(skip=skip, limit=limit)

        # Calculate pagination metadata
        total_pages = (total_count + limit - 1) // limit if total_count > 0 else 1
        current_page = (skip // limit) + 1 if limit > 0 else 1

        return PaginatedResponse(
            items=[ESTProfileResponse.model_validate(ep) for ep in est_profiles],
            total=total_count,
            page=current_page,
            per_page=limit,
            total_pages=total_pages,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve EST profiles: {e!s}",
        ) from e


@router.post(
    "",
    response_model=ESTProfileResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create EST profile",
    description="Create a new EST profile configuration",
)
async def create_est_profile(
    est_profile_create: ESTProfileCreate,
    session: AsyncSession = Depends(get_database_session),
) -> ESTProfileResponse:
    """Create a new EST profile.

    Args:
        est_profile_create: EST profile creation data
        session: Database session

    Returns:
        ESTProfileResponse: Created EST profile
    """
    try:
        ca_backend_repo = CABackendRepository(session)
        est_profile_repo = ESTProfileRepository(session)

        # Check if CA backend exists
        ca_backend = await ca_backend_repo.get_by_id(est_profile_create.ca_backend_id)
        if not ca_backend:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA backend with ID '{est_profile_create.ca_backend_id}' not found",
            )

        # Check if name already exists
        existing = await est_profile_repo.get_by_name(est_profile_create.name)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"EST profile with name '{est_profile_create.name}' already exists",
            )

        # Create the EST profile
        est_profile = await est_profile_repo.create(**est_profile_create.model_dump())

        return ESTProfileResponse.model_validate(est_profile)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create EST profile: {e!s}",
        ) from e


@router.get(
    "/{est_profile_id}",
    response_model=ESTProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Get EST profile",
    description="Get a specific EST profile by ID",
)
async def get_est_profile(
    est_profile_id: UUID,
    session: AsyncSession = Depends(get_database_session),
) -> ESTProfileResponse:
    """Get a specific EST profile by ID.

    Args:
        est_profile_id: UUID of the EST profile
        session: Database session

    Returns:
        ESTProfileResponse: EST profile details
    """
    try:
        repo = ESTProfileRepository(session)
        est_profile = await repo.get_by_id(est_profile_id)

        if not est_profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"EST profile with ID '{est_profile_id}' not found",
            )

        return ESTProfileResponse.model_validate(est_profile)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve EST profile: {e!s}",
        ) from e


@router.put(
    "/{est_profile_id}",
    response_model=ESTProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Update EST profile",
    description="Update an existing EST profile configuration",
)
async def update_est_profile(
    est_profile_id: UUID,
    est_profile_update: ESTProfileUpdate,
    session: AsyncSession = Depends(get_database_session),
) -> ESTProfileResponse:
    """Update an existing EST profile.

    Args:
        est_profile_id: UUID of the EST profile
        est_profile_update: EST profile update data
        session: Database session

    Returns:
        ESTProfileResponse: Updated EST profile
    """
    try:
        ca_backend_repo = CABackendRepository(session)
        est_profile_repo = ESTProfileRepository(session)

        # Check if EST profile exists
        existing = await est_profile_repo.get_by_id(est_profile_id)
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"EST profile with ID '{est_profile_id}' not found",
            )

        # Check if CA backend exists if being updated
        if est_profile_update.ca_backend_id:
            ca_backend = await ca_backend_repo.get_by_id(est_profile_update.ca_backend_id)
            if not ca_backend:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"CA backend with ID '{est_profile_update.ca_backend_id}' not found",
                )

        # Check if name is being changed and already exists
        if est_profile_update.name and est_profile_update.name != existing.name:
            name_exists = await est_profile_repo.get_by_name(est_profile_update.name)
            if name_exists:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"EST profile with name '{est_profile_update.name}' already exists",
                )

        # Update the EST profile
        update_data = est_profile_update.model_dump(exclude_unset=True)
        updated_est_profile = await est_profile_repo.update(est_profile_id, **update_data)

        if not updated_est_profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"EST profile with ID '{est_profile_id}' not found",
            )

        return ESTProfileResponse.model_validate(updated_est_profile)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update EST profile: {e!s}",
        ) from e


@router.delete(
    "/{est_profile_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete EST profile",
    description="Delete an EST profile configuration",
)
async def delete_est_profile(
    est_profile_id: UUID,
    session: AsyncSession = Depends(get_database_session),
) -> None:
    """Delete an EST profile.

    Args:
        est_profile_id: UUID of the EST profile
        session: Database session
    """
    try:
        repo = ESTProfileRepository(session)

        # Check if EST profile exists
        existing = await repo.get_by_id(est_profile_id)
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"EST profile with ID '{est_profile_id}' not found",
            )

        # Check if EST profile is in use by any enrollment events
        if existing.enrollment_events:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"EST profile with ID '{est_profile_id}' is in use by "
                f"{len(existing.enrollment_events)} enrollment event(s)",
            )

        # Delete the EST profile
        deleted = await repo.delete(est_profile_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"EST profile with ID '{est_profile_id}' not found",
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete EST profile: {e!s}",
        ) from e
