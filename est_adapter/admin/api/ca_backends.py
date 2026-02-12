"""CA Backend admin API endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from est_adapter.admin.dependencies import get_database_session
from est_adapter.admin.repository import CABackendRepository
from est_adapter.admin.schemas.ca_backend import (
    CABackendCreate,
    CABackendResponse,
    CABackendUpdate,
)
from est_adapter.admin.schemas.common import PaginatedResponse

router = APIRouter(prefix="/api/v1/ca-backends", tags=["ca-backends"])


@router.get(
    "",
    response_model=PaginatedResponse[CABackendResponse],
    status_code=status.HTTP_200_OK,
    summary="List CA backends",
    description="Get a paginated list of all CA backends",
)
async def list_ca_backends(
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    session: AsyncSession = Depends(get_database_session),
) -> PaginatedResponse[CABackendResponse]:
    """List all CA backends with pagination.

    Args:
        skip: Number of records to skip for pagination
        limit: Maximum number of records to return
        session: Database session

    Returns:
        PaginatedResponse: Paginated list of CA backends
    """
    try:
        repo = CABackendRepository(session)

        # Get total count for pagination
        total_count = await repo.count()

        # Get paginated results
        ca_backends = await repo.get_all(skip=skip, limit=limit)

        # Calculate pagination metadata
        total_pages = (total_count + limit - 1) // limit if total_count > 0 else 1
        current_page = (skip // limit) + 1 if limit > 0 else 1

        return PaginatedResponse(
            items=[CABackendResponse.model_validate(cb) for cb in ca_backends],
            total=total_count,
            page=current_page,
            per_page=limit,
            total_pages=total_pages,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve CA backends: {e!s}",
        ) from e


@router.post(
    "",
    response_model=CABackendResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create CA backend",
    description="Create a new CA backend configuration",
)
async def create_ca_backend(
    ca_backend_create: CABackendCreate,
    session: AsyncSession = Depends(get_database_session),
) -> CABackendResponse:
    """Create a new CA backend.

    Args:
        ca_backend_create: CA backend creation data
        session: Database session

    Returns:
        CABackendResponse: Created CA backend
    """
    try:
        repo = CABackendRepository(session)

        # Check if name already exists
        existing = await repo.get_by_name(ca_backend_create.name)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"CA backend with name '{ca_backend_create.name}' already exists",
            )

        # Create the CA backend
        ca_backend = await repo.create(**ca_backend_create.model_dump())

        return CABackendResponse.model_validate(ca_backend)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create CA backend: {e!s}",
        ) from e


@router.get(
    "/{ca_backend_id}",
    response_model=CABackendResponse,
    status_code=status.HTTP_200_OK,
    summary="Get CA backend",
    description="Get a specific CA backend by ID",
)
async def get_ca_backend(
    ca_backend_id: UUID,
    session: AsyncSession = Depends(get_database_session),
) -> CABackendResponse:
    """Get a specific CA backend by ID.

    Args:
        ca_backend_id: UUID of the CA backend
        session: Database session

    Returns:
        CABackendResponse: CA backend details
    """
    try:
        repo = CABackendRepository(session)
        ca_backend = await repo.get_by_id(ca_backend_id)

        if not ca_backend:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA backend with ID '{ca_backend_id}' not found",
            )

        return CABackendResponse.model_validate(ca_backend)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve CA backend: {e!s}",
        ) from e


@router.put(
    "/{ca_backend_id}",
    response_model=CABackendResponse,
    status_code=status.HTTP_200_OK,
    summary="Update CA backend",
    description="Update an existing CA backend configuration",
)
async def update_ca_backend(
    ca_backend_id: UUID,
    ca_backend_update: CABackendUpdate,
    session: AsyncSession = Depends(get_database_session),
) -> CABackendResponse:
    """Update an existing CA backend.

    Args:
        ca_backend_id: UUID of the CA backend
        ca_backend_update: CA backend update data
        session: Database session

    Returns:
        CABackendResponse: Updated CA backend
    """
    try:
        repo = CABackendRepository(session)

        # Check if CA backend exists
        existing = await repo.get_by_id(ca_backend_id)
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA backend with ID '{ca_backend_id}' not found",
            )

        # Check if name is being changed and already exists
        if ca_backend_update.name and ca_backend_update.name != existing.name:
            name_exists = await repo.get_by_name(ca_backend_update.name)
            if name_exists:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"CA backend with name '{ca_backend_update.name}' already exists",
                )

        # Update the CA backend
        update_data = ca_backend_update.model_dump(exclude_unset=True)
        updated_ca_backend = await repo.update(ca_backend_id, **update_data)

        if not updated_ca_backend:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA backend with ID '{ca_backend_id}' not found",
            )

        return CABackendResponse.model_validate(updated_ca_backend)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update CA backend: {e!s}",
        ) from e


@router.delete(
    "/{ca_backend_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete CA backend",
    description="Delete a CA backend configuration",
)
async def delete_ca_backend(
    ca_backend_id: UUID,
    session: AsyncSession = Depends(get_database_session),
) -> None:
    """Delete a CA backend.

    Args:
        ca_backend_id: UUID of the CA backend
        session: Database session
    """
    try:
        repo = CABackendRepository(session)

        # Check if CA backend exists
        existing = await repo.get_by_id(ca_backend_id)
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA backend with ID '{ca_backend_id}' not found",
            )

        # Check if CA backend is in use by any EST profiles
        if existing.est_profiles:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"CA backend with ID '{ca_backend_id}' is in use by {len(existing.est_profiles)} EST profile(s)",
            )

        # Delete the CA backend
        deleted = await repo.delete(ca_backend_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA backend with ID '{ca_backend_id}' not found",
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete CA backend: {e!s}",
        ) from e
