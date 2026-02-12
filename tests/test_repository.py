"""Tests for the repository layer."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from est_adapter.admin.models import Base, CABackend, ESTProfile, EnrollmentEvent
from est_adapter.admin.repository import (
    CABackendRepository,
    ESTProfileRepository,
    EnrollmentEventRepository,
)


@pytest.fixture
async def async_session() -> AsyncSession:
    """Create an async session for testing with SQLite in-memory database."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session_maker() as session:
        yield session


@pytest.mark.asyncio
async def test_cabackend_repository(async_session: AsyncSession) -> None:
    """Test CABackendRepository CRUD operations."""
    repo = CABackendRepository(async_session)

    # Create
    cab = await repo.create(
        name="test_ca",
        type="self_signed",
        config={"key_size": 2048},
        is_enabled=True,
        description="Test CA Backend",
    )
    assert cab.id is not None
    assert cab.name == "test_ca"

    # Get by ID
    cab_by_id = await repo.get_by_id(cab.id)
    assert cab_by_id is not None
    assert cab_by_id.name == "test_ca"

    # Get by name
    cab_by_name = await repo.get_by_name("test_ca")
    assert cab_by_name is not None
    assert cab_by_name.id == cab.id

    # Get all
    all_backends = await repo.get_all()
    assert len(all_backends) == 1

    # Get enabled
    enabled_backends = await repo.get_enabled_backends()
    assert len(enabled_backends) == 1

    # Update
    updated = await repo.update(cab.id, description="Updated description")
    assert updated is not None
    assert updated.description == "Updated description"

    # Count
    count = await repo.count()
    assert count == 1

    # Delete
    deleted = await repo.delete(cab.id)
    assert deleted is True

    # Verify deletion
    cab_after_delete = await repo.get_by_id(cab.id)
    assert cab_after_delete is None


@pytest.mark.asyncio
async def test_est_profile_repository(async_session: AsyncSession) -> None:
    """Test ESTProfileRepository CRUD operations."""
    # First create a CA backend
    ca_repo = CABackendRepository(async_session)
    ca_backend = await ca_repo.create(
        name="test_ca_for_profile",
        type="self_signed",
        config={"key_size": 2048},
        is_enabled=True,
    )

    repo = ESTProfileRepository(async_session)

    # Create
    profile = await repo.create(
        name="test_profile",
        ca_backend_id=ca_backend.id,
        allowed_subjects=["CN=test"],
        validation_rules={"min_key_size": 2048},
        is_enabled=True,
        description="Test EST Profile",
    )
    assert profile.id is not None
    assert profile.name == "test_profile"

    # Get by ID
    profile_by_id = await repo.get_by_id(profile.id)
    assert profile_by_id is not None
    assert profile_by_id.name == "test_profile"

    # Get by name
    profile_by_name = await repo.get_by_name("test_profile")
    assert profile_by_name is not None
    assert profile_by_name.id == profile.id

    # Get all
    all_profiles = await repo.get_all()
    assert len(all_profiles) == 1

    # Get enabled
    enabled_profiles = await repo.get_enabled_profiles()
    assert len(enabled_profiles) == 1

    # Get by CA backend
    profiles_by_ca = await repo.get_profiles_by_ca_backend(ca_backend.id)
    assert len(profiles_by_ca) == 1

    # Update
    updated = await repo.update(profile.id, description="Updated description")
    assert updated is not None
    assert updated.description == "Updated description"

    # Update allowed subjects
    updated_subjects = await repo.update_allowed_subjects(profile.id, ["CN=updated"])
    assert updated_subjects is not None
    assert updated_subjects.allowed_subjects == ["CN=updated"]

    # Count
    count = await repo.count()
    assert count == 1

    # Delete
    deleted = await repo.delete(profile.id)
    assert deleted is True

    # Verify deletion
    profile_after_delete = await repo.get_by_id(profile.id)
    assert profile_after_delete is None


@pytest.mark.asyncio
async def test_enrollment_event_repository(async_session: AsyncSession) -> None:
    """Test EnrollmentEventRepository CRUD operations."""
    # First create a CA backend and EST profile
    ca_repo = CABackendRepository(async_session)
    ca_backend = await ca_repo.create(
        name="test_ca_for_event",
        type="self_signed",
        config={"key_size": 2048},
        is_enabled=True,
    )

    profile_repo = ESTProfileRepository(async_session)
    profile = await profile_repo.create(
        name="test_profile_for_event",
        ca_backend_id=ca_backend.id,
        is_enabled=True,
    )

    repo = EnrollmentEventRepository(async_session)

    # Create
    event = await repo.create(
        profile_id=profile.id,
        device_id="device_123",
        subject_dn="CN=device_123",
        status="pending",
        ip_address="192.168.1.1",
        user_agent="test-agent",
        request_id="req_123",
        correlation_id="corr_123",
    )
    assert event.id is not None
    assert event.status == "pending"

    # Get by ID
    event_by_id = await repo.get_by_id(event.id)
    assert event_by_id is not None
    assert event_by_id.status == "pending"

    # Get by profile
    events_by_profile = await repo.get_by_profile(profile.id)
    assert len(events_by_profile) == 1

    # Get by status
    events_by_status = await repo.get_by_status("pending")
    assert len(events_by_status) == 1

    # Get by device
    events_by_device = await repo.get_by_device("device_123")
    assert len(events_by_device) == 1

    # Get by correlation ID
    event_by_corr = await repo.get_by_correlation_id("corr_123")
    assert event_by_corr is not None
    assert event_by_corr.id == event.id

    # Get recent
    recent_events = await repo.get_recent(hours=24)
    assert len(recent_events) == 1

    # Update status
    updated_event = await repo.update_status(event.id, "approved", error_message=None)
    assert updated_event is not None
    assert updated_event.status == "approved"

    # Count by status
    pending_count = await repo.count_by_status("pending")
    assert pending_count == 0

    approved_count = await repo.count_by_status("approved")
    assert approved_count == 1

    # Count by profile
    profile_count = await repo.count_by_profile(profile.id)
    assert profile_count == 1

    # Delete
    deleted = await repo.delete(event.id)
    assert deleted is True

    # Verify deletion
    event_after_delete = await repo.get_by_id(event.id)
    assert event_after_delete is None


@pytest.mark.asyncio
async def test_repository_filters(async_session: AsyncSession) -> None:
    """Test repository filtering capabilities."""
    repo = CABackendRepository(async_session)

    # Create multiple backends
    await repo.create(
        name="ca1",
        type="self_signed",
        config={},
        is_enabled=True,
    )
    await repo.create(
        name="ca2",
        type="acme",
        config={},
        is_enabled=False,
    )
    await repo.create(
        name="ca3",
        type="self_signed",
        config={},
        is_enabled=True,
    )

    # Test filtering by type
    self_signed_backends = await repo.get_backends_by_type("self_signed")
    assert len(self_signed_backends) == 2

    # Test filtering by enabled status
    enabled_backends = await repo.get_enabled_backends()
    assert len(enabled_backends) == 2

    # Test count with filters
    enabled_count = await repo.count(filters={"is_enabled": True})
    assert enabled_count == 2

    # Test get_all with filters
    acme_backends = await repo.get_all(filters={"type": "acme"})
    assert len(acme_backends) == 1
    assert acme_backends[0].type == "acme"


@pytest.mark.asyncio
async def test_repository_pagination(async_session: AsyncSession) -> None:
    """Test repository pagination capabilities."""
    repo = CABackendRepository(async_session)

    # Create multiple backends
    for i in range(10):
        await repo.create(
            name=f"ca_{i:02d}",
            type="self_signed",
            config={},
            is_enabled=True,
        )

    # Test pagination
    first_page = await repo.get_all(skip=0, limit=5)
    assert len(first_page) == 5

    second_page = await repo.get_all(skip=5, limit=5)
    assert len(second_page) == 5

    # Verify no overlap
    first_ids = {str(ca.id) for ca in first_page}
    second_ids = {str(ca.id) for ca in second_page}
    assert first_ids.isdisjoint(second_ids)

    # Test total count
    total_count = await repo.count()
    assert total_count == 10
