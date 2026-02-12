"""Tests for the admin API endpoints."""

import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from est_adapter.admin.models import Base
from est_adapter.admin.database import init_database, get_async_session
from est_adapter.main import create_app
from est_adapter.config import Settings


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


@pytest.fixture
def test_client() -> TestClient:
    """Create a test client for the admin API."""
    # Set environment variable for test configuration
    os.environ["EST_ADAPTER_CONFIG"] = "test_config.yaml"

    # Create test settings
    settings = Settings(
        admin={
            "enabled": True,
            "api": {"enabled": True, "port": 8081, "host": "0.0.0.0"},
            "web": {"enabled": True, "port": 8501, "host": "0.0.0.0"},
            "database": {"url": "sqlite+aiosqlite:///:memory:?cache=shared&mode=memory", "pool_size": 10, "max_overflow": 20},
        }
    )

    # Manually initialize database before creating the app
    # This is needed because TestClient doesn't trigger lifespan
    import asyncio
    from est_adapter.admin.database import init_database

    asyncio.run(init_database(settings.admin.database.url))

    app = create_app(settings)
    return TestClient(app)


class TestCAEndpoints:
    """Test CA backend endpoints."""

    def test_list_ca_backends_empty(self, test_client: TestClient) -> None:
        """Test listing CA backends when none exist."""
        response = test_client.get("/api/v1/ca-backends")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert len(data["items"]) == 0

    def test_create_ca_backend(self, test_client: TestClient) -> None:
        """Test creating a CA backend."""
        response = test_client.post(
            "/api/v1/ca-backends",
            json={
                "name": "test-ca",
                "type": "self_signed",
                "config": {"subject": "CN=Test CA", "validity_days": 3650},
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test-ca"
        assert data["type"] == "self_signed"
        assert "id" in data

    def test_get_ca_backend(self, test_client: TestClient) -> None:
        """Test getting a specific CA backend."""
        # First create a CA backend
        create_response = test_client.post(
            "/api/v1/ca-backends",
            json={
                "name": "test-ca",
                "type": "self_signed",
                "config": {"subject": "CN=Test CA", "validity_days": 3650},
            },
        )
        ca_id = create_response.json()["id"]

        # Get the CA backend
        response = test_client.get(f"/api/v1/ca-backends/{ca_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == ca_id
        assert data["name"] == "test-ca"

    def test_update_ca_backend(self, test_client: TestClient) -> None:
        """Test updating a CA backend."""
        # First create a CA backend
        create_response = test_client.post(
            "/api/v1/ca-backends",
            json={
                "name": "test-ca",
                "type": "self_signed",
                "config": {"subject": "CN=Test CA", "validity_days": 3650},
            },
        )
        ca_id = create_response.json()["id"]

        # Update the CA backend
        response = test_client.put(
            f"/api/v1/ca-backends/{ca_id}",
            json={"description": "Updated description"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["description"] == "Updated description"

    def test_delete_ca_backend(self, test_client: TestClient) -> None:
        """Test deleting a CA backend."""
        # First create a CA backend
        create_response = test_client.post(
            "/api/v1/ca-backends",
            json={
                "name": "test-ca",
                "type": "self_signed",
                "config": {"subject": "CN=Test CA", "validity_days": 3650},
            },
        )
        ca_id = create_response.json()["id"]

        # Delete the CA backend
        response = test_client.delete(f"/api/v1/ca-backends/{ca_id}")
        assert response.status_code == 204

        # Verify deletion
        get_response = test_client.get(f"/api/v1/ca-backends/{ca_id}")
        assert get_response.status_code == 404


class TestESTProfileEndpoints:
    """Test EST profile endpoints."""

    def test_list_est_profiles_empty(self, test_client: TestClient) -> None:
        """Test listing EST profiles when none exist."""
        response = test_client.get("/api/v1/est-profiles")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert len(data["items"]) == 0

    def test_create_est_profile(self, test_client: TestClient) -> None:
        """Test creating an EST profile."""
        # First create a CA backend
        ca_response = test_client.post(
            "/api/v1/ca-backends",
            json={
                "name": "test-ca",
                "type": "self_signed",
                "config": {"subject": "CN=Test CA", "validity_days": 3650},
            },
        )
        ca_id = ca_response.json()["id"]

        # Create an EST profile
        response = test_client.post(
            "/api/v1/est-profiles",
            json={
                "name": "test-profile",
                "ca_backend_id": ca_id,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test-profile"
        assert data["ca_backend_id"] == ca_id
        assert "id" in data

    def test_get_est_profile(self, test_client: TestClient) -> None:
        """Test getting a specific EST profile."""
        # First create a CA backend and EST profile
        ca_response = test_client.post(
            "/api/v1/ca-backends",
            json={
                "name": "test-ca",
                "type": "self_signed",
                "config": {"subject": "CN=Test CA", "validity_days": 3650},
            },
        )
        ca_id = ca_response.json()["id"]

        profile_response = test_client.post(
            "/api/v1/est-profiles",
            json={
                "name": "test-profile",
                "ca_backend_id": ca_id,
            },
        )
        profile_id = profile_response.json()["id"]

        # Get the EST profile
        response = test_client.get(f"/api/v1/est-profiles/{profile_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == profile_id
        assert data["name"] == "test-profile"

    def test_update_est_profile(self, test_client: TestClient) -> None:
        """Test updating an EST profile."""
        # First create a CA backend and EST profile
        ca_response = test_client.post(
            "/api/v1/ca-backends",
            json={
                "name": "test-ca",
                "type": "self_signed",
                "config": {"subject": "CN=Test CA", "validity_days": 3650},
            },
        )
        ca_id = ca_response.json()["id"]

        profile_response = test_client.post(
            "/api/v1/est-profiles",
            json={
                "name": "test-profile",
                "ca_backend_id": ca_id,
            },
        )
        profile_id = profile_response.json()["id"]

        # Update the EST profile
        response = test_client.put(
            f"/api/v1/est-profiles/{profile_id}",
            json={"description": "Updated description"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["description"] == "Updated description"

    def test_delete_est_profile(self, test_client: TestClient) -> None:
        """Test deleting an EST profile."""
        # First create a CA backend and EST profile
        ca_response = test_client.post(
            "/api/v1/ca-backends",
            json={
                "name": "test-ca",
                "type": "self_signed",
                "config": {"subject": "CN=Test CA", "validity_days": 3650},
            },
        )
        ca_id = ca_response.json()["id"]

        profile_response = test_client.post(
            "/api/v1/est-profiles",
            json={
                "name": "test-profile",
                "ca_backend_id": ca_id,
            },
        )
        profile_id = profile_response.json()["id"]

        # Delete the EST profile
        response = test_client.delete(f"/api/v1/est-profiles/{profile_id}")
        assert response.status_code == 204

        # Verify deletion
        get_response = test_client.get(f"/api/v1/est-profiles/{profile_id}")
        assert get_response.status_code == 404


class TestEnrollmentEventEndpoints:
    """Test enrollment event endpoints."""

    def test_list_enrollment_events_empty(self, test_client: TestClient) -> None:
        """Test listing enrollment events when none exist."""
        response = test_client.get("/api/v1/enrollment-events")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert len(data["items"]) == 0

    def test_search_enrollment_events(self, test_client: TestClient) -> None:
        """Test searching enrollment events."""
        response = test_client.get("/api/v1/enrollment-events/search")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert len(data["items"]) == 0

    def test_get_enrollment_stats(self, test_client: TestClient) -> None:
        """Test getting enrollment statistics."""
        response = test_client.get("/api/v1/enrollment-events/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "pending" in data
        assert "approved" in data
        assert "rejected" in data
        assert "error" in data


class TestStatusEndpoints:
    """Test status endpoints."""

    def test_health_check(self, test_client: TestClient) -> None:
        """Test health check endpoint."""
        response = test_client.get("/api/v1/status/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["database"] == "connected"

    def test_metrics(self, test_client: TestClient) -> None:
        """Test metrics endpoint."""
        response = test_client.get("/api/v1/status/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "ca_backends" in data
        assert "est_profiles" in data
        assert "enrollment_events" in data


class TestAdminAPIIntegration:
    """Integration tests for admin API."""

    def test_full_workflow(self, test_client: TestClient) -> None:
        """Test a full workflow: create CA backend, create EST profile, check metrics."""
        # Create CA backend
        ca_response = test_client.post(
            "/api/v1/ca-backends",
            json={
                "name": "workflow-ca",
                "type": "self_signed",
                "config": {"subject": "CN=Workflow CA", "validity_days": 3650},
            },
        )
        assert ca_response.status_code == 201
        ca_id = ca_response.json()["id"]

        # Create EST profile
        profile_response = test_client.post(
            "/api/v1/est-profiles",
            json={
                "name": "workflow-profile",
                "ca_backend_id": ca_id,
            },
        )
        assert profile_response.status_code == 201
        profile_id = profile_response.json()["id"]

        # Check metrics
        metrics_response = test_client.get("/api/v1/status/metrics")
        assert metrics_response.status_code == 200
        metrics = metrics_response.json()
        assert metrics["ca_backends"] == 1
        assert metrics["est_profiles"] == 1

        # List CA backends
        ca_list_response = test_client.get("/api/v1/ca-backends")
        assert ca_list_response.status_code == 200
        ca_list = ca_list_response.json()
        assert ca_list["total"] == 1
        assert ca_list["items"][0]["name"] == "workflow-ca"

        # List EST profiles
        profile_list_response = test_client.get("/api/v1/est-profiles")
        assert profile_list_response.status_code == 200
        profile_list = profile_list_response.json()
        assert profile_list["total"] == 1
        assert profile_list["items"][0]["name"] == "workflow-profile"

    def test_error_handling(self, test_client: TestClient) -> None:
        """Test error handling in admin API."""
        # Try to get non-existent CA backend
        response = test_client.get("/api/v1/ca-backends/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404

        # Try to create CA backend with invalid type
        response = test_client.post(
            "/api/v1/ca-backends",
            json={
                "name": "invalid-ca",
                "type": "invalid_type",
                "config": {},
            },
        )
        assert response.status_code == 422

        # Try to create EST profile with non-existent CA backend
        response = test_client.post(
            "/api/v1/est-profiles",
            json={
                "name": "invalid-profile",
                "ca_backend_id": "00000000-0000-0000-0000-000000000000",
            },
        )
        assert response.status_code == 404
