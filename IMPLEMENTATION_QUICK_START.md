# Implementation Quick Start Guide

## Overview

This guide provides a step-by-step approach to implementing admin API and web UI for certificate-orchestrator-proxy. Follow these steps in order.

## Prerequisites

1. **Python 3.11+** installed
2. **uv** package manager installed
3. **PostgreSQL** database (or use SQLite for development)
4. **Redis** (optional, for rate limiting)

## Step 1: Install Dependencies

```bash
cd /Users/stuartswerdloff/PythonProjects/certificate-orchestrator-proxy

# Install all dependencies including admin features
uv sync --extra admin --extra dev-admin

# Activate virtual environment
source .venv/bin/activate  # On macOS/Linux
# or
.venv\Scripts\activate  # On Windows
```

## Step 2: Set Up Database

### Option A: PostgreSQL (Recommended for Production)
```bash
# Start PostgreSQL with Docker
docker run -d \
  --name postgres-est \
  -e POSTGRES_DB=est_adapter \
  -e POSTGRES_USER=est_adapter \
  -e POSTGRES_PASSWORD=yourpassword \
  -p 5432:5432 \
  postgres:16-alpine

# Update config.yaml with database URL
# admin:
#   database:
#     url: "postgresql+asyncpg://est_adapter:yourpassword@localhost:5432/est_adapter"
```

### Option B: SQLite (For Development/Testing Only - NOT Recommended for Production)
```bash
# Update config.yaml with SQLite URL
# admin:
#   database:
#     url: "sqlite+aiosqlite:///./est_adapter.db"

# ⚠️ IMPORTANT: SQLite IS a database and works with SQLAlchemy/Alembic!
# However, it has single-writer limitations that make it unsuitable for production.

# SQLite + SQLAlchemy/Alembic works perfectly for:
# ✅ Development (zero setup, no server needed)
# ✅ Testing (controlled environment)
# ✅ Single-user applications

# SQLite is NOT suitable for production because:
# ❌ Concurrent writes are LIKELY in certificate-orchestrator-proxy
# ❌ Single-writer limitation causes lock contention
# ❌ Performance degrades with concurrent writes
# ❌ Not designed for network access

# See CONCURRENT_WRITE_ANALYSIS.md for detailed analysis.
# See CONCURRENT_WRITE_SUMMARY.md for quick reference.
# See DECISION_SUMMARY.md for final decision.

# For development/testing only - use PostgreSQL for all other environments.
```

## Step 3: Create Database Models

Create the following files in the `est_adapter/admin/models/` directory:

1. **base.py** - Base model with common fields
2. **ca_backend.py** - CA Backend model
3. **est_profile.py** - EST Profile model
4. **enrollment_event.py** - Enrollment Event model

## Step 4: Set Up Alembic Migrations

```bash
# Initialize Alembic
alembic init migrations

# Update alembic.ini with your database URL
# sqlalchemy.url = postgresql+asyncpg://est_adapter:yourpassword@localhost:5432/est_adapter

# Create initial migration
alembic revision --autogenerate -m "Initial migration"

# Apply migration
alembic upgrade head
```

## Step 5: Create Repository Layer

Create the following files in the `est_adapter/admin/repository/` directory:

1. **base.py** - Base repository with CRUD operations
2. **ca_backend.py** - CA Backend repository
3. **est_profile.py** - EST Profile repository
4. **enrollment_event.py** - Enrollment Event repository

## Step 6: Create Pydantic Schemas

Create the following files in the `est_adapter/admin/schemas/` directory:

1. **common.py** - Common schemas (BaseSchema, PaginatedResponse, etc.)
2. **ca_backend.py** - CA Backend schemas
3. **est_profile.py** - EST Profile schemas
4. **enrollment_event.py** - Enrollment Event schemas

## Step 7: Create API Endpoints

Create the following files in the `est_adapter/admin/api/` directory:

1. **ca_backends.py** - CA Backend API endpoints
2. **est_profiles.py** - EST Profile API endpoints
3. **enrollment_events.py** - Enrollment Event API endpoints
4. **status.py** - Status and health check endpoints

## Step 8: Update Configuration

1. Update `est_adapter/config.py` with admin configuration classes
2. Update `config.yaml.example` with admin configuration examples
3. Update `est_adapter/main.py` to include admin API routes

## Step 9: Create Docker Compose Setup

Create `docker-compose.yml` with:
- PostgreSQL service
- Redis service (optional)
- Est-adapter service with admin API
- Admin-web service (optional, for Streamlit UI)

## Step 10: Test the Implementation

```bash
# Run unit tests
uv run pytest tests/unit/ -v

# Run integration tests
uv run pytest tests/integration/ -v

# Run all tests
uv run pytest -v

# Run with coverage
uv run pytest --cov=est_adapter --cov-report=html
```

## Step 11: Start the Services

```bash
# Start with Docker Compose
docker-compose --profile full up -d

# Or run manually
uv run est-adapter
```

## Step 12: Test the API

```bash
# Test health endpoint
curl http://localhost:8080/api/v1/status/health

# Test CA Backend creation
curl -X POST http://localhost:8080/api/v1/ca-backends \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "name": "test-ca",
    "type": "self_signed",
    "config": {"subject": "CN=Test CA"}
  }'

# Test EST Profile creation
curl -X POST http://localhost:8080/api/v1/est-profiles \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "name": "test-profile",
    "ca_backend_id": "uuid-of-ca-backend"
  }'
```

## Step 13: Access Web UI (Optional)

If you enabled the Streamlit web UI:

```bash
# Start Streamlit UI
streamlit run est_adapter/admin/web/app.py --server.port 8501

# Access at http://localhost:8501
```

## Step 14: Monitor and Debug

```bash
# View logs
docker-compose logs -f est-adapter

# Check database
docker exec -it postgres-est psql -U est_adapter -d est_adapter

# Check Redis (if using)
docker exec -it redis-redis redis-cli ping
```

## Common Issues and Solutions

### Issue 1: Database Connection Error
**Solution**: Check database URL in config.yaml and ensure database is running.

```bash
# Test database connection
docker exec -it postgres-est psql -U est_adapter -d est_adapter -c "SELECT 1;"
```

### Issue 2: Alembic Migration Error
**Solution**: Ensure database models are imported in `migrations/env.py`.

```python
# In migrations/env.py
from est_adapter.admin.models.base import Base
target_metadata = Base.metadata
```

### Issue 3: API Authentication Error
**Solution**: Ensure API key is included in request headers.

```bash
# Include API key in header
-H "X-API-Key: your-api-key"
```

### Issue 4: Rate Limiting Error
**Solution**: Check Redis connection or increase rate limits in config.

```bash
# Test Redis connection
docker exec -it redis-redis redis-cli ping
```

## Development Workflow

### 1. Create a New Feature
```bash
# Create feature branch
git checkout -b feature/admin-api

# Make changes
# ...

# Run tests
uv run pytest

# Commit changes
git add .
git commit -m "feat: add admin API endpoints"

# Push and create PR
git push origin feature/admin-api
```

### 2. Update Database Schema
```bash
# Make model changes
# ...

# Generate migration
alembic revision --autogenerate -m "description"

# Review migration file
# ...

# Apply migration
alembic upgrade head
```

### 3. Run Tests
```bash
# Run specific test file
uv run pytest tests/unit/test_ca_backend.py -v

# Run with coverage
uv run pytest --cov=est_adapter/admin --cov-report=html

# Run in watch mode (requires pytest-watch)
uv run ptw
```

## Production Deployment Checklist

- [ ] Use PostgreSQL instead of SQLite
- [ ] Set strong API keys
- [ ] Configure CORS properly
- [ ] Enable HTTPS for admin API
- [ ] Set up monitoring and alerting
- [ ] Configure backup strategy
- [ ] Set up log rotation
- [ ] Configure firewall rules
- [ ] Use environment variables for secrets
- [ ] Set up CI/CD pipeline

## Performance Optimization

### Database
```python
# Add indexes for frequently queried columns
# In migration file:
op.create_index("idx_enrollment_events_profile_id", "enrollment_events", ["profile_id"])
op.create_index("idx_enrollment_events_status", "enrollment_events", ["status"])
op.create_index("idx_enrollment_events_created_at", "enrollment_events", ["created_at"])
```

### API
```python
# Use pagination for large datasets
@router.get("/ca-backends")
async def list_ca_backends(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    # ...
```

### Caching
```python
# Use Redis for caching frequently accessed data
import redis.asyncio as redis

redis_client = redis.Redis(host="localhost", port=6379)

@router.get("/ca-backends/{id}")
async def get_ca_backend(id: UUID):
    # Check cache first
    cached = await redis_client.get(f"ca_backend:{id}")
    if cached:
        return json.loads(cached)
    
    # Fetch from database
    ca_backend = await repository.get_by_id(id)
    
    # Cache for 5 minutes
    await redis_client.setex(
        f"ca_backend:{id}",
        300,
        json.dumps(ca_backend.to_dict()),
    )
    
    return ca_backend
```

## Security Best Practices

### 1. API Keys
```python
# Generate strong API keys
import secrets

api_key = secrets.token_urlsafe(32)
print(f"API Key: {api_key}")
```

### 2. Password Hashing
```python
# Generate bcrypt password hash
import bcrypt

password = "your-secure-password"
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
print(f"Hashed password: {hashed.decode()}")
```

### 3. Input Validation
```python
# Always validate user input
from pydantic import BaseModel, Field, validator

class UserInput(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    
    @validator("name")
    def validate_name(cls, v):
        if not v.isalnum():
            raise ValueError("Name must be alphanumeric")
        return v
```

## Monitoring and Logging

### 1. Structured Logging
```python
from loguru import logger

logger.info("User created", user_id=user_id, action="create")
logger.error("Database connection failed", error=str(e))
```

### 2. Metrics Collection
```python
from prometheus_client import Counter, Histogram

api_requests_total = Counter(
    "api_requests_total",
    "Total API requests",
    ["method", "endpoint", "status"]
)

api_request_duration = Histogram(
    "api_request_duration_seconds",
    "API request duration",
    ["method", "endpoint"]
)

# Use in API endpoints
@api_request_duration.labels(method="POST", endpoint="/ca-backends").time()
async def create_ca_backend(...):
    # ...
```

## Testing Strategy

### 1. Unit Tests
```python
# tests/unit/test_ca_backend.py
import pytest
from est_adapter.admin.repository.ca_backend import CABackendRepository

@pytest.mark.unit
async def test_create_ca_backend(session):
    repository = CABackendRepository(session)
    
    ca_backend = await repository.create(
        name="test-ca",
        type="self_signed",
        config={"subject": "CN=Test CA"},
    )
    
    assert ca_backend.id is not None
    assert ca_backend.name == "test-ca"
```

### 2. Integration Tests
```python
# tests/integration/test_api.py
import pytest
from httpx import AsyncClient

@pytest.mark.integration
async def test_create_ca_backend_api(client: AsyncClient):
    response = await client.post(
        "/api/v1/ca-backends",
        json={
            "name": "test-ca",
            "type": "self_signed",
            "config": {"subject": "CN=Test CA"},
        },
        headers={"X-API-Key": "test-key"},
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "test-ca"
```

### 3. End-to-End Tests
```python
# tests/e2e/test_workflow.py
import pytest
from httpx import AsyncClient

@pytest.mark.e2e
async def test_full_enrollment_workflow(client: AsyncClient):
    # 1. Create CA Backend
    ca_response = await client.post(
        "/api/v1/ca-backends",
        json={
            "name": "test-ca",
            "type": "self_signed",
            "config": {"subject": "CN=Test CA"},
        },
        headers={"X-API-Key": "test-key"},
    )
    ca_data = ca_response.json()
    
    # 2. Create EST Profile
    profile_response = await client.post(
        "/api/v1/est-profiles",
        json={
            "name": "test-profile",
            "ca_backend_id": ca_data["id"],
        },
        headers={"X-API-Key": "test-key"},
    )
    profile_data = profile_response.json()
    
    # 3. Enroll certificate via EST endpoint
    # (This would involve generating a CSR and calling the EST endpoint)
    
    # 4. Check enrollment event
    events_response = await client.get(
        f"/api/v1/enrollment-events?profile_id={profile_data['id']}",
        headers={"X-API-Key": "test-key"},
    )
    events_data = events_response.json()
    
    assert len(events_data) > 0
    assert events_data[0]["status"] == "approved"
```

## API Reference

### CA Backend Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/ca-backends` | List CA Backends | Yes |
| POST | `/api/v1/ca-backends` | Create CA Backend | Yes |
| GET | `/api/v1/ca-backends/{id}` | Get CA Backend | Yes |
| PUT | `/api/v1/ca-backends/{id}` | Update CA Backend | Yes |
| DELETE | `/api/v1/ca-backends/{id}` | Delete CA Backend | Yes |

### EST Profile Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/est-profiles` | List EST Profiles | Yes |
| POST | `/api/v1/est-profiles` | Create EST Profile | Yes |
| GET | `/api/v1/est-profiles/{id}` | Get EST Profile | Yes |
| PUT | `/api/v1/est-profiles/{id}` | Update EST Profile | Yes |
| DELETE | `/api/v1/est-profiles/{id}` | Delete EST Profile | Yes |

### Enrollment Event Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/enrollment-events` | List Enrollment Events | Yes |
| GET | `/api/v1/enrollment-events/search` | Search Enrollment Events | Yes |
| GET | `/api/v1/enrollment-events/{id}` | Get Enrollment Event | Yes |
| GET | `/api/v1/enrollment-events/stats` | Get Enrollment Statistics | Yes |

### Status Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/status/health` | Health Check | No |
| GET | `/api/v1/status/metrics` | System Metrics | Yes |

## Configuration Reference

### Admin Configuration

```yaml
admin:
  enabled: true
  
  api:
    enabled: true
    port: 8080
    host: "0.0.0.0"
    auth:
      method: "api_key"
      api_keys:
        - name: "admin"
          key: "your-api-key-here"
  
  web:
    enabled: true
    port: 8501
    host: "0.0.0.0"
    auth:
      method: "basic"
      users:
        - username: "admin"
          password_hash: "$2b$12$..."
  
  database:
    url: "postgresql+asyncpg://user:pass@localhost:5432/est_adapter"
    pool_size: 10
    max_overflow: 20
```

## Troubleshooting

### 1. Database Connection Issues
```bash
# Check database is running
docker ps | grep postgres

# Check database logs
docker logs postgres-est

# Test connection manually
docker exec -it postgres-est psql -U est_adapter -d est_adapter -c "SELECT 1;"
```

### 2. API Authentication Issues
```bash
# Check API key is correct
# Ensure X-API-Key header is included
# Check API key is in config.yaml
```

### 3. Rate Limiting Issues
```bash
# Check Redis is running
docker ps | grep redis

# Test Redis connection
docker exec -it redis-redis redis-cli ping

# Check rate limit configuration in config.yaml
```

### 4. Migration Issues
```bash
# Check migration history
alembic history

# Downgrade if needed
alembic downgrade -1

# Re-run migration
alembic upgrade head
```

## Next Steps

1. **Start with Phase 1**: Database layer implementation
2. **Test each phase**: Write tests before moving to next phase
3. **Review code**: Get code review before merging
4. **Document**: Update documentation as you implement
5. **Monitor**: Set up monitoring before production deployment

## Support

For questions or issues:
1. Check the detailed implementation guide: `ADMIN_API_IMPLEMENTATION.md`
2. Review the proposal document: `ADMIN_API_WEB_UI_PROPOSAL.md`
3. Check existing code in `est_adapter/` directory
4. Review tests in `tests/` directory

---
**Document Version**: 1.0
**Date**: 2026-02-12
**Author**: Xander (AI assistant)
**Status**: Quick Start Guide