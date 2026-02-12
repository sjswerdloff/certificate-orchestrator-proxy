# Admin API and Web UI for Certificate-Orchestrator-Proxy

## Overview

This document provides an overview of the proposed admin API and web UI for certificate-orchestrator-proxy, bringing it to feature parity with RTSec.Kryptonian while maintaining alignment with the existing Python/FastAPI architecture.

## Problem Statement

The certificate-orchestrator-proxy currently provides:
- ✅ EST protocol server (RFC 7030)
- ✅ Multiple CA backends (Self-Signed, SCEP)
- ✅ Authentication (HTTP Basic, client certificate)
- ✅ Audit logging
- ✅ Policy-based validation

But it lacks:
- ❌ Admin REST API for configuration management
- ❌ Web-based user interface
- ❌ Enrollment event monitoring
- ❌ Rate limiting
- ❌ Docker orchestration

## Proposed Solution

### 1. Admin REST API

**Endpoints:**
- `/api/v1/ca-backends` - CA backend management
- `/api/v1/est-profiles` - EST profile management
- `/api/v1/enrollment-events` - Enrollment event monitoring
- `/api/v1/status` - System status and health

**Features:**
- RESTful design with proper HTTP methods
- Pydantic validation for all requests/responses
- API key authentication
- Rate limiting
- OpenAPI documentation
- Pagination and filtering

### 2. Web UI

**Technology:** Streamlit (Python-native web framework)

**Features:**
- Dashboard with system overview
- CA backend management interface
- EST profile management interface
- Enrollment events viewer
- Configuration editor
- Basic authentication

### 3. Database Layer

**Technology:** SQLAlchemy + Alembic + PostgreSQL

**Models:**
- `ca_backends` - CA backend configurations
- `est_profiles` - EST endpoint profiles
- `enrollment_events` - Enrollment event logs

### 4. Docker Orchestration

**Technology:** Docker Compose

**Services:**
- PostgreSQL database
- Redis (for rate limiting)
- Est-adapter (main application)
- Admin-web (optional Streamlit UI)

## Architecture

```
certificate-orchestrator-proxy/
├── est_adapter/
│   ├── admin/                    # New admin module
│   │   ├── api/                 # REST API endpoints
│   │   ├── models/              # Database models
│   │   ├── schemas/             # Pydantic schemas
│   │   ├── repository/          # Database repository layer
│   │   ├── database/            # Database connection
│   │   └── auth/                # API authentication
│   ├── config.py                # Enhanced configuration
│   └── main.py                  # Updated main entry point
├── migrations/                  # Alembic migrations
├── docker-compose.yml           # Docker orchestration
└── config.yaml.example          # Updated configuration example
```

## Implementation Phases

### Phase 1: Database Layer (Week 1-2)
- Add SQLAlchemy and Alembic
- Create database models
- Set up migrations
- Create repository layer

### Phase 2: Admin REST API (Week 3-4)
- Create API endpoints
- Add API authentication
- Add rate limiting
- Generate OpenAPI specs

### Phase 3: Web UI (Week 5-6)
- Set up Streamlit application
- Create dashboard components
- Build management interfaces
- Add authentication

### Phase 4: Integration & Testing (Week 7-8)
- Integrate with existing EST endpoints
- Add enrollment event logging
- Create Docker Compose setup
- Write comprehensive tests

### Phase 5: Documentation & Deployment (Week 9-10)
- Update documentation
- Create deployment guides
- Add monitoring and metrics
- Prepare for production

## Key Benefits

### 1. Feature Parity with RTSec.Kryptonian
- Admin REST API for configuration management
- Web-based user interface
- Enrollment event monitoring
- Rate limiting
- Docker orchestration

### 2. Python Native
- Uses existing Python ecosystem
- FastAPI for REST API
- Streamlit for Web UI
- SQLAlchemy for database
- Pydantic for validation

### 3. Modular Design
- Can be implemented incrementally
- Admin features can be disabled
- Database is optional
- Backward compatible with existing EST endpoints

### 4. Production Ready
- Docker Compose orchestration
- Database migrations
- API authentication
- Rate limiting
- Monitoring and metrics

### 5. Healthcare Focused
- Medical-grade audit logging
- Compliance-friendly design
- Security best practices
- HIPAA-ready architecture

## Quick Start

### 1. Install Dependencies
```bash
cd /Users/stuartswerdloff/PythonProjects/certificate-orchestrator-proxy
uv sync --extra admin --extra dev-admin
```

### 2. Set Up Database

**Option A: PostgreSQL (Recommended for all environments)**
```bash
# PostgreSQL with Docker
docker run -d \
  --name postgres-est \
  -e POSTGRES_DB=est_adapter \
  -e POSTGRES_USER=est_adapter \
  -e POSTGRES_PASSWORD=yourpassword \
  -p 5432:5432 \
  postgres:16-alpine
```

**Option B: SQLite (For development/testing only)**
```bash
# SQLite requires no setup - just use the file path
# admin:
#   database:
#     url: "sqlite+aiosqlite:///./est_adapter.db"
```

**Important Clarification:** SQLite IS a database and works perfectly with SQLAlchemy/Alembic! However, it has single-writer limitations that make it unsuitable for production with concurrent writes.

**See:**
- `SQLITE_VS_POSTGRESQL.md` - Detailed comparison
- `CONCURRENT_WRITE_ANALYSIS.md` - Why concurrent writes are likely
- `DECISION_SUMMARY.md` - Final decision and rationale
```

### 3. Run Migrations
```bash
alembic upgrade head
```

### 4. Start Services
```bash
docker-compose --profile full up -d
```

### 5. Test API
```bash
curl http://localhost:8080/api/v1/status/health
```

## API Reference

### CA Backend Management

**List CA Backends:**
```bash
GET /api/v1/ca-backends
Headers: X-API-Key: your-api-key
```

**Create CA Backend:**
```bash
POST /api/v1/ca-backends
Headers: X-API-Key: your-api-key
Content-Type: application/json
Body: {
  "name": "test-ca",
  "type": "self_signed",
  "config": {"subject": "CN=Test CA"}
}
```

**Get CA Backend:**
```bash
GET /api/v1/ca-backends/{id}
Headers: X-API-Key: your-api-key
```

**Update CA Backend:**
```bash
PUT /api/v1/ca-backends/{id}
Headers: X-API-Key: your-api-key
Content-Type: application/json
Body: {
  "name": "updated-name",
  "is_enabled": false
}
```

**Delete CA Backend:**
```bash
DELETE /api/v1/ca-backends/{id}
Headers: X-API-Key: your-api-key
```

### EST Profile Management

**List EST Profiles:**
```bash
GET /api/v1/est-profiles
Headers: X-API-Key: your-api-key
```

**Create EST Profile:**
```bash
POST /api/v1/est-profiles
Headers: X-API-Key: your-api-key
Content-Type: application/json
Body: {
  "name": "test-profile",
  "ca_backend_id": "uuid-of-ca-backend"
}
```

### Enrollment Event Monitoring

**List Enrollment Events:**
```bash
GET /api/v1/enrollment-events?profile_id=uuid&status=approved&hours=24
Headers: X-API-Key: your-api-key
```

**Search Enrollment Events:**
```bash
GET /api/v1/enrollment-events/search?query=search-term
Headers: X-API-Key: your-api-key
```

**Get Enrollment Statistics:**
```bash
GET /api/v1/enrollment-events/stats?hours=24
Headers: X-API-Key: your-api-key
```

### Status Endpoints

**Health Check:**
```bash
GET /api/v1/status/health
# No authentication required
```

**System Metrics:**
```bash
GET /api/v1/status/metrics
Headers: X-API-Key: your-api-key
```

## Configuration

### Admin Configuration Example

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
    # ⚠️ PostgreSQL is REQUIRED for production
    # Concurrent writes are likely (enrollment events, audit logs)
    # See CONCURRENT_WRITE_ANALYSIS.md for details
    url: "postgresql+asyncpg://user:pass@localhost:5432/est_adapter"
    pool_size: 10
    max_overflow: 20
```

### EST Configuration with Rate Limiting

```yaml
est:
  endpoints:
    cacerts:
      enabled: true
      rate_limit: 100  # requests per minute
    simpleenroll:
      enabled: true
      rate_limit: 30   # requests per minute
    simplereenroll:
      enabled: true
      rate_limit: 30   # requests per minute
```

## Testing

### Unit Tests
```bash
uv run pytest tests/unit/ -v
```

### Integration Tests
```bash
uv run pytest tests/integration/ -v
```

### End-to-End Tests
```bash
uv run pytest tests/e2e/ -v
```

### Coverage
```bash
uv run pytest --cov=est_adapter --cov-report=html
```

## Deployment

### Development
```bash
# Start with Docker Compose
docker-compose --profile full up -d

# View logs
docker-compose logs -f est-adapter
```

### Production
```bash
# Build Docker image
docker build -t est-adapter:latest .

# Run with Docker Compose
docker-compose --profile full up -d

# Monitor
docker-compose logs -f
```

## Monitoring

### Health Check
```bash
curl http://localhost:8080/api/v1/status/health
```

### Metrics
```bash
curl http://localhost:8080/api/v1/status/metrics
```

### Logs
```bash
docker-compose logs -f est-adapter
```

## Security

### API Authentication
- API keys for admin API
- Basic auth for web UI
- JWT tokens (optional, for future)

### Rate Limiting
- Per-endpoint rate limits
- Redis-based rate limiting
- Configurable limits

### Input Validation
- Pydantic validation for all inputs
- SQL injection prevention
- XSS prevention in web UI

## Comparison with RTSec.Kryptonian

| Feature | RTSec.Kryptonian | Certificate-Orchestrator-Proxy (Current) | Certificate-Orchestrator-Proxy (Proposed) |
|---------|------------------|------------------------------------------|-------------------------------------------|
| **Language** | C#/.NET | Python | Python |
| **EST Protocol** | ✅ | ✅ | ✅ |
| **Admin REST API** | ✅ | ❌ | ✅ |
| **Web UI** | ✅ (Blazor) | ❌ | ✅ (Streamlit) |
| **Database** | PostgreSQL | ❌ | ✅ (PostgreSQL - REQUIRED for concurrent writes) |
| **Rate Limiting** | ✅ | ❌ | ✅ |
| **Docker Orchestration** | ✅ | ❌ | ✅ |
| **OpenAPI Specs** | ✅ | ❌ | ✅ |
| **CA Backends** | Self-Signed, ACME | Self-Signed, SCEP | Self-Signed, SCEP, ACME (planned) |
| **Authentication** | API keys, mTLS, HTTP Basic | HTTP Basic, client cert | API keys, HTTP Basic, client cert |
| **Concurrent Writes** | ✅ (PostgreSQL MVCC) | ❌ (No database) | ✅ (PostgreSQL MVCC - required for production) |

## Migration Path

### From Current State
1. **Backward Compatibility**: Existing EST endpoints remain unchanged
2. **Configuration Migration**: Add new config sections, keep existing ones
3. **Database Migration**: Optional - can run without database initially
4. **Gradual Rollout**: Admin API and Web UI can be enabled/disabled via config

### Rollback Plan
- Keep existing configuration format
- Database is optional (can run without it)
- Web UI can be disabled
- Admin API can be disabled

## Success Metrics

### Technical Metrics
- API response time < 100ms for admin endpoints
- Web UI load time < 2 seconds
- 99.9% uptime for admin services
- 100% test coverage for new code

### Business Metrics
- Reduced configuration time (target: 50% reduction)
- Improved monitoring capabilities
- Better user experience for administrators
- Increased adoption in healthcare organizations

## Risks and Mitigations

### Risk 1: Database Complexity
**Mitigation**: Use PostgreSQL from the start. SQLite is a full-featured database but has single-writer limitations that make it unsuitable for production with concurrent writes. Certificate-orchestrator-proxy will have concurrent writes in production (enrollment events, audit logs, configuration updates), making PostgreSQL the better choice even for small deployments.

### Risk 2: Web UI Performance
**Mitigation**: Use Streamlit's caching features, implement pagination

### Risk 3: Security Vulnerabilities
**Mitigation**: Regular security audits, input validation, rate limiting

### Risk 4: Integration Complexity
**Mitigation**: Modular design, comprehensive testing, gradual rollout

## Next Steps

1. **Review Proposal**: Review `ADMIN_API_WEB_UI_PROPOSAL.md`
2. **Review Implementation Guide**: Review `ADMIN_API_IMPLEMENTATION.md`
3. **Review Quick Start**: Review `IMPLEMENTATION_QUICK_START.md`
4. **Plan Implementation**: Create implementation tickets
5. **Start Phase 1**: Database layer implementation
6. **Regular Reviews**: Weekly progress reviews and adjustments

## Documentation Files

1. **ADMIN_API_WEB_UI_PROPOSAL.md** - Comprehensive proposal document
2. **ADMIN_API_IMPLEMENTATION.md** - Detailed technical implementation guide
3. **IMPLEMENTATION_QUICK_START.md** - Step-by-step quick start guide
4. **README_ADMIN_API.md** - This overview document

## Support

For questions or issues:
1. Review the detailed implementation guide
2. Check existing code in `est_adapter/` directory
3. Review tests in `tests/` directory
4. Check Docker Compose setup

## License

This proposal and implementation guide are provided as-is for the certificate-orchestrator-proxy project.

---
**Document Version**: 1.0
**Date**: 2026-02-12
**Author**: Xander (AI assistant)
**Status**: Proposal Overview