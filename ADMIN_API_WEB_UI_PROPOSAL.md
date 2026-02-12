# Proposal: Admin API and Web UI for Certificate-Orchestrator-Proxy

## Executive Summary

This proposal outlines a plan to add administrative REST API and web-based user interface to the certificate-orchestrator-proxy project, bringing it to feature parity with RTSec.Kryptonian while maintaining alignment with the existing Python/FastAPI architecture.

## Current State Analysis

### Existing Capabilities
- **EST Protocol Server**: Full RFC 7030 implementation (cacerts, simpleenroll, simplereenroll)
- **Configuration**: YAML-based configuration with Pydantic validation
- **Authentication**: HTTP Basic auth and client certificate authentication
- **Audit Logging**: Medical-grade structured logging
- **Validation**: Policy-based CSR validation

### Missing Capabilities
- **Admin REST API**: No API for managing CA backends, EST profiles, or viewing enrollment events
- **Web UI**: No graphical interface for configuration and monitoring
- **OpenAPI Specifications**: No formal API documentation
- **Rate Limiting**: No built-in rate limiting for EST endpoints
- **Docker Orchestration**: No Docker Compose setup

## Proposed Solution Architecture

### 1. Admin REST API

#### API Endpoints Structure
```
/api/v1/
├── ca-backends/          # CA backend management
│   ├── GET /             # List all CA backends
│   ├── POST /            # Create CA backend
│   ├── GET /{id}         # Get CA backend details
│   ├── PUT /{id}         # Update CA backend
│   └── DELETE /{id}      # Delete CA backend
├── est-profiles/         # EST profile management
│   ├── GET /             # List all EST profiles
│   ├── POST /            # Create EST profile
│   ├── GET /{id}         # Get EST profile details
│   ├── PUT /{id}         # Update EST profile
│   └── DELETE /{id}      # Delete EST profile
├── enrollment-events/    # Enrollment event monitoring
│   ├── GET /             # List enrollment events (with filters)
│   └── GET /{id}         # Get specific enrollment event
└── status/               # System status
    ├── GET /health       # Health check
    ├── GET /metrics      # Prometheus metrics
    └── GET /version      # Version information
```

#### Technology Stack
- **FastAPI**: Already in use, extends existing API
- **SQLAlchemy**: For database operations (currently no database)
- **Alembic**: For database migrations
- **Pydantic**: For request/response validation (already in use)
- **python-multipart**: For file uploads (if needed)
- **python-jose[cryptography]**: For JWT tokens (optional, for API authentication)

### 2. Web UI

#### Technology Stack
- **Streamlit**: Lightweight, Python-native web framework
  - Pros: Simple, no JavaScript required, integrates with Python ecosystem
  - Cons: Less customizable than React/Vue
- **Alternative: React + FastAPI**: More complex but more powerful
  - Pros: Modern UI, better UX, more customizable
  - Cons: Requires separate frontend build process

**Recommendation**: Start with Streamlit for MVP, consider React for v2.0

#### UI Components
1. **Dashboard**: System overview, enrollment statistics, health status
2. **CA Backends Management**: CRUD operations for CA configurations
3. **EST Profiles Management**: CRUD operations for EST endpoint profiles
4. **Enrollment Events Viewer**: Filterable, searchable event log
5. **Configuration Editor**: YAML configuration editor with validation
6. **Certificate Management**: View issued certificates, revoke certificates

### 3. Database Layer

#### Current State
- No persistent storage (configuration in YAML file only)
- No enrollment event storage
- No CA backend state persistence

#### Proposed Database Schema
```sql
-- CA Backends table
CREATE TABLE ca_backends (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,  -- 'self_signed', 'acme', 'scep'
    config JSONB NOT NULL,
    is_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- EST Profiles table
CREATE TABLE est_profiles (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    ca_backend_id UUID REFERENCES ca_backends(id),
    allowed_subjects JSONB,  -- List of allowed subject patterns
    validation_rules JSONB,  -- Custom validation rules
    is_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Enrollment Events table
CREATE TABLE enrollment_events (
    id UUID PRIMARY KEY,
    profile_id UUID REFERENCES est_profiles(id),
    device_id VARCHAR(255),
    subject_dn VARCHAR(500),
    status VARCHAR(50),  -- 'pending', 'approved', 'rejected', 'error'
    error_message TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Certificates table (optional, for certificate lifecycle management)
CREATE TABLE certificates (
    id UUID PRIMARY KEY,
    serial_number VARCHAR(255) UNIQUE,
    subject_dn VARCHAR(500),
    issued_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    revocation_reason VARCHAR(255),
    ca_backend_id UUID REFERENCES ca_backends(id),
    metadata JSONB
);
```

### 4. Configuration Management

#### Enhanced Configuration Schema
```yaml
# New configuration sections
admin:
  enabled: true
  api:
    enabled: true
    port: 8080
    host: "0.0.0.0"
    auth:
      method: "api_key"  # api_key, jwt, or none
      api_keys:
        - name: "admin"
          key: "your-api-key-here"
  web:
    enabled: true
    port: 8501
    host: "0.0.0.0"
    auth:
      method: "basic"  # basic, oauth2, or none
      users:
        - username: "admin"
          password_hash: "$2b$12$..."
  database:
    url: "postgresql://user:pass@localhost:5432/est_adapter"
    pool_size: 10
    max_overflow: 20

# Enhanced EST configuration
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

### 5. Rate Limiting

#### Implementation
- **Library**: `slowapi` or `fastapi-limiter`
- **Storage**: Redis (optional) or in-memory
- **Configuration**: Per-endpoint rate limits
- **Headers**: Include rate limit info in response headers

### 6. Docker Orchestration

#### Docker Compose Setup
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: est_adapter
      POSTGRES_USER: est_adapter
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  est-adapter:
    build: .
    environment:
      EST_ADAPTER_CONFIG: /app/config.yaml
      DB_PASSWORD: ${DB_PASSWORD}
    ports:
      - "8443:8443"  # EST endpoints
      - "8080:8080"  # Admin API
      - "8501:8501"  # Web UI
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./ca_data:/app/ca_data
      - ./logs:/app/logs
    depends_on:
      - postgres
      - redis
    profiles:
      - "full"  # Run all services
      - "api"   # Run only API (no web UI)

  admin-web:
    build: .
    command: streamlit run est_adapter/admin/web/app.py --server.port 8501 --server.address 0.0.0.0
    environment:
      EST_ADAPTER_CONFIG: /app/config.yaml
      DB_PASSWORD: ${DB_PASSWORD}
    ports:
      - "8501:8501"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    depends_on:
      - postgres
      - est-adapter
    profiles:
      - "web"  # Run only web UI

volumes:
  postgres_data:
```

## Implementation Plan

### Phase 1: Database Layer (Week 1-2)
1. **Choose PostgreSQL** for all environments (development, testing, production)
2. Add SQLAlchemy and Alembic to dependencies
3. Create database models with concurrent write considerations
4. Set up Alembic migrations
5. Create repository layer for database operations
6. Add database connection management with connection pooling
7. **Rationale**: Concurrent writes are likely (enrollment events, audit logs), making PostgreSQL required from day one

### Phase 2: Admin REST API (Week 3-4)
1. Create API models and DTOs
2. Implement CA backend management endpoints
3. Implement EST profile management endpoints
4. Implement enrollment event endpoints
5. Add API authentication (API keys)
6. Add rate limiting
7. Generate OpenAPI specifications

### Phase 3: Web UI (Week 5-6)
1. Set up Streamlit application structure
2. Create dashboard components
3. Build CA backend management UI
4. Build EST profile management UI
5. Build enrollment events viewer
6. Add configuration editor
7. Add authentication (basic auth)

### Phase 4: Integration & Testing (Week 7-8)
1. Integrate database with existing EST endpoints
2. Add enrollment event logging to EST endpoints
3. Create Docker Compose setup
4. Write comprehensive tests
5. Performance testing
6. Security review

### Phase 5: Documentation & Deployment (Week 9-10)
1. Update README with new features
2. Create API documentation
3. Create deployment guides
4. Add monitoring and metrics
5. Prepare for production deployment

## Dependencies to Add

### Core Dependencies
```toml
[project.optional-dependencies]
admin = [
    "sqlalchemy>=2.0.0",
    "alembic>=1.13.0",
    "psycopg2-binary>=2.9.0",  # or asyncpg for async support
    "redis>=5.0.0",  # For rate limiting
    "slowapi>=0.1.9",  # Rate limiting middleware
    "python-multipart>=0.0.6",  # For file uploads
    "python-jose[cryptography]>=3.3.0",  # JWT tokens
    "streamlit>=1.30.0",  # Web UI
    "streamlit-authenticator>=0.2.0",  # Authentication
    "plotly>=5.18.0",  # Charts for dashboard
    "pandas>=2.1.0",  # Data manipulation
]
```

### Development Dependencies
```toml
[project.optional-dependencies]
dev-admin = [
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=6.0.0",
    "httpx>=0.28.0",
    "factory-boy>=3.3.0",  # Test factories
    "faker>=24.0.0",  # Test data generation
]
```

## API Design Principles

### 1. RESTful Design
- Use proper HTTP methods (GET, POST, PUT, DELETE)
- Use proper HTTP status codes
- Use proper resource naming (plural nouns)
- Use proper error responses

### 2. Pagination & Filtering
```python
# Example: List CA backends with pagination
GET /api/v1/ca-backends?page=1&limit=20&enabled=true&type=self_signed

# Response
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "pages": 5
  }
}
```

### 3. Error Handling
```python
# Standard error response
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid CA backend configuration",
    "details": [
      {
        "field": "config.url",
        "message": "URL must be a valid HTTPS endpoint"
      }
    ]
  }
}
```

### 4. Versioning
- API version in URL: `/api/v1/...`
- Support for multiple API versions
- Backward compatibility

## Security Considerations

### 1. API Authentication
- **Option A**: API keys (simpler, recommended for MVP)
- **Option B**: JWT tokens (more secure, requires OAuth2)
- **Option C**: mTLS (for internal services)

### 2. Web UI Authentication
- **Option A**: Basic auth (simpler, recommended for MVP)
- **Option B**: OAuth2 (more secure, requires identity provider)
- **Option C**: Session-based with password hashing

### 3. Rate Limiting
- Per-endpoint rate limits
- Per-IP rate limits
- Per-user rate limits (if authenticated)

### 4. Input Validation
- All API inputs validated with Pydantic
- SQL injection prevention with SQLAlchemy
- XSS prevention in web UI

## Testing Strategy

### 1. Unit Tests
- Test all API endpoints
- Test database models
- Test business logic
- Test configuration validation

### 2. Integration Tests
- Test API with database
- Test EST endpoints with admin API
- Test web UI with backend

### 3. End-to-End Tests
- Full workflow: create CA backend → create EST profile → enroll certificate
- Web UI user flows
- Docker Compose deployment

### 4. Performance Tests
- Load testing for API endpoints
- Stress testing for EST endpoints
- Database performance testing

## Migration Path

### From Current State to Proposed State
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

## Conclusion

This proposal provides a comprehensive plan to add admin API and web UI to certificate-orchestrator-proxy while maintaining alignment with the existing Python/FastAPI architecture. The solution is modular, allowing for gradual implementation and rollback if needed.

**Key Benefits:**
1. **Feature Parity**: Brings certificate-orchestrator-proxy closer to RTSec.Kryptonian
2. **Python Native**: Uses existing Python ecosystem and tools
3. **Modular Design**: Can be implemented incrementally
4. **Production Ready**: Includes Docker orchestration and monitoring
5. **Healthcare Focused**: Maintains medical-grade audit logging and compliance

**Next Steps:**
1. Review and approve this proposal
2. Create implementation tickets
3. Start Phase 1: Database Layer
4. Regular progress reviews and adjustments

---
**Document Version**: 1.0
**Date**: 2026-02-12
**Author**: Xander (AI assistant)
**Status**: Proposal for Review