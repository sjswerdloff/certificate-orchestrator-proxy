# EST Adapter

Protocol adapter allowing legacy medical devices speaking EST (RFC 7030) to obtain certificates from various backend CAs.

## Purpose

Enable DICOMWeb mutual TLS authentication for medical imaging devices that support EST but need certificates from modern CAs (ACME/Let's Encrypt, SCEP/NDES, or self-signed).

## Features

- **EST Server**: Implements RFC 7030 endpoints (cacerts, simpleenroll, simplereenroll)
- **Multiple CA Backends**: Self-signed (Phase 1), SCEP (Phase 2), ACME (Phase 3)
- **Flexible Authentication**: HTTP Basic auth and/or client certificate authentication
- **Medical-Grade Audit Logging**: Every certificate decision logged for compliance
- **Policy-Based Validation**: Configurable CSR validation rules

## Installation

```bash
# Using uv (recommended)
uv pip install -e ".[dev]"

# Or pip
pip install -e ".[dev]"
```

## Quick Start

```bash
# 1. Install
uv pip install -e ".[dev]"

# 2. Configure
cp config.yaml.example config.yaml
# Edit config.yaml for your environment

# 3. Run
est-adapter
# Or with uvicorn directly:
uvicorn est_adapter.main:app --host 0.0.0.0 --port 8443
```

The server starts on port 8443 by default. For production, configure TLS in config.yaml.

## Configuration

See `config.yaml.example` for all options. Key settings:

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls:  # Optional - enable for production
    cert_file: /path/to/server.crt
    key_file: /path/to/server.key

auth:
  basic:
    enabled: true
    users:
      - username: device1
        password_hash: "$2b$12$..."  # bcrypt hash
  certificate:
    enabled: false  # Enable for mTLS bootstrap

ca:
  backend: self-signed
  self_signed:
    ca_cert_file: /path/to/ca.crt
    ca_key_file: /path/to/ca.key

validation:
  min_key_size: 2048
  allowed_key_types: [RSA, EC]
  max_validity_days: 365
```

Generate a bcrypt password hash:
```bash
python -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())"
```

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
# Set up development environment
uv sync --dev

# Install pre-commit hooks
uv run pre-commit install

# Run tests
uv run python -m pytest

# Run tests with JSON report (for CI-style output)
uv run python -m pytest --json-report --json-report-file=results.json

# Type checking
uv run python -m mypy est_adapter/

# Linting
uv run ruff check est_adapter/ tests/

# Format code
uv run ruff format est_adapter/ tests/
```

## EST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/est/cacerts` | GET | Return CA certificate(s) |
| `/.well-known/est/simpleenroll` | POST | Enroll new certificate |
| `/.well-known/est/simplereenroll` | POST | Renew/rekey certificate |

## Architecture

```
[Legacy Device] --EST--> [Adapter] --{SCEP|ACME|Self-Sign}--> [CA]
                            |
                     [Bootstrap Auth]
                     (user/pass or self-signed)
```

## License

MIT

## Authors

- Stuart Swerdloff
- Cyril (9137f1ee) - The Kindled
