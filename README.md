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

## Configuration

```bash
cp config.yaml.example config.yaml
# Edit config.yaml for your environment
```

## Development

```bash
# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Type checking
mypy est_adapter/

# Linting
ruff check est_adapter/ tests/
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
