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

## EST Client

The `est_adapter.client` package provides a Python EST client and a YAML-driven CLI for enrolling devices against any RFC 7030 compliant EST server, including the Kryptonian Gateway with its activation-code bootstrap flow.

### Programmatic Usage

```python
from est_adapter.client.est_client import ESTClient, KryptonianDeviceIdentity

# Standard EST enrollment with HTTP Basic auth
with ESTClient(
    "https://est.example.com",
    username="device-operator",
    password="secret",
) as client:
    # Retrieve CA certificates
    ca_certs = client.get_ca_certs()

    # High-level enroll: generates key, builds CSR, submits enrollment
    result = client.enroll(
        "linac-01.radonc.hospital.org",
        key_size=2048,
        organization="Example Hospital Radiation Oncology",
        san_dns_names=["linac-01.local"],
    )

    result.save_certificate_pem("device.cert.pem")
    result.save_private_key_pem("device.key.pem")
    print(f"Issued: {result.certificate.subject}")
```

### Kryptonian Gateway Activation-Code Flow

The Kryptonian Gateway extends EST with a one-time activation-code bootstrap. The admin
registers a device alias in the gateway, which generates an activation code. The device
presents that code along with its identity headers during enrollment.

```python
from est_adapter.client.est_client import ESTClient, KryptonianDeviceIdentity

device_identity = KryptonianDeviceIdentity(
    activation_code="YOUR_ACTIVATION_CODE_HERE",
    manufacturer="Varian",
    model="TrueBeam",
    serial_number="TB-2024-001",
)

with ESTClient("https://kryptonian-gateway.example.com") as client:
    result = client.enroll(
        "linac-01.radonc.hospital.org",
        kryptonian_device=device_identity,
    )
    result.save_certificate_pem("device.cert.pem")
    result.save_private_key_pem("device.key.pem")
```

Internally this adds the headers `X-Activation-Code`, `X-Device-Manufacturer`,
`X-Device-Model`, and `X-Device-Serial-Number` to the enrollment POST.

### YAML CLI

Copy and edit the example config:

```bash
cp enrollment.example.yaml enrollment.yaml
# Edit enrollment.yaml: set server_url, device fields, and kryptonian_activation.activation_code
```

Then run enrollment:

```bash
uv run python -m est_adapter.client.enroll_device enrollment.yaml
# Output files default to ./certs/device.cert.pem and ./certs/device.key.pem

# Specify a different output directory
uv run python -m est_adapter.client.enroll_device enrollment.yaml --output-dir /etc/est/certs
```

Minimal `enrollment.yaml` for Kryptonian activation:

```yaml
server_url: "https://kryptonian-gateway.mangotree-b3d09362.eastus.azurecontainerapps.io"

device:
  common_name: "linac-01.radonc.hospital.org"
  manufacturer: "Varian"
  model: "TrueBeam"
  serial_number: "TB-2024-001"
  organization: "Example Hospital Radiation Oncology"
  key_size: 2048

kryptonian_activation:
  activation_code: "YOUR_ACTIVATION_CODE_HERE"

timeout: 30.0
```

See `enrollment.example.yaml` for the full documented configuration format including
TLS settings and mutual TLS re-enrollment.

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
