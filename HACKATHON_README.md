# EST Adapter — Hackathon Quick Start

Certificate enrollment gateway for medical devices using the EST protocol (RFC 7030). Devices speak EST to this adapter; the adapter handles CA backend operations behind the scenes.

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Medical Device │         │   EST Adapter   │         │  CA Backend     │
│  (CT Scanner,   │──EST──► │   (This App)    │────────►│  (Self-Signed,  │
│   MRI, Linac)   │         │                 │         │   ACME, SCEP)   │
└─────────────────┘         └─────────────────┘         └─────────────────┘
     Speaks only EST            Validates, signs,          Device never
     to the adapter             audits, returns cert       touches this
```

## Prerequisites

- Docker (Docker Desktop or Docker Engine)
- OpenSSL (for certificate generation)
- curl (for testing)
- OpenVPN connection to the hackathon network

## Setup (5 minutes)

### 1. Get your VPN IP

Connect to the hackathon OpenVPN and note your assigned IP:

```bash
# macOS
ifconfig utun0 | grep inet

# Linux
ip addr show tun0 | grep inet
```

### 2. Run the setup script

```bash
./scripts/setup-hackathon.sh <your-vpn-ip>
```

This creates a `data/` directory with:

```
data/est-adapter/
├── config.yaml              # Pre-configured for your VPN IP
├── certs/
│   ├── ca/                  # Root CA (signs device certificates)
│   │   ├── ca.crt
│   │   └── ca.key
│   ├── tls/                 # Server TLS (your VPN IP in SAN)
│   │   ├── server.crt
│   │   └── server.key
│   ├── trust/               # Trust anchors for client cert auth
│   │   └── ca-trust.pem
│   └── test/                # Pre-made test CSR and client cert
│       ├── enroll-device.b64
│       ├── enroll-device.csr
│       ├── client.crt
│       └── client.key
├── db/                      # SQLite database (auto-created)
└── logs/                    # Audit trail
```

**Default credentials:** `device1` / `hackathon2026`

### 3. Start the adapter

```bash
docker compose up -d
```

Verify it's running:

```bash
curl -k https://localhost:8443/health
# {"status":"healthy","version":"0.1.0"}
```

### 4. Run the demo

```bash
./scripts/demo-enrollment.sh <your-vpn-ip>
```

This walks through the complete enrollment flow interactively. Add `--non-interactive` to skip pauses.

## The EST Enrollment Flow

### Step 1: Get CA Certificate (`/cacerts`)

The device asks "Who will be signing my certificates?" — no authentication required.

```bash
curl -k https://<your-vpn-ip>:8443/.well-known/est/cacerts
```

Returns the CA certificate as base64 PKCS#7. The device uses this to verify future certificate chains.

### Step 2: Generate CSR

The device generates a key pair and Certificate Signing Request locally. The private key never leaves the device.

```bash
# Generate device key
openssl genrsa -out device.key 2048

# Create CSR
openssl req -new -key device.key -out device.csr \
  -subj "/CN=CT-Scanner-001/O=Hospital/OU=Radiology/C=US"

# Convert to EST wire format (base64 DER)
openssl req -in device.csr -outform DER -out device.der
base64 -i device.der > device.b64
```

### Step 3: Enroll (`/simpleenroll`)

The device submits its CSR with HTTP Basic authentication:

```bash
curl -k -X POST https://<your-vpn-ip>:8443/.well-known/est/simpleenroll \
  -u device1:hackathon2026 \
  -H "Content-Type: application/pkcs10" \
  --data-binary @device.b64
```

Returns a signed certificate as base64 PKCS#7.

### Step 4: Decode the Certificate

```bash
# Save response to file, then decode
base64 -d response.b64 > response.der
openssl pkcs7 -in response.der -inform DER -print_certs -out device_cert.pem
openssl x509 -in device_cert.pem -noout -subject -issuer -dates -serial
```

### Step 5: Renew (`/simplereenroll`)

Same as enroll — the device submits a new CSR to get a fresh certificate:

```bash
curl -k -X POST https://<your-vpn-ip>:8443/.well-known/est/simplereenroll \
  -u device1:hackathon2026 \
  -H "Content-Type: application/pkcs10" \
  --data-binary @device.b64
```

A new certificate is issued with a different serial number.

## Accessing from Other Machines on the VPN

The server TLS certificate includes your VPN IP as a Subject Alternative Name. Other hackathon participants can:

```bash
# Trust your CA (so they don't need -k)
curl --cacert your-ca.crt https://<your-vpn-ip>:8443/.well-known/est/cacerts
```

Distribute your `data/est-adapter/certs/ca/ca.crt` to participants who need to trust your adapter.

## Configuration

All configuration is in `data/est-adapter/config.yaml`. Key sections:

### Authentication

```yaml
auth:
  method: basic          # basic, client_cert, or both
  basic:
    users:
      - username: device1
        password_hash: "$2b$12$..."
```

Generate new password hashes:
```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())"
```

### CSR Validation Policy

```yaml
validation:
  min_key_size: 2048
  allowed_key_types: [RSA, EC]
  allowed_ec_curves: [secp256r1, secp384r1]
  max_validity_days: 365
  required_subject_fields: [CN]
  subject_cn_pattern: "^[a-zA-Z0-9._-]+$"
```

The adapter rejects CSRs that don't meet policy — try submitting a 1024-bit key or a CN with special characters to see validation in action.

### CA Backend

```yaml
ca:
  mode: provided         # or auto_generate
  provided:
    cert_file: /data/est-adapter/certs/ca/ca.crt
    key_file: /data/est-adapter/certs/ca/ca.key
```

`auto_generate` creates a new CA on first run. `provided` uses certs from the setup script.

## EST Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/.well-known/est/cacerts` | GET | None | Get CA certificate chain (PKCS#7) |
| `/.well-known/est/simpleenroll` | POST | Basic | Submit CSR, receive signed certificate |
| `/.well-known/est/simplereenroll` | POST | Basic | Submit CSR for certificate renewal |
| `/health` | GET | None | Health check |

## Architecture

```
est_adapter/
├── main.py              # FastAPI app, startup, health check
├── config.py            # YAML config with Pydantic validation
├── routes/est.py        # EST protocol endpoints (RFC 7030)
├── ca/backend.py        # CA backend (self-signed, extensible)
├── crypto/
│   ├── cert.py          # X.509 certificate generation, PKCS#7 encoding
│   └── csr.py           # CSR parsing (PEM, DER, base64)
├── auth/handler.py      # HTTP Basic + client cert authentication
├── validation/policy.py # CSR policy validation engine
├── audit/logger.py      # Medical-grade audit logging
├── admin/               # Admin REST API (CRUD for backends, profiles)
└── database.py          # SQLAlchemy async (SQLite/PostgreSQL)
```

## Troubleshooting

**Container won't start:**
```bash
docker logs est-adapter
```
Usually a config.yaml path issue. Verify `data/est-adapter/config.yaml` exists and paths point to `/data/est-adapter/...`.

**TLS certificate error (not VPN IP):**
Re-run setup with your current VPN IP:
```bash
rm -rf data/
./scripts/setup-hackathon.sh <new-vpn-ip>
docker compose up -d --build
```

**Authentication fails:**
Check that `config.yaml` has a real bcrypt hash (not `$2b$12$placeholder...`). Re-run `setup-hackathon.sh` or generate a hash manually.

**CSR rejected:**
Check the error message — the adapter validates key size, key type, required fields, and CN pattern. Adjust `validation:` in config.yaml or fix your CSR.

## Stopping

```bash
docker compose down

# To also remove generated data:
rm -rf data/ demo-output/
```

## Real-World Use Case: DIMSE-DICOMWeb Adapter Pairs

In a typical RT or imaging environment, the systems that need certificates aren't the legacy devices themselves — they're the **protocol adapters** that sit between legacy DIMSE equipment and modern DICOMWeb services. The legacy devices remain blissfully unaware of TLS, certificates, or DICOMWeb.

### The Problem

Legacy medical devices (CT scanners, linacs, PACS, treatment planning systems) speak DIMSE — an unencrypted protocol from the 1990s. Moving data between institutions or across network segments requires encryption, but these devices can't be upgraded to speak HTTPS.

### The Solution: Adapter Pairs

Each legacy device gets a local adapter that translates between DIMSE (localhost, unencrypted) and DICOMWeb (network, mTLS-encrypted). The adapters come in pairs — one on each end of the connection:

```
  Device Host A                          Network                    Device Host B
 ┌────────────────────────────┐    (encrypted, mTLS)    ┌────────────────────────────┐
 │                            │                         │                            │
 │  ┌──────────┐  ┌────────┐ │                         │ ┌────────┐  ┌──────────┐   │
 │  │ CT       │  │ dicom- │ │   STOW-RS / HTTPS       │ │ dicom- │  │ PACS     │   │
 │  │ Scanner  ├──► broker ├─┼────────────────────────► ├─► broker ├──► Archive  │   │
 │  │ (DIMSE   │  │        │ │  (cert from EST Adapter) │ │        │  │ (DIMSE   │   │
 │  │  SCU)    │  │ front: │ │                         │ │ front: │  │  SCP)    │   │
 │  └──────────┘  │ dimse  │ │                         │ │ diweb  │  └──────────┘   │
 │     C-STORE    │ back:  │ │                         │ │ back:  │     C-STORE     │
 │   (localhost)  │ diweb  │ │                         │ │ dimse  │   (localhost)   │
 │                └────────┘ │                         │ └────────┘                 │
 └────────────────────────────┘                         └────────────────────────────┘
```

An existing implementation of this adapter pattern is [dicom-broker](https://git.christofschadt.de/IHE-RO-Tooling/dicom-broker) — a Rust application that bidirectionally translates between DIMSE and DICOMWeb with full TLS support on both sides. It can run as a Windows Service, Linux systemd service, or in Docker.

**SCU-side adapter** (sender): The legacy SCU (e.g. CT scanner) is configured to C-STORE to a local AE title — which is actually dicom-broker listening on localhost. The broker translates to STOW-RS over HTTPS using certificates from the EST adapter:

```toml
# SCU-side dicom-broker config (runs on CT scanner host)
# Legacy device C-STOREs to this broker on localhost

[frontend]
mode = "dimse"

[frontend.scp]
ae_title = "CT_PROXY"
host = "127.0.0.1"       # localhost only — no encryption needed
port = 11112

[backend]
mode = "dicom_web"

[dicomweb]
# Outbound: STOW-RS to the receiving broker over mTLS
base_url = "https://10.8.0.20:5136/dicomweb"
tls_ca_cert    = "/certs/ca-trust.pem"          # from EST /cacerts
tls_client_cert = "/certs/adapter.crt"          # from EST /simpleenroll
tls_client_key  = "/certs/adapter.key"
```

**SCP-side adapter** (receiver): Accepts incoming STOW-RS requests over mTLS, then forwards via DIMSE C-STORE to the local legacy SCP (e.g. PACS) on localhost:

```toml
# SCP-side dicom-broker config (runs on PACS host)
# Receives STOW-RS over HTTPS, forwards as C-STORE to local PACS

[frontend]
mode = "dicom_web"
tls_cert = "/certs/adapter.crt"               # from EST /simpleenroll
tls_key  = "/certs/adapter.key"

[frontend.dicomweb]
bind_addr = "0.0.0.0:5136"
path = "/dicomweb"

[backend]
mode = "dimse"

[dimse_client]
host = "127.0.0.1"        # localhost only — the legacy PACS
port = 104
calling_ae_title = "BROKER"
called_ae_title = "PACS_ARCHIVE"
```

The broker also supports a **"both" mode** where it runs DIMSE SCP and DICOMWeb HTTP frontends simultaneously with a shared local archive, enabling it to serve as a full protocol bridge in either direction:

```toml
# Full bridge mode — accepts both DIMSE and DICOMWeb, stores locally
[frontend]
mode = "both"
tls_cert = "/certs/adapter.crt"
tls_key  = "/certs/adapter.key"

[frontend.dicomweb]
bind_addr = "0.0.0.0:5136"

[backend]
mode = "archive"

[archive]
dir = "./dicom-archive"
```

### Where EST Fits In

The EST adapter's real customers are these dicom-broker instances. Each broker needs a certificate to authenticate on the network. The enrollment flow:

1. **Deploy dicom-broker** on the device's host (same machine or same Docker network)
2. **Bootstrap via EST** — call `/cacerts` to get the CA trust anchor, then `/simpleenroll` with a CSR
3. **Configure dicom-broker** with the issued certificate (`tls_cert`, `tls_key`, `tls_ca_cert`, `tls_client_cert`, `tls_client_key`)
4. **Renew via EST** — call `/simplereenroll` before expiry, update the cert files, no manual intervention

```bash
# dicom-broker bootstrap — run once per adapter deployment

# 1. Get CA trust anchor from EST server
curl -k https://est-server:8443/.well-known/est/cacerts \
  | base64 -d | openssl pkcs7 -inform DER -print_certs > /certs/ca-trust.pem

# 2. Generate key and CSR for this adapter
openssl genrsa -out /certs/adapter.key 2048
openssl req -new -key /certs/adapter.key \
  -subj "/CN=ct-scanner-001-broker/O=Hospital/OU=Radiology" \
  -outform DER | base64 > /tmp/adapter.csr.b64

# 3. Enroll via EST
curl -k -X POST https://est-server:8443/.well-known/est/simpleenroll \
  -u ct-scanner-001:enrollmentpassword \
  -H "Content-Type: application/pkcs10" \
  --data-binary @/tmp/adapter.csr.b64 \
  | base64 -d | openssl pkcs7 -inform DER -print_certs > /certs/adapter.crt

# 4. dicom-broker config now references these files:
#    tls_cert        = "/certs/adapter.crt"     (frontend TLS)
#    tls_key         = "/certs/adapter.key"      (frontend TLS)
#    tls_ca_cert     = "/certs/ca-trust.pem"     (backend mTLS verify)
#    tls_client_cert = "/certs/adapter.crt"      (backend mTLS identity)
#    tls_client_key  = "/certs/adapter.key"      (backend mTLS identity)
```

### Why This Architecture Works

- **Legacy devices are untouched** — they just talk DIMSE to a local AE title, same as always
- **Encryption happens at the broker boundary** — all traffic leaving the host is mTLS (HTTPS for DICOMWeb, DICOM-TLS for DIMSE)
- **Certificate lifecycle is automated** — EST handles enrollment and renewal, no manual cert installs across dozens of devices
- **Each broker has its own identity** — audit trails show which broker (and therefore which device) initiated each transfer
- **Brokers can run in Docker** — containerized alongside the legacy application or as a sidecar
- **Bidirectional translation** — dicom-broker supports DIMSE→DICOMWeb, DICOMWeb→DIMSE, and full bridge mode with local archive

### Hackathon Exercise

For the hackathon, you can simulate the complete scenario:

1. Run the EST adapter (this project) as the central certificate authority
2. Enroll two broker identities — one "sender" and one "receiver"
3. Configure two dicom-broker instances with the issued certificates
4. Send a DICOM object via C-STORE to the sender broker, watch it arrive at the receiver over mTLS

```bash
# Enroll "sender" broker (SCU-side, on the CT scanner host)
curl -k -X POST https://<est-ip>:8443/.well-known/est/simpleenroll \
  -u device1:hackathon2026 \
  -H "Content-Type: application/pkcs10" \
  --data-binary @sender-broker.csr.b64 > sender.cert.b64

# Enroll "receiver" broker (SCP-side, on the PACS host)
curl -k -X POST https://<est-ip>:8443/.well-known/est/simpleenroll \
  -u hackathon:hackathon2026 \
  -H "Content-Type: application/pkcs10" \
  --data-binary @receiver-broker.csr.b64 > receiver.cert.b64

# Both certs are signed by the same CA — the brokers trust each other for mTLS
# The sender's [dicomweb] section points to the receiver's HTTPS frontend
# A C-STORE to the sender on localhost becomes STOW-RS over mTLS to the receiver
```

## Comparison with RTSec.Kryptonian

This project and [RTSec.Kryptonian](https://github.com/AAPM-RT-SEC/RTSec.Kryptonian) are two independent implementations of the same use case:

| | EST Adapter (this) | RTSec.Kryptonian |
|---|---|---|
| Language | Python 3.13 | C# / .NET 8 |
| Framework | FastAPI | ASP.NET Core |
| Database | SQLite (async) | PostgreSQL |
| Admin UI | REST API | Blazor (MudBlazor) |
| Config | YAML text file | Environment vars + DB |
| Deployment | Single container | Multi-container (API + DB + Web) |
| CA Backends | Self-signed (SCEP/ACME planned) | Self-signed, ACME |

Both implement the same EST protocol endpoints and can be tested with the same client tooling. The choice demonstrates that the EST adapter pattern works across technology stacks.

## License

MIT
