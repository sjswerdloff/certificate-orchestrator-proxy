#!/bin/bash
#
# Generate certificates for EST Adapter deployment
#
# Creates:
# - Root CA certificate and key (for signing device certificates)
# - Server TLS certificate with VPN IP SAN (for HTTPS)
# - Test client certificate (for mTLS testing)
# - Test CSR (for enrollment demo)
#
# Usage: ./generate-certs.sh <vpn-ip> [output_dir]
#
# Example:
#   ./generate-certs.sh 10.8.0.5
#   ./generate-certs.sh 10.8.0.5 ./data/certs
#

set -e

# =============================================================================
# Arguments
# =============================================================================
VPN_IP="${1:?Usage: $0 <vpn-ip> [output_dir]}"
OUTPUT_DIR="${2:-./data/est-adapter/certs}"
CA_DAYS=3650
CERT_DAYS=365
CA_KEY_SIZE=4096
CERT_KEY_SIZE=2048

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Validate IP format (basic check)
if ! echo "$VPN_IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    log_error "Invalid IP address: $VPN_IP"
    exit 1
fi

# Check for OpenSSL
if ! command -v openssl &> /dev/null; then
    log_error "OpenSSL is not installed."
    exit 1
fi

# Create output directories
mkdir -p "$OUTPUT_DIR/ca"
mkdir -p "$OUTPUT_DIR/tls"
mkdir -p "$OUTPUT_DIR/trust"
mkdir -p "$OUTPUT_DIR/test"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

log_info "Generating certificates for VPN IP: $VPN_IP"
log_info "Output directory: $OUTPUT_DIR"

# =============================================================================
# Root CA
# =============================================================================
log_info "Generating Root CA..."

openssl genrsa -out "$OUTPUT_DIR/ca/ca.key" $CA_KEY_SIZE 2>/dev/null

cat > "$WORK_DIR/ca.cnf" << EOF
[req]
default_bits = $CA_KEY_SIZE
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[dn]
C = US
ST = California
O = EST Adapter Hackathon
OU = Certificate Authority
CN = EST Adapter Hackathon CA

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

openssl req -x509 -new -nodes \
    -key "$OUTPUT_DIR/ca/ca.key" \
    -sha256 \
    -days $CA_DAYS \
    -out "$OUTPUT_DIR/ca/ca.crt" \
    -config "$WORK_DIR/ca.cnf"

chmod 600 "$OUTPUT_DIR/ca/ca.key"

# Copy CA cert to trust directory (for client cert verification)
cp "$OUTPUT_DIR/ca/ca.crt" "$OUTPUT_DIR/trust/ca-trust.pem"

log_info "Root CA created: ca/ca.crt, ca/ca.key"

# =============================================================================
# Server TLS Certificate (with VPN IP SAN)
# =============================================================================
log_info "Generating Server TLS certificate with SAN IP=$VPN_IP..."

openssl genrsa -out "$OUTPUT_DIR/tls/server.key" $CERT_KEY_SIZE 2>/dev/null

cat > "$WORK_DIR/server.cnf" << EOF
[req]
default_bits = $CERT_KEY_SIZE
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = US
ST = California
O = EST Adapter Hackathon
OU = Server
CN = est-adapter

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = est-adapter
IP.1 = 127.0.0.1
IP.2 = ::1
IP.3 = $VPN_IP
EOF

openssl req -new \
    -key "$OUTPUT_DIR/tls/server.key" \
    -out "$WORK_DIR/server.csr" \
    -config "$WORK_DIR/server.cnf"

cat > "$WORK_DIR/server_ext.cnf" << EOF
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = est-adapter
IP.1 = 127.0.0.1
IP.2 = ::1
IP.3 = $VPN_IP
EOF

openssl x509 -req \
    -in "$WORK_DIR/server.csr" \
    -CA "$OUTPUT_DIR/ca/ca.crt" \
    -CAkey "$OUTPUT_DIR/ca/ca.key" \
    -CAcreateserial \
    -out "$OUTPUT_DIR/tls/server.crt" \
    -days $CERT_DAYS \
    -sha256 \
    -extfile "$WORK_DIR/server_ext.cnf"

chmod 600 "$OUTPUT_DIR/tls/server.key"

log_info "Server TLS certificate created: tls/server.crt, tls/server.key"

# =============================================================================
# Test Client Certificate (for mTLS testing)
# =============================================================================
log_info "Generating test client certificate..."

openssl genrsa -out "$OUTPUT_DIR/test/client.key" $CERT_KEY_SIZE 2>/dev/null

cat > "$WORK_DIR/client.cnf" << EOF
[req]
default_bits = $CERT_KEY_SIZE
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C = US
ST = California
O = EST Adapter Hackathon
OU = Test Device
CN = test-device-001
EOF

openssl req -new \
    -key "$OUTPUT_DIR/test/client.key" \
    -out "$WORK_DIR/client.csr" \
    -config "$WORK_DIR/client.cnf"

cat > "$WORK_DIR/client_ext.cnf" << EOF
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req \
    -in "$WORK_DIR/client.csr" \
    -CA "$OUTPUT_DIR/ca/ca.crt" \
    -CAkey "$OUTPUT_DIR/ca/ca.key" \
    -CAcreateserial \
    -out "$OUTPUT_DIR/test/client.crt" \
    -days $CERT_DAYS \
    -sha256 \
    -extfile "$WORK_DIR/client_ext.cnf"

log_info "Test client certificate created: test/client.crt, test/client.key"

# =============================================================================
# Test Enrollment CSR (for demo)
# =============================================================================
log_info "Generating test enrollment CSR..."

openssl genrsa -out "$OUTPUT_DIR/test/enroll-device.key" $CERT_KEY_SIZE 2>/dev/null

cat > "$WORK_DIR/enroll.cnf" << EOF
[req]
default_bits = $CERT_KEY_SIZE
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C = US
ST = California
O = Hospital System
OU = Radiology
CN = CT-Scanner-001
EOF

# PEM CSR (for reference)
openssl req -new \
    -key "$OUTPUT_DIR/test/enroll-device.key" \
    -out "$OUTPUT_DIR/test/enroll-device.csr" \
    -config "$WORK_DIR/enroll.cnf"

# DER CSR (for EST protocol)
openssl req -new \
    -key "$OUTPUT_DIR/test/enroll-device.key" \
    -out "$OUTPUT_DIR/test/enroll-device.der" \
    -config "$WORK_DIR/enroll.cnf" \
    -outform DER

# Base64-encoded DER (what EST actually sends)
base64 -i "$OUTPUT_DIR/test/enroll-device.der" > "$OUTPUT_DIR/test/enroll-device.b64"

log_info "Test enrollment CSR created: test/enroll-device.{csr,der,b64}"

# =============================================================================
# Summary
# =============================================================================
echo ""
log_info "=========================================="
log_info "Certificate generation complete!"
log_info "=========================================="
echo ""
echo "Directory structure:"
echo "  $OUTPUT_DIR/"
echo "  ├── ca/"
echo "  │   ├─�� ca.crt          (CA certificate - distribute to clients)"
echo "  │   └── ca.key          (CA private key - keep secret)"
echo "  ├── tls/"
echo "  │   ├── server.crt      (Server TLS cert, SAN includes $VPN_IP)"
echo "  │   └── server.key      (Server TLS private key)"
echo "  ├── trust/"
echo "  │   └── ca-trust.pem    (Trust anchor for client cert validation)"
echo "  └── test/"
echo "      ├── client.crt      (Test client certificate)"
echo "      ├── client.key      (Test client private key)"
echo "      ├── enroll-device.csr  (Test CSR - PEM)"
echo "      ├── enroll-device.der  (Test CSR - DER)"
echo "      └── enroll-device.b64  (Test CSR - base64, for EST)"
echo ""
echo "Server certificate SANs:"
openssl x509 -in "$OUTPUT_DIR/tls/server.crt" -noout -ext subjectAltName 2>/dev/null || echo "  (could not display SANs)"
echo ""
log_warn "These certificates are for HACKATHON/TESTING use only."
log_warn "Do NOT use in production environments."
