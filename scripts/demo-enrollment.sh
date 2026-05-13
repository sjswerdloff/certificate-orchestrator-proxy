#!/bin/bash
#
# Demo: Medical Device Certificate Enrollment Flow (EST Adapter)
#
# Demonstrates the complete EST (RFC 7030) enrollment flow:
# 1. Get CA certificates (cacerts)
# 2. Generate device key pair and CSR
# 3. Enroll for a certificate (simpleenroll)
# 4. Verify the issued certificate
# 5. Re-enroll for renewal (simplereenroll)
#
# Usage: ./demo-enrollment.sh <server-ip> [port] [--non-interactive]
#
# Example:
#   ./demo-enrollment.sh 10.8.0.5
#   ./demo-enrollment.sh 10.8.0.5 8443 --non-interactive
#

set -e

# =============================================================================
# Configuration
# =============================================================================
SERVER_IP="${1:?Usage: $0 <server-ip> [port] [--non-interactive]}"
PORT="${2:-8443}"
BASE_URL="https://$SERVER_IP:$PORT"
USERNAME="${EST_USERNAME:-device1}"
PASSWORD="${EST_PASSWORD:-hackathon2026}"
DEVICE_NAME="${DEVICE_NAME:-CT-Scanner-001}"
DEMO_DIR="./demo-output"
INTERACTIVE=true

# Check for --non-interactive flag
for arg in "$@"; do
    if [ "$arg" = "--non-interactive" ]; then
        INTERACTIVE=false
    fi
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# =============================================================================
# Helper Functions
# =============================================================================
print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_step()    { echo -e "${CYAN}▶ $1${NC}"; }
print_substep() { echo -e "  ${YELLOW}→${NC} $1"; }
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error()   { echo -e "${RED}✗ $1${NC}"; }
print_device()  { echo -e "${BOLD}${GREEN}[DEVICE]${NC} $1"; }
print_hub()     { echo -e "${BOLD}${YELLOW}[HUB]${NC} $1"; }

wait_for_keypress() {
    if [ "$INTERACTIVE" = true ]; then
        echo ""
        echo -e "${BOLD}Press Enter to continue...${NC}"
        read -r
    fi
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_error "$1 is required but not installed."
        exit 1
    fi
}

# =============================================================================
# Prerequisites
# =============================================================================
print_header "Checking Prerequisites"

check_command curl
check_command openssl
print_success "Required tools available"

mkdir -p "$DEMO_DIR"

# =============================================================================
# Step 0: Health Check
# =============================================================================
print_header "Step 0: Verify EST Adapter is Running"

print_step "Checking health at $BASE_URL..."
HEALTH_RESPONSE=$(curl -sk "$BASE_URL/health" 2>/dev/null || echo "FAILED")

if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
    print_success "EST Adapter is healthy!"
    echo "$HEALTH_RESPONSE"
else
    print_error "EST Adapter is not reachable at $BASE_URL"
    echo "Response: $HEALTH_RESPONSE"
    echo ""
    echo "Make sure the adapter is running:"
    echo "  docker compose up -d"
    exit 1
fi

wait_for_keypress

# =============================================================================
# Step 1: Get CA Certificates
# =============================================================================
print_header "Step 1: Device Asks 'Who Will Sign My Certificate?'"

print_device "Requesting CA certificates from EST server..."
print_hub "Returning CA certificate chain (PKCS#7)"

HTTP_CODE=$(curl -sk -w "%{http_code}" \
    "$BASE_URL/.well-known/est/cacerts" \
    -o "$DEMO_DIR/cacerts_response.b64")

if [ "$HTTP_CODE" = "200" ]; then
    print_success "Received CA certificates (HTTP $HTTP_CODE)"

    # Decode base64 → DER → PEM
    base64 -d "$DEMO_DIR/cacerts_response.b64" > "$DEMO_DIR/cacerts.der" 2>/dev/null || \
        cat "$DEMO_DIR/cacerts_response.b64" | tr -d '\r\n' | base64 -d > "$DEMO_DIR/cacerts.der" 2>/dev/null || \
        base64 -D -i "$DEMO_DIR/cacerts_response.b64" -o "$DEMO_DIR/cacerts.der"

    openssl pkcs7 -in "$DEMO_DIR/cacerts.der" -inform DER -print_certs \
        -out "$DEMO_DIR/ca_chain.pem" 2>/dev/null

    echo ""
    echo -e "${BOLD}CA Certificate:${NC}"
    openssl x509 -in "$DEMO_DIR/ca_chain.pem" -noout -subject -issuer -dates 2>/dev/null || \
        echo "  (Could not parse — check response format)"
    print_success "Device now knows which CA to trust!"
else
    print_error "Failed to get CA certificates (HTTP $HTTP_CODE)"
    cat "$DEMO_DIR/cacerts_response.b64"
    exit 1
fi

wait_for_keypress

# =============================================================================
# Step 2: Generate Device Key and CSR
# =============================================================================
print_header "Step 2: Device Generates Key Pair and Certificate Request"

print_device "Generating 2048-bit RSA private key..."
openssl genrsa -out "$DEMO_DIR/device.key" 2048 2>/dev/null
print_success "Private key generated (kept secret on device)"

print_device "Creating Certificate Signing Request (CSR)..."
print_substep "Device identity: CN=$DEVICE_NAME"

openssl req -new \
    -key "$DEMO_DIR/device.key" \
    -out "$DEMO_DIR/device.csr" \
    -subj "/CN=$DEVICE_NAME/O=Hospital-System/OU=Radiology/C=US" \
    2>/dev/null

# Convert to DER then base64 (EST wire format per RFC 7030)
openssl req -in "$DEMO_DIR/device.csr" -outform DER \
    -out "$DEMO_DIR/device.csr.der" 2>/dev/null

base64 -i "$DEMO_DIR/device.csr.der" > "$DEMO_DIR/device.csr.b64" 2>/dev/null || \
    base64 "$DEMO_DIR/device.csr.der" | tr -d '\n' > "$DEMO_DIR/device.csr.b64"

echo ""
echo -e "${BOLD}CSR Contents:${NC}"
openssl req -in "$DEMO_DIR/device.csr" -noout -subject 2>/dev/null

print_success "CSR ready to send to EST server"

wait_for_keypress

# =============================================================================
# Step 3: Simple Enroll
# =============================================================================
print_header "Step 3: Device Requests Certificate (simpleenroll)"

print_device "Sending CSR to EST server with HTTP Basic auth..."
print_hub "Authenticating device..."
print_hub "Validating CSR against policy..."
print_hub "Signing with CA backend..."

echo ""
print_step "POST $BASE_URL/.well-known/est/simpleenroll"

HTTP_CODE=$(curl -sk -w "%{http_code}" -X POST \
    "$BASE_URL/.well-known/est/simpleenroll" \
    -u "$USERNAME:$PASSWORD" \
    -H "Content-Type: application/pkcs10" \
    --data-binary @"$DEMO_DIR/device.csr.b64" \
    -o "$DEMO_DIR/enroll_response.b64")

echo ""
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Certificate issued! (HTTP $HTTP_CODE)"

    # Decode response
    base64 -d "$DEMO_DIR/enroll_response.b64" > "$DEMO_DIR/enroll_response.der" 2>/dev/null || \
        cat "$DEMO_DIR/enroll_response.b64" | tr -d '\r\n' | base64 -d > "$DEMO_DIR/enroll_response.der" 2>/dev/null || \
        base64 -D -i "$DEMO_DIR/enroll_response.b64" -o "$DEMO_DIR/enroll_response.der"

    openssl pkcs7 -in "$DEMO_DIR/enroll_response.der" -inform DER -print_certs \
        -out "$DEMO_DIR/device_cert.pem" 2>/dev/null

    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  ISSUED CERTIFICATE${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    openssl x509 -in "$DEMO_DIR/device_cert.pem" -noout \
        -subject -issuer -dates -serial 2>/dev/null
    echo ""

    # Verify cert was signed by our CA
    print_step "Verifying certificate chain..."
    if openssl verify -CAfile "$DEMO_DIR/ca_chain.pem" "$DEMO_DIR/device_cert.pem" 2>/dev/null; then
        print_success "Certificate chain verified! Device cert was signed by our CA."
    else
        print_error "Chain verification failed"
    fi
else
    print_error "Enrollment failed (HTTP $HTTP_CODE)"
    echo "Response:"
    cat "$DEMO_DIR/enroll_response.b64"
    exit 1
fi

wait_for_keypress

# =============================================================================
# Step 4: Re-enroll (Certificate Renewal)
# =============================================================================
print_header "Step 4: Device Renews Certificate (simplereenroll)"

print_device "Certificate is approaching expiry, requesting renewal..."
print_substep "Using same CSR for simplicity (real devices may rekey)"

HTTP_CODE=$(curl -sk -w "%{http_code}" -X POST \
    "$BASE_URL/.well-known/est/simplereenroll" \
    -u "$USERNAME:$PASSWORD" \
    -H "Content-Type: application/pkcs10" \
    --data-binary @"$DEMO_DIR/device.csr.b64" \
    -o "$DEMO_DIR/reenroll_response.b64")

echo ""
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Renewed certificate issued! (HTTP $HTTP_CODE)"

    base64 -d "$DEMO_DIR/reenroll_response.b64" > "$DEMO_DIR/reenroll_response.der" 2>/dev/null || \
        cat "$DEMO_DIR/reenroll_response.b64" | tr -d '\r\n' | base64 -d > "$DEMO_DIR/reenroll_response.der" 2>/dev/null || \
        base64 -D -i "$DEMO_DIR/reenroll_response.b64" -o "$DEMO_DIR/reenroll_response.der"

    openssl pkcs7 -in "$DEMO_DIR/reenroll_response.der" -inform DER -print_certs \
        -out "$DEMO_DIR/device_cert_renewed.pem" 2>/dev/null

    echo -e "${BOLD}Renewed Certificate:${NC}"
    openssl x509 -in "$DEMO_DIR/device_cert_renewed.pem" -noout \
        -subject -serial -dates 2>/dev/null

    # Show different serial numbers
    echo ""
    SERIAL_1=$(openssl x509 -in "$DEMO_DIR/device_cert.pem" -noout -serial 2>/dev/null)
    SERIAL_2=$(openssl x509 -in "$DEMO_DIR/device_cert_renewed.pem" -noout -serial 2>/dev/null)
    print_substep "Original serial:  $SERIAL_1"
    print_substep "Renewed serial:   $SERIAL_2"

    if [ "$SERIAL_1" != "$SERIAL_2" ]; then
        print_success "Different serial numbers confirm this is a new certificate"
    fi
else
    print_error "Re-enrollment failed (HTTP $HTTP_CODE)"
    cat "$DEMO_DIR/reenroll_response.b64"
fi

wait_for_keypress

# =============================================================================
# Summary
# =============================================================================
print_header "Demo Complete!"

echo -e "${BOLD}What Just Happened:${NC}"
echo ""
echo "  1. Device asked EST server: 'Who will sign my certificates?'"
echo "     → Server returned CA certificate (PKCS#7)"
echo ""
echo "  2. Device generated a key pair and Certificate Signing Request"
echo "     → CSR encoded as base64 DER per RFC 7030"
echo ""
echo "  3. Device submitted CSR to /simpleenroll with HTTP Basic auth"
echo "     → Server validated CSR against policy, signed with CA, returned cert"
echo ""
echo "  4. Device submitted CSR to /simplereenroll for certificate renewal"
echo "     → Server issued a new certificate with different serial number"
echo ""
echo -e "${BOLD}Key Point:${NC} The device used standard EST protocol (RFC 7030)."
echo "           Any EST-capable medical device can enroll this way."
echo ""
echo -e "${BOLD}Files created in $DEMO_DIR/:${NC}"
ls -la "$DEMO_DIR/"
echo ""
