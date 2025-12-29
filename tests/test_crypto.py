"""Contract tests for crypto module.

Tests CSR parsing, signature verification, and certificate generation.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from est_adapter.crypto.cert import (
    encode_certificate_der,
    encode_certificate_pem,
    encode_pkcs7_certs,
    encode_pkcs7_certs_base64,
    generate_ca_certificate,
    generate_certificate,
)
from est_adapter.crypto.csr import (
    CSRInfo,
    encode_csr_der,
    encode_csr_pem,
    parse_csr,
    verify_csr_signature,
)
from est_adapter.exceptions import CSRValidationError

if TYPE_CHECKING:
    pass


# --- Fixtures ---


@pytest.fixture
def rsa_key() -> rsa.RSAPrivateKey:
    """Generate an RSA private key for testing."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


@pytest.fixture
def ec_key() -> ec.EllipticCurvePrivateKey:
    """Generate an EC private key for testing."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def rsa_csr(rsa_key: rsa.RSAPrivateKey) -> x509.CertificateSigningRequest:
    """Generate an RSA CSR for testing."""
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            ])
        )
        .sign(rsa_key, hashes.SHA256())
    )


@pytest.fixture
def ec_csr(ec_key: ec.EllipticCurvePrivateKey) -> x509.CertificateSigningRequest:
    """Generate an EC CSR for testing."""
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "ec-test.example.com"),
            ])
        )
        .sign(ec_key, hashes.SHA256())
    )


@pytest.fixture
def ca_key() -> rsa.RSAPrivateKey:
    """Generate a CA private key for testing."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )


@pytest.fixture
def ca_certificate(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Generate a CA certificate for testing."""
    return generate_ca_certificate(
        ca_key=ca_key,
        subject="CN=Test CA,O=Test Organization",
        validity_days=365,
    )


# --- CSR Parsing Tests ---


class TestCSRParsing:
    """Tests for CSR parsing functionality."""

    def test_parse_pem_csr(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """Parse CSR from PEM format."""
        pem_data = rsa_csr.public_bytes(Encoding.PEM)

        result = parse_csr(pem_data)

        assert isinstance(result, CSRInfo)
        assert result.key_type == "RSA"
        assert result.key_size == 2048
        assert result.common_name == "test.example.com"
        assert "CN=test.example.com" in result.subject_dn
        assert result.subject_fields["CN"] == "test.example.com"
        assert result.subject_fields["O"] == "Test Org"

    def test_parse_der_csr(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """Parse CSR from DER format."""
        der_data = rsa_csr.public_bytes(Encoding.DER)

        result = parse_csr(der_data)

        assert result.key_type == "RSA"
        assert result.common_name == "test.example.com"

    def test_parse_base64_csr(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """Parse CSR from base64-encoded DER string."""
        der_data = rsa_csr.public_bytes(Encoding.DER)
        base64_str = base64.b64encode(der_data).decode("ascii")

        result = parse_csr(base64_str)

        assert result.key_type == "RSA"
        assert result.common_name == "test.example.com"

    def test_parse_pem_string(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """Parse CSR from PEM string (not bytes)."""
        pem_str = rsa_csr.public_bytes(Encoding.PEM).decode("utf-8")

        result = parse_csr(pem_str)

        assert result.key_type == "RSA"

    def test_parse_ec_csr(self, ec_csr: x509.CertificateSigningRequest) -> None:
        """Parse EC CSR and verify curve information."""
        pem_data = ec_csr.public_bytes(Encoding.PEM)

        result = parse_csr(pem_data)

        assert result.key_type == "EC"
        assert result.key_size == 256
        assert result.ec_curve == "secp256r1"

    def test_parse_invalid_data_raises_error(self) -> None:
        """Parsing invalid data raises CSRValidationError."""
        with pytest.raises(CSRValidationError) as exc_info:
            parse_csr(b"not a valid CSR")

        assert "Invalid CSR format" in str(exc_info.value)

    def test_parse_empty_data_raises_error(self) -> None:
        """Parsing empty data raises CSRValidationError."""
        with pytest.raises(CSRValidationError):
            parse_csr(b"")

    def test_parse_invalid_base64_raises_error(self) -> None:
        """Parsing invalid base64 string raises CSRValidationError."""
        with pytest.raises(CSRValidationError):
            parse_csr("not-valid-base64!!!")


# --- CSR Signature Verification Tests ---


class TestCSRSignatureVerification:
    """Tests for CSR signature verification."""

    def test_verify_valid_signature(
        self, rsa_csr: x509.CertificateSigningRequest
    ) -> None:
        """Valid CSR signature verifies successfully."""
        csr_info = parse_csr(rsa_csr.public_bytes(Encoding.PEM))

        result = verify_csr_signature(csr_info)

        assert result is True

    def test_verify_ec_signature(
        self, ec_csr: x509.CertificateSigningRequest
    ) -> None:
        """EC CSR signature verifies successfully."""
        csr_info = parse_csr(ec_csr.public_bytes(Encoding.PEM))

        result = verify_csr_signature(csr_info)

        assert result is True


# --- CSR Encoding Tests ---


class TestCSREncoding:
    """Tests for CSR encoding functions."""

    def test_encode_csr_der(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """Encode CSR to DER format."""
        result = encode_csr_der(rsa_csr)

        assert isinstance(result, bytes)
        # DER doesn't have PEM headers
        assert not result.startswith(b"-----BEGIN")

    def test_encode_csr_pem(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """Encode CSR to PEM format."""
        result = encode_csr_pem(rsa_csr)

        assert isinstance(result, bytes)
        assert result.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")


# --- Certificate Generation Tests ---


class TestCertificateGeneration:
    """Tests for certificate generation from CSRs."""

    def test_generate_certificate_from_rsa_csr(
        self,
        rsa_csr: x509.CertificateSigningRequest,
        ca_certificate: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """Generate certificate from RSA CSR."""
        cert = generate_certificate(
            csr=rsa_csr,
            ca_cert=ca_certificate,
            ca_key=ca_key,
            validity_days=365,
        )

        assert isinstance(cert, x509.Certificate)
        assert cert.subject == rsa_csr.subject
        assert cert.issuer == ca_certificate.subject

    def test_generate_certificate_from_ec_csr(
        self,
        ec_csr: x509.CertificateSigningRequest,
        ca_certificate: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """Generate certificate from EC CSR."""
        cert = generate_certificate(
            csr=ec_csr,
            ca_cert=ca_certificate,
            ca_key=ca_key,
            validity_days=90,
        )

        assert isinstance(cert, x509.Certificate)
        assert cert.subject == ec_csr.subject

    def test_certificate_has_basic_constraints(
        self,
        rsa_csr: x509.CertificateSigningRequest,
        ca_certificate: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """Generated certificate has BasicConstraints extension."""
        cert = generate_certificate(
            csr=rsa_csr,
            ca_cert=ca_certificate,
            ca_key=ca_key,
        )

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_certificate_has_key_usage(
        self,
        rsa_csr: x509.CertificateSigningRequest,
        ca_certificate: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """Generated certificate has KeyUsage extension."""
        cert = generate_certificate(
            csr=rsa_csr,
            ca_cert=ca_certificate,
            ca_key=ca_key,
        )

        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True
        assert ku.value.key_encipherment is True

    def test_certificate_with_custom_serial(
        self,
        rsa_csr: x509.CertificateSigningRequest,
        ca_certificate: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """Generate certificate with custom serial number."""
        custom_serial = 123456789

        cert = generate_certificate(
            csr=rsa_csr,
            ca_cert=ca_certificate,
            ca_key=ca_key,
            serial_number=custom_serial,
        )

        assert cert.serial_number == custom_serial


# --- CA Certificate Generation Tests ---


class TestCACertificateGeneration:
    """Tests for CA certificate generation."""

    def test_generate_ca_certificate(self, ca_key: rsa.RSAPrivateKey) -> None:
        """Generate self-signed CA certificate."""
        cert = generate_ca_certificate(
            ca_key=ca_key,
            subject="CN=Test CA,O=Test Org",
            validity_days=365,
        )

        assert isinstance(cert, x509.Certificate)
        # Self-signed: subject == issuer
        assert cert.subject == cert.issuer

    def test_ca_has_basic_constraints(self, ca_key: rsa.RSAPrivateKey) -> None:
        """CA certificate has proper BasicConstraints."""
        cert = generate_ca_certificate(
            ca_key=ca_key,
            subject="CN=Test CA",
        )

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.critical is True

    def test_ca_has_key_usage(self, ca_key: rsa.RSAPrivateKey) -> None:
        """CA certificate has proper KeyUsage."""
        cert = generate_ca_certificate(
            ca_key=ca_key,
            subject="CN=Test CA",
        )

        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True

    def test_ca_with_ec_key(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        """Generate CA certificate with EC key."""
        cert = generate_ca_certificate(
            ca_key=ec_key,
            subject="CN=EC CA",
        )

        assert isinstance(cert, x509.Certificate)


# --- Certificate Encoding Tests ---


class TestCertificateEncoding:
    """Tests for certificate encoding functions."""

    def test_encode_pem(self, ca_certificate: x509.Certificate) -> None:
        """Encode certificate to PEM."""
        result = encode_certificate_pem(ca_certificate)

        assert isinstance(result, bytes)
        assert result.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_encode_der(self, ca_certificate: x509.Certificate) -> None:
        """Encode certificate to DER."""
        result = encode_certificate_der(ca_certificate)

        assert isinstance(result, bytes)
        assert not result.startswith(b"-----BEGIN")

    def test_encode_pkcs7(self, ca_certificate: x509.Certificate) -> None:
        """Encode certificate to PKCS#7."""
        result = encode_pkcs7_certs([ca_certificate])

        assert isinstance(result, bytes)
        # DER-encoded PKCS#7

    def test_encode_pkcs7_base64(self, ca_certificate: x509.Certificate) -> None:
        """Encode certificate to base64 PKCS#7."""
        result = encode_pkcs7_certs_base64([ca_certificate])

        assert isinstance(result, str)
        # Should be valid base64
        decoded = base64.b64decode(result)
        assert len(decoded) > 0

    def test_encode_pkcs7_multiple_certs(
        self,
        ca_certificate: x509.Certificate,
        rsa_csr: x509.CertificateSigningRequest,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """Encode multiple certificates to PKCS#7."""
        end_cert = generate_certificate(
            csr=rsa_csr,
            ca_cert=ca_certificate,
            ca_key=ca_key,
        )

        result = encode_pkcs7_certs([ca_certificate, end_cert])

        assert isinstance(result, bytes)
