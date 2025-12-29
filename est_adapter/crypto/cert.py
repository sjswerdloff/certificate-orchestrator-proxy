"""Certificate generation and encoding.

Handles X.509 certificate creation from CSRs and encoding to
various formats (PEM, DER, PKCS#7).
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtensionOID, NameOID

# Type alias for private keys that can sign certificates
# DH and X25519/X448 keys are for key exchange only, not signing
CertificateSigningKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def generate_certificate(
    csr: x509.CertificateSigningRequest,
    ca_cert: x509.Certificate,
    ca_key: CertificateSigningKey,
    validity_days: int = 365,
    serial_number: int | None = None,
) -> x509.Certificate:
    """Generate a certificate from a CSR.

    Args:
        csr: The certificate signing request.
        ca_cert: CA certificate for issuer info.
        ca_key: CA private key for signing.
        validity_days: Certificate validity period in days.
        serial_number: Serial number to use, or None to generate.

    Returns:
        Signed X.509 certificate.
    """
    if serial_number is None:
        serial_number = x509.random_serial_number()

    now = datetime.now(UTC)
    not_before = now
    not_after = now + timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # Add standard end-entity extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # Extended key usage for TLS client/server
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    )

    # Copy Subject Alternative Name from CSR if present
    try:
        san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        builder = builder.add_extension(san.value, critical=san.critical)
    except x509.ExtensionNotFound:
        pass  # No SAN in CSR, that's OK

    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False,
    )

    # Authority Key Identifier
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value,
        ),
        critical=False,
    )

    # Sign with CA key
    return builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )


def generate_ca_certificate(
    ca_key: CertificateSigningKey,
    subject: str,
    validity_days: int = 3650,
) -> x509.Certificate:
    """Generate a self-signed CA certificate.

    Args:
        ca_key: Private key for the CA.
        subject: Subject DN string (e.g., "CN=My CA,O=Org").
        validity_days: Certificate validity period in days.

    Returns:
        Self-signed CA certificate.
    """
    # Parse subject string to X509 Name
    subject_name = _parse_subject_dn(subject)

    now = datetime.now(UTC)
    not_before = now
    not_after = now + timedelta(days=validity_days)

    public_key = ca_key.public_key()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)  # Self-signed
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # CA-specific extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )

    # Sign with own key (self-signed)
    return builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )


def _parse_subject_dn(subject: str) -> x509.Name:
    """Parse subject DN string to X509 Name.

    Args:
        subject: DN string like "CN=example,O=Org".

    Returns:
        X509 Name object.
    """
    oid_map = {
        "CN": NameOID.COMMON_NAME,
        "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "EMAIL": NameOID.EMAIL_ADDRESS,
    }

    attrs = []
    for raw_part in subject.split(","):
        part = raw_part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            key = key.strip().upper()
            value = value.strip()
            if key in oid_map:
                attrs.append(x509.NameAttribute(oid_map[key], value))

    return x509.Name(attrs)


def encode_certificate_pem(cert: x509.Certificate) -> bytes:
    """Encode certificate to PEM format.

    Args:
        cert: Certificate to encode.

    Returns:
        PEM-encoded bytes.
    """
    return cert.public_bytes(serialization.Encoding.PEM)


def encode_certificate_der(cert: x509.Certificate) -> bytes:
    """Encode certificate to DER format.

    Args:
        cert: Certificate to encode.

    Returns:
        DER-encoded bytes.
    """
    return cert.public_bytes(serialization.Encoding.DER)


def encode_pkcs7_certs(certs: list[x509.Certificate]) -> bytes:
    """Encode certificates as PKCS#7 (for EST cacerts response).

    Args:
        certs: List of certificates to encode.

    Returns:
        DER-encoded PKCS#7 structure.
    """
    # Use serialize_certificates for certs-only (degenerate) PKCS#7
    # This function was added in cryptography 37.0.0
    return pkcs7.serialize_certificates(certs, serialization.Encoding.DER)


def encode_pkcs7_certs_base64(certs: list[x509.Certificate]) -> str:
    """Encode certificates as base64 PKCS#7.

    Args:
        certs: List of certificates to encode.

    Returns:
        Base64-encoded PKCS#7 string.
    """
    der = encode_pkcs7_certs(certs)
    return base64.b64encode(der).decode("ascii")
