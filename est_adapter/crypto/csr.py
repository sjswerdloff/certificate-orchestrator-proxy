"""CSR (Certificate Signing Request) parsing and validation.

Handles PKCS#10 CSR parsing, signature verification, and extraction
of key/subject information for policy validation.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from est_adapter.exceptions import CSRValidationError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

# OID to short name mapping for subject fields
OID_SHORT_NAMES = {
    NameOID.COMMON_NAME: "CN",
    NameOID.COUNTRY_NAME: "C",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.LOCALITY_NAME: "L",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.EMAIL_ADDRESS: "EMAIL",
}


@dataclass(frozen=True)
class CSRInfo:
    """Parsed information from a CSR."""

    csr: x509.CertificateSigningRequest
    subject_dn: str
    common_name: str | None
    key_type: str
    key_size: int
    ec_curve: str | None
    subject_fields: dict[str, str]


def parse_csr(csr_data: bytes | str) -> CSRInfo:
    """Parse a PKCS#10 CSR from PEM or DER format.

    Args:
        csr_data: CSR data as bytes (DER or PEM) or base64 string.

    Returns:
        CSRInfo with parsed information.

    Raises:
        CSRValidationError: If CSR cannot be parsed.
    """
    # Handle string input (base64 encoded or PEM)
    if isinstance(csr_data, str):
        try:
            csr_data = csr_data.strip()
            # PEM stays as encoded string, base64 DER gets decoded
            csr_data = csr_data.encode("utf-8") if csr_data.startswith("-----BEGIN") else base64.b64decode(csr_data)
        except Exception as e:
            raise CSRValidationError.invalid_format(reason=str(e)) from e

    # Try parsing as PEM first, then DER
    csr: x509.CertificateSigningRequest
    try:
        if isinstance(csr_data, bytes) and csr_data.startswith(b"-----BEGIN"):
            csr = x509.load_pem_x509_csr(csr_data)
        else:
            csr = x509.load_der_x509_csr(csr_data)
    except Exception as e:
        raise CSRValidationError.invalid_format(reason=str(e)) from e

    # Extract key information
    public_key = csr.public_key()
    key_type, key_size, ec_curve = _extract_key_info(public_key)

    # Extract subject fields
    subject_fields = _extract_subject_fields(csr.subject)
    common_name = subject_fields.get("CN")
    subject_dn = _format_subject_dn(csr.subject)

    return CSRInfo(
        csr=csr,
        subject_dn=subject_dn,
        common_name=common_name,
        key_type=key_type,
        key_size=key_size,
        ec_curve=ec_curve,
        subject_fields=subject_fields,
    )


def verify_csr_signature(csr_info: CSRInfo) -> bool:
    """Verify that the CSR is properly self-signed.

    Args:
        csr_info: Parsed CSR information.

    Returns:
        True if signature is valid.

    Raises:
        CSRValidationError: If signature verification fails.
    """
    try:
        # is_signature_valid property does the verification
        is_valid = csr_info.csr.is_signature_valid
    except Exception as e:
        raise CSRValidationError.invalid_signature() from e
    else:
        if not is_valid:
            raise CSRValidationError.invalid_signature()
        return True


def _extract_key_info(public_key: PublicKeyTypes) -> tuple[str, int, str | None]:
    """Extract key type, size, and curve from public key.

    Args:
        public_key: The public key from the CSR.

    Returns:
        Tuple of (key_type, key_size, ec_curve or None).
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        # EC key "size" is typically represented by curve bit size
        key_size = public_key.curve.key_size
        return "EC", key_size, curve_name
    # Unknown key type - let validation catch it
    return "UNKNOWN", 0, None


def _extract_subject_fields(subject: x509.Name) -> dict[str, str]:
    """Extract subject fields as dictionary.

    Args:
        subject: X509 Name object.

    Returns:
        Dictionary mapping field short names to values.
    """
    fields: dict[str, str] = {}
    for attr in subject:
        short_name = OID_SHORT_NAMES.get(attr.oid)
        if short_name:
            value = attr.value
            if isinstance(value, str):
                fields[short_name] = value
            elif isinstance(value, bytes):
                fields[short_name] = value.decode("utf-8", errors="replace")
    return fields


def _format_subject_dn(subject: x509.Name) -> str:
    """Format subject as DN string.

    Args:
        subject: X509 Name object.

    Returns:
        DN string like "CN=example,O=Org".
    """
    parts = []
    for attr in subject:
        short_name = OID_SHORT_NAMES.get(attr.oid)
        if short_name:
            value = attr.value
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            parts.append(f"{short_name}={value}")
    return ",".join(parts)


def encode_csr_der(csr: x509.CertificateSigningRequest) -> bytes:
    """Encode CSR to DER format.

    Args:
        csr: The CSR to encode.

    Returns:
        DER-encoded bytes.
    """
    return csr.public_bytes(Encoding.DER)


def encode_csr_pem(csr: x509.CertificateSigningRequest) -> bytes:
    """Encode CSR to PEM format.

    Args:
        csr: The CSR to encode.

    Returns:
        PEM-encoded bytes.
    """
    return csr.public_bytes(Encoding.PEM)
