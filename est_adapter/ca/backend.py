"""Certificate Authority backend implementations.

Supports two modes:
- AUTO_GENERATE: Creates a self-signed CA on first run
- PROVIDED: Uses externally-provided CA certificate and key
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from est_adapter.audit.logger import log_ca_initialized, log_certificate_issued
from est_adapter.config import CAConfig, CAMode
from est_adapter.crypto.cert import (
    CertificateSigningKey,
    encode_certificate_pem,
    encode_pkcs7_certs,
    generate_ca_certificate,
    generate_certificate,
)
from est_adapter.exceptions import CABackendError

if TYPE_CHECKING:
    from est_adapter.crypto.csr import CSRInfo


class CABackend(Protocol):
    """Protocol for CA backend implementations."""

    @property
    def ca_certificate(self) -> x509.Certificate:
        """Get the CA certificate."""
        ...

    def sign_csr(
        self,
        csr_info: CSRInfo,
        validity_days: int,
        requestor_identity: str,
    ) -> x509.Certificate:
        """Sign a CSR and return the certificate."""
        ...

    def get_ca_certs_pkcs7(self) -> bytes:
        """Get CA certificate chain as PKCS#7 for /cacerts endpoint."""
        ...


class SelfSignedCABackend:
    """Self-signed CA backend supporting both auto-generate and provided modes."""

    def __init__(
        self,
        ca_cert: x509.Certificate,
        ca_key: CertificateSigningKey,
    ) -> None:
        """Initialize with CA certificate and private key.

        Args:
            ca_cert: CA certificate.
            ca_key: CA private key.
        """
        self._ca_cert = ca_cert
        self._ca_key = ca_key

    @property
    def ca_certificate(self) -> x509.Certificate:
        """Get the CA certificate."""
        return self._ca_cert

    def sign_csr(
        self,
        csr_info: CSRInfo,
        validity_days: int,
        requestor_identity: str,
    ) -> x509.Certificate:
        """Sign a CSR and return the certificate.

        Args:
            csr_info: Parsed CSR information.
            validity_days: Certificate validity period in days.
            requestor_identity: Identity of the requestor for audit.

        Returns:
            Signed X.509 certificate.
        """
        cert = generate_certificate(
            csr=csr_info.csr,
            ca_cert=self._ca_cert,
            ca_key=self._ca_key,
            validity_days=validity_days,
        )

        # Audit log the issuance
        log_certificate_issued(
            subject=csr_info.subject_dn,
            serial_number=cert.serial_number,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            requestor_identity=requestor_identity,
        )

        return cert

    def get_ca_certs_pkcs7(self) -> bytes:
        """Get CA certificate as PKCS#7 for /cacerts endpoint.

        Returns:
            DER-encoded PKCS#7 containing CA certificate.
        """
        return encode_pkcs7_certs([self._ca_cert])


def create_ca_backend(config: CAConfig) -> SelfSignedCABackend:
    """Create CA backend based on configuration.

    Args:
        config: CA configuration.

    Returns:
        Configured CA backend.

    Raises:
        CABackendError: If CA initialization fails.
    """
    if config.mode == CAMode.AUTO_GENERATE:
        return _create_auto_generate_backend(config)
    if config.mode == CAMode.PROVIDED:
        return _create_provided_backend(config)
    # Should never reach here due to enum, but be safe
    msg = f"Unknown CA mode: {config.mode}"
    raise CABackendError(msg)


def _create_auto_generate_backend(config: CAConfig) -> SelfSignedCABackend:
    """Create auto-generate CA backend.

    Generates a new CA or loads existing from storage.
    """
    storage_path = Path(config.auto_generate.storage_path)
    cert_path = storage_path / "ca.crt"
    key_path = storage_path / "ca.key"

    # Check if CA already exists
    if cert_path.exists() and key_path.exists():
        return _load_ca_from_files(cert_path, key_path, mode="auto_generate")

    # Generate new CA
    storage_path.mkdir(parents=True, exist_ok=True)

    # Generate RSA key (4096 bits for CA)
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Generate self-signed CA certificate
    ca_cert = generate_ca_certificate(
        ca_key=ca_key,
        subject=config.auto_generate.subject,
        validity_days=config.auto_generate.validity_days,
    )

    # Save to storage
    _save_ca_to_files(ca_cert, ca_key, cert_path, key_path)

    log_ca_initialized(mode="auto_generate", ca_subject=config.auto_generate.subject)

    return SelfSignedCABackend(ca_cert, ca_key)


def _create_provided_backend(config: CAConfig) -> SelfSignedCABackend:
    """Create provided CA backend from external files."""
    if config.provided is None:
        msg = "Provided CA mode requires 'provided' configuration"
        raise CABackendError(msg)

    return _load_ca_from_files(
        config.provided.cert_file,
        config.provided.key_file,
        mode="provided",
    )


def _load_ca_from_files(
    cert_path: Path,
    key_path: Path,
    mode: str,
) -> SelfSignedCABackend:
    """Load CA certificate and key from files.

    Args:
        cert_path: Path to CA certificate (PEM format).
        key_path: Path to CA private key (PEM format).
        mode: CA mode for logging.

    Returns:
        Configured CA backend.

    Raises:
        CABackendError: If files cannot be loaded.
    """
    try:
        cert_data = cert_path.read_bytes()
        ca_cert = x509.load_pem_x509_certificate(cert_data)
    except FileNotFoundError:
        raise CABackendError.not_initialized() from None
    except Exception as e:
        msg = f"Failed to load CA certificate: {e}"
        raise CABackendError(msg) from e

    try:
        key_data = key_path.read_bytes()
        ca_key = serialization.load_pem_private_key(key_data, password=None)
    except FileNotFoundError:
        raise CABackendError.not_initialized() from None
    except Exception as e:
        msg = f"Failed to load CA private key: {e}"
        raise CABackendError(msg) from e

    # Validate key is a signing key type
    if not isinstance(ca_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        msg = f"Unsupported CA key type: {type(ca_key).__name__}"
        raise CABackendError(msg)

    # Extract subject for logging (RFC4514 format)
    subject_str = ca_cert.subject.rfc4514_string()

    log_ca_initialized(mode=mode, ca_subject=subject_str)

    return SelfSignedCABackend(ca_cert, ca_key)


def _save_ca_to_files(
    ca_cert: x509.Certificate,
    ca_key: CertificateSigningKey,
    cert_path: Path,
    key_path: Path,
) -> None:
    """Save CA certificate and key to files.

    Args:
        ca_cert: CA certificate.
        ca_key: CA private key.
        cert_path: Path to save certificate.
        key_path: Path to save private key.

    Raises:
        CABackendError: If files cannot be saved.
    """
    try:
        cert_pem = encode_certificate_pem(ca_cert)
        cert_path.write_bytes(cert_pem)

        key_pem = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_pem)

        # Set restrictive permissions on key file
        key_path.chmod(0o600)
    except Exception as e:
        msg = f"Failed to save CA files: {e}"
        raise CABackendError(msg) from e
