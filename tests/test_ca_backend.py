"""Contract tests for CA backend module.

Tests CA backend modes: AUTO_GENERATE and PROVIDED.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID

from est_adapter.ca.backend import (
    SelfSignedCABackend,
    create_ca_backend,
)
from est_adapter.config import (
    CAAutoGenerateConfig,
    CAConfig,
    CAMode,
    CAProvidedConfig,
)
from est_adapter.crypto.cert import encode_certificate_pem
from est_adapter.crypto.csr import CSRInfo, parse_csr
from est_adapter.exceptions import CABackendError

# --- Fixtures ---


@pytest.fixture
def ca_key() -> rsa.RSAPrivateKey:
    """CA private key for testing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def ca_certificate(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Self-signed CA certificate for testing."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ],
    )

    # SubjectKeyIdentifier is required for signing certificates
    ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture
def client_csr() -> x509.CertificateSigningRequest:
    """Client CSR for testing certificate signing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com"),
        ],
    )

    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())


@pytest.fixture
def csr_info(client_csr: x509.CertificateSigningRequest) -> CSRInfo:
    """Parsed CSR info for testing."""
    return parse_csr(client_csr.public_bytes(Encoding.PEM))


@pytest.fixture
def temp_ca_storage(tmp_path: Path) -> Path:
    """Temporary CA storage directory."""
    ca_dir = tmp_path / "ca_storage"
    ca_dir.mkdir()
    return ca_dir


@pytest.fixture
def ca_files(
    temp_ca_storage: Path,
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
) -> tuple[Path, Path]:
    """Create CA certificate and key files in temp storage."""
    cert_path = temp_ca_storage / "ca.crt"
    key_path = temp_ca_storage / "ca.key"

    # Write certificate
    cert_pem = encode_certificate_pem(ca_certificate)
    cert_path.write_bytes(cert_pem)

    # Write key
    key_pem = ca_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption(),
    )
    key_path.write_bytes(key_pem)

    return cert_path, key_path


# --- SelfSignedCABackend Tests ---


class TestSelfSignedCABackend:
    """Tests for SelfSignedCABackend class."""

    def test_ca_certificate_property(
        self,
        ca_key: rsa.RSAPrivateKey,
        ca_certificate: x509.Certificate,
    ) -> None:
        """CA certificate property returns the certificate."""
        backend = SelfSignedCABackend(ca_certificate, ca_key)

        assert backend.ca_certificate == ca_certificate

    def test_sign_csr_produces_valid_certificate(
        self,
        ca_key: rsa.RSAPrivateKey,
        ca_certificate: x509.Certificate,
        csr_info: CSRInfo,
    ) -> None:
        """sign_csr produces a valid certificate signed by CA."""
        backend = SelfSignedCABackend(ca_certificate, ca_key)

        with patch("est_adapter.ca.backend.log_certificate_issued"):
            cert = backend.sign_csr(csr_info, validity_days=30, requestor_identity="test")

        assert isinstance(cert, x509.Certificate)
        # Verify subject from CSR
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "client.example.com"
        # Verify issuer is CA
        assert cert.issuer == ca_certificate.subject

    def test_sign_csr_respects_validity_days(
        self,
        ca_key: rsa.RSAPrivateKey,
        ca_certificate: x509.Certificate,
        csr_info: CSRInfo,
    ) -> None:
        """sign_csr creates certificate with specified validity."""
        backend = SelfSignedCABackend(ca_certificate, ca_key)

        with patch("est_adapter.ca.backend.log_certificate_issued"):
            cert = backend.sign_csr(csr_info, validity_days=90, requestor_identity="test")

        # Verify validity is approximately 90 days
        validity = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert 89 <= validity.days <= 91

    def test_sign_csr_logs_audit_event(
        self,
        ca_key: rsa.RSAPrivateKey,
        ca_certificate: x509.Certificate,
        csr_info: CSRInfo,
    ) -> None:
        """sign_csr calls audit logging."""
        backend = SelfSignedCABackend(ca_certificate, ca_key)

        with patch("est_adapter.ca.backend.log_certificate_issued") as mock_log:
            backend.sign_csr(csr_info, validity_days=30, requestor_identity="testuser")

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["requestor_identity"] == "testuser"

    def test_get_ca_certs_pkcs7_returns_der(
        self,
        ca_key: rsa.RSAPrivateKey,
        ca_certificate: x509.Certificate,
    ) -> None:
        """get_ca_certs_pkcs7 returns DER-encoded PKCS#7."""
        backend = SelfSignedCABackend(ca_certificate, ca_key)

        result = backend.get_ca_certs_pkcs7()

        assert isinstance(result, bytes)
        # PKCS#7 DER starts with SEQUENCE tag (0x30)
        assert result[0] == 0x30


# --- create_ca_backend Factory Tests ---


class TestCreateCABackendAutoGenerate:
    """Tests for create_ca_backend with AUTO_GENERATE mode."""

    def test_creates_new_ca_when_storage_empty(
        self,
        temp_ca_storage: Path,
    ) -> None:
        """AUTO_GENERATE creates new CA when storage is empty."""
        config = CAConfig(
            mode=CAMode.AUTO_GENERATE,
            auto_generate=CAAutoGenerateConfig(
                storage_path=temp_ca_storage,
                subject="CN=Test CA,O=Test",
                validity_days=365,
            ),
        )

        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)

        assert backend is not None
        assert isinstance(backend.ca_certificate, x509.Certificate)
        # Verify files were created
        assert (temp_ca_storage / "ca.crt").exists()
        assert (temp_ca_storage / "ca.key").exists()

    def test_loads_existing_ca_from_storage(
        self,
        temp_ca_storage: Path,
        ca_key: rsa.RSAPrivateKey,
        ca_certificate: x509.Certificate,
    ) -> None:
        """AUTO_GENERATE loads existing CA if files exist."""
        # Create existing CA files
        cert_path = temp_ca_storage / "ca.crt"
        key_path = temp_ca_storage / "ca.key"

        cert_pem = encode_certificate_pem(ca_certificate)
        cert_path.write_bytes(cert_pem)

        key_pem = ca_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
        key_path.write_bytes(key_pem)

        config = CAConfig(
            mode=CAMode.AUTO_GENERATE,
            auto_generate=CAAutoGenerateConfig(storage_path=temp_ca_storage),
        )

        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)

        # Verify it loaded the existing cert (same subject)
        assert backend.ca_certificate.subject == ca_certificate.subject

    def test_creates_storage_directory(self, tmp_path: Path) -> None:
        """AUTO_GENERATE creates storage directory if it doesn't exist."""
        storage_path = tmp_path / "new" / "nested" / "ca_storage"
        assert not storage_path.exists()

        config = CAConfig(
            mode=CAMode.AUTO_GENERATE,
            auto_generate=CAAutoGenerateConfig(storage_path=storage_path),
        )

        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)

        assert backend is not None
        assert storage_path.exists()


class TestCreateCABackendProvided:
    """Tests for create_ca_backend with PROVIDED mode."""

    def test_loads_from_provided_files(
        self,
        ca_files: tuple[Path, Path],
    ) -> None:
        """PROVIDED mode loads CA from provided files."""
        cert_path, key_path = ca_files

        config = CAConfig(
            mode=CAMode.PROVIDED,
            provided=CAProvidedConfig(
                cert_file=cert_path,
                key_file=key_path,
            ),
        )

        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)

        assert backend is not None
        assert isinstance(backend.ca_certificate, x509.Certificate)

    def test_raises_error_when_provided_config_missing(self) -> None:
        """PROVIDED mode raises error when provided config is None."""
        config = CAConfig(
            mode=CAMode.PROVIDED,
            provided=None,
        )

        with pytest.raises(CABackendError, match="requires 'provided' configuration"):
            create_ca_backend(config)

    def test_raises_error_when_cert_file_missing(
        self,
        temp_ca_storage: Path,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """PROVIDED mode raises error when cert file doesn't exist."""
        key_path = temp_ca_storage / "ca.key"
        key_pem = ca_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
        key_path.write_bytes(key_pem)

        config = CAConfig(
            mode=CAMode.PROVIDED,
            provided=CAProvidedConfig(
                cert_file=temp_ca_storage / "nonexistent.crt",
                key_file=key_path,
            ),
        )

        with pytest.raises(CABackendError, match="not initialized"):
            create_ca_backend(config)

    def test_raises_error_when_key_file_missing(
        self,
        temp_ca_storage: Path,
        ca_certificate: x509.Certificate,
    ) -> None:
        """PROVIDED mode raises error when key file doesn't exist."""
        cert_path = temp_ca_storage / "ca.crt"
        cert_pem = encode_certificate_pem(ca_certificate)
        cert_path.write_bytes(cert_pem)

        config = CAConfig(
            mode=CAMode.PROVIDED,
            provided=CAProvidedConfig(
                cert_file=cert_path,
                key_file=temp_ca_storage / "nonexistent.key",
            ),
        )

        with pytest.raises(CABackendError, match="not initialized"):
            create_ca_backend(config)

    def test_raises_error_for_invalid_cert_format(
        self,
        temp_ca_storage: Path,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """PROVIDED mode raises error for invalid cert format."""
        cert_path = temp_ca_storage / "ca.crt"
        key_path = temp_ca_storage / "ca.key"

        # Write invalid cert
        cert_path.write_text("not a valid certificate")

        # Write valid key
        key_pem = ca_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
        key_path.write_bytes(key_pem)

        config = CAConfig(
            mode=CAMode.PROVIDED,
            provided=CAProvidedConfig(
                cert_file=cert_path,
                key_file=key_path,
            ),
        )

        with pytest.raises(CABackendError, match="Failed to load CA certificate"):
            create_ca_backend(config)

    def test_raises_error_for_invalid_key_format(
        self,
        temp_ca_storage: Path,
        ca_certificate: x509.Certificate,
    ) -> None:
        """PROVIDED mode raises error for invalid key format."""
        cert_path = temp_ca_storage / "ca.crt"
        key_path = temp_ca_storage / "ca.key"

        # Write valid cert
        cert_pem = encode_certificate_pem(ca_certificate)
        cert_path.write_bytes(cert_pem)

        # Write invalid key
        key_path.write_text("not a valid key")

        config = CAConfig(
            mode=CAMode.PROVIDED,
            provided=CAProvidedConfig(
                cert_file=cert_path,
                key_file=key_path,
            ),
        )

        with pytest.raises(CABackendError, match="Failed to load CA private key"):
            create_ca_backend(config)


# --- File Permission Tests ---


class TestCAFilePermissions:
    """Tests for CA file security."""

    def test_key_file_has_restrictive_permissions(
        self,
        temp_ca_storage: Path,
    ) -> None:
        """AUTO_GENERATE sets restrictive permissions on key file."""
        config = CAConfig(
            mode=CAMode.AUTO_GENERATE,
            auto_generate=CAAutoGenerateConfig(storage_path=temp_ca_storage),
        )

        with patch("est_adapter.ca.backend.log_ca_initialized"):
            create_ca_backend(config)

        key_path = temp_ca_storage / "ca.key"
        # Check permissions (owner read/write only)
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600
