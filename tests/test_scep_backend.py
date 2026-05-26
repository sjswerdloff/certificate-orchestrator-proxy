"""Contract tests for SCEPCABackend.

Tests Protocol compliance, ca_certificate property (lazy fetch), sign_csr flow
with mocked SCEPClient, get_ca_certs_pkcs7, error handling, and the factory
function.  All external dependencies (SCEPClient, audit loggers) are mocked
so no real network calls are made.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from est_adapter.ca.backend import SCEPCABackend, SelfSignedCABackend, create_ca_backend
from est_adapter.config import CAConfig, CAMode, SCEPConfig
from est_adapter.crypto.cert import encode_certificate_pem
from est_adapter.crypto.csr import CSRInfo, parse_csr
from est_adapter.exceptions import CABackendError

# ---------------------------------------------------------------------------
# Shared certificate helpers
# ---------------------------------------------------------------------------


def _make_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA key for tests."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _make_ec_key() -> ec.EllipticCurvePrivateKey:
    """Generate an EC P-256 key for tests."""
    return ec.generate_private_key(ec.SECP256R1())


def _make_ca_cert(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """Build a minimal self-signed CA certificate for testing."""
    now = datetime.now(UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SCEP CA")])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )


def _make_leaf_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    cn: str = "device.example.com",
) -> x509.Certificate:
    """Build a minimal leaf certificate signed by the given CA."""
    now = datetime.now(UTC)
    leaf_key = _make_rsa_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ski = x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key())
    ca_ski_ext = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski_ext.value),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


def _make_csr_info(cn: str = "device.example.com") -> CSRInfo:
    """Build a CSRInfo for the given CN."""
    key = _make_rsa_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    return parse_csr(csr.public_bytes(Encoding.PEM))


def _make_scep_config(**overrides: object) -> SCEPConfig:
    """Create a minimal SCEPConfig for testing."""
    kwargs: dict[str, object] = {
        "scep_url": "https://ca.example.com/scep/scep",
        "challenge_password": "test-secret",
        "verify_tls": False,
    }
    kwargs.update(overrides)
    return SCEPConfig(**kwargs)


def _build_mock_scep_client(
    ca_cert: x509.Certificate,
    leaf_cert: x509.Certificate,
) -> MagicMock:
    """Build a MagicMock SCEPClient that simulates a successful enrollment.

    Mocks both get_ca_cert (singular — convenience wrapper) and get_ca_certs
    (plural — returns a 2-tuple of (ca_cert, encryption_cert)) because
    SCEPCABackend._fetch_ca_cert calls get_ca_certs to discover the
    encryption/RA cert.

    Args:
        ca_cert: CA certificate returned by get_ca_cert / get_ca_certs.
        leaf_cert: Leaf certificate returned by enroll.

    Returns:
        A MagicMock configured as a context manager.
    """
    mock = MagicMock()
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=None)
    mock.get_ca_cert = MagicMock(return_value=ca_cert)
    # get_ca_certs returns (ca_cert, encryption_cert); None = no separate RA cert
    mock.get_ca_certs = MagicMock(return_value=(ca_cert, None))
    mock.enroll = MagicMock(return_value=leaf_cert)
    return mock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ca_key() -> rsa.RSAPrivateKey:
    """CA RSA private key."""
    return _make_rsa_key()


@pytest.fixture
def ca_cert(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Self-signed CA certificate for tests."""
    return _make_ca_cert(ca_key)


@pytest.fixture
def scep_config() -> SCEPConfig:
    """Minimal SCEPConfig for tests."""
    return _make_scep_config()


@pytest.fixture
def backend(scep_config: SCEPConfig) -> SCEPCABackend:
    """SCEPCABackend without a pre-loaded CA cert."""
    return SCEPCABackend(scep_config)


@pytest.fixture
def backend_with_ca(scep_config: SCEPConfig, ca_cert: x509.Certificate) -> SCEPCABackend:
    """SCEPCABackend pre-loaded with a CA certificate."""
    return SCEPCABackend(scep_config, ca_cert=ca_cert)


@pytest.fixture
def csr_info() -> CSRInfo:
    """Parsed CSR for signing tests."""
    return _make_csr_info()


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------


class TestSCEPCABackendProtocolCompliance:
    """Verify SCEPCABackend satisfies the CABackend Protocol surface."""

    def test_has_ca_certificate_property(
        self,
        backend: SCEPCABackend,
        ca_cert: x509.Certificate,
    ) -> None:
        """ca_certificate property is accessible and returns an x509.Certificate."""
        mock_client = _build_mock_scep_client(ca_cert, MagicMock())
        with patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client):
            result = backend.ca_certificate
        assert isinstance(result, x509.Certificate)

    def test_has_sign_csr_method(self, backend: SCEPCABackend) -> None:
        """sign_csr method exists and is callable."""
        assert callable(backend.sign_csr)

    def test_has_get_ca_certs_pkcs7_method(self, backend: SCEPCABackend) -> None:
        """get_ca_certs_pkcs7 method exists and is callable."""
        assert callable(backend.get_ca_certs_pkcs7)


# ---------------------------------------------------------------------------
# Ephemeral key generation
# ---------------------------------------------------------------------------


class TestEphemeralKeyGeneration:
    """Tests for the ephemeral RSA key generation on init."""

    def test_generates_rsa_key(self, backend: SCEPCABackend) -> None:
        """SCEPCABackend generates an RSA key on init."""
        assert isinstance(backend._signing_key, rsa.RSAPrivateKey)

    def test_key_is_2048_bits(self, backend: SCEPCABackend) -> None:
        """The ephemeral signing key is RSA-2048."""
        assert backend._signing_key.key_size == 2048

    def test_each_backend_has_unique_key(self, scep_config: SCEPConfig) -> None:
        """Each SCEPCABackend instance generates its own unique key."""
        b1 = SCEPCABackend(scep_config)
        b2 = SCEPCABackend(scep_config)
        pub1 = b1._signing_key.public_key().public_numbers()
        pub2 = b2._signing_key.public_key().public_numbers()
        assert pub1.n != pub2.n


# ---------------------------------------------------------------------------
# ca_certificate property (lazy fetch)
# ---------------------------------------------------------------------------


class TestCaCertificateProperty:
    """Tests for the ca_certificate property."""

    def test_returns_pre_loaded_cert(
        self,
        backend_with_ca: SCEPCABackend,
        ca_cert: x509.Certificate,
    ) -> None:
        """ca_certificate returns the pre-loaded cert value.

        When _ca_cert is pre-loaded but _encryption_cert is None, the backend
        makes a GetCACert call to discover the RA/encryption cert.  We patch
        SCEPClient to avoid a real network call and verify the returned cert
        is the pre-loaded one.
        """
        mock_client = _build_mock_scep_client(ca_cert, MagicMock())
        with patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client):
            result = backend_with_ca.ca_certificate

        assert result.serial_number == ca_cert.serial_number

    def test_fetches_cert_when_none(
        self,
        backend: SCEPCABackend,
        ca_cert: x509.Certificate,
    ) -> None:
        """ca_certificate calls GetCACert when no cert is pre-loaded."""
        mock_client = _build_mock_scep_client(ca_cert, MagicMock())

        with patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client):
            result = backend.ca_certificate

        # _fetch_ca_cert calls get_ca_certs (returns tuple of ca_cert + encryption_cert)
        mock_client.get_ca_certs.assert_called_once()
        assert result.serial_number == ca_cert.serial_number

    def test_caches_fetched_cert(
        self,
        backend: SCEPCABackend,
        ca_cert: x509.Certificate,
    ) -> None:
        """Once both ca_cert and encryption_cert are fetched, no more GetCACert calls."""
        # When get_ca_certs returns a real encryption cert, _encryption_cert is set
        # and subsequent accesses to ca_certificate skip the network call.
        encryption_key = _make_rsa_key()
        encryption_cert = _make_ca_cert(encryption_key)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get_ca_certs = MagicMock(return_value=(ca_cert, encryption_cert))
        mock_client.enroll = MagicMock(return_value=MagicMock())

        with patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client):
            _ = backend.ca_certificate
            _ = backend.ca_certificate  # second access

        # get_ca_certs called once; after that both _ca_cert and _encryption_cert are set
        assert mock_client.get_ca_certs.call_count == 1

    def test_propagates_get_ca_cert_error(self, backend: SCEPCABackend) -> None:
        """ca_certificate propagates CABackendError from GetCACert."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get_ca_certs.side_effect = CABackendError.scep_connection_error(reason="refused")

        with (
            patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client),
            pytest.raises(CABackendError, match="SCEP connection error"),
        ):
            _ = backend.ca_certificate


# ---------------------------------------------------------------------------
# get_ca_certs_pkcs7
# ---------------------------------------------------------------------------


class TestGetCaCertsPkcs7:
    """Tests for get_ca_certs_pkcs7."""

    def test_returns_der_bytes(
        self,
        backend_with_ca: SCEPCABackend,
        ca_cert: x509.Certificate,
    ) -> None:
        """get_ca_certs_pkcs7 returns bytes starting with DER SEQUENCE tag."""
        # backend_with_ca has a pre-loaded CA cert but _encryption_cert is None,
        # so ca_certificate will try to discover the encryption cert via GetCACert.
        mock_client = _build_mock_scep_client(ca_cert, MagicMock())
        with patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client):
            result = backend_with_ca.get_ca_certs_pkcs7()
        assert isinstance(result, bytes)
        assert result[0] == 0x30

    def test_fetches_cert_if_none_cached(
        self,
        backend: SCEPCABackend,
        ca_cert: x509.Certificate,
    ) -> None:
        """get_ca_certs_pkcs7 calls GetCACert if no cert is cached."""
        mock_client = _build_mock_scep_client(ca_cert, MagicMock())

        with patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client):
            result = backend.get_ca_certs_pkcs7()

        # _fetch_ca_cert calls get_ca_certs (returns tuple) not get_ca_cert
        mock_client.get_ca_certs.assert_called_once()
        assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# sign_csr — mocked SCEPClient
# ---------------------------------------------------------------------------


class TestSignCsr:
    """Tests for the sign_csr method."""

    def test_returns_x509_certificate(
        self,
        backend_with_ca: SCEPCABackend,
        csr_info: CSRInfo,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """sign_csr returns an x509.Certificate."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_scep_client(ca_cert, leaf_cert)

        with (
            patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            result = backend_with_ca.sign_csr(csr_info, validity_days=90, requestor_identity="test-device")

        assert isinstance(result, x509.Certificate)
        assert result.serial_number == leaf_cert.serial_number

    def test_passes_csr_der_to_enroll(
        self,
        backend_with_ca: SCEPCABackend,
        csr_info: CSRInfo,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """sign_csr passes DER-encoded CSR bytes to SCEPClient.enroll."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_scep_client(ca_cert, leaf_cert)

        with (
            patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            backend_with_ca.sign_csr(csr_info, validity_days=90, requestor_identity="test")

        call_kwargs = mock_client.enroll.call_args.kwargs
        # CSR DER should match the CSRInfo's DER
        expected_der = csr_info.csr.public_bytes(serialization.Encoding.DER)
        assert call_kwargs["csr_der"] == expected_der

    def test_passes_challenge_password_to_enroll(
        self,
        csr_info: CSRInfo,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """sign_csr passes the configured challenge password to enroll."""
        config = _make_scep_config(challenge_password="my-secret-pw")
        backend = SCEPCABackend(config, ca_cert=ca_cert)
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_scep_client(ca_cert, leaf_cert)

        with (
            patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            backend.sign_csr(csr_info, validity_days=90, requestor_identity="test")

        call_kwargs = mock_client.enroll.call_args.kwargs
        assert call_kwargs["challenge_password"] == "my-secret-pw"

    def test_passes_ca_cert_to_enroll(
        self,
        backend_with_ca: SCEPCABackend,
        csr_info: CSRInfo,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """sign_csr passes the CA cert to enroll as the encryption recipient."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_scep_client(ca_cert, leaf_cert)

        with (
            patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            backend_with_ca.sign_csr(csr_info, validity_days=90, requestor_identity="test")

        call_kwargs = mock_client.enroll.call_args.kwargs
        assert call_kwargs["ca_cert"].serial_number == ca_cert.serial_number

    def test_calls_audit_log_with_requestor_identity(
        self,
        backend_with_ca: SCEPCABackend,
        csr_info: CSRInfo,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """sign_csr calls log_certificate_issued with requestor_identity."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_scep_client(ca_cert, leaf_cert)

        with (
            patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued") as mock_log,
        ):
            backend_with_ca.sign_csr(csr_info, validity_days=90, requestor_identity="nurse-station-3")

        mock_log.assert_called_once()
        assert mock_log.call_args.kwargs["requestor_identity"] == "nurse-station-3"

    def test_raises_when_enroll_fails(
        self,
        backend_with_ca: SCEPCABackend,
        csr_info: CSRInfo,
        ca_cert: x509.Certificate,
    ) -> None:
        """sign_csr propagates CABackendError from SCEPClient.enroll."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        # get_ca_certs must return a valid 2-tuple (backend calls it to discover RA cert)
        mock_client.get_ca_certs = MagicMock(return_value=(ca_cert, None))
        mock_client.enroll.side_effect = CABackendError.scep_enrollment_failed(reason="bad challenge")

        with (
            patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client),
            pytest.raises(CABackendError, match="SCEP enrollment failed"),
        ):
            backend_with_ca.sign_csr(csr_info, validity_days=90, requestor_identity="test")

    def test_fetches_ca_cert_when_not_pre_loaded(
        self,
        backend: SCEPCABackend,
        csr_info: CSRInfo,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """sign_csr fetches the CA cert via GetCACert when not pre-loaded."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_scep_client(ca_cert, leaf_cert)

        with (
            patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            backend.sign_csr(csr_info, validity_days=90, requestor_identity="test")

        # get_ca_certs should have been called to fetch the cert + discover encryption cert
        mock_client.get_ca_certs.assert_called()

    def test_validity_days_accepted_but_not_forwarded(
        self,
        backend_with_ca: SCEPCABackend,
        csr_info: CSRInfo,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """sign_csr accepts validity_days for Protocol compat but doesn't forward it."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_scep_client(ca_cert, leaf_cert)

        with (
            patch("est_adapter.ca.backend.SCEPClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            # Should not raise for any validity_days value
            result = backend_with_ca.sign_csr(csr_info, validity_days=365, requestor_identity="test")

        assert isinstance(result, x509.Certificate)
        # enroll should not have received validity_days
        call_kwargs = mock_client.enroll.call_args.kwargs
        assert "validity_days" not in call_kwargs


# ---------------------------------------------------------------------------
# Factory function — create_ca_backend with SCEP mode
# ---------------------------------------------------------------------------


class TestCreateCABackendScep:
    """Tests for the create_ca_backend factory with CAMode.SCEP."""

    def test_creates_scep_backend_when_mode_is_scep(self) -> None:
        """create_ca_backend returns SCEPCABackend when mode is SCEP."""
        scep_cfg = _make_scep_config()
        config = CAConfig(mode=CAMode.SCEP, scep=scep_cfg)

        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)

        assert isinstance(backend, SCEPCABackend)

    def test_raises_when_scep_config_missing(self) -> None:
        """create_ca_backend raises CABackendError when scep config is None."""
        config = CAConfig(mode=CAMode.SCEP, scep=None)

        with pytest.raises(CABackendError, match="requires 'scep' configuration"):
            create_ca_backend(config)

    def test_loads_ca_cert_from_file_when_provided(
        self,
        tmp_path: Path,
        ca_cert: x509.Certificate,
    ) -> None:
        """create_ca_backend pre-loads ca_cert when ca_cert_file is configured."""
        cert_file = tmp_path / "ca.pem"
        cert_file.write_bytes(encode_certificate_pem(ca_cert))

        scep_cfg = _make_scep_config(ca_cert_file=cert_file)
        config = CAConfig(mode=CAMode.SCEP, scep=scep_cfg)

        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)

        assert isinstance(backend, SCEPCABackend)
        assert backend._ca_cert is not None
        assert backend._ca_cert.serial_number == ca_cert.serial_number

    def test_ca_cert_is_none_when_no_file_provided(self) -> None:
        """create_ca_backend leaves _ca_cert as None when no ca_cert_file is given."""
        scep_cfg = _make_scep_config()  # no ca_cert_file
        config = CAConfig(mode=CAMode.SCEP, scep=scep_cfg)

        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)

        assert isinstance(backend, SCEPCABackend)
        assert backend._ca_cert is None

    def test_raises_when_ca_cert_file_missing(self, tmp_path: Path) -> None:
        """create_ca_backend raises CABackendError when ca_cert_file does not exist."""
        scep_cfg = _make_scep_config(ca_cert_file=tmp_path / "nonexistent.pem")
        config = CAConfig(mode=CAMode.SCEP, scep=scep_cfg)

        with pytest.raises(CABackendError, match="not initialized"):
            create_ca_backend(config)

    def test_raises_when_ca_cert_file_invalid(self, tmp_path: Path) -> None:
        """create_ca_backend raises CABackendError when ca_cert_file has bad content."""
        cert_file = tmp_path / "bad.pem"
        cert_file.write_text("THIS IS NOT A CERTIFICATE")

        scep_cfg = _make_scep_config(ca_cert_file=cert_file)
        config = CAConfig(mode=CAMode.SCEP, scep=scep_cfg)

        with pytest.raises(CABackendError, match="Failed to load CA certificate"):
            create_ca_backend(config)

    def test_calls_log_ca_initialized_with_mode_scep(self) -> None:
        """create_ca_backend calls log_ca_initialized with mode='scep'."""
        scep_cfg = _make_scep_config()
        config = CAConfig(mode=CAMode.SCEP, scep=scep_cfg)

        with patch("est_adapter.ca.backend.log_ca_initialized") as mock_log:
            create_ca_backend(config)

        mock_log.assert_called_once()
        assert mock_log.call_args.kwargs["mode"] == "scep"

    def test_log_ca_initialized_shows_subject_when_cert_provided(
        self,
        tmp_path: Path,
        ca_cert: x509.Certificate,
    ) -> None:
        """log_ca_initialized shows the cert subject when ca_cert_file is given."""
        cert_file = tmp_path / "ca.pem"
        cert_file.write_bytes(encode_certificate_pem(ca_cert))

        scep_cfg = _make_scep_config(ca_cert_file=cert_file)
        config = CAConfig(mode=CAMode.SCEP, scep=scep_cfg)

        with patch("est_adapter.ca.backend.log_ca_initialized") as mock_log:
            create_ca_backend(config)

        ca_subject = mock_log.call_args.kwargs["ca_subject"]
        assert "Test SCEP CA" in ca_subject

    def test_log_ca_initialized_shows_placeholder_when_no_cert(self) -> None:
        """log_ca_initialized shows a placeholder when no cert is pre-loaded."""
        scep_cfg = _make_scep_config()
        config = CAConfig(mode=CAMode.SCEP, scep=scep_cfg)

        with patch("est_adapter.ca.backend.log_ca_initialized") as mock_log:
            create_ca_backend(config)

        ca_subject = mock_log.call_args.kwargs["ca_subject"]
        assert "GetCACert" in ca_subject or "fetch" in ca_subject.lower() or "will be fetched" in ca_subject

    def test_existing_modes_still_work(self, tmp_path: Path) -> None:
        """AUTO_GENERATE mode still returns SelfSignedCABackend after SCEP addition."""
        config = CAConfig(
            mode=CAMode.AUTO_GENERATE,
            auto_generate={"storage_path": tmp_path / "ca_storage"},
        )
        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)
        assert isinstance(backend, SelfSignedCABackend)


# ---------------------------------------------------------------------------
# SCEPConfig validation
# ---------------------------------------------------------------------------


class TestSCEPConfig:
    """Tests for SCEPConfig Pydantic model."""

    def test_valid_config_creates_model(self) -> None:
        """SCEPConfig accepts valid configuration."""
        cfg = SCEPConfig(
            scep_url="https://ca.example.com/scep/scep",
            challenge_password="secret",
        )
        assert cfg.scep_url == "https://ca.example.com/scep/scep"
        assert cfg.challenge_password == "secret"
        assert cfg.verify_tls is True  # default
        assert cfg.timeout_seconds == 60  # default

    def test_defaults_are_applied(self) -> None:
        """SCEPConfig applies defaults for optional fields."""
        cfg = SCEPConfig(scep_url="https://ca.example.com/scep/scep", challenge_password="x")
        assert cfg.ca_cert_file is None
        assert cfg.verify_tls is True
        assert cfg.timeout_seconds == 60

    def test_config_is_frozen(self) -> None:
        """SCEPConfig is immutable (frozen=True)."""
        cfg = SCEPConfig(scep_url="https://ca.example.com/scep/scep", challenge_password="x")
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            cfg.challenge_password = "new-value"  # type: ignore[misc]

    def test_ca_mode_scep_value(self) -> None:
        """CAMode.SCEP has the string value 'scep'."""
        assert CAMode.SCEP == "scep"
