"""Tests for EST client.

Tests the client against our own EST server using TestClient-backed httpx transport.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from est_adapter.auth.handler import hash_password_for_config
from est_adapter.client.est_client import (
    ESTAuthenticationError,
    ESTClient,
    ESTEnrollmentError,
    ESTServerError,
    _encode_csr,
    _parse_pkcs7_response,
)
from est_adapter.config import (
    AuthConfig,
    AuthMethod,
    BasicAuthConfig,
    BasicAuthUser,
    Settings,
)

if TYPE_CHECKING:
    from collections.abc import Generator

    from fastapi import FastAPI


# --- Fixtures ---


@pytest.fixture(scope="module")
def test_settings() -> Settings:
    """Settings with basic auth for testing."""
    password_hash = hash_password_for_config("testpass")
    return Settings(
        auth=AuthConfig(
            method=AuthMethod.BASIC,
            basic=BasicAuthConfig(
                users=[BasicAuthUser(username="testuser", password_hash=password_hash)],
            ),
        ),
    )


@pytest.fixture(scope="module")
def test_app(test_settings: Settings) -> Generator[FastAPI, None, None]:
    """FastAPI app for testing."""
    from est_adapter.main import create_app

    with (
        patch("est_adapter.main.log_startup"),
        patch("est_adapter.main.log_shutdown"),
        patch("est_adapter.ca.backend.log_ca_initialized"),
    ):
        yield create_app(test_settings)


def _make_est_client_from_testclient(
    test_client: TestClient,
    auth: httpx.BasicAuth | None = None,
) -> ESTClient:
    """Create an ESTClient that uses a TestClient's internal httpx client."""
    est = ESTClient.__new__(ESTClient)
    est._base_url = "http://testserver"  # noqa: SLF001
    est._est_path = "/.well-known/est"  # noqa: SLF001
    est._timeout = 5.0  # noqa: SLF001
    # TestClient IS an httpx.Client subclass — use it directly
    est._client = test_client  # noqa: SLF001
    if auth:
        est._client._auth = auth  # type: ignore[attr-defined]  # noqa: SLF001
    return est


@pytest.fixture(scope="module")
def _test_client_no_auth(test_app: FastAPI) -> Generator[TestClient, None, None]:
    """TestClient without auth."""
    with TestClient(test_app) as tc:
        yield tc


@pytest.fixture(scope="module")
def _test_client_with_auth(test_app: FastAPI) -> Generator[TestClient, None, None]:
    """TestClient with basic auth."""
    with TestClient(test_app) as tc:
        yield tc


@pytest.fixture(scope="module")
def est_client(_test_client_no_auth: TestClient) -> ESTClient:
    """EST client without auth, backed by the test server."""
    return _make_est_client_from_testclient(_test_client_no_auth)


@pytest.fixture(scope="module")
def est_client_with_auth(_test_client_with_auth: TestClient) -> ESTClient:
    """EST client with basic auth, backed by the test server."""
    return _make_est_client_from_testclient(
        _test_client_with_auth,
        auth=httpx.BasicAuth("testuser", "testpass"),
    )


@pytest.fixture
def client_key() -> rsa.RSAPrivateKey:
    """Generate a fresh RSA key for CSR creation."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def valid_csr(client_key: rsa.RSAPrivateKey) -> x509.CertificateSigningRequest:
    """Generate a valid CSR."""
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-device.local")]))
        .sign(client_key, hashes.SHA256())
    )


# --- Unit Tests: Helper Functions ---


class TestEncodeCsr:
    """Tests for CSR encoding."""

    def test_returns_pem(self, valid_csr: x509.CertificateSigningRequest) -> None:
        """Encoded CSR is valid PEM."""
        encoded = _encode_csr(valid_csr)
        assert encoded.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")

    def test_round_trips(self, valid_csr: x509.CertificateSigningRequest) -> None:
        """Encoded CSR can be decoded back to a CSR."""
        encoded = _encode_csr(valid_csr)
        loaded = x509.load_pem_x509_csr(encoded)
        assert loaded.subject == valid_csr.subject


class TestParsePkcs7Response:
    """Tests for PKCS#7 response parsing."""

    def test_parses_valid_pkcs7(self) -> None:
        """Valid PKCS#7 with a certificate is parsed correctly."""
        # Create a self-signed cert for testing
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        from datetime import UTC, datetime, timedelta

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        der = pkcs7.serialize_certificates([cert], serialization.Encoding.DER)
        b64 = base64.b64encode(der)

        result = _parse_pkcs7_response(b64)
        assert len(result) == 1
        assert result[0].subject == cert.subject

    def test_invalid_base64_raises(self) -> None:
        """Invalid base64 raises ESTServerError."""
        with pytest.raises(ESTServerError, match="decode base64"):
            _parse_pkcs7_response(b"not valid base64!!!")

    def test_invalid_pkcs7_raises(self) -> None:
        """Valid base64 but invalid PKCS#7 raises ESTServerError."""
        with pytest.raises(ESTServerError, match="parse PKCS"):
            _parse_pkcs7_response(base64.b64encode(b"not pkcs7"))


# --- Integration Tests: Against Test Server ---


class TestGetCaCerts:
    """Tests for get_ca_certs against the test server."""

    @pytest.mark.integration
    def test_retrieves_ca_certificate(self, est_client: ESTClient) -> None:
        """Client retrieves at least one CA certificate."""
        certs = est_client.get_ca_certs()
        assert len(certs) >= 1
        assert isinstance(certs[0], x509.Certificate)

    @pytest.mark.integration
    def test_ca_cert_is_ca(self, est_client: ESTClient) -> None:
        """Retrieved certificate has CA basic constraint."""
        certs = est_client.get_ca_certs()
        bc = certs[0].extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True


class TestSimpleEnroll:
    """Tests for simple_enroll against the test server."""

    @pytest.mark.integration
    def test_enroll_without_auth_raises(
        self,
        est_client: ESTClient,
        valid_csr: x509.CertificateSigningRequest,
    ) -> None:
        """Enrollment without auth raises ESTAuthenticationError."""
        with pytest.raises(ESTAuthenticationError):
            est_client.simple_enroll(valid_csr)

    @pytest.mark.integration
    def test_enroll_with_auth_returns_certificate(
        self,
        est_client_with_auth: ESTClient,
        valid_csr: x509.CertificateSigningRequest,
    ) -> None:
        """Enrollment with valid auth returns a certificate."""
        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch("est_adapter.routes.est.log_csr_validation"),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            cert = est_client_with_auth.simple_enroll(valid_csr)

        assert isinstance(cert, x509.Certificate)
        assert cert.subject == valid_csr.subject

    @pytest.mark.integration
    def test_enroll_cert_signed_by_ca(
        self,
        est_client_with_auth: ESTClient,
        valid_csr: x509.CertificateSigningRequest,
    ) -> None:
        """Issued certificate is signed by the server's CA."""
        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch("est_adapter.routes.est.log_csr_validation"),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            cert = est_client_with_auth.simple_enroll(valid_csr)

        ca_certs = est_client_with_auth.get_ca_certs()
        assert cert.issuer == ca_certs[0].subject

    @pytest.mark.integration
    def test_enroll_invalid_csr_raises(
        self,
        est_client_with_auth: ESTClient,
    ) -> None:
        """Enrollment with a weak key CSR raises ESTEnrollmentError."""
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        weak_csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak")]))
            .sign(weak_key, hashes.SHA256())
        )

        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch("est_adapter.routes.est.log_csr_validation"),
            pytest.raises(ESTEnrollmentError),
        ):
            est_client_with_auth.simple_enroll(weak_csr)


class TestSimpleReenroll:
    """Tests for simple_reenroll against the test server."""

    @pytest.mark.integration
    def test_reenroll_with_auth_returns_certificate(
        self,
        est_client_with_auth: ESTClient,
        valid_csr: x509.CertificateSigningRequest,
    ) -> None:
        """Re-enrollment with valid auth returns a certificate."""
        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch("est_adapter.routes.est.log_csr_validation"),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            cert = est_client_with_auth.simple_reenroll(valid_csr)

        assert isinstance(cert, x509.Certificate)

    @pytest.mark.integration
    def test_reenroll_without_auth_raises(
        self,
        est_client: ESTClient,
        valid_csr: x509.CertificateSigningRequest,
    ) -> None:
        """Re-enrollment without auth raises ESTAuthenticationError."""
        with pytest.raises(ESTAuthenticationError):
            est_client.simple_reenroll(valid_csr)


class TestHighLevelEnroll:
    """Tests for the high-level enroll convenience method."""

    @pytest.mark.integration
    def test_enroll_generates_key_and_certificate(
        self,
        est_client_with_auth: ESTClient,
    ) -> None:
        """High-level enroll produces certificate and private key."""
        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch("est_adapter.routes.est.log_csr_validation"),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            result = est_client_with_auth.enroll("my-device.local")

        assert isinstance(result.certificate, x509.Certificate)
        assert result.private_key is not None
        # CN should match what we requested
        cn = result.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "my-device.local"

    @pytest.mark.integration
    def test_enroll_with_san(
        self,
        est_client_with_auth: ESTClient,
    ) -> None:
        """High-level enroll with SAN DNS names."""
        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch("est_adapter.routes.est.log_csr_validation"),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            result = est_client_with_auth.enroll(
                "my-device.local",
                san_dns_names=["alt1.local", "alt2.local"],
            )

        assert isinstance(result.certificate, x509.Certificate)

    @pytest.mark.integration
    def test_enroll_saves_to_files(
        self,
        est_client_with_auth: ESTClient,
        tmp_path: Path,
    ) -> None:
        """Enrolled certificate and key can be saved to files."""

        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch("est_adapter.routes.est.log_csr_validation"),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            result = est_client_with_auth.enroll("save-test.local")

        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"

        result.save_certificate_pem(cert_path)
        result.save_private_key_pem(key_path)

        assert cert_path.exists()
        assert key_path.exists()

        # Verify saved files are loadable
        loaded_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        assert loaded_cert.subject == result.certificate.subject

        loaded_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        assert isinstance(loaded_key, rsa.RSAPrivateKey)
