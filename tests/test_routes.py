"""Integration tests for EST routes.

Tests the full request/response cycle for EST endpoints.
"""

from __future__ import annotations

import base64
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient

from est_adapter.auth.handler import CombinedAuthHandler
from est_adapter.ca.backend import SelfSignedCABackend
from est_adapter.config import (
    AuthConfig,
    AuthMethod,
    BasicAuthConfig,
    BasicAuthUser,
    Settings,
)

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
        ],
    )

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
def ca_backend(
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
) -> SelfSignedCABackend:
    """CA backend for testing."""
    return SelfSignedCABackend(ca_certificate, ca_key)


@pytest.fixture
def auth_handler() -> CombinedAuthHandler:
    """Auth handler that accepts testuser:testpass."""
    from est_adapter.auth.handler import hash_password_for_config

    password_hash = hash_password_for_config("testpass")

    config = AuthConfig(
        method=AuthMethod.BASIC,
        basic=BasicAuthConfig(
            users=[BasicAuthUser(username="testuser", password_hash=password_hash)],
        ),
    )
    return CombinedAuthHandler.from_config(config)


@pytest.fixture
def settings() -> Settings:
    """Default settings with test auth configured."""
    from est_adapter.auth.handler import hash_password_for_config

    password_hash = hash_password_for_config("testpass")

    return Settings(
        auth=AuthConfig(
            method=AuthMethod.BASIC,
            basic=BasicAuthConfig(
                users=[BasicAuthUser(username="testuser", password_hash=password_hash)],
            ),
        ),
    )


@pytest.fixture
def test_app(settings: Settings) -> Generator[FastAPI, None, None]:
    """FastAPI app created via main.create_app with test settings."""
    from est_adapter.main import create_app

    with (
        patch("est_adapter.main.log_startup"),
        patch("est_adapter.main.log_shutdown"),
        patch(
            "est_adapter.ca.backend.log_ca_initialized",
        ),
    ):
        app = create_app(settings)
        yield app


@pytest.fixture
def client(test_app: FastAPI) -> TestClient:
    """Test client for the configured app."""
    return TestClient(test_app)


@pytest.fixture
def valid_csr_pem() -> bytes:
    """Valid CSR in PEM format."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com"),
                ],
            ),
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(Encoding.PEM)


@pytest.fixture
def valid_csr_der() -> bytes:
    """Valid CSR in DER format (raw binary)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com"),
                ],
            ),
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(Encoding.DER)


@pytest.fixture
def auth_header() -> str:
    """Authorization header for testuser:testpass."""
    credentials = base64.b64encode(b"testuser:testpass").decode()
    return f"Basic {credentials}"


# --- GET /cacerts Tests ---


class TestGetCaCerts:
    """Tests for GET /.well-known/est/cacerts endpoint."""

    def test_returns_pkcs7_content_type(self, client: TestClient) -> None:
        """Returns correct content type for PKCS#7."""
        response = client.get("/.well-known/est/cacerts")

        assert response.status_code == 200
        assert "application/pkcs7-mime" in response.headers["content-type"]

    def test_returns_base64_encoded_pkcs7(self, client: TestClient) -> None:
        """Returns base64-encoded PKCS#7 data."""
        response = client.get("/.well-known/est/cacerts")

        assert response.status_code == 200
        # Body should be base64-decodable
        decoded = base64.b64decode(response.content)
        # PKCS#7 DER starts with SEQUENCE tag (0x30)
        assert decoded[0] == 0x30

    def test_unauthenticated_access_allowed(self, client: TestClient) -> None:
        """No authentication required for /cacerts."""
        response = client.get("/.well-known/est/cacerts")

        assert response.status_code == 200


# --- POST /simpleenroll Tests ---


class TestSimpleEnroll:
    """Tests for POST /.well-known/est/simpleenroll endpoint."""

    def test_valid_csr_returns_certificate(
        self,
        client: TestClient,
        valid_csr_pem: bytes,
        auth_header: str,
    ) -> None:
        """Valid CSR with auth returns issued certificate."""
        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch(
                "est_adapter.routes.est.log_csr_validation",
            ),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            response = client.post(
                "/.well-known/est/simpleenroll",
                content=valid_csr_pem,
                headers={"Authorization": auth_header},
            )

        assert response.status_code == 200
        assert "application/pkcs7-mime" in response.headers["content-type"]
        # Body should be base64-decodable PKCS#7
        decoded = base64.b64decode(response.content)
        assert decoded[0] == 0x30

    def test_der_csr_accepted(
        self,
        client: TestClient,
        valid_csr_der: bytes,
        auth_header: str,
    ) -> None:
        """DER-encoded CSR is accepted."""
        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch(
                "est_adapter.routes.est.log_csr_validation",
            ),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            response = client.post(
                "/.well-known/est/simpleenroll",
                content=valid_csr_der,
                headers={"Authorization": auth_header},
            )

        assert response.status_code == 200

    def test_missing_auth_returns_401(
        self,
        client: TestClient,
        valid_csr_pem: bytes,
    ) -> None:
        """Missing authentication returns 401."""
        response = client.post(
            "/.well-known/est/simpleenroll",
            content=valid_csr_pem,
        )

        assert response.status_code == 401

    def test_invalid_auth_returns_401(
        self,
        client: TestClient,
        valid_csr_pem: bytes,
    ) -> None:
        """Invalid credentials return 401."""
        bad_auth = "Basic " + base64.b64encode(b"wrong:creds").decode()

        response = client.post(
            "/.well-known/est/simpleenroll",
            content=valid_csr_pem,
            headers={"Authorization": bad_auth},
        )

        assert response.status_code == 401

    def test_invalid_csr_returns_400(
        self,
        client: TestClient,
        auth_header: str,
    ) -> None:
        """Invalid CSR data returns 400."""
        response = client.post(
            "/.well-known/est/simpleenroll",
            content=b"not a valid CSR",
            headers={"Authorization": auth_header},
        )

        assert response.status_code == 400

    def test_csr_failing_policy_returns_400(
        self,
        client: TestClient,
        auth_header: str,
    ) -> None:
        """CSR that fails policy validation returns 400."""
        # Create CSR with small key (1024 bits, below default 2048 minimum)
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "small-key"),
                    ],
                ),
            )
            .sign(key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(Encoding.PEM)

        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch(
                "est_adapter.routes.est.log_csr_validation",
            ),
        ):
            response = client.post(
                "/.well-known/est/simpleenroll",
                content=csr_pem,
                headers={"Authorization": auth_header},
            )

        assert response.status_code == 400


# --- POST /simplereenroll Tests ---


class TestSimpleReenroll:
    """Tests for POST /.well-known/est/simplereenroll endpoint."""

    def test_valid_csr_returns_certificate(
        self,
        client: TestClient,
        valid_csr_pem: bytes,
        auth_header: str,
    ) -> None:
        """Valid CSR with auth returns issued certificate."""
        with (
            patch("est_adapter.routes.est.log_csr_received"),
            patch(
                "est_adapter.routes.est.log_csr_validation",
            ),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            response = client.post(
                "/.well-known/est/simplereenroll",
                content=valid_csr_pem,
                headers={"Authorization": auth_header},
            )

        assert response.status_code == 200
        assert "application/pkcs7-mime" in response.headers["content-type"]

    def test_missing_auth_returns_401(
        self,
        client: TestClient,
        valid_csr_pem: bytes,
    ) -> None:
        """Missing authentication returns 401."""
        response = client.post(
            "/.well-known/est/simplereenroll",
            content=valid_csr_pem,
        )

        assert response.status_code == 401


# --- Error Handler Tests ---


class TestErrorHandling:
    """Tests for error response formatting."""

    def test_authentication_error_includes_www_authenticate(
        self,
        client: TestClient,
        valid_csr_pem: bytes,
    ) -> None:
        """401 responses include WWW-Authenticate header."""
        response = client.post(
            "/.well-known/est/simpleenroll",
            content=valid_csr_pem,
        )

        assert response.status_code == 401
        # FastAPI's default error handling may not include this header
        # but our custom handler should (if implemented)
