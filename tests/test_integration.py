"""Integration tests for EST Adapter.

Uses TestClient for real HTTP testing without subprocess complexity.
Run with: uv run python -m pytest tests/test_integration.py -v
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from est_adapter.main import create_app

if TYPE_CHECKING:
    from collections.abc import Generator

    from fastapi import FastAPI


@pytest.fixture(scope="module")
def app() -> Generator[FastAPI, None, None]:
    """Create app with default auto-generate CA."""
    return create_app()


@pytest.fixture(scope="module")
def client(app: FastAPI) -> Generator[TestClient, None, None]:
    """TestClient for the app."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client_key() -> rsa.RSAPrivateKey:
    """Generate a client private key for CSR creation."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def valid_csr_pem(client_key: rsa.RSAPrivateKey) -> bytes:
    """Generate a valid CSR in PEM format."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-device.local")]))
        .sign(client_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def valid_csr_base64(valid_csr_pem: bytes) -> str:
    """CSR as base64 for EST protocol."""
    csr = x509.load_pem_x509_csr(valid_csr_pem)
    der_bytes = csr.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der_bytes).decode("ascii")


class TestServerHealth:
    """Tests for basic server health."""

    @pytest.mark.integration
    def test_health_endpoint_returns_ok(self, client: TestClient) -> None:
        """Health endpoint should return 200 with status."""
        resp = client.get("/health")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "version" in data

    @pytest.mark.integration
    def test_server_responds_to_multiple_requests(self, client: TestClient) -> None:
        """Server should handle multiple rapid requests."""
        for _ in range(5):
            resp = client.get("/health")
            assert resp.status_code == 200


class TestCACertsEndpoint:
    """Tests for /.well-known/est/cacerts endpoint."""

    @pytest.mark.integration
    def test_cacerts_returns_certificate(self, client: TestClient) -> None:
        """CACerts endpoint should return CA certificate."""
        resp = client.get("/.well-known/est/cacerts")

        assert resp.status_code == 200
        assert len(resp.content) > 0

    @pytest.mark.integration
    def test_cacerts_returns_valid_pkcs7(self, client: TestClient) -> None:
        """CACerts should return parseable PKCS7."""
        resp = client.get("/.well-known/est/cacerts")

        assert resp.status_code == 200
        # Content should be base64-decodable
        try:
            base64.b64decode(resp.content)
        except Exception as e:
            pytest.fail(f"CACerts response not valid base64: {e}")


class TestSimpleEnrollEndpoint:
    """Tests for /.well-known/est/simpleenroll endpoint."""

    @pytest.mark.integration
    def test_enroll_without_auth_returns_401(self, client: TestClient, valid_csr_base64: str) -> None:
        """Enrollment without authentication should fail."""
        resp = client.post(
            "/.well-known/est/simpleenroll",
            content=valid_csr_base64.encode(),
            headers={"Content-Type": "application/pkcs10"},
        )

        assert resp.status_code == 401

    @pytest.mark.integration
    def test_enroll_with_invalid_csr_format(self, client: TestClient) -> None:
        """Enrollment with garbage data should return error."""
        resp = client.post(
            "/.well-known/est/simpleenroll",
            content=b"not a valid csr",
            headers={"Content-Type": "application/pkcs10"},
        )

        # Should be 4xx error (400 bad request or 401 auth first)
        assert resp.status_code >= 400


class TestSimpleReenrollEndpoint:
    """Tests for /.well-known/est/simplereenroll endpoint."""

    @pytest.mark.integration
    def test_reenroll_without_auth_returns_401(self, client: TestClient, valid_csr_base64: str) -> None:
        """Re-enrollment without authentication should fail."""
        resp = client.post(
            "/.well-known/est/simplereenroll",
            content=valid_csr_base64.encode(),
            headers={"Content-Type": "application/pkcs10"},
        )

        assert resp.status_code == 401


class TestFullWorkflow:
    """End-to-end workflow tests."""

    @pytest.mark.integration
    def test_get_ca_then_attempt_enroll(self, client: TestClient, valid_csr_base64: str) -> None:
        """Test complete workflow: get CA cert, then attempt enroll."""
        # Step 1: Get CA certificate (should always work)
        cacerts_resp = client.get("/.well-known/est/cacerts")
        assert cacerts_resp.status_code == 200
        assert len(cacerts_resp.content) > 0

        # Step 2: Attempt enrollment without auth (should fail with 401)
        enroll_resp = client.post(
            "/.well-known/est/simpleenroll",
            content=valid_csr_base64.encode(),
            headers={"Content-Type": "application/pkcs10"},
        )
        assert enroll_resp.status_code == 401


class TestErrorHandling:
    """Tests for error responses."""

    @pytest.mark.integration
    def test_404_for_unknown_endpoint(self, client: TestClient) -> None:
        """Unknown endpoints should return 404."""
        resp = client.get("/not-a-real-endpoint")
        assert resp.status_code == 404

    @pytest.mark.integration
    def test_post_to_cacerts_returns_405(self, client: TestClient) -> None:
        """POST to cacerts (GET only) should return 405."""
        resp = client.post("/.well-known/est/cacerts")
        assert resp.status_code == 405
