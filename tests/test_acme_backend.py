"""Contract tests for ACMECABackend.

Tests Protocol compliance, account key management, full sign_csr flow with
mocked ACME client, challenge router, error handling, and the factory function.
All external dependencies (ACMEClient, audit loggers) are mocked so no real
network calls are made.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient

from est_adapter.ca.backend import ACMECABackend, SelfSignedCABackend, create_ca_backend
from est_adapter.config import ACMEConfig, CAConfig, CAMode
from est_adapter.crypto.cert import encode_certificate_pem
from est_adapter.crypto.csr import CSRInfo, parse_csr
from est_adapter.exceptions import CABackendError

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_p256_key() -> ec.EllipticCurvePrivateKey:
    """Generate a test EC P-256 key (fast; intentionally small for tests)."""
    return ec.generate_private_key(ec.SECP256R1())


def _make_rsa_key() -> rsa.RSAPrivateKey:
    """Generate a small RSA key for test CSRs."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_ca_cert(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """Build a minimal self-signed CA certificate for testing."""
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )


def _make_leaf_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    cn: str = "device.example.com",
) -> x509.Certificate:
    """Build a minimal leaf (end-entity) certificate signed by the given CA."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    leaf_key = _make_rsa_key()
    ski = x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key())
    ca_ski_ext = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=90))
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
    return parse_csr(csr.public_bytes(serialization.Encoding.PEM))


def _make_acme_config(tmp_path: Path, **overrides: object) -> ACMEConfig:
    """Create a minimal ACMEConfig pointing at a temp directory."""
    kwargs = {
        "directory_url": "https://acme.example.com/acme/directory",
        "account_email": "test@example.com",
        "account_storage_path": tmp_path / "acme_account",
        "verify_tls": False,
    }
    kwargs.update(overrides)
    return ACMEConfig(**kwargs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ca_key() -> rsa.RSAPrivateKey:
    """CA RSA private key for test certificates."""
    return _make_rsa_key()


@pytest.fixture
def ca_cert(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Self-signed CA certificate for tests."""
    return _make_ca_cert(ca_key)


@pytest.fixture
def acme_config(tmp_path: Path) -> ACMEConfig:
    """Minimal ACMEConfig for tests."""
    return _make_acme_config(tmp_path)


@pytest.fixture
def backend(acme_config: ACMEConfig) -> ACMECABackend:
    """ACMECABackend with patched audit logger (no side effects)."""
    with patch("est_adapter.ca.backend.log_ca_initialized"):
        return ACMECABackend(acme_config)


@pytest.fixture
def backend_with_ca(acme_config: ACMEConfig, ca_cert: x509.Certificate) -> ACMECABackend:
    """ACMECABackend pre-loaded with a CA certificate."""
    with patch("est_adapter.ca.backend.log_ca_initialized"):
        return ACMECABackend(acme_config, ca_cert=ca_cert)


@pytest.fixture
def csr_info() -> CSRInfo:
    """Parsed CSR for signing tests."""
    return _make_csr_info()


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------


class TestACMECABackendProtocolCompliance:
    """Verify ACMECABackend satisfies the CABackend Protocol surface."""

    def test_has_ca_certificate_property(self, backend_with_ca: ACMECABackend) -> None:
        """ca_certificate property is accessible and returns an x509.Certificate."""
        result = backend_with_ca.ca_certificate
        assert isinstance(result, x509.Certificate)

    def test_has_sign_csr_method(self, backend: ACMECABackend) -> None:
        """sign_csr method exists and is callable."""
        assert callable(backend.sign_csr)

    def test_has_get_ca_certs_pkcs7_method(self, backend: ACMECABackend) -> None:
        """get_ca_certs_pkcs7 method exists and is callable."""
        assert callable(backend.get_ca_certs_pkcs7)

    def test_has_challenge_router_property(self, backend: ACMECABackend) -> None:
        """challenge_router property is accessible."""
        from fastapi import APIRouter

        router = backend.challenge_router
        assert isinstance(router, APIRouter)


# ---------------------------------------------------------------------------
# Account key management
# ---------------------------------------------------------------------------


class TestAccountKeyManagement:
    """Tests for account key loading and saving."""

    def test_generates_ec_p256_key_on_first_run(self, acme_config: ACMEConfig) -> None:
        """A fresh backend generates a new EC P-256 account key."""
        backend = ACMECABackend(acme_config)
        assert isinstance(backend._account_key, ec.EllipticCurvePrivateKey)
        assert isinstance(backend._account_key.curve, ec.SECP256R1)

    def test_key_file_written_to_storage(self, acme_config: ACMEConfig) -> None:
        """Account key is persisted to account_storage_path/account.key."""
        ACMECABackend(acme_config)
        key_path = Path(acme_config.account_storage_path) / "account.key"
        assert key_path.exists()

    def test_key_file_has_restrictive_permissions(self, acme_config: ACMEConfig) -> None:
        """Account key file is written with 0o600 permissions."""
        ACMECABackend(acme_config)
        key_path = Path(acme_config.account_storage_path) / "account.key"
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_loads_existing_key_on_second_run(self, acme_config: ACMEConfig) -> None:
        """A second backend instance loads the same key rather than generating a new one."""
        b1 = ACMECABackend(acme_config)
        pub1 = b1._account_key.public_key().public_numbers()

        b2 = ACMECABackend(acme_config)
        pub2 = b2._account_key.public_key().public_numbers()

        assert pub1.x == pub2.x
        assert pub1.y == pub2.y

    def test_account_kid_none_on_first_run(self, acme_config: ACMEConfig) -> None:
        """Account KID is None when no account.json exists."""
        backend = ACMECABackend(acme_config)
        assert backend._account_kid is None

    def test_save_and_load_account_info(self, acme_config: ACMEConfig) -> None:
        """Saving account info persists the KID for subsequent loads."""
        backend = ACMECABackend(acme_config)
        backend._save_account_info("https://acme.example.com/acct/42")
        kid = backend._load_account_info()
        assert kid == "https://acme.example.com/acct/42"

    def test_load_account_info_returns_none_on_corrupt_file(self, acme_config: ACMEConfig) -> None:
        """Corrupt account.json returns None rather than raising."""
        info_path = Path(acme_config.account_storage_path) / "account.json"
        info_path.parent.mkdir(parents=True, exist_ok=True)
        info_path.write_text("NOT VALID JSON{{{{")
        backend = ACMECABackend(acme_config)
        # _load_account_info is called during __init__; result stored in _account_kid
        assert backend._account_kid is None


# ---------------------------------------------------------------------------
# ca_certificate property
# ---------------------------------------------------------------------------


class TestCaCertificateProperty:
    """Tests for the ca_certificate property."""

    def test_raises_not_initialized_when_no_cert(self, backend: ACMECABackend) -> None:
        """ca_certificate raises CABackendError when no cert has been loaded."""
        with pytest.raises(CABackendError, match="not initialized"):
            _ = backend.ca_certificate

    def test_returns_cert_when_set(self, backend_with_ca: ACMECABackend, ca_cert: x509.Certificate) -> None:
        """ca_certificate returns the pre-loaded CA certificate."""
        assert backend_with_ca.ca_certificate == ca_cert


# ---------------------------------------------------------------------------
# get_ca_certs_pkcs7
# ---------------------------------------------------------------------------


class TestGetCaCertsPkcs7:
    """Tests for get_ca_certs_pkcs7."""

    def test_raises_when_no_ca_cert(self, backend: ACMECABackend) -> None:
        """get_ca_certs_pkcs7 raises when CA certificate is not available."""
        with pytest.raises(CABackendError, match="not initialized"):
            backend.get_ca_certs_pkcs7()

    def test_returns_der_pkcs7_when_cert_set(
        self,
        backend_with_ca: ACMECABackend,
    ) -> None:
        """get_ca_certs_pkcs7 returns valid DER-encoded PKCS#7."""
        result = backend_with_ca.get_ca_certs_pkcs7()
        assert isinstance(result, bytes)
        # DER SEQUENCE starts with 0x30
        assert result[0] == 0x30


# ---------------------------------------------------------------------------
# Challenge router
# ---------------------------------------------------------------------------


class TestChallengeRouter:
    """Tests for the ACME HTTP-01 challenge router."""

    def _app_with_backend(self, backend: ACMECABackend) -> TestClient:
        """Build a test FastAPI app that mounts the challenge router."""
        app = FastAPI()
        app.include_router(backend.challenge_router)
        return TestClient(app)

    def test_serves_registered_token(self, backend: ACMECABackend) -> None:
        """GET /.well-known/acme-challenge/{token} returns key authorization."""
        backend._challenge_tokens["abc123"] = "abc123.THUMBPRINT"
        client = self._app_with_backend(backend)

        response = client.get("/.well-known/acme-challenge/abc123")

        assert response.status_code == 200
        assert response.text == "abc123.THUMBPRINT"

    def test_returns_404_for_unknown_token(self, backend: ACMECABackend) -> None:
        """GET /.well-known/acme-challenge/{token} returns 404 for unknown tokens."""
        client = self._app_with_backend(backend)

        response = client.get("/.well-known/acme-challenge/notregistered")

        assert response.status_code == 404

    def test_returns_correct_content_type(self, backend: ACMECABackend) -> None:
        """Challenge response has text/plain content type."""
        backend._challenge_tokens["tok"] = "tok.THUMBPRINT"
        client = self._app_with_backend(backend)

        response = client.get("/.well-known/acme-challenge/tok")

        assert "text/plain" in response.headers["content-type"]


# ---------------------------------------------------------------------------
# sign_csr — full mocked ACME flow
# ---------------------------------------------------------------------------


def _build_mock_acme_client(
    leaf_cert: x509.Certificate,
    ca_cert: x509.Certificate,
    account_url: str = "https://acme.example.com/acct/1",
) -> MagicMock:
    """Build a MagicMock ACMEClient that simulates a successful ACME order.

    Args:
        leaf_cert: The leaf certificate to return from download_certificate.
        ca_cert: The CA certificate to include as the second cert in the chain.
        account_url: Account URL returned by create_account.

    Returns:
        A MagicMock configured as an async context manager.
    """
    from est_adapter.ca.acme_client import ACMEAuthorization, ACMEChallenge, ACMEOrder

    mock_client = MagicMock()

    # Context-manager protocol
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    # fetch_directory — just needs to succeed
    mock_client.fetch_directory = AsyncMock(return_value=MagicMock())

    # create_account — returns (account_url, account_url)
    mock_client.create_account = AsyncMock(return_value=(account_url, account_url))

    # create_order — returns an order with one authorization URL
    order_pending = ACMEOrder(
        status="pending",
        finalize="https://acme.example.com/acme/order/1/finalize",
        authorizations=["https://acme.example.com/acme/authz/1"],
        url="https://acme.example.com/acme/order/1",
    )
    mock_client.create_order = AsyncMock(return_value=order_pending)

    # get_authorization — returns an auth with an http-01 challenge
    challenge = ACMEChallenge(
        type="http-01",
        url="https://acme.example.com/acme/challenge/1",
        token="testtoken123",
        status="pending",
    )
    auth = ACMEAuthorization(
        status="pending",
        identifier={"type": "dns", "value": "device.example.com"},
        challenges=[challenge],
    )
    mock_client.get_authorization = AsyncMock(return_value=auth)

    # key_authorization — deterministic value for testing
    mock_client.key_authorization = MagicMock(return_value="testtoken123.THUMBPRINT")

    # respond_to_challenge — success
    mock_client.respond_to_challenge = AsyncMock(return_value=None)

    # poll_authorization — immediately valid
    valid_auth = ACMEAuthorization(
        status="valid",
        identifier={"type": "dns", "value": "device.example.com"},
        challenges=[challenge],
    )
    mock_client.poll_authorization = AsyncMock(return_value=valid_auth)

    # finalize_order — returns order moving toward valid
    order_processing = ACMEOrder(
        status="processing",
        finalize="https://acme.example.com/acme/order/1/finalize",
        authorizations=["https://acme.example.com/acme/authz/1"],
        url="https://acme.example.com/acme/order/1",
        certificate="https://acme.example.com/acme/cert/1",
    )
    mock_client.finalize_order = AsyncMock(return_value=order_processing)

    # poll_order — valid order with certificate URL
    order_valid = ACMEOrder(
        status="valid",
        finalize="https://acme.example.com/acme/order/1/finalize",
        authorizations=["https://acme.example.com/acme/authz/1"],
        url="https://acme.example.com/acme/order/1",
        certificate="https://acme.example.com/acme/cert/1",
    )
    mock_client.poll_order = AsyncMock(return_value=order_valid)

    # download_certificate — leaf cert first, then CA cert
    mock_client.download_certificate = AsyncMock(return_value=[leaf_cert, ca_cert])

    return mock_client


class TestSignCsr:
    """Tests for the sign_csr / _sign_csr_async flow."""

    def test_sign_csr_returns_leaf_certificate(
        self,
        backend: ACMECABackend,
        csr_info: CSRInfo,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """sign_csr returns the leaf x509.Certificate from the ACME chain."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_acme_client(leaf_cert, ca_cert)

        with (
            patch("est_adapter.ca.backend.ACMEClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            result = backend.sign_csr(csr_info, validity_days=90, requestor_identity="test-device")

        assert isinstance(result, x509.Certificate)
        # Verify it is the leaf, not the CA
        assert result.serial_number == leaf_cert.serial_number

    def test_sign_csr_extracts_ca_cert_from_chain(
        self,
        backend: ACMECABackend,
        csr_info: CSRInfo,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """sign_csr caches the CA cert from the chain when not pre-loaded."""
        assert backend._ca_cert is None
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_acme_client(leaf_cert, ca_cert)

        with (
            patch("est_adapter.ca.backend.ACMEClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            backend.sign_csr(csr_info, validity_days=90, requestor_identity="test")

        # The CA cert should now be cached (from the chain)
        assert backend._ca_cert is not None
        assert backend._ca_cert.serial_number == ca_cert.serial_number

    def test_sign_csr_does_not_overwrite_existing_ca_cert(
        self,
        backend_with_ca: ACMECABackend,
        csr_info: CSRInfo,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """sign_csr does not replace an already-cached CA certificate."""
        original_ca_cert = backend_with_ca._ca_cert
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)

        # Provide a different CA cert in the chain
        different_ca_key = _make_rsa_key()
        different_ca_cert = _make_ca_cert(different_ca_key)
        mock_client = _build_mock_acme_client(leaf_cert, different_ca_cert)

        with (
            patch("est_adapter.ca.backend.ACMEClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            backend_with_ca.sign_csr(csr_info, validity_days=90, requestor_identity="test")

        # Original CA cert should still be in place
        assert backend_with_ca._ca_cert is original_ca_cert

    def test_sign_csr_registers_and_removes_challenge_token(
        self,
        backend: ACMECABackend,
        csr_info: CSRInfo,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """Challenge token is registered during flow and removed when done."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_acme_client(leaf_cert, ca_cert)

        tokens_during_challenge: list[dict[str, str]] = []

        original_respond = mock_client.respond_to_challenge

        async def capture_tokens(challenge_url: str) -> None:
            # Snapshot the token dict when challenge is responded to
            with backend._challenge_lock:
                tokens_during_challenge.append(dict(backend._challenge_tokens))
            await original_respond(challenge_url)

        mock_client.respond_to_challenge = capture_tokens

        with (
            patch("est_adapter.ca.backend.ACMEClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            backend.sign_csr(csr_info, validity_days=90, requestor_identity="test")

        # Token was present during challenge
        assert len(tokens_during_challenge) == 1
        assert "testtoken123" in tokens_during_challenge[0]

        # Token was cleaned up after completion
        assert "testtoken123" not in backend._challenge_tokens

    def test_sign_csr_saves_account_kid_after_first_use(
        self,
        backend: ACMECABackend,
        csr_info: CSRInfo,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """Account KID is persisted to account.json after successful account creation."""
        assert backend._account_kid is None
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_acme_client(leaf_cert, ca_cert)

        with (
            patch("est_adapter.ca.backend.ACMEClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
        ):
            backend.sign_csr(csr_info, validity_days=90, requestor_identity="test")

        info_path = Path(backend._config.account_storage_path) / "account.json"
        assert info_path.exists()
        data = json.loads(info_path.read_text())
        assert data["kid"] == "https://acme.example.com/acct/1"

    def test_sign_csr_calls_audit_log(
        self,
        backend: ACMECABackend,
        csr_info: CSRInfo,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """sign_csr calls log_certificate_issued with requestor_identity."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_acme_client(leaf_cert, ca_cert)

        with (
            patch("est_adapter.ca.backend.ACMEClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued") as mock_log,
        ):
            backend.sign_csr(csr_info, validity_days=90, requestor_identity="nurse-station-1")

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["requestor_identity"] == "nurse-station-1"

    def test_sign_csr_raises_when_no_http01_challenge(
        self,
        backend: ACMECABackend,
        csr_info: CSRInfo,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """sign_csr raises CABackendError when server offers no http-01 challenge."""
        from est_adapter.ca.acme_client import ACMEAuthorization, ACMEChallenge

        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_acme_client(leaf_cert, ca_cert)

        # Replace authorization with one that has only a dns-01 challenge
        tls_challenge = ACMEChallenge(type="dns-01", url="https://acme.example.com/ch/2", token="tok", status="pending")
        auth_no_http = ACMEAuthorization(
            status="pending",
            identifier={"type": "dns", "value": "device.example.com"},
            challenges=[tls_challenge],
        )
        mock_client.get_authorization = AsyncMock(return_value=auth_no_http)

        with (
            patch("est_adapter.ca.backend.ACMEClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
            pytest.raises(CABackendError, match="No http-01 challenge"),
        ):
            backend.sign_csr(csr_info, validity_days=90, requestor_identity="test")

    def test_sign_csr_removes_token_on_authorization_failure(
        self,
        backend: ACMECABackend,
        csr_info: CSRInfo,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """Token is cleaned up even when poll_authorization raises."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_acme_client(leaf_cert, ca_cert)
        mock_client.poll_authorization = AsyncMock(side_effect=CABackendError("authorization failed"))

        with (
            patch("est_adapter.ca.backend.ACMEClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
            pytest.raises(CABackendError, match="authorization failed"),
        ):
            backend.sign_csr(csr_info, validity_days=90, requestor_identity="test")

        # Token must be removed even after failure
        assert "testtoken123" not in backend._challenge_tokens

    def test_sign_csr_raises_when_order_has_no_url(
        self,
        backend: ACMECABackend,
        csr_info: CSRInfo,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """sign_csr raises CABackendError when finalize_order returns no order URL."""
        from est_adapter.ca.acme_client import ACMEOrder as _ACMEOrder

        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_acme_client(leaf_cert, ca_cert)

        # Return an order with no URL
        order_no_url = _ACMEOrder(
            status="processing",
            finalize="https://acme.example.com/acme/order/1/finalize",
            authorizations=[],
            url=None,
        )
        mock_client.finalize_order = AsyncMock(return_value=order_no_url)

        with (
            patch("est_adapter.ca.backend.ACMEClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
            pytest.raises(CABackendError, match="order URL"),
        ):
            backend.sign_csr(csr_info, validity_days=90, requestor_identity="test")

    def test_sign_csr_raises_when_order_has_no_certificate_url(
        self,
        backend: ACMECABackend,
        csr_info: CSRInfo,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """sign_csr raises CABackendError when poll_order returns no certificate URL."""
        from est_adapter.ca.acme_client import ACMEOrder as _ACMEOrder

        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_client = _build_mock_acme_client(leaf_cert, ca_cert)

        order_no_cert_url = _ACMEOrder(
            status="valid",
            finalize="https://acme.example.com/acme/order/1/finalize",
            authorizations=[],
            url="https://acme.example.com/acme/order/1",
            certificate=None,
        )
        mock_client.poll_order = AsyncMock(return_value=order_no_cert_url)

        with (
            patch("est_adapter.ca.backend.ACMEClient", return_value=mock_client),
            patch("est_adapter.ca.backend.log_certificate_issued"),
            pytest.raises(CABackendError, match="no certificate URL"),
        ):
            backend.sign_csr(csr_info, validity_days=90, requestor_identity="test")


# ---------------------------------------------------------------------------
# Factory function — create_ca_backend with ACME mode
# ---------------------------------------------------------------------------


class TestCreateCABackendAcme:
    """Tests for the create_ca_backend factory with CAMode.ACME."""

    def test_creates_acme_backend_when_mode_is_acme(self, tmp_path: Path) -> None:
        """create_ca_backend returns ACMECABackend when mode is ACME."""
        acme_cfg = _make_acme_config(tmp_path)
        config = CAConfig(mode=CAMode.ACME, acme=acme_cfg)

        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)

        assert isinstance(backend, ACMECABackend)

    def test_raises_when_acme_config_missing(self) -> None:
        """create_ca_backend raises CABackendError when acme config is None."""
        config = CAConfig(mode=CAMode.ACME, acme=None)

        with pytest.raises(CABackendError, match="requires 'acme' configuration"):
            create_ca_backend(config)

    def test_loads_ca_cert_from_file_when_provided(
        self,
        tmp_path: Path,
        ca_cert: x509.Certificate,
    ) -> None:
        """create_ca_backend pre-loads ca_cert when ca_cert_file is configured."""
        # Write CA cert to a temp file
        cert_file = tmp_path / "root_ca.pem"
        cert_file.write_bytes(encode_certificate_pem(ca_cert))

        acme_cfg = _make_acme_config(tmp_path, ca_cert_file=cert_file)
        config = CAConfig(mode=CAMode.ACME, acme=acme_cfg)

        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)

        assert isinstance(backend, ACMECABackend)
        assert backend._ca_cert is not None
        assert backend._ca_cert.serial_number == ca_cert.serial_number

    def test_raises_when_ca_cert_file_missing(self, tmp_path: Path) -> None:
        """create_ca_backend raises CABackendError when ca_cert_file does not exist."""
        acme_cfg = _make_acme_config(tmp_path, ca_cert_file=tmp_path / "nonexistent.pem")
        config = CAConfig(mode=CAMode.ACME, acme=acme_cfg)

        with pytest.raises(CABackendError, match="not initialized"):
            create_ca_backend(config)

    def test_raises_when_ca_cert_file_invalid(self, tmp_path: Path) -> None:
        """create_ca_backend raises CABackendError when ca_cert_file has bad content."""
        cert_file = tmp_path / "bad.pem"
        cert_file.write_text("THIS IS NOT A CERTIFICATE")

        acme_cfg = _make_acme_config(tmp_path, ca_cert_file=cert_file)
        config = CAConfig(mode=CAMode.ACME, acme=acme_cfg)

        with pytest.raises(CABackendError, match="Failed to load CA certificate"):
            create_ca_backend(config)

    def test_calls_log_ca_initialized(self, tmp_path: Path) -> None:
        """create_ca_backend calls log_ca_initialized with mode='acme'."""
        acme_cfg = _make_acme_config(tmp_path)
        config = CAConfig(mode=CAMode.ACME, acme=acme_cfg)

        with patch("est_adapter.ca.backend.log_ca_initialized") as mock_log:
            create_ca_backend(config)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["mode"] == "acme"

    def test_existing_modes_still_return_self_signed_backend(self, tmp_path: Path) -> None:
        """AUTO_GENERATE and PROVIDED modes still return SelfSignedCABackend."""
        config = CAConfig(
            mode=CAMode.AUTO_GENERATE,
            auto_generate={"storage_path": tmp_path / "ca_storage"},
        )
        with patch("est_adapter.ca.backend.log_ca_initialized"):
            backend = create_ca_backend(config)
        assert isinstance(backend, SelfSignedCABackend)
