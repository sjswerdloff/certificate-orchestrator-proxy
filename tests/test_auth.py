"""Contract tests for auth module.

Tests HTTP Basic and client certificate authentication.
"""

from __future__ import annotations

import base64

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from est_adapter.auth.handler import (
    AuthResult,
    BasicAuthHandler,
    ClientCertAuthHandler,
    CombinedAuthHandler,
    hash_password_for_config,
)
from est_adapter.config import (
    AuthConfig,
    AuthMethod,
    BasicAuthConfig,
    BasicAuthUser,
)

# --- Fixtures ---


@pytest.fixture
def test_password() -> str:
    """Test password."""
    return "test_password_123"


@pytest.fixture
def test_password_hash(test_password: str) -> str:
    """Hash of test password."""
    return hash_password_for_config(test_password)


@pytest.fixture
def basic_auth_config(test_password_hash: str) -> AuthConfig:
    """Auth config with basic auth enabled."""
    return AuthConfig(
        method=AuthMethod.BASIC,
        basic=BasicAuthConfig(
            users=[BasicAuthUser(username="testuser", password_hash=test_password_hash)],
        ),
    )


@pytest.fixture
def ca_key() -> rsa.RSAPrivateKey:
    """CA private key for generating test certificates."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def ca_certificate(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Self-signed CA certificate for trust anchor."""
    from datetime import UTC, datetime, timedelta

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture
def client_certificate(
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
) -> x509.Certificate:
    """Client certificate signed by CA."""
    from datetime import UTC, datetime, timedelta

    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Client"),
    ])

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture
def untrusted_certificate() -> x509.Certificate:
    """Client certificate NOT signed by trusted CA."""
    from datetime import UTC, datetime, timedelta

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted"),
    ])

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )


# --- AuthResult Tests ---


class TestAuthResult:
    """Tests for AuthResult dataclass."""

    def test_success_result(self) -> None:
        """Success result is authenticated with identity."""
        result = AuthResult.success(identity="testuser", method="basic")

        assert result.authenticated is True
        assert result.identity == "testuser"
        assert result.method == "basic"

    def test_failure_result(self) -> None:
        """Failure result is not authenticated."""
        result = AuthResult.failure(method="basic")

        assert result.authenticated is False
        assert result.identity == ""
        assert result.method == "basic"


# --- BasicAuthHandler Tests ---


class TestBasicAuthHandler:
    """Tests for HTTP Basic authentication handler."""

    def test_valid_credentials(
        self,
        test_password: str,
        test_password_hash: str,
    ) -> None:
        """Valid username and password authenticates successfully."""
        handler = BasicAuthHandler({"testuser": test_password_hash})
        auth_header = _make_basic_auth_header("testuser", test_password)

        result = handler.authenticate(auth_header)

        assert result.authenticated is True
        assert result.identity == "testuser"
        assert result.method == "basic"

    def test_invalid_password(self, test_password_hash: str) -> None:
        """Invalid password fails authentication."""
        handler = BasicAuthHandler({"testuser": test_password_hash})
        auth_header = _make_basic_auth_header("testuser", "wrong_password")

        result = handler.authenticate(auth_header)

        assert result.authenticated is False

    def test_unknown_user(self, test_password_hash: str) -> None:
        """Unknown username fails authentication."""
        handler = BasicAuthHandler({"testuser": test_password_hash})
        auth_header = _make_basic_auth_header("unknown", "any_password")

        result = handler.authenticate(auth_header)

        assert result.authenticated is False

    def test_no_auth_header(self, test_password_hash: str) -> None:
        """Missing auth header fails authentication."""
        handler = BasicAuthHandler({"testuser": test_password_hash})

        result = handler.authenticate(None)

        assert result.authenticated is False

    def test_wrong_auth_scheme(self, test_password_hash: str) -> None:
        """Non-Basic auth scheme fails."""
        handler = BasicAuthHandler({"testuser": test_password_hash})

        result = handler.authenticate("Bearer some_token")

        assert result.authenticated is False

    def test_malformed_credentials(self, test_password_hash: str) -> None:
        """Malformed base64 credentials fail."""
        handler = BasicAuthHandler({"testuser": test_password_hash})

        result = handler.authenticate("Basic not_valid_base64!!!")

        assert result.authenticated is False

    def test_from_config(self, basic_auth_config: AuthConfig) -> None:
        """Create handler from config."""
        handler = BasicAuthHandler.from_config(basic_auth_config)

        assert handler is not None


# --- ClientCertAuthHandler Tests ---


class TestClientCertAuthHandler:
    """Tests for client certificate authentication handler."""

    def test_valid_client_cert(
        self,
        ca_certificate: x509.Certificate,
        client_certificate: x509.Certificate,
    ) -> None:
        """Client cert signed by trusted CA authenticates."""
        handler = ClientCertAuthHandler([ca_certificate])

        result = handler.authenticate(client_certificate)

        assert result.authenticated is True
        assert "CN=Test Client" in result.identity
        assert result.method == "client_cert"

    def test_untrusted_client_cert(
        self,
        ca_certificate: x509.Certificate,
        untrusted_certificate: x509.Certificate,
    ) -> None:
        """Client cert NOT signed by trusted CA fails."""
        handler = ClientCertAuthHandler([ca_certificate])

        result = handler.authenticate(untrusted_certificate)

        assert result.authenticated is False

    def test_no_client_cert(self, ca_certificate: x509.Certificate) -> None:
        """Missing client cert fails authentication."""
        handler = ClientCertAuthHandler([ca_certificate])

        result = handler.authenticate(None)

        assert result.authenticated is False


# --- CombinedAuthHandler Tests ---


class TestCombinedAuthHandler:
    """Tests for combined authentication handler."""

    def test_basic_only_mode(
        self,
        basic_auth_config: AuthConfig,
        test_password: str,
    ) -> None:
        """Basic-only mode authenticates with valid credentials."""
        handler = CombinedAuthHandler.from_config(basic_auth_config)
        auth_header = _make_basic_auth_header("testuser", test_password)

        result = handler.authenticate(authorization_header=auth_header)

        assert result.authenticated is True
        assert result.method == "basic"

    def test_basic_only_fails_without_creds(
        self,
        basic_auth_config: AuthConfig,
    ) -> None:
        """Basic-only mode fails without credentials."""
        handler = CombinedAuthHandler.from_config(basic_auth_config)

        result = handler.authenticate()

        assert result.authenticated is False

    def test_from_config(self, basic_auth_config: AuthConfig) -> None:
        """Create handler from config."""
        handler = CombinedAuthHandler.from_config(basic_auth_config)

        assert handler is not None


# --- Utility Function Tests ---


class TestPasswordHashing:
    """Tests for password hashing utility."""

    def test_hash_password(self) -> None:
        """Hash password returns hex string."""
        result = hash_password_for_config("test123")

        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 hex digest

    def test_same_password_same_hash(self) -> None:
        """Same password produces same hash."""
        hash1 = hash_password_for_config("test123")
        hash2 = hash_password_for_config("test123")

        assert hash1 == hash2

    def test_different_password_different_hash(self) -> None:
        """Different passwords produce different hashes."""
        hash1 = hash_password_for_config("password1")
        hash2 = hash_password_for_config("password2")

        assert hash1 != hash2


# --- Helper Functions ---


def _make_basic_auth_header(username: str, password: str) -> str:
    """Create HTTP Basic auth header value."""
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"
