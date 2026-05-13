"""Contract tests for auth module.

Tests HTTP Basic and client certificate authentication.
"""

from __future__ import annotations

import base64
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from est_adapter.auth.handler import (
    AuthResult,
    BasicAuthHandler,
    ClientCertAuthHandler,
    CombinedAuthHandler,
    _load_certificates,
    _verify_certificate_signature,
    hash_password_for_config,
)
from est_adapter.config import (
    AuthConfig,
    AuthMethod,
    BasicAuthConfig,
    BasicAuthUser,
    ClientCertAuthConfig,
)
from est_adapter.exceptions import AuthenticationError

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

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ],
    )

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
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Client"),
        ],
    )

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
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted"),
        ],
    )

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
        """Hash password returns bcrypt string."""
        result = hash_password_for_config("test123")

        assert isinstance(result, str)
        assert result.startswith("$2b$")  # bcrypt identifier
        assert len(result) == 60  # bcrypt hash length

    def test_password_verifies(self) -> None:
        """Password verifies against its hash."""
        import bcrypt

        test_password = "test123"  # noqa: S105 - test credential
        hashed = hash_password_for_config(test_password)

        # bcrypt.checkpw verifies password against hash
        assert bcrypt.checkpw(test_password.encode("utf-8"), hashed.encode("utf-8"))

    def test_different_password_different_hash(self) -> None:
        """Different passwords produce different hashes."""
        hash1 = hash_password_for_config("password1")
        hash2 = hash_password_for_config("password2")

        assert hash1 != hash2


# --- Additional Fixtures ---


@pytest.fixture
def ec_ca_key() -> ec.EllipticCurvePrivateKey:
    """EC CA private key for generating EC-signed test certificates."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def ec_ca_certificate(ec_ca_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """Self-signed EC CA certificate for trust anchor."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test EC CA"),
        ],
    )

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ec_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ec_ca_key, hashes.SHA256())
    )


@pytest.fixture
def ec_client_certificate(
    ec_ca_key: ec.EllipticCurvePrivateKey,
    ec_ca_certificate: x509.Certificate,
) -> x509.Certificate:
    """Client certificate signed by EC CA."""
    client_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "EC Test Client"),
        ],
    )

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ec_ca_certificate.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(ec_ca_key, hashes.SHA256())
    )


@pytest.fixture
def expired_client_certificate(
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
) -> x509.Certificate:
    """Client certificate that is expired (not_valid_after in the past)."""
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Expired Client"),
        ],
    )

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=730))
        .not_valid_after(datetime.now(UTC) - timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture
def future_client_certificate(
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
) -> x509.Certificate:
    """Client certificate whose validity period has not yet started."""
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Future Client"),
        ],
    )

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) + timedelta(days=30))
        .not_valid_after(datetime.now(UTC) + timedelta(days=395))
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture
def wrong_ca_signed_cert(
    ca_certificate: x509.Certificate,
) -> x509.Certificate:
    """Certificate whose issuer DN matches the trusted CA but is signed by a different key.

    This tests the case where the issuer field matches but signature verification fails,
    meaning the code must reach the 'continue' branch after catching the verification exception.
    """
    # Different key - not the real CA key
    rogue_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Forged Client"),
        ],
    )

    # Use the trusted CA's subject as issuer but sign with a rogue key
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)  # issuer DN matches trust anchor
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(rogue_ca_key, hashes.SHA256())  # signed by wrong key
    )


@pytest.fixture
def trust_anchor_pem_file(ca_certificate: x509.Certificate) -> Path:
    """Write CA certificate to a temp PEM file and return path."""
    pem_bytes = ca_certificate.public_bytes(serialization.Encoding.PEM)
    tmp = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    tmp.write(pem_bytes)
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


@pytest.fixture
def multi_cert_pem_file(
    ca_certificate: x509.Certificate,
    ec_ca_certificate: x509.Certificate,
) -> Path:
    """PEM file containing two certificates."""
    pem_bytes = ca_certificate.public_bytes(serialization.Encoding.PEM)
    pem_bytes += ec_ca_certificate.public_bytes(serialization.Encoding.PEM)
    tmp = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    tmp.write(pem_bytes)
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


@pytest.fixture
def client_cert_auth_config(trust_anchor_pem_file: Path) -> AuthConfig:
    """Auth config with client cert auth enabled."""
    return AuthConfig(
        method=AuthMethod.CLIENT_CERT,
        client_cert=ClientCertAuthConfig(trust_anchors=trust_anchor_pem_file),
    )


@pytest.fixture
def both_auth_config(
    trust_anchor_pem_file: Path,
    test_password_hash: str,
) -> AuthConfig:
    """Auth config with BOTH auth method enabled."""
    return AuthConfig(
        method=AuthMethod.BOTH,
        basic=BasicAuthConfig(
            users=[BasicAuthUser(username="testuser", password_hash=test_password_hash)],
        ),
        client_cert=ClientCertAuthConfig(trust_anchors=trust_anchor_pem_file),
    )


# --- Additional ClientCertAuthHandler Tests ---


class TestClientCertAuthHandlerExtended:
    """Additional tests for certificate validity and signature verification."""

    def test_expired_certificate_is_rejected(
        self,
        ca_certificate: x509.Certificate,
        expired_client_certificate: x509.Certificate,
    ) -> None:
        """Expired certificate must be rejected — not_valid_after is a hard security boundary."""
        handler = ClientCertAuthHandler([ca_certificate])

        result = handler.authenticate(expired_client_certificate)

        # Security property: a time-expired cert must NEVER authenticate
        assert result.authenticated is False
        assert result.method == "client_cert"

    def test_not_yet_valid_certificate_is_rejected(
        self,
        ca_certificate: x509.Certificate,
        future_client_certificate: x509.Certificate,
    ) -> None:
        """Certificate whose validity period has not started must be rejected."""
        handler = ClientCertAuthHandler([ca_certificate])

        result = handler.authenticate(future_client_certificate)

        # Security property: presenting a cert before its activation window is an anomaly
        assert result.authenticated is False
        assert result.method == "client_cert"

    def test_issuer_dn_match_but_wrong_signature_is_rejected(
        self,
        ca_certificate: x509.Certificate,
        wrong_ca_signed_cert: x509.Certificate,
    ) -> None:
        """Certificate forged with matching issuer DN but wrong signing key must be rejected.

        This is the critical anti-spoofing test: an attacker can craft a certificate
        whose issuer DN matches a trusted CA, but without the CA's private key the
        cryptographic signature will not verify. The handler must reject it.
        """
        handler = ClientCertAuthHandler([ca_certificate])

        result = handler.authenticate(wrong_ca_signed_cert)

        # Security property: DN match alone is not sufficient; cryptographic
        # signature must verify against the trust anchor's actual public key
        assert result.authenticated is False
        assert result.method == "client_cert"

    def test_ec_signed_certificate_authenticates(
        self,
        ec_ca_certificate: x509.Certificate,
        ec_client_certificate: x509.Certificate,
    ) -> None:
        """Certificate signed by an EC CA (ECDSA) authenticates correctly."""
        handler = ClientCertAuthHandler([ec_ca_certificate])

        result = handler.authenticate(ec_client_certificate)

        assert result.authenticated is True
        assert "CN=EC Test Client" in result.identity
        assert result.method == "client_cert"

    def test_from_config_loads_trust_anchors(
        self,
        client_cert_auth_config: AuthConfig,
    ) -> None:
        """from_config creates handler when client_cert section is configured."""
        handler = ClientCertAuthHandler.from_config(client_cert_auth_config)

        assert handler is not None

    def test_from_config_returns_none_when_not_configured(self) -> None:
        """from_config returns None when client_cert section is absent."""
        config = AuthConfig(method=AuthMethod.BASIC)

        handler = ClientCertAuthHandler.from_config(config)

        assert handler is None

    def test_multiple_trust_anchors_correct_one_used(
        self,
        ca_certificate: x509.Certificate,
        ec_ca_certificate: x509.Certificate,
        ec_client_certificate: x509.Certificate,
    ) -> None:
        """With multiple trust anchors, the correct issuer is found and used."""
        # Load both CAs; client cert was issued by ec_ca_certificate
        handler = ClientCertAuthHandler([ca_certificate, ec_ca_certificate])

        result = handler.authenticate(ec_client_certificate)

        assert result.authenticated is True
        assert result.method == "client_cert"


# --- CombinedAuthHandler Extended Tests ---


class TestCombinedAuthHandlerExtended:
    """Tests for CombinedAuthHandler covering all auth method branches."""

    def test_basic_method_raises_when_handler_not_configured(self) -> None:
        """BASIC method with no basic_handler raises AuthenticationError (misconfiguration)."""
        handler = CombinedAuthHandler(
            method=AuthMethod.BASIC,
            basic_handler=None,
            client_cert_handler=None,
        )

        with pytest.raises(AuthenticationError) as exc_info:
            handler.authenticate(authorization_header="Basic dGVzdDp0ZXN0")

        # Security property: a misconfigured auth system must fail hard, not silently pass
        assert "Basic auth not configured" in str(exc_info.value)

    def test_client_cert_method_authenticates_with_valid_cert(
        self,
        client_cert_auth_config: AuthConfig,
        ca_certificate: x509.Certificate,
        client_certificate: x509.Certificate,
    ) -> None:
        """CLIENT_CERT method authenticates a valid client certificate."""
        handler = CombinedAuthHandler.from_config(client_cert_auth_config)

        result = handler.authenticate(client_cert=client_certificate)

        assert result.authenticated is True
        assert result.method == "client_cert"

    def test_client_cert_method_raises_when_handler_not_configured(self) -> None:
        """CLIENT_CERT method with no cert_handler raises AuthenticationError."""
        handler = CombinedAuthHandler(
            method=AuthMethod.CLIENT_CERT,
            basic_handler=None,
            client_cert_handler=None,
        )

        with pytest.raises(AuthenticationError) as exc_info:
            handler.authenticate()

        assert "Client cert auth not configured" in str(exc_info.value)

    def test_both_method_cert_succeeds_basic_not_attempted(
        self,
        both_auth_config: AuthConfig,
        client_certificate: x509.Certificate,
    ) -> None:
        """BOTH mode: a valid client cert authenticates without needing basic credentials."""
        handler = CombinedAuthHandler.from_config(both_auth_config)

        result = handler.authenticate(client_cert=client_certificate)

        # Security property: stronger auth (cert) is preferred and sufficient on its own
        assert result.authenticated is True
        assert result.method == "client_cert"

    def test_both_method_falls_back_to_basic_when_cert_fails(
        self,
        both_auth_config: AuthConfig,
        untrusted_certificate: x509.Certificate,
        test_password: str,
    ) -> None:
        """BOTH mode: if cert fails, valid basic credentials still authenticate."""
        handler = CombinedAuthHandler.from_config(both_auth_config)
        auth_header = _make_basic_auth_header("testuser", test_password)

        result = handler.authenticate(
            authorization_header=auth_header,
            client_cert=untrusted_certificate,
        )

        assert result.authenticated is True
        assert result.method == "basic"

    def test_both_method_fails_when_neither_provided(
        self,
        both_auth_config: AuthConfig,
    ) -> None:
        """BOTH mode: no credentials at all yields failure, not an error."""
        handler = CombinedAuthHandler.from_config(both_auth_config)

        result = handler.authenticate()

        assert result.authenticated is False
        assert result.method == "both"

    def test_both_method_only_basic_present_no_cert(
        self,
        both_auth_config: AuthConfig,
        test_password: str,
    ) -> None:
        """BOTH mode: basic credentials alone authenticate when no cert provided."""
        handler = CombinedAuthHandler.from_config(both_auth_config)
        auth_header = _make_basic_auth_header("testuser", test_password)

        result = handler.authenticate(authorization_header=auth_header)

        assert result.authenticated is True
        assert result.method == "basic"

    def test_both_method_only_cert_present_no_basic(
        self,
        both_auth_config: AuthConfig,
        client_certificate: x509.Certificate,
    ) -> None:
        """BOTH mode: valid cert alone authenticates when no basic header provided."""
        handler = CombinedAuthHandler.from_config(both_auth_config)

        result = handler.authenticate(client_cert=client_certificate)

        assert result.authenticated is True
        assert result.method == "client_cert"

    def test_unknown_method_raises_authentication_error(self) -> None:
        """An unknown/unexpected AuthMethod value raises AuthenticationError."""
        # Bypass enum validation to construct an invalid state
        handler = CombinedAuthHandler(
            method="totally_unknown",  # type: ignore[arg-type]
            basic_handler=None,
            client_cert_handler=None,
        )

        with pytest.raises(AuthenticationError) as exc_info:
            handler.authenticate()

        assert "Unknown auth method" in str(exc_info.value)


# --- _verify_certificate_signature Tests ---


class TestVerifyCertificateSignature:
    """Direct tests for the cryptographic signature verification helper."""

    def test_rsa_signed_cert_verifies(
        self,
        ca_key: rsa.RSAPrivateKey,
        ca_certificate: x509.Certificate,
        client_certificate: x509.Certificate,
    ) -> None:
        """RSA-signed certificate verifies successfully against issuing CA."""
        # Should not raise
        _verify_certificate_signature(client_certificate, ca_certificate)

    def test_ec_signed_cert_verifies(
        self,
        ec_ca_certificate: x509.Certificate,
        ec_client_certificate: x509.Certificate,
    ) -> None:
        """EC-signed certificate verifies successfully against issuing EC CA."""
        # Should not raise
        _verify_certificate_signature(ec_client_certificate, ec_ca_certificate)

    def test_wrong_key_raises(
        self,
        ca_certificate: x509.Certificate,
        wrong_ca_signed_cert: x509.Certificate,
    ) -> None:
        """Signature verification raises when signed by a different key."""
        with pytest.raises(Exception):  # cryptography raises InvalidSignature
            _verify_certificate_signature(wrong_ca_signed_cert, ca_certificate)

    def test_unsupported_key_type_raises_type_error(
        self,
        ca_certificate: x509.Certificate,
        client_certificate: x509.Certificate,
    ) -> None:
        """Unsupported public key type raises TypeError with descriptive message."""
        mock_issuer = MagicMock()
        mock_issuer.public_key.return_value = MagicMock()  # not RSA or EC

        with pytest.raises(TypeError) as exc_info:
            _verify_certificate_signature(client_certificate, mock_issuer)

        assert "Unsupported public key type" in str(exc_info.value)

    def test_no_signature_hash_algorithm_raises_value_error(
        self,
        ca_certificate: x509.Certificate,
    ) -> None:
        """Certificate with no signature hash algorithm raises ValueError."""
        mock_cert = MagicMock()
        mock_cert.signature_hash_algorithm = None

        with pytest.raises(ValueError, match="no signature hash algorithm"):
            _verify_certificate_signature(mock_cert, ca_certificate)


# --- _load_certificates Tests ---


class TestLoadCertificates:
    """Tests for the PEM certificate loading helper."""

    def test_loads_single_certificate(
        self,
        trust_anchor_pem_file: Path,
    ) -> None:
        """Loads exactly one certificate from a single-cert PEM file."""
        certs = _load_certificates(trust_anchor_pem_file)

        assert len(certs) == 1
        assert isinstance(certs[0], x509.Certificate)

    def test_loads_multiple_certificates(
        self,
        multi_cert_pem_file: Path,
    ) -> None:
        """Loads all certificates from a multi-cert PEM file."""
        certs = _load_certificates(multi_cert_pem_file)

        assert len(certs) == 2

    def test_missing_file_raises_authentication_error(self) -> None:
        """Missing PEM file raises AuthenticationError (not FileNotFoundError propagated)."""
        missing = Path("/nonexistent/path/trust.pem")

        with pytest.raises(AuthenticationError) as exc_info:
            _load_certificates(missing)

        # Security property: error message must identify the missing path
        # so operators can diagnose misconfigurations quickly
        assert "Trust anchors file not found" in str(exc_info.value)
        assert str(missing) in str(exc_info.value)

    def test_unreadable_file_raises_authentication_error(
        self,
        trust_anchor_pem_file: Path,
    ) -> None:
        """Generic I/O error loading the file raises AuthenticationError."""
        with patch("pathlib.Path.read_bytes", side_effect=OSError("permission denied")):
            with pytest.raises(AuthenticationError) as exc_info:
                _load_certificates(trust_anchor_pem_file)

        assert "Failed to load trust anchors" in str(exc_info.value)

    def test_empty_file_raises_authentication_error(self) -> None:
        """PEM file with no valid certificate blocks raises AuthenticationError."""
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="wb") as f:
            f.write(b"not a certificate at all\n")
            empty_path = Path(f.name)

        with pytest.raises(AuthenticationError) as exc_info:
            _load_certificates(empty_path)

        assert "No valid certificates found" in str(exc_info.value)

    def test_pem_with_malformed_cert_skips_and_loads_valid(
        self,
        ca_certificate: x509.Certificate,
    ) -> None:
        """PEM file containing one malformed block and one valid cert loads the valid cert."""
        valid_pem = ca_certificate.public_bytes(serialization.Encoding.PEM)
        # Construct a syntactically plausible but cryptographically invalid block
        corrupt_block = b"-----BEGIN CERTIFICATE-----\nTGhpcyBpcyBub3QgYSB2YWxpZCBjZXJ0\n-----END CERTIFICATE-----\n"

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="wb") as f:
            f.write(corrupt_block + valid_pem)
            mixed_path = Path(f.name)

        certs = _load_certificates(mixed_path)

        # Malformed block is silently skipped; valid cert is loaded
        assert len(certs) == 1
        assert isinstance(certs[0], x509.Certificate)


# --- BasicAuthHandler Security Property Tests ---


class TestBasicAuthSecurityProperties:
    """Security-focused tests for BasicAuthHandler edge cases."""

    def test_credentials_without_colon_fail_gracefully(
        self,
        test_password_hash: str,
    ) -> None:
        """Base64-encoded credentials missing the colon separator fail without error."""
        handler = BasicAuthHandler({"testuser": test_password_hash})
        # Base64 of "nodivider" — no colon
        encoded = base64.b64encode(b"nodivider").decode("ascii")
        auth_header = f"Basic {encoded}"

        result = handler.authenticate(auth_header)

        # Security property: malformed credentials must fail, not crash or pass
        assert result.authenticated is False
        assert result.method == "basic"

    def test_corrupted_bcrypt_hash_fails_securely(self) -> None:
        """A stored hash that is malformed (not valid bcrypt) causes authentication to fail, not crash.

        This guards against a config corruption scenario where a corrupted hash entry
        would otherwise allow all passwords to match.
        """
        handler = BasicAuthHandler({"testuser": "not_a_valid_bcrypt_hash"})
        auth_header = _make_basic_auth_header("testuser", "any_password")

        result = handler.authenticate(auth_header)

        # Security property: invalid hash format must produce failure, not exception or pass
        assert result.authenticated is False
        assert result.method == "basic"

    def test_password_with_colon_authenticates_correctly(
        self,
        test_password_hash: str,
    ) -> None:
        """Password containing a colon character is parsed correctly via split(':', 1)."""
        password_with_colon = "pass:word:with:colons"
        import bcrypt

        hashed = bcrypt.hashpw(password_with_colon.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode()
        handler = BasicAuthHandler({"testuser": hashed})
        auth_header = _make_basic_auth_header("testuser", password_with_colon)

        result = handler.authenticate(auth_header)

        assert result.authenticated is True
        assert result.identity == "testuser"

    def test_unknown_user_returns_failure_not_error(self, test_password_hash: str) -> None:
        """Unknown user returns AuthResult.failure, not raises, preserving the method field."""
        handler = BasicAuthHandler({"testuser": test_password_hash})
        auth_header = _make_basic_auth_header("nonexistent", "any_password")

        result = handler.authenticate(auth_header)

        assert result.authenticated is False
        assert result.identity == ""
        assert result.method == "basic"

    def test_hash_rounds_parameter_applied(self) -> None:
        """hash_password_for_config respects the rounds parameter (work factor)."""
        import bcrypt

        hashed = hash_password_for_config("password", rounds=4)
        # bcrypt cost factor is encoded in the hash string: $2b$<rounds>$...
        assert bcrypt.checkpw(b"password", hashed.encode("utf-8"))
        assert "$2b$04$" in hashed


# --- Helper Functions ---


def _make_basic_auth_header(username: str, password: str) -> str:
    """Create HTTP Basic auth header value."""
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"
