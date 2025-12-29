"""Authentication handlers for EST adapter.

Supports HTTP Basic authentication and client certificate authentication.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import bcrypt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from est_adapter.audit.logger import log_auth_attempt
from est_adapter.config import AuthConfig, AuthMethod
from est_adapter.exceptions import AuthenticationError


@dataclass(frozen=True)
class AuthResult:
    """Result of authentication attempt."""

    authenticated: bool
    identity: str
    method: str

    @classmethod
    def success(cls, identity: str, method: str) -> AuthResult:
        """Create successful authentication result."""
        return cls(authenticated=True, identity=identity, method=method)

    @classmethod
    def failure(cls, method: str) -> AuthResult:
        """Create failed authentication result."""
        return cls(authenticated=False, identity="", method=method)


class BasicAuthHandler:
    """HTTP Basic authentication handler."""

    def __init__(self, users: dict[str, str]) -> None:
        """Initialize with username to password hash mapping.

        Args:
            users: Dictionary mapping usernames to password hashes.
        """
        self._users = users

    @classmethod
    def from_config(cls, config: AuthConfig) -> BasicAuthHandler:
        """Create handler from configuration."""
        users = {user.username: user.password_hash for user in config.basic.users}
        return cls(users)

    def authenticate(
        self,
        authorization_header: str | None,
    ) -> AuthResult:
        """Authenticate using HTTP Basic credentials.

        Args:
            authorization_header: The Authorization header value.

        Returns:
            AuthResult indicating success or failure.
        """
        if not authorization_header:
            log_auth_attempt(method="basic", success=False, reason="no credentials")
            return AuthResult.failure("basic")

        # Parse Basic auth header
        if not authorization_header.startswith("Basic "):
            log_auth_attempt(
                method="basic",
                success=False,
                reason="invalid auth scheme",
            )
            return AuthResult.failure("basic")

        try:
            encoded = authorization_header[6:]  # Remove "Basic " prefix
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            log_auth_attempt(
                method="basic",
                success=False,
                reason="malformed credentials",
            )
            return AuthResult.failure("basic")

        # Look up user
        stored_hash = self._users.get(username)
        if not stored_hash:
            # Perform dummy bcrypt check to prevent timing attacks
            _verify_password("dummy", "$2b$12$" + "0" * 53)
            log_auth_attempt(
                method="basic",
                success=False,
                username=username,
                reason="unknown user",
            )
            return AuthResult.failure("basic")

        # Verify password using bcrypt (timing-safe by design)
        if not _verify_password(password, stored_hash):
            log_auth_attempt(
                method="basic",
                success=False,
                username=username,
                reason="invalid password",
            )
            return AuthResult.failure("basic")

        log_auth_attempt(method="basic", success=True, username=username)
        return AuthResult.success(identity=username, method="basic")


class ClientCertAuthHandler:
    """Client certificate authentication handler."""

    def __init__(self, trust_anchors: list[x509.Certificate]) -> None:
        """Initialize with trusted CA certificates.

        Args:
            trust_anchors: List of trusted CA certificates.
        """
        self._trust_anchors = trust_anchors

    @classmethod
    def from_config(cls, config: AuthConfig) -> ClientCertAuthHandler | None:
        """Create handler from configuration.

        Returns None if client cert auth is not configured.
        """
        if config.client_cert is None:
            return None

        trust_path = Path(config.client_cert.trust_anchors)
        trust_anchors = _load_certificates(trust_path)
        return cls(trust_anchors)

    def authenticate(
        self,
        client_cert: x509.Certificate | None,
    ) -> AuthResult:
        """Authenticate using client certificate.

        Performs cryptographic verification including:
        - Signature verification against trusted CA public key
        - Validity period checking (not before/not after)

        Args:
            client_cert: The client's X.509 certificate.

        Returns:
            AuthResult indicating success or failure.
        """
        if client_cert is None:
            log_auth_attempt(
                method="client_cert",
                success=False,
                reason="no certificate",
            )
            return AuthResult.failure("client_cert")

        # Extract subject for identification
        subject = client_cert.subject.rfc4514_string()

        # Check certificate validity period
        now = datetime.now(UTC)
        if now < client_cert.not_valid_before_utc:
            log_auth_attempt(
                method="client_cert",
                success=False,
                client_cert_subject=subject,
                reason="certificate not yet valid",
            )
            return AuthResult.failure("client_cert")

        if now > client_cert.not_valid_after_utc:
            log_auth_attempt(
                method="client_cert",
                success=False,
                client_cert_subject=subject,
                reason="certificate expired",
            )
            return AuthResult.failure("client_cert")

        # Find matching trust anchor and verify signature
        issuer = client_cert.issuer
        verified = False

        for anchor in self._trust_anchors:
            if issuer == anchor.subject:
                # Found potential issuer - verify signature cryptographically
                try:
                    _verify_certificate_signature(client_cert, anchor)
                    verified = True
                    break
                except Exception:  # noqa: S112 - expected: trying multiple anchors
                    # Signature doesn't match this anchor, try next
                    continue

        if not verified:
            log_auth_attempt(
                method="client_cert",
                success=False,
                client_cert_subject=subject,
                reason="untrusted issuer or invalid signature",
            )
            return AuthResult.failure("client_cert")

        log_auth_attempt(
            method="client_cert",
            success=True,
            client_cert_subject=subject,
        )
        return AuthResult.success(identity=subject, method="client_cert")


class CombinedAuthHandler:
    """Combined authentication handler supporting multiple methods."""

    def __init__(
        self,
        method: AuthMethod,
        basic_handler: BasicAuthHandler | None,
        client_cert_handler: ClientCertAuthHandler | None,
    ) -> None:
        """Initialize with configured handlers.

        Args:
            method: The configured authentication method.
            basic_handler: HTTP Basic auth handler (if configured).
            client_cert_handler: Client cert auth handler (if configured).
        """
        self._method = method
        self._basic_handler = basic_handler
        self._client_cert_handler = client_cert_handler

    @classmethod
    def from_config(cls, config: AuthConfig) -> CombinedAuthHandler:
        """Create combined handler from configuration."""
        basic_handler = BasicAuthHandler.from_config(config)
        client_cert_handler = ClientCertAuthHandler.from_config(config)
        return cls(
            method=config.method,
            basic_handler=basic_handler,
            client_cert_handler=client_cert_handler,
        )

    def authenticate(
        self,
        authorization_header: str | None = None,
        client_cert: x509.Certificate | None = None,
    ) -> AuthResult:
        """Authenticate using configured method(s).

        Args:
            authorization_header: HTTP Authorization header.
            client_cert: Client X.509 certificate.

        Returns:
            AuthResult indicating success or failure.

        Raises:
            AuthenticationError: If authentication is required but fails.
        """
        if self._method == AuthMethod.BASIC:
            if self._basic_handler is None:
                msg = "Basic auth not configured"
                raise AuthenticationError(msg)
            return self._basic_handler.authenticate(authorization_header)

        if self._method == AuthMethod.CLIENT_CERT:
            if self._client_cert_handler is None:
                msg = "Client cert auth not configured"
                raise AuthenticationError(msg)
            return self._client_cert_handler.authenticate(client_cert)

        if self._method == AuthMethod.BOTH:
            # Try client cert first (stronger), then basic
            if self._client_cert_handler and client_cert:
                result = self._client_cert_handler.authenticate(client_cert)
                if result.authenticated:
                    return result

            if self._basic_handler and authorization_header:
                return self._basic_handler.authenticate(authorization_header)

            return AuthResult.failure("both")

        msg = f"Unknown auth method: {self._method}"
        raise AuthenticationError(msg)


def _verify_certificate_signature(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
) -> None:
    """Verify certificate signature against issuer's public key.

    Args:
        cert: Certificate to verify.
        issuer_cert: Issuer certificate containing public key.

    Raises:
        Exception: If signature verification fails.
    """
    public_key = issuer_cert.public_key()
    signature = cert.signature
    data = cert.tbs_certificate_bytes
    sig_hash = cert.signature_hash_algorithm

    if sig_hash is None:
        msg = "Certificate has no signature hash algorithm"
        raise ValueError(msg)

    if isinstance(public_key, rsa.RSAPublicKey):
        # RSA verification with PKCS1v15 padding
        public_key.verify(signature, data, padding.PKCS1v15(), sig_hash)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        # EC verification with ECDSA
        public_key.verify(signature, data, ec.ECDSA(sig_hash))
    else:
        msg = f"Unsupported public key type: {type(public_key)}"
        raise TypeError(msg)


def _verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored bcrypt hash.

    Args:
        password: Plain text password to verify.
        stored_hash: bcrypt hash from configuration.

    Returns:
        True if password matches, False otherwise.
    """
    try:
        return bool(bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")))
    except (ValueError, TypeError):
        # Invalid hash format - fail securely
        return False


def _load_certificates(path: Path) -> list[x509.Certificate]:
    """Load certificates from a PEM file.

    Args:
        path: Path to PEM file containing one or more certificates.

    Returns:
        List of certificates.

    Raises:
        AuthenticationError: If file cannot be loaded.
    """
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        msg = f"Trust anchors file not found: {path}"
        raise AuthenticationError(msg) from None
    except Exception as e:
        msg = f"Failed to load trust anchors: {e}"
        raise AuthenticationError(msg) from e

    # Parse all certificates from PEM file
    certificates: list[x509.Certificate] = []
    pem_marker = b"-----BEGIN CERTIFICATE-----"

    parts = data.split(pem_marker)
    for part in parts[1:]:  # Skip empty first part
        cert_pem = pem_marker + part
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            certificates.append(cert)
        except Exception:  # noqa: S112 - intentionally skip malformed certs
            continue

    if not certificates:
        msg = f"No valid certificates found in: {path}"
        raise AuthenticationError(msg)

    return certificates


def hash_password_for_config(password: str, rounds: int = 12) -> str:
    """Hash a password for use in configuration file.

    This is a utility function for administrators to generate
    password hashes for the config file. Uses bcrypt with configurable
    work factor.

    Args:
        password: Plain text password.
        rounds: bcrypt work factor (default 12, higher = more secure but slower).

    Returns:
        bcrypt hash suitable for config file.
    """
    salt = bcrypt.gensalt(rounds=rounds)
    return str(bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8"))
