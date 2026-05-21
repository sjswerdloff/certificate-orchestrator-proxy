"""EST client implementation per RFC 7030.

Provides certificate enrollment, re-enrollment, and CA certificate
retrieval against any EST server (RFC 7030 compliant).
"""

from __future__ import annotations

import base64
import contextlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

# EST content types per RFC 7030
CONTENT_TYPE_PKCS7 = "application/pkcs7-mime"
CONTENT_TYPE_PKCS10 = "application/pkcs10"

# Type alias matching server-side
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

# HTTP status codes used in EST responses
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401


@dataclass
class EnrollmentResult:
    """Result of an EST enrollment operation.

    Attributes:
        certificate: The issued certificate.
        ca_chain: CA certificates from the server (if retrieved).
        private_key: The private key corresponding to the certificate.
    """

    certificate: x509.Certificate
    ca_chain: list[x509.Certificate] = field(default_factory=list)
    private_key: PrivateKey | None = None

    def save_certificate_pem(self, path: Path) -> None:
        """Save the issued certificate to a PEM file."""
        path.write_bytes(self.certificate.public_bytes(serialization.Encoding.PEM))

    def save_private_key_pem(self, path: Path, password: bytes | None = None) -> None:
        """Save the private key to a PEM file."""
        if self.private_key is None:
            msg = "No private key associated with this enrollment"
            raise ValueError(msg)
        encryption: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        )
        path.write_bytes(
            self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption,
            )
        )


class ESTClientError(Exception):
    """Base exception for EST client errors."""


class ESTAuthenticationError(ESTClientError):
    """Server rejected authentication (HTTP 401)."""


class ESTEnrollmentError(ESTClientError):
    """Server rejected the enrollment request."""


class ESTServerError(ESTClientError):
    """Server returned an unexpected error."""


@dataclass
class KryptonianDeviceIdentity:
    """Device identity for Kryptonian Gateway activation-code enrollment.

    The Kryptonian Gateway extends EST with a one-time activation code
    bootstrap flow. The admin registers a device alias, the gateway generates
    an activation code, and the device presents its identity during enrollment.

    See: https://github.com/AAPM-RT-SEC/RTSec.Kryptonian

    Attributes:
        activation_code: One-time bootstrap code from the gateway admin.
        manufacturer: Device manufacturer name.
        model: Device model identifier.
        serial_number: Device serial number.
    """

    activation_code: str
    manufacturer: str
    model: str
    serial_number: str

    def to_headers(self) -> dict[str, str]:
        """Convert to HTTP headers for Kryptonian EST enrollment."""
        return {
            "X-Activation-Code": self.activation_code,
            "X-Device-Manufacturer": self.manufacturer,
            "X-Device-Model": self.model,
            "X-Device-Serial-Number": self.serial_number,
        }


class ESTClient:
    """Client for EST (Enrollment over Secure Transport) per RFC 7030.

    Supports:
    - GET /cacerts: Retrieve CA certificates
    - POST /simpleenroll: Initial certificate enrollment
    - POST /simplereenroll: Certificate re-enrollment/renewal

    Authentication methods:
    - HTTP Basic (username/password)
    - Mutual TLS (client certificate)

    Args:
        base_url: EST server URL (e.g., "https://est.example.com").
        username: Username for HTTP Basic auth.
        password: Password for HTTP Basic auth.
        client_cert: Path to client certificate PEM for mutual TLS.
        client_key: Path to client key PEM for mutual TLS.
        ca_bundle: Path to CA bundle for server TLS verification,
            or False to disable verification (not recommended).
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        *,
        username: str | None = None,
        password: str | None = None,
        client_cert: Path | str | None = None,
        client_key: Path | str | None = None,
        ca_bundle: Path | str | bool = True,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._est_path = "/.well-known/est"
        self._timeout = timeout

        # Build auth
        auth: httpx.BasicAuth | None = None
        if username and password:
            auth = httpx.BasicAuth(username, password)

        # Build TLS cert pair
        cert: tuple[str, str] | str | None = None
        if client_cert and client_key:
            cert = (str(client_cert), str(client_key))
        elif client_cert:
            cert = str(client_cert)

        verify: str | bool = str(ca_bundle) if isinstance(ca_bundle, Path) else ca_bundle

        self._client = httpx.Client(
            base_url=self._base_url,
            auth=auth,
            cert=cert,
            verify=verify,
            timeout=timeout,
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def get_ca_certs(self) -> list[x509.Certificate]:
        """Retrieve CA certificates from the EST server.

        Returns:
            List of CA certificates from the server's PKCS#7 response.

        Raises:
            ESTServerError: If the server returns an error.
        """
        response = self._client.get(f"{self._est_path}/cacerts")

        if response.status_code != HTTP_OK:
            msg = f"GET /cacerts failed: HTTP {response.status_code}"
            raise ESTServerError(msg)

        return _parse_pkcs7_response(response.content)

    def simple_enroll(
        self,
        csr: x509.CertificateSigningRequest,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> x509.Certificate:
        """Enroll by submitting a CSR.

        Args:
            csr: A signed certificate signing request.
            extra_headers: Additional HTTP headers (e.g., for Kryptonian activation).

        Returns:
            The issued certificate.

        Raises:
            ESTAuthenticationError: If authentication fails (HTTP 401).
            ESTEnrollmentError: If the CSR is rejected (HTTP 4xx).
            ESTServerError: For other server errors.
        """
        body = _encode_csr(csr)

        headers: dict[str, str] = {"Content-Type": CONTENT_TYPE_PKCS10}
        if extra_headers:
            headers.update(extra_headers)

        response = self._client.post(
            f"{self._est_path}/simpleenroll",
            content=body,
            headers=headers,
        )

        return _handle_enroll_response(response, "simpleenroll")

    def simple_reenroll(
        self,
        csr: x509.CertificateSigningRequest,
    ) -> x509.Certificate:
        """Re-enroll (renew) by submitting a CSR.

        Args:
            csr: A signed certificate signing request.

        Returns:
            The issued certificate.

        Raises:
            ESTAuthenticationError: If authentication fails (HTTP 401).
            ESTEnrollmentError: If the CSR is rejected (HTTP 4xx).
            ESTServerError: For other server errors.
        """
        body = _encode_csr(csr)

        response = self._client.post(
            f"{self._est_path}/simplereenroll",
            content=body,
            headers={"Content-Type": CONTENT_TYPE_PKCS10},
        )

        return _handle_enroll_response(response, "simplereenroll")

    def enroll(
        self,
        common_name: str,
        *,
        key_size: int = 2048,
        san_dns_names: list[str] | None = None,
        organization: str | None = None,
        kryptonian_device: KryptonianDeviceIdentity | None = None,
        renewal: bool = False,
    ) -> EnrollmentResult:
        """High-level enrollment or renewal: generate key, create CSR, enroll.

        Convenience method that handles key generation and CSR creation.

        Args:
            common_name: Subject CN for the certificate.
            key_size: RSA key size in bits.
            san_dns_names: Optional Subject Alternative Name DNS entries.
            organization: Optional organization name for the subject.
            kryptonian_device: Optional Kryptonian Gateway device identity
                for activation-code enrollment.
            renewal: If True, use simplereenroll (requires mTLS with
                existing device certificate for authentication).

        Returns:
            EnrollmentResult with certificate and private key.
        """
        # Generate key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Build CSR
        name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        if organization:
            name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

        builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(name_attrs))

        if san_dns_names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns_names]),
                critical=False,
            )

        csr = builder.sign(private_key, hashes.SHA256())

        # Build extra headers for Kryptonian if provided
        extra_headers = kryptonian_device.to_headers() if kryptonian_device else None

        # Enroll or renew
        certificate = self.simple_reenroll(csr) if renewal else self.simple_enroll(csr, extra_headers=extra_headers)

        # Optionally get CA chain
        ca_chain: list[x509.Certificate] = []
        with contextlib.suppress(ESTServerError):
            ca_chain = self.get_ca_certs()

        return EnrollmentResult(
            certificate=certificate,
            ca_chain=ca_chain,
            private_key=private_key,
        )


def _encode_csr(csr: x509.CertificateSigningRequest) -> bytes:
    """Encode CSR as PEM for EST protocol submission."""
    return csr.public_bytes(serialization.Encoding.PEM)


def _parse_pkcs7_response(content: bytes) -> list[x509.Certificate]:
    """Parse a base64-encoded PKCS#7 response into certificates."""
    try:
        der_bytes = base64.b64decode(content)
    except Exception as e:
        msg = f"Failed to decode base64 PKCS#7 response: {e}"
        raise ESTServerError(msg) from e

    try:
        return pkcs7.load_der_pkcs7_certificates(der_bytes)
    except Exception as e:
        msg = f"Failed to parse PKCS#7 certificates: {e}"
        raise ESTServerError(msg) from e


def _handle_enroll_response(response: httpx.Response, endpoint: str) -> x509.Certificate:
    """Handle enrollment response, raising appropriate errors."""
    if response.status_code == HTTP_UNAUTHORIZED:
        msg = f"Authentication failed for {endpoint}"
        raise ESTAuthenticationError(msg)

    if response.status_code == HTTP_BAD_REQUEST:
        msg = f"CSR rejected by {endpoint}: {response.text}"
        raise ESTEnrollmentError(msg)

    if response.status_code != HTTP_OK:
        msg = f"{endpoint} failed: HTTP {response.status_code}: {response.text}"
        raise ESTServerError(msg)

    certs = _parse_pkcs7_response(response.content)
    if not certs:
        msg = f"No certificate in {endpoint} response"
        raise ESTServerError(msg)

    return certs[0]
