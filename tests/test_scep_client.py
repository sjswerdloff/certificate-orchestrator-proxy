"""Unit tests for SCEPClient.

All HTTP calls are mocked via httpx.Client patching so no real network
connections are made.  Tests verify Protocol contracts:
- get_ca_cert parses DER and PKCS7 responses correctly
- enroll builds and posts a valid PKCSReq, then parses the CertRep
- error paths raise CABackendError with informative messages
- context-manager protocol works

Note on pyscep (temporary stand-in):
    _build_pkcs_req now delegates to pyscep for CMS construction.
    _parse_cert_rep now delegates to pyscep for CertRep parsing.
    The enroll() tests mock _parse_cert_rep at the module level to isolate
    transport-layer contracts from CMS parsing details.  Dedicated tests for
    _build_pkcs_req verify the output bytes are a valid DER SEQUENCE.
    TODO(scep-native): simplify tests once pyscep is replaced with native impl.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    serialize_certificates,
)
from cryptography.x509.oid import NameOID

from est_adapter.ca.scep_client import (
    SCEPClient,
    _build_ephemeral_cert,
    _build_pkcs_req,
    _is_ca_cert,
)
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


def _make_self_signed_cert(
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    cn: str = "Test CA",
    is_ca: bool = True,
) -> x509.Certificate:
    """Build a minimal self-signed certificate for testing."""
    now = datetime.now(UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )


def _make_leaf_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    cn: str = "device.example.com",
) -> x509.Certificate:
    """Build a leaf certificate signed by the given CA."""
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


def _make_csr_der(cn: str = "device.example.com") -> bytes:
    """Build a DER-encoded PKCS#10 CSR."""
    key = _make_rsa_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    return csr.public_bytes(Encoding.DER)


def _make_mock_response(
    status_code: int = 200,
    content: bytes = b"",
    content_type: str = "application/x-x509-ca-cert",
    text: str = "",
) -> MagicMock:
    """Build a mock httpx.Response."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.content = content
    mock.text = text
    mock.headers = {"Content-Type": content_type}
    return mock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ca_key() -> rsa.RSAPrivateKey:
    """RSA CA private key."""
    return _make_rsa_key()


@pytest.fixture
def ca_cert(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Self-signed CA certificate."""
    return _make_self_signed_cert(ca_key, cn="Test SCEP CA", is_ca=True)


@pytest.fixture
def ephem_key() -> rsa.RSAPrivateKey:
    """Ephemeral RSA key for SCEP transaction signing."""
    return _make_rsa_key()


@pytest.fixture
def ephem_cert(ephem_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Ephemeral self-signed certificate."""
    return _build_ephemeral_cert(ephem_key, cn="SCEP Client")


@pytest.fixture
def leaf_cert(ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Leaf certificate issued by test CA."""
    return _make_leaf_cert(ca_cert, ca_key)


@pytest.fixture
def csr_der() -> bytes:
    """DER-encoded PKCS#10 CSR."""
    return _make_csr_der()


@pytest.fixture
def scep_client() -> SCEPClient:
    """SCEPClient instance with TLS verification disabled."""
    return SCEPClient("https://ca.example.com/scep/scep", verify_tls=False)


# ---------------------------------------------------------------------------
# Helper function unit tests
# ---------------------------------------------------------------------------


class TestBuildEphemeralCert:
    """Tests for the _build_ephemeral_cert helper."""

    def test_returns_x509_certificate(self) -> None:
        """_build_ephemeral_cert returns an x509.Certificate."""
        key = _make_rsa_key()
        cert = _build_ephemeral_cert(key)
        assert isinstance(cert, x509.Certificate)

    def test_cert_has_matching_public_key(self) -> None:
        """The ephemeral cert's public key matches the provided key."""
        key = _make_rsa_key()
        cert = _build_ephemeral_cert(key)
        key_nums = key.public_key().public_numbers()
        cert_nums = cert.public_key().public_numbers()
        assert key_nums.n == cert_nums.n

    def test_cert_is_not_ca(self) -> None:
        """Ephemeral cert is not a CA cert (BasicConstraints CA=False)."""
        key = _make_rsa_key()
        cert = _build_ephemeral_cert(key)
        assert not _is_ca_cert(cert)

    def test_cert_has_custom_cn(self) -> None:
        """Ephemeral cert uses the provided CN."""
        key = _make_rsa_key()
        cert = _build_ephemeral_cert(key, cn="My SCEP Client")
        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn_attr) == 1
        assert cn_attr[0].value == "My SCEP Client"

    def test_cert_valid_for_24_hours(self) -> None:
        """Ephemeral cert expires roughly 24 hours after creation."""
        key = _make_rsa_key()
        cert = _build_ephemeral_cert(key)
        duration = cert.not_valid_after_utc - cert.not_valid_before_utc
        # Allow some clock skew buffer (cert is backdated 5 min)
        assert duration.total_seconds() > 23 * 3600
        assert duration.total_seconds() < 25 * 3600


class TestIsCaCert:
    """Tests for the _is_ca_cert helper."""

    def test_ca_cert_returns_true(self, ca_cert: x509.Certificate) -> None:
        """CA certificate returns True."""
        assert _is_ca_cert(ca_cert) is True

    def test_leaf_cert_returns_false(self, leaf_cert: x509.Certificate) -> None:
        """Leaf certificate returns False."""
        assert _is_ca_cert(leaf_cert) is False

    def test_cert_without_basic_constraints_returns_false(self) -> None:
        """Certificate without BasicConstraints extension returns False."""
        key = _make_rsa_key()
        now = datetime.now(UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No Extensions")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        assert _is_ca_cert(cert) is False


class TestBuildPkcsReq:
    """Tests for the _build_pkcs_req helper.

    _build_pkcs_req now delegates to pyscep (temporary stand-in) for CMS
    construction.  We test the contract — the output bytes — not the
    internal implementation.
    """

    def test_returns_bytes(
        self,
        csr_der: bytes,
        ca_cert: x509.Certificate,
        ephem_cert: x509.Certificate,
        ephem_key: rsa.RSAPrivateKey,
    ) -> None:
        """_build_pkcs_req returns non-empty bytes."""
        result = _build_pkcs_req(csr_der, ca_cert, ephem_cert, ephem_key)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_result_is_der_sequence(
        self,
        csr_der: bytes,
        ca_cert: x509.Certificate,
        ephem_cert: x509.Certificate,
        ephem_key: rsa.RSAPrivateKey,
    ) -> None:
        """PKCSReq is a DER-encoded SEQUENCE (starts with 0x30)."""
        result = _build_pkcs_req(csr_der, ca_cert, ephem_cert, ephem_key)
        assert result[0] == 0x30

    def test_different_csrs_produce_different_output(
        self,
        ca_cert: x509.Certificate,
        ephem_cert: x509.Certificate,
        ephem_key: rsa.RSAPrivateKey,
    ) -> None:
        """Different CSR inputs produce different PKCSReq messages."""
        csr1 = _make_csr_der("device1.example.com")
        csr2 = _make_csr_der("device2.example.com")
        req1 = _build_pkcs_req(csr1, ca_cert, ephem_cert, ephem_key)
        req2 = _build_pkcs_req(csr2, ca_cert, ephem_cert, ephem_key)
        assert req1 != req2


# ---------------------------------------------------------------------------
# SCEPClient.get_ca_cert
# ---------------------------------------------------------------------------


class TestGetCaCert:
    """Tests for SCEPClient.get_ca_cert."""

    def test_parses_der_cert_response(
        self,
        scep_client: SCEPClient,
        ca_cert: x509.Certificate,
    ) -> None:
        """get_ca_cert parses a DER-encoded certificate response."""
        der = ca_cert.public_bytes(Encoding.DER)
        mock_resp = _make_mock_response(content=der, content_type="application/x-x509-ca-cert")

        with patch.object(scep_client._http, "get", return_value=mock_resp):
            result = scep_client.get_ca_cert()

        assert isinstance(result, x509.Certificate)
        assert result.serial_number == ca_cert.serial_number

    def test_parses_pkcs7_response(
        self,
        scep_client: SCEPClient,
        ca_cert: x509.Certificate,
    ) -> None:
        """get_ca_cert parses a PKCS7-encoded certificate response."""
        # Serialize as PKCS7 (as returned for RA certs or multi-cert scenarios)
        pkcs7_der = serialize_certificates([ca_cert], Encoding.DER)
        mock_resp = _make_mock_response(content=pkcs7_der, content_type="application/x-x509-ca-ra-cert")

        with patch.object(scep_client._http, "get", return_value=mock_resp):
            result = scep_client.get_ca_cert()

        assert isinstance(result, x509.Certificate)
        assert result.serial_number == ca_cert.serial_number

    def test_raises_on_http_error_status(self, scep_client: SCEPClient) -> None:
        """get_ca_cert raises CABackendError on non-200 HTTP response."""
        mock_resp = _make_mock_response(status_code=500, content=b"Internal Error")

        with (
            patch.object(scep_client._http, "get", return_value=mock_resp),
            pytest.raises(CABackendError, match="SCEP enrollment failed"),
        ):
            scep_client.get_ca_cert()

    def test_raises_on_connection_error(self, scep_client: SCEPClient) -> None:
        """get_ca_cert raises CABackendError on connection failure."""
        import httpx

        with (
            patch.object(scep_client._http, "get", side_effect=httpx.ConnectError("refused")),
            pytest.raises(CABackendError, match="SCEP connection error"),
        ):
            scep_client.get_ca_cert()

    def test_raises_on_invalid_der_content(self, scep_client: SCEPClient) -> None:
        """get_ca_cert raises CABackendError when DER content is not a valid cert."""
        mock_resp = _make_mock_response(content=b"THIS IS NOT A CERT", content_type="application/x-x509-ca-cert")

        with (
            patch.object(scep_client._http, "get", return_value=mock_resp),
            pytest.raises(CABackendError, match="SCEP enrollment failed"),
        ):
            scep_client.get_ca_cert()

    def test_requests_get_ca_cert_operation(self, scep_client: SCEPClient, ca_cert: x509.Certificate) -> None:
        """get_ca_cert sends GET to ?operation=GetCACert."""
        der = ca_cert.public_bytes(Encoding.DER)
        mock_resp = _make_mock_response(content=der)
        captured_urls: list[str] = []

        def capturing_get(url: str, **kwargs: Any) -> MagicMock:
            captured_urls.append(url)
            return mock_resp

        with patch.object(scep_client._http, "get", side_effect=capturing_get):
            scep_client.get_ca_cert()

        assert len(captured_urls) == 1
        assert "operation=GetCACert" in captured_urls[0]


# ---------------------------------------------------------------------------
# SCEPClient.enroll
#
# The enroll() tests mock _parse_cert_rep at the module level to isolate
# the transport-layer contract (correct URL, headers, body) from the CMS
# parsing that pyscep handles.  _parse_cert_rep is tested separately.
#
# Similarly, _build_pkcs_req is mocked to return a fixed sentinel so the
# tests do not depend on pyscep being installed and working in CI.
# ---------------------------------------------------------------------------

_SENTINEL_PKCS_REQ = b"\x30\x00"  # minimal valid-looking DER for mocking


class TestEnroll:
    """Tests for SCEPClient.enroll — transport-layer contract."""

    def test_enroll_posts_to_pki_operation(
        self,
        scep_client: SCEPClient,
        csr_der: bytes,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """enroll POSTs to ?operation=PKIOperation."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_resp = _make_mock_response(content=b"certrepbytes", content_type="application/x-pki-message")

        captured_urls: list[str] = []

        def capturing_post(url: str, **kwargs: Any) -> MagicMock:
            captured_urls.append(url)
            return mock_resp

        ephem_key = _make_rsa_key()

        with (
            patch("est_adapter.ca.scep_client._build_pkcs_req", return_value=_SENTINEL_PKCS_REQ),
            patch("est_adapter.ca.scep_client._parse_cert_rep", return_value=leaf_cert),
            patch.object(scep_client._http, "post", side_effect=capturing_post),
        ):
            scep_client.enroll(csr_der, "secret", ca_cert, ephem_key)

        assert len(captured_urls) == 1
        assert "operation=PKIOperation" in captured_urls[0]

    def test_enroll_sends_correct_content_type(
        self,
        scep_client: SCEPClient,
        csr_der: bytes,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """enroll sends Content-Type: application/x-pki-message."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_resp = _make_mock_response(content=b"certrepbytes", content_type="application/x-pki-message")

        captured_headers: list[dict[str, str]] = []

        def capturing_post(url: str, **kwargs: Any) -> MagicMock:
            captured_headers.append(kwargs.get("headers", {}))
            return mock_resp

        ephem_key = _make_rsa_key()

        with (
            patch("est_adapter.ca.scep_client._build_pkcs_req", return_value=_SENTINEL_PKCS_REQ),
            patch("est_adapter.ca.scep_client._parse_cert_rep", return_value=leaf_cert),
            patch.object(scep_client._http, "post", side_effect=capturing_post),
        ):
            scep_client.enroll(csr_der, "secret", ca_cert, ephem_key)

        assert len(captured_headers) == 1
        assert captured_headers[0].get("Content-Type") == "application/x-pki-message"

    def test_enroll_sends_pkcs_req_as_body(
        self,
        scep_client: SCEPClient,
        csr_der: bytes,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """enroll sends the output of _build_pkcs_req as the POST body."""
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_resp = _make_mock_response(content=b"certrepbytes", content_type="application/x-pki-message")

        captured_bodies: list[bytes] = []

        def capturing_post(url: str, **kwargs: Any) -> MagicMock:
            captured_bodies.append(kwargs.get("content", b""))
            return mock_resp

        ephem_key = _make_rsa_key()
        sentinel_body = b"\x30\x82\xab\xcd"

        with (
            patch("est_adapter.ca.scep_client._build_pkcs_req", return_value=sentinel_body),
            patch("est_adapter.ca.scep_client._parse_cert_rep", return_value=leaf_cert),
            patch.object(scep_client._http, "post", side_effect=capturing_post),
        ):
            scep_client.enroll(csr_der, "secret", ca_cert, ephem_key)

        assert len(captured_bodies) == 1
        assert captured_bodies[0] == sentinel_body

    def test_enroll_raises_on_http_error(
        self,
        scep_client: SCEPClient,
        csr_der: bytes,
        ca_cert: x509.Certificate,
    ) -> None:
        """enroll raises CABackendError on HTTP 500."""
        ephem_key = _make_rsa_key()
        mock_resp = _make_mock_response(status_code=500, content=b"Error", text="Error")

        with (
            patch("est_adapter.ca.scep_client._build_pkcs_req", return_value=_SENTINEL_PKCS_REQ),
            patch.object(scep_client._http, "post", return_value=mock_resp),
            pytest.raises(CABackendError, match="SCEP enrollment failed"),
        ):
            scep_client.enroll(csr_der, "secret", ca_cert, ephem_key)

    def test_enroll_raises_on_connection_error(
        self,
        scep_client: SCEPClient,
        csr_der: bytes,
        ca_cert: x509.Certificate,
    ) -> None:
        """enroll raises CABackendError on connection failure."""
        import httpx

        ephem_key = _make_rsa_key()

        with (
            patch("est_adapter.ca.scep_client._build_pkcs_req", return_value=_SENTINEL_PKCS_REQ),
            patch.object(scep_client._http, "post", side_effect=httpx.ConnectError("refused")),
            pytest.raises(CABackendError, match="SCEP connection error"),
        ):
            scep_client.enroll(csr_der, "secret", ca_cert, ephem_key)

    def test_enroll_with_ec_signing_key_uses_ephemeral_rsa(
        self,
        scep_client: SCEPClient,
        csr_der: bytes,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """enroll generates an ephemeral RSA key when given an EC signing key."""
        ec_key = _make_ec_key()
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_resp = _make_mock_response(content=b"certrepbytes", content_type="application/x-pki-message")

        captured_build_args: list[tuple[Any, ...]] = []

        def capturing_build(
            csr: bytes, ca: Any, sign_cert: Any, sign_key: Any, challenge_password: str | None = None
        ) -> bytes:
            captured_build_args.append((csr, ca, sign_cert, sign_key))
            return _SENTINEL_PKCS_REQ

        with (
            patch("est_adapter.ca.scep_client._build_pkcs_req", side_effect=capturing_build),
            patch("est_adapter.ca.scep_client._parse_cert_rep", return_value=leaf_cert),
            patch.object(scep_client._http, "post", return_value=mock_resp),
        ):
            result = scep_client.enroll(csr_der, "secret", ca_cert, ec_key)

        assert isinstance(result, x509.Certificate)
        # The signing key passed to _build_pkcs_req must be RSA (ephemeral), not EC
        _, _, _, build_sign_key = captured_build_args[0]
        assert isinstance(build_sign_key, rsa.RSAPrivateKey)

    def test_enroll_returns_what_parse_cert_rep_returns(
        self,
        scep_client: SCEPClient,
        csr_der: bytes,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """enroll returns the certificate that _parse_cert_rep returns."""
        ephem_key = _make_rsa_key()
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_resp = _make_mock_response(content=b"certrepbytes", content_type="application/x-pki-message")

        with (
            patch("est_adapter.ca.scep_client._build_pkcs_req", return_value=_SENTINEL_PKCS_REQ),
            patch("est_adapter.ca.scep_client._parse_cert_rep", return_value=leaf_cert),
            patch.object(scep_client._http, "post", return_value=mock_resp),
        ):
            result = scep_client.enroll(csr_der, "secret", ca_cert, ephem_key)

        assert result.serial_number == leaf_cert.serial_number
        assert not _is_ca_cert(result)

    def test_enroll_uses_encryption_cert_when_provided(
        self,
        scep_client: SCEPClient,
        csr_der: bytes,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """enroll passes encryption_cert to _build_pkcs_req as recipient when provided."""
        ephem_key = _make_rsa_key()
        encryption_key = _make_rsa_key()
        encryption_cert = _make_self_signed_cert(encryption_key, cn="RA Decrypter", is_ca=False)
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_resp = _make_mock_response(content=b"certrepbytes", content_type="application/x-pki-message")

        captured_recipient: list[x509.Certificate] = []

        def capturing_build(
            csr: bytes, recipient: x509.Certificate, sign_cert: Any, sign_key: Any, challenge_password: str | None = None
        ) -> bytes:
            captured_recipient.append(recipient)
            return _SENTINEL_PKCS_REQ

        with (
            patch("est_adapter.ca.scep_client._build_pkcs_req", side_effect=capturing_build),
            patch("est_adapter.ca.scep_client._parse_cert_rep", return_value=leaf_cert),
            patch.object(scep_client._http, "post", return_value=mock_resp),
        ):
            scep_client.enroll(csr_der, "secret", ca_cert, ephem_key, encryption_cert=encryption_cert)

        assert len(captured_recipient) == 1
        assert captured_recipient[0].serial_number == encryption_cert.serial_number

    def test_enroll_uses_ca_cert_as_recipient_when_no_encryption_cert(
        self,
        scep_client: SCEPClient,
        csr_der: bytes,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> None:
        """enroll passes ca_cert to _build_pkcs_req when no encryption_cert is given."""
        ephem_key = _make_rsa_key()
        leaf_cert = _make_leaf_cert(ca_cert, ca_key)
        mock_resp = _make_mock_response(content=b"certrepbytes", content_type="application/x-pki-message")

        captured_recipient: list[x509.Certificate] = []

        def capturing_build(
            csr: bytes, recipient: x509.Certificate, sign_cert: Any, sign_key: Any, challenge_password: str | None = None
        ) -> bytes:
            captured_recipient.append(recipient)
            return _SENTINEL_PKCS_REQ

        with (
            patch("est_adapter.ca.scep_client._build_pkcs_req", side_effect=capturing_build),
            patch("est_adapter.ca.scep_client._parse_cert_rep", return_value=leaf_cert),
            patch.object(scep_client._http, "post", return_value=mock_resp),
        ):
            scep_client.enroll(csr_der, "secret", ca_cert, ephem_key)

        assert len(captured_recipient) == 1
        assert captured_recipient[0].serial_number == ca_cert.serial_number


# ---------------------------------------------------------------------------
# Context manager protocol
# ---------------------------------------------------------------------------


class TestContextManager:
    """Tests for SCEPClient context-manager support."""

    def test_context_manager_closes_http_client(self) -> None:
        """Exiting the context manager closes the HTTP client."""
        client = SCEPClient("https://ca.example.com/scep/scep", verify_tls=False)
        with patch.object(client._http, "close") as mock_close, client:
            pass
        mock_close.assert_called_once()

    def test_with_statement_returns_client(self) -> None:
        """The context manager yields the SCEPClient itself."""
        client = SCEPClient("https://ca.example.com/scep/scep", verify_tls=False)
        with client as ctx:
            assert ctx is client
        client.close()  # Manual cleanup since we exited context manager

    def test_close_idempotent(self) -> None:
        """Calling close() twice does not raise."""
        client = SCEPClient("https://ca.example.com/scep/scep", verify_tls=False)
        client.close()
        client.close()  # Should not raise


# ---------------------------------------------------------------------------
# Constructor / TLS options
# ---------------------------------------------------------------------------


class TestConstructor:
    """Tests for SCEPClient constructor options."""

    def test_default_url_stored(self) -> None:
        """SCEP URL is stored on the client."""
        client = SCEPClient("https://ca.example.com/scep/scep")
        assert client._scep_url == "https://ca.example.com/scep/scep"
        client.close()

    def test_trailing_slash_stripped(self) -> None:
        """Trailing slash is stripped from the SCEP URL."""
        client = SCEPClient("https://ca.example.com/scep/scep/")
        assert not client._scep_url.endswith("/")
        client.close()

    def test_verify_false_disables_tls(self) -> None:
        """verify_tls=False configures httpx to skip certificate verification."""
        with patch("est_adapter.ca.scep_client.httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = MagicMock()
            SCEPClient("https://ca.example.com/scep/scep", verify_tls=False)
        mock_client_cls.assert_called_once_with(verify=False)

    def test_custom_ca_cert_path_used(self) -> None:
        """ca_cert_path is passed to httpx.Client verify parameter."""
        with patch("est_adapter.ca.scep_client.httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = MagicMock()
            SCEPClient("https://ca.example.com/scep/scep", verify_tls=True, ca_cert_path="/path/to/ca.pem")
        mock_client_cls.assert_called_once_with(verify="/path/to/ca.pem")
