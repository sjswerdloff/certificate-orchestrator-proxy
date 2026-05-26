"""Contract tests for ACMEClient.

Tests the ACME client module in isolation with mocked httpx responses.
Verifies JWS signing, key authorization, protocol state machine, and
error handling — without making real network calls.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding as CryptoEncoding
from cryptography.x509.oid import NameOID

from est_adapter.ca.acme_client import (
    ACMEChallenge,
    ACMEClient,
    ACMEDirectory,
    ACMEOrder,
    _b64url,
    _int_to_32bytes,
    _split_pem,
)
from est_adapter.exceptions import CABackendError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_decode(s: str) -> bytes:
    """Decode a base64url string without padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _make_p256_key() -> ec.EllipticCurvePrivateKey:
    """Generate an EC P-256 key for tests."""
    return ec.generate_private_key(ec.SECP256R1())


def _make_mock_response(
    status_code: int,
    json_body: dict | None = None,
    headers: dict | None = None,
    content: bytes | None = None,
) -> MagicMock:
    """Build a MagicMock that looks like an httpx.Response.

    Args:
        status_code: HTTP status code.
        json_body: Optional dict returned by .json().
        headers: Optional response headers dict.
        content: Optional raw bytes for .content.

    Returns:
        Configured MagicMock instance.
    """
    mock = MagicMock()
    mock.status_code = status_code
    mock.headers = headers or {}
    if json_body is not None:
        mock.json.return_value = json_body
    if content is not None:
        mock.content = content
    return mock


def _make_directory_json() -> dict:
    """Return a minimal ACME directory JSON dict."""
    return {
        "newNonce": "https://acme.example.com/acme/new-nonce",
        "newAccount": "https://acme.example.com/acme/new-account",
        "newOrder": "https://acme.example.com/acme/new-order",
        "revokeCert": "https://acme.example.com/acme/revoke-cert",
        "keyChange": "https://acme.example.com/acme/key-change",
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def account_key() -> ec.EllipticCurvePrivateKey:
    """EC P-256 account key."""
    return _make_p256_key()


@pytest.fixture
def client(account_key: ec.EllipticCurvePrivateKey) -> ACMEClient:
    """ACMEClient with mocked httpx (verify_tls=False avoids real TLS)."""
    return ACMEClient(
        directory_url="https://acme.example.com/acme/directory",
        account_key=account_key,
        verify_tls=False,
    )


@pytest.fixture
def client_with_kid(account_key: ec.EllipticCurvePrivateKey) -> ACMEClient:
    """ACMEClient pre-seeded with an account KID."""
    return ACMEClient(
        directory_url="https://acme.example.com/acme/directory",
        account_key=account_key,
        account_kid="https://acme.example.com/acme/acct/1",
        verify_tls=False,
    )


# ---------------------------------------------------------------------------
# Module-level pure-function tests
# ---------------------------------------------------------------------------


class TestB64Url:
    """Tests for _b64url helper."""

    def test_empty_bytes(self) -> None:
        """_b64url of empty bytes is empty string."""
        assert _b64url(b"") == ""

    def test_no_padding(self) -> None:
        """_b64url never includes '=' padding."""
        result = _b64url(b"hello")
        assert "=" not in result

    def test_url_safe_charset(self) -> None:
        """_b64url uses '-' and '_' not '+' and '/'."""
        # bytes that would produce + or / in standard base64
        data = b"\xfb\xff\xfe"
        result = _b64url(data)
        assert "+" not in result
        assert "/" not in result

    def test_round_trip(self) -> None:
        """_b64url is decodable back to the original bytes."""
        original = b"RFC 8555 ACME test data"
        encoded = _b64url(original)
        assert _b64url_decode(encoded) == original


class TestIntTo32Bytes:
    """Tests for _int_to_32bytes helper."""

    def test_zero(self) -> None:
        """Zero is 32 zero bytes."""
        assert _int_to_32bytes(0) == b"\x00" * 32

    def test_one(self) -> None:
        """1 encodes as 31 zeros followed by 0x01."""
        result = _int_to_32bytes(1)
        assert len(result) == 32
        assert result[-1] == 1
        assert result[:-1] == b"\x00" * 31

    def test_known_value(self) -> None:
        """Known value encodes correctly."""
        n = 0xFF
        result = _int_to_32bytes(n)
        assert len(result) == 32
        assert result[-1] == 0xFF

    def test_big_endian(self) -> None:
        """Encoding is big-endian."""
        n = 0x0102
        result = _int_to_32bytes(n)
        assert result[-2] == 0x01
        assert result[-1] == 0x02


class TestSplitPem:
    """Tests for _split_pem helper."""

    def test_single_cert(self) -> None:
        """Split returns one block for a single PEM cert."""
        pem = b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"
        blocks = _split_pem(pem)
        assert len(blocks) == 1

    def test_two_certs(self) -> None:
        """Split returns two blocks for two concatenated PEM certs."""
        block = b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"
        blocks = _split_pem(block + block)
        assert len(blocks) == 2

    def test_empty_input(self) -> None:
        """Split of empty bytes returns empty list."""
        assert _split_pem(b"") == []


# ---------------------------------------------------------------------------
# JWK and thumbprint tests
# ---------------------------------------------------------------------------


class TestJwkDict:
    """Tests for ACMEClient._jwk_dict()."""

    def test_kty_is_ec(self, client: ACMEClient) -> None:
        """JWK kty is 'EC'."""
        jwk = client._jwk_dict()
        assert jwk["kty"] == "EC"

    def test_crv_is_p256(self, client: ACMEClient) -> None:
        """JWK crv is 'P-256'."""
        jwk = client._jwk_dict()
        assert jwk["crv"] == "P-256"

    def test_x_y_are_base64url(self, client: ACMEClient) -> None:
        """JWK x and y coordinates are non-empty base64url strings."""
        jwk = client._jwk_dict()
        for coord in ("x", "y"):
            assert "=" not in jwk[coord]
            assert len(jwk[coord]) > 0

    def test_x_y_decode_to_32_bytes(self, client: ACMEClient) -> None:
        """Decoded x and y are exactly 32 bytes (P-256 requirement)."""
        jwk = client._jwk_dict()
        for coord in ("x", "y"):
            decoded = _b64url_decode(jwk[coord])
            assert len(decoded) == 32, f"Coordinate {coord} should be 32 bytes"

    def test_x_y_match_key(self, client: ACMEClient, account_key: ec.EllipticCurvePrivateKey) -> None:
        """JWK x, y coordinates match the actual public key numbers."""
        pub_numbers = account_key.public_key().public_numbers()
        jwk = client._jwk_dict()
        assert _b64url_decode(jwk["x"]) == _int_to_32bytes(pub_numbers.x)
        assert _b64url_decode(jwk["y"]) == _int_to_32bytes(pub_numbers.y)


class TestThumbprint:
    """Tests for ACMEClient._thumbprint()."""

    def test_returns_string(self, client: ACMEClient) -> None:
        """Thumbprint is a non-empty string."""
        tp = client._thumbprint()
        assert isinstance(tp, str)
        assert len(tp) > 0

    def test_no_padding(self, client: ACMEClient) -> None:
        """Thumbprint has no '=' padding."""
        assert "=" not in client._thumbprint()

    def test_sha256_of_canonical_jwk(self, client: ACMEClient) -> None:
        """Thumbprint is SHA-256 of the lexicographic JWK dict."""
        jwk = client._jwk_dict()
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        expected = _b64url(hashlib.sha256(canonical).digest())
        assert client._thumbprint() == expected

    def test_stable_across_calls(self, client: ACMEClient) -> None:
        """Same key always produces same thumbprint."""
        assert client._thumbprint() == client._thumbprint()


class TestKeyAuthorization:
    """Tests for ACMEClient.key_authorization()."""

    def test_format_is_token_dot_thumbprint(self, client: ACMEClient) -> None:
        """Key authorization is 'token.thumbprint'."""
        token = "abc123"
        result = client.key_authorization(token)
        expected_thumbprint = client._thumbprint()
        assert result == f"{token}.{expected_thumbprint}"

    def test_contains_no_extra_dots(self, client: ACMEClient) -> None:
        """Key authorization has exactly one dot separator."""
        result = client.key_authorization("tokenvalue")
        assert result.count(".") == 1

    def test_different_tokens_give_different_results(self, client: ACMEClient) -> None:
        """Different tokens produce different key authorizations."""
        assert client.key_authorization("token_a") != client.key_authorization("token_b")


# ---------------------------------------------------------------------------
# _build_jws tests
# ---------------------------------------------------------------------------


class TestBuildJws:
    """Tests for ACMEClient._build_jws()."""

    def test_produces_valid_json(self, client_with_kid: ACMEClient) -> None:
        """_build_jws produces parseable JSON."""
        jws = client_with_kid._build_jws({"test": True}, "https://example.com", "nonce123")
        parsed = json.loads(jws)
        assert "protected" in parsed
        assert "payload" in parsed
        assert "signature" in parsed

    def test_protected_contains_alg_nonce_url_kid(self, client_with_kid: ACMEClient) -> None:
        """Protected header has alg, nonce, url, kid fields."""
        jws = client_with_kid._build_jws({"x": 1}, "https://example.com/order", "n1")
        parsed = json.loads(jws)
        protected = json.loads(_b64url_decode(parsed["protected"]))
        assert protected["alg"] == "ES256"
        assert protected["nonce"] == "n1"
        assert protected["url"] == "https://example.com/order"
        assert protected["kid"] == "https://acme.example.com/acme/acct/1"

    def test_protected_uses_jwk_when_no_kid(self, client: ACMEClient) -> None:
        """Protected header includes jwk when use_kid=False."""
        jws = client._build_jws({}, "https://example.com/new-account", "n2", use_kid=False)
        parsed = json.loads(jws)
        protected = json.loads(_b64url_decode(parsed["protected"]))
        assert "jwk" in protected
        assert protected["jwk"]["kty"] == "EC"
        assert "kid" not in protected

    def test_post_as_get_has_empty_payload(self, client_with_kid: ACMEClient) -> None:
        """POST-as-GET (payload='') produces empty string payload field."""
        jws = client_with_kid._build_jws("", "https://example.com/auth/1", "n3")
        parsed = json.loads(jws)
        assert parsed["payload"] == ""

    def test_dict_payload_is_b64url_json(self, client_with_kid: ACMEClient) -> None:
        """Dict payload is base64url-encoded JSON."""
        payload = {"csr": "abc"}
        jws = client_with_kid._build_jws(payload, "https://example.com/finalize", "n4")
        parsed = json.loads(jws)
        decoded_payload = json.loads(_b64url_decode(parsed["payload"]))
        assert decoded_payload == payload

    def test_raises_when_kid_required_but_not_set(self, client: ACMEClient) -> None:
        """_build_jws raises CABackendError when KID needed but not set."""
        with pytest.raises(CABackendError, match="Account KID not set"):
            client._build_jws({}, "https://example.com/order", "n5", use_kid=True)

    def test_signature_is_verifiable(self, client_with_kid: ACMEClient, account_key: ec.EllipticCurvePrivateKey) -> None:
        """JWS signature verifies against the account public key."""
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        jws_str = client_with_kid._build_jws({"order": "test"}, "https://example.com", "n6")
        parsed = json.loads(jws_str)

        protected_b64 = parsed["protected"]
        payload_b64 = parsed["payload"]
        signing_input = f"{protected_b64}.{payload_b64}".encode()

        raw_sig = _b64url_decode(parsed["signature"])
        assert len(raw_sig) == 64  # 32 bytes r + 32 bytes s
        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        der_sig = encode_dss_signature(r, s)

        # Verification raises if signature is invalid
        from cryptography.hazmat.primitives.asymmetric import ec as ec_module

        account_key.public_key().verify(der_sig, signing_input, ec_module.ECDSA(hashes.SHA256()))


# ---------------------------------------------------------------------------
# fetch_directory tests
# ---------------------------------------------------------------------------


class TestFetchDirectory:
    """Tests for ACMEClient.fetch_directory()."""

    @pytest.mark.asyncio
    async def test_returns_directory(self, client: ACMEClient) -> None:
        """fetch_directory parses all URL fields from JSON response."""
        dir_json = _make_directory_json()
        mock_resp = _make_mock_response(200, dir_json, headers={"Replay-Nonce": "nonce1"})

        with patch.object(client._http, "get", return_value=mock_resp):
            directory = await client.fetch_directory()

        assert isinstance(directory, ACMEDirectory)
        assert directory.new_nonce == dir_json["newNonce"]
        assert directory.new_account == dir_json["newAccount"]
        assert directory.new_order == dir_json["newOrder"]
        assert directory.revoke_cert == dir_json["revokeCert"]
        assert directory.key_change == dir_json["keyChange"]

    @pytest.mark.asyncio
    async def test_captures_nonce_from_response(self, client: ACMEClient) -> None:
        """fetch_directory stores Replay-Nonce from response."""
        dir_json = _make_directory_json()
        mock_resp = _make_mock_response(200, dir_json, headers={"Replay-Nonce": "saved-nonce"})

        with patch.object(client._http, "get", return_value=mock_resp):
            await client.fetch_directory()

        assert client._nonce == "saved-nonce"

    @pytest.mark.asyncio
    async def test_caches_directory(self, client: ACMEClient) -> None:
        """fetch_directory result is cached; second call skips the HTTP request."""
        dir_json = _make_directory_json()
        mock_resp = _make_mock_response(200, dir_json, headers={"Replay-Nonce": "n1"})

        with patch.object(client._http, "get", return_value=mock_resp) as mock_get:
            await client.fetch_directory()
            # Calling _ensure_directory should not re-fetch
            await client._ensure_directory()

        mock_get.assert_called_once()

    @pytest.mark.asyncio
    async def test_raises_on_http_error(self, client: ACMEClient) -> None:
        """fetch_directory raises CABackendError on non-200 response."""
        mock_resp = _make_mock_response(
            503,
            {"type": "urn:acme:error:serverInternal", "detail": "unavailable"},
        )

        with patch.object(client._http, "get", return_value=mock_resp), pytest.raises(CABackendError, match="fetch directory"):
            await client.fetch_directory()


# ---------------------------------------------------------------------------
# get_nonce tests
# ---------------------------------------------------------------------------


class TestGetNonce:
    """Tests for ACMEClient.get_nonce()."""

    @pytest.mark.asyncio
    async def test_returns_nonce_from_header(self, client: ACMEClient) -> None:
        """get_nonce returns the Replay-Nonce header value."""
        _seed_directory(client)
        mock_head = _make_mock_response(200, headers={"Replay-Nonce": "fresh-nonce-42"})

        with patch.object(client._http, "head", return_value=mock_head):
            nonce = await client.get_nonce()

        assert nonce == "fresh-nonce-42"

    @pytest.mark.asyncio
    async def test_raises_when_nonce_header_missing(self, client: ACMEClient) -> None:
        """get_nonce raises CABackendError when server returns no nonce."""
        _seed_directory(client)
        mock_head = _make_mock_response(200, headers={})

        with patch.object(client._http, "head", return_value=mock_head), pytest.raises(CABackendError, match="Replay-Nonce"):
            await client.get_nonce()


# ---------------------------------------------------------------------------
# create_account tests
# ---------------------------------------------------------------------------


class TestCreateAccount:
    """Tests for ACMEClient.create_account()."""

    @pytest.mark.asyncio
    async def test_returns_account_url_and_kid(self, client: ACMEClient) -> None:
        """create_account returns (account_url, kid) from Location header."""
        _seed_directory(client)
        client._nonce = "nonce-for-account"
        account_url = "https://acme.example.com/acme/acct/42"

        mock_resp = _make_mock_response(
            201,
            {"status": "valid"},
            headers={"Location": account_url, "Replay-Nonce": "n2"},
        )

        with patch.object(client._http, "post", return_value=mock_resp):
            url, kid = await client.create_account("test@example.com")

        assert url == account_url
        assert kid == account_url

    @pytest.mark.asyncio
    async def test_stores_account_kid(self, client: ACMEClient) -> None:
        """create_account stores the KID on the client instance."""
        _seed_directory(client)
        client._nonce = "n1"
        account_url = "https://acme.example.com/acme/acct/99"

        mock_resp = _make_mock_response(
            201,
            {"status": "valid"},
            headers={"Location": account_url, "Replay-Nonce": "n2"},
        )

        with patch.object(client._http, "post", return_value=mock_resp):
            await client.create_account("user@example.com")

        assert client._account_kid == account_url

    @pytest.mark.asyncio
    async def test_uses_jwk_not_kid_in_header(self, client: ACMEClient) -> None:
        """create_account uses JWK in protected header (not KID)."""
        _seed_directory(client)
        client._nonce = "n1"
        captured_body: list[str] = []

        async def capture_post(url: str, *, content: str, headers: dict) -> MagicMock:
            captured_body.append(content)
            return _make_mock_response(
                201,
                {"status": "valid"},
                headers={"Location": "https://acme.example.com/acme/acct/1", "Replay-Nonce": "n2"},
            )

        with patch.object(client._http, "post", side_effect=capture_post):
            await client.create_account("user@example.com")

        assert len(captured_body) == 1
        jws = json.loads(captured_body[0])
        protected = json.loads(_b64url_decode(jws["protected"]))
        assert "jwk" in protected
        assert "kid" not in protected

    @pytest.mark.asyncio
    async def test_raises_when_location_missing(self, client: ACMEClient) -> None:
        """create_account raises CABackendError when Location header is absent."""
        _seed_directory(client)
        client._nonce = "n1"

        mock_resp = _make_mock_response(
            201,
            {"status": "valid"},
            headers={"Replay-Nonce": "n2"},  # No Location
        )

        with (
            patch.object(client._http, "post", return_value=mock_resp),
            pytest.raises(CABackendError, match="Location header"),
        ):
            await client.create_account("user@example.com")

    @pytest.mark.asyncio
    async def test_raises_on_acme_error(self, client: ACMEClient) -> None:
        """create_account raises CABackendError with ACME error detail."""
        _seed_directory(client)
        client._nonce = "n1"

        mock_resp = _make_mock_response(
            400,
            {"type": "urn:ietf:params:acme:error:malformed", "detail": "Bad JWK"},
        )

        with patch.object(client._http, "post", return_value=mock_resp), pytest.raises(CABackendError, match="Bad JWK"):
            await client.create_account("bad@example.com")


# ---------------------------------------------------------------------------
# create_order tests
# ---------------------------------------------------------------------------


class TestCreateOrder:
    """Tests for ACMEClient.create_order()."""

    @pytest.mark.asyncio
    async def test_returns_acme_order(self, client_with_kid: ACMEClient) -> None:
        """create_order returns an ACMEOrder with parsed fields."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"
        order_url = "https://acme.example.com/acme/order/1"
        order_json = {
            "status": "pending",
            "finalize": "https://acme.example.com/acme/order/1/finalize",
            "authorizations": ["https://acme.example.com/acme/authz/1"],
            "identifiers": [{"type": "dns", "value": "example.com"}],
        }

        mock_resp = _make_mock_response(
            201,
            order_json,
            headers={"Location": order_url, "Replay-Nonce": "n2"},
        )

        with patch.object(client_with_kid._http, "post", return_value=mock_resp):
            order = await client_with_kid.create_order(["example.com"])

        assert isinstance(order, ACMEOrder)
        assert order.status == "pending"
        assert order.url == order_url
        assert len(order.authorizations) == 1

    @pytest.mark.asyncio
    async def test_sends_identifiers_in_payload(self, client_with_kid: ACMEClient) -> None:
        """create_order encodes identifiers correctly in the JWS payload."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"
        captured: list[str] = []

        async def capture_post(url: str, *, content: str, headers: dict) -> MagicMock:
            captured.append(content)
            return _make_mock_response(
                201,
                {
                    "status": "pending",
                    "finalize": "https://acme.example.com/acme/order/1/finalize",
                    "authorizations": [],
                },
                headers={"Location": "https://acme.example.com/acme/order/1", "Replay-Nonce": "n2"},
            )

        with patch.object(client_with_kid._http, "post", side_effect=capture_post):
            await client_with_kid.create_order(["device.example.com", "alt.example.com"])

        jws = json.loads(captured[0])
        payload = json.loads(_b64url_decode(jws["payload"]))
        assert payload["identifiers"] == [
            {"type": "dns", "value": "device.example.com"},
            {"type": "dns", "value": "alt.example.com"},
        ]


# ---------------------------------------------------------------------------
# get_authorization tests
# ---------------------------------------------------------------------------


class TestGetAuthorization:
    """Tests for ACMEClient.get_authorization()."""

    @pytest.mark.asyncio
    async def test_parses_authorization(self, client_with_kid: ACMEClient) -> None:
        """get_authorization parses status, identifier, and challenges."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"
        auth_url = "https://acme.example.com/acme/authz/1"
        auth_json = {
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [
                {
                    "type": "http-01",
                    "url": "https://acme.example.com/acme/chall/1",
                    "token": "tok123",
                    "status": "pending",
                }
            ],
        }

        mock_resp = _make_mock_response(200, auth_json, headers={"Replay-Nonce": "n2"})

        with patch.object(client_with_kid._http, "post", return_value=mock_resp):
            auth = await client_with_kid.get_authorization(auth_url)

        assert auth.status == "pending"
        assert auth.identifier == {"type": "dns", "value": "example.com"}
        assert len(auth.challenges) == 1
        chall = auth.challenges[0]
        assert isinstance(chall, ACMEChallenge)
        assert chall.type == "http-01"
        assert chall.token == "tok123"

    @pytest.mark.asyncio
    async def test_uses_post_as_get(self, client_with_kid: ACMEClient) -> None:
        """get_authorization sends POST-as-GET (empty payload)."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"
        captured: list[str] = []

        async def capture_post(url: str, *, content: str, headers: dict) -> MagicMock:
            captured.append(content)
            return _make_mock_response(
                200,
                {"status": "valid", "identifier": {}, "challenges": []},
                headers={"Replay-Nonce": "n2"},
            )

        with patch.object(client_with_kid._http, "post", side_effect=capture_post):
            await client_with_kid.get_authorization("https://acme.example.com/acme/authz/1")

        jws = json.loads(captured[0])
        assert jws["payload"] == ""


# ---------------------------------------------------------------------------
# respond_to_challenge tests
# ---------------------------------------------------------------------------


class TestRespondToChallenge:
    """Tests for ACMEClient.respond_to_challenge()."""

    @pytest.mark.asyncio
    async def test_posts_empty_object(self, client_with_kid: ACMEClient) -> None:
        """respond_to_challenge posts {} as the payload."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"
        captured: list[str] = []

        async def capture_post(url: str, *, content: str, headers: dict) -> MagicMock:
            captured.append(content)
            return _make_mock_response(200, {"status": "processing"}, headers={"Replay-Nonce": "n2"})

        with patch.object(client_with_kid._http, "post", side_effect=capture_post):
            await client_with_kid.respond_to_challenge("https://acme.example.com/acme/chall/1")

        jws = json.loads(captured[0])
        payload = json.loads(_b64url_decode(jws["payload"]))
        assert payload == {}


# ---------------------------------------------------------------------------
# poll_authorization tests
# ---------------------------------------------------------------------------


class TestPollAuthorization:
    """Tests for ACMEClient.poll_authorization()."""

    @pytest.mark.asyncio
    async def test_returns_when_valid(self, client_with_kid: ACMEClient) -> None:
        """poll_authorization returns immediately when status is valid."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"
        auth_json = {"status": "valid", "identifier": {"type": "dns", "value": "x"}, "challenges": []}

        mock_resp = _make_mock_response(200, auth_json, headers={"Replay-Nonce": "n2"})

        with (
            patch.object(client_with_kid._http, "post", return_value=mock_resp),
            patch.object(client_with_kid._http, "head", return_value=_make_nonce_resp("n1")),
        ):
            auth = await client_with_kid.poll_authorization("https://acme.example.com/acme/authz/1")

        assert auth.status == "valid"

    @pytest.mark.asyncio
    async def test_raises_on_invalid_status(self, client_with_kid: ACMEClient) -> None:
        """poll_authorization raises CABackendError when status becomes invalid."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"
        auth_json = {"status": "invalid", "identifier": {}, "challenges": []}

        mock_resp = _make_mock_response(200, auth_json, headers={"Replay-Nonce": "n2"})

        with (
            patch.object(client_with_kid._http, "post", return_value=mock_resp),
            pytest.raises(CABackendError, match="invalid"),
        ):
            await client_with_kid.poll_authorization("https://acme.example.com/acme/authz/1")

    @pytest.mark.asyncio
    async def test_raises_on_timeout(self, client_with_kid: ACMEClient) -> None:
        """poll_authorization raises CABackendError on timeout."""
        _seed_directory(client_with_kid)

        call_count = 0

        async def pending_post(url: str, *, content: str, headers: dict) -> MagicMock:
            nonlocal call_count
            call_count += 1
            client_with_kid._nonce = f"n{call_count + 1}"
            return _make_mock_response(
                200,
                {"status": "pending", "identifier": {}, "challenges": []},
                headers={"Replay-Nonce": f"n{call_count + 2}"},
            )

        client_with_kid._nonce = "n1"
        with (
            patch.object(client_with_kid._http, "post", side_effect=pending_post),
            patch("asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(CABackendError, match="timed out"),
        ):
            await client_with_kid.poll_authorization(
                "https://acme.example.com/acme/authz/1",
                timeout=0.001,
                interval=0.001,
            )


# ---------------------------------------------------------------------------
# finalize_order tests
# ---------------------------------------------------------------------------


class TestFinalizeOrder:
    """Tests for ACMEClient.finalize_order()."""

    @pytest.mark.asyncio
    async def test_sends_csr_as_b64url(self, client_with_kid: ACMEClient) -> None:
        """finalize_order base64url-encodes the DER CSR in payload."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"
        fake_csr_der = b"\x30\x82\x01\x00" + b"\xab" * 100
        captured: list[str] = []

        async def capture_post(url: str, *, content: str, headers: dict) -> MagicMock:
            captured.append(content)
            return _make_mock_response(
                200,
                {
                    "status": "processing",
                    "finalize": "https://acme.example.com/acme/order/1/finalize",
                    "authorizations": [],
                },
                headers={"Replay-Nonce": "n2"},
            )

        with patch.object(client_with_kid._http, "post", side_effect=capture_post):
            await client_with_kid.finalize_order("https://acme.example.com/acme/order/1/finalize", fake_csr_der)

        jws = json.loads(captured[0])
        payload = json.loads(_b64url_decode(jws["payload"]))
        decoded_csr = _b64url_decode(payload["csr"])
        assert decoded_csr == fake_csr_der

    @pytest.mark.asyncio
    async def test_returns_updated_order(self, client_with_kid: ACMEClient) -> None:
        """finalize_order returns ACMEOrder from response body."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"

        mock_resp = _make_mock_response(
            200,
            {
                "status": "processing",
                "finalize": "https://acme.example.com/acme/order/1/finalize",
                "authorizations": [],
            },
            headers={"Replay-Nonce": "n2"},
        )

        with patch.object(client_with_kid._http, "post", return_value=mock_resp):
            order = await client_with_kid.finalize_order(
                "https://acme.example.com/acme/order/1/finalize",
                b"\x30\x00",
            )

        assert isinstance(order, ACMEOrder)
        assert order.status == "processing"


# ---------------------------------------------------------------------------
# poll_order tests
# ---------------------------------------------------------------------------


class TestPollOrder:
    """Tests for ACMEClient.poll_order()."""

    @pytest.mark.asyncio
    async def test_returns_when_valid(self, client_with_kid: ACMEClient) -> None:
        """poll_order returns when order reaches valid status."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"
        order_url = "https://acme.example.com/acme/order/1"

        mock_resp = _make_mock_response(
            200,
            {
                "status": "valid",
                "finalize": f"{order_url}/finalize",
                "authorizations": [],
                "certificate": f"{order_url}/cert",
            },
            headers={"Replay-Nonce": "n2"},
        )

        with patch.object(client_with_kid._http, "post", return_value=mock_resp):
            order = await client_with_kid.poll_order(order_url)

        assert order.status == "valid"
        assert order.certificate == f"{order_url}/cert"

    @pytest.mark.asyncio
    async def test_raises_on_invalid_order(self, client_with_kid: ACMEClient) -> None:
        """poll_order raises CABackendError when order becomes invalid."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"

        mock_resp = _make_mock_response(
            200,
            {"status": "invalid", "finalize": "", "authorizations": []},
            headers={"Replay-Nonce": "n2"},
        )

        with (
            patch.object(client_with_kid._http, "post", return_value=mock_resp),
            pytest.raises(CABackendError, match="invalid"),
        ):
            await client_with_kid.poll_order("https://acme.example.com/acme/order/1")

    @pytest.mark.asyncio
    async def test_raises_on_timeout(self, client_with_kid: ACMEClient) -> None:
        """poll_order raises CABackendError on timeout."""
        _seed_directory(client_with_kid)

        call_count = 0

        async def processing_post(url: str, *, content: str, headers: dict) -> MagicMock:
            nonlocal call_count
            call_count += 1
            client_with_kid._nonce = f"n{call_count + 1}"
            return _make_mock_response(
                200,
                {"status": "processing", "finalize": "", "authorizations": []},
                headers={"Replay-Nonce": f"n{call_count + 2}"},
            )

        client_with_kid._nonce = "n1"
        with (
            patch.object(client_with_kid._http, "post", side_effect=processing_post),
            patch("asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(CABackendError, match="timed out"),
        ):
            await client_with_kid.poll_order(
                "https://acme.example.com/acme/order/1",
                timeout=0.001,
                interval=0.001,
            )


# ---------------------------------------------------------------------------
# download_certificate tests
# ---------------------------------------------------------------------------


class TestDownloadCertificate:
    """Tests for ACMEClient.download_certificate()."""

    @pytest.mark.asyncio
    async def test_parses_certificate_chain(self, client_with_kid: ACMEClient) -> None:
        """download_certificate returns a list of x509.Certificate objects."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"

        # Build a real PEM cert to return
        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        pem_bytes = cert.public_bytes(CryptoEncoding.PEM)

        mock_resp = _make_mock_response(
            200,
            headers={"Replay-Nonce": "n2"},
            content=pem_bytes,
        )
        mock_resp.json.side_effect = Exception("not json")  # content is PEM not JSON

        with patch.object(client_with_kid._http, "post", return_value=mock_resp):
            certs = await client_with_kid.download_certificate("https://acme.example.com/acme/order/1/cert")

        assert len(certs) == 1
        assert isinstance(certs[0], x509.Certificate)

    @pytest.mark.asyncio
    async def test_raises_on_empty_chain(self, client_with_kid: ACMEClient) -> None:
        """download_certificate raises CABackendError for empty PEM response."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"

        mock_resp = _make_mock_response(
            200,
            headers={"Replay-Nonce": "n2"},
            content=b"",
        )

        with (
            patch.object(client_with_kid._http, "post", return_value=mock_resp),
            pytest.raises(CABackendError, match="empty certificate chain"),
        ):
            await client_with_kid.download_certificate("https://acme.example.com/acme/order/1/cert")


# ---------------------------------------------------------------------------
# Context manager tests
# ---------------------------------------------------------------------------


class TestContextManager:
    """Tests for ACMEClient async context manager."""

    @pytest.mark.asyncio
    async def test_enter_returns_self(self, account_key: ec.EllipticCurvePrivateKey) -> None:
        """__aenter__ returns the client itself."""
        client = ACMEClient("https://acme.example.com/directory", account_key, verify_tls=False)
        async with client as c:
            assert c is client

    @pytest.mark.asyncio
    async def test_close_called_on_exit(self, account_key: ec.EllipticCurvePrivateKey) -> None:
        """__aexit__ calls close() which closes the httpx client."""
        client = ACMEClient("https://acme.example.com/directory", account_key, verify_tls=False)
        with patch.object(client._http, "aclose", new_callable=AsyncMock) as mock_close:
            async with client:
                pass
        mock_close.assert_called_once()


# ---------------------------------------------------------------------------
# Nonce replay and Content-Type tests
# ---------------------------------------------------------------------------


class TestNonceBehavior:
    """Tests for nonce management."""

    @pytest.mark.asyncio
    async def test_captured_nonce_used_on_next_call(self, client: ACMEClient) -> None:
        """Nonce captured from a response is consumed by the next POST."""
        _seed_directory(client)
        # Pre-seed nonce; no HEAD call needed
        client._nonce = "pre-seeded-nonce"

        captured_jws: list[dict] = []

        async def capture_post(url: str, *, content: str, headers: dict) -> MagicMock:
            captured_jws.append(json.loads(content))
            return _make_mock_response(
                200,
                {"status": "valid", "identifier": {}, "challenges": []},
                headers={"Replay-Nonce": "next-nonce"},
            )

        client._account_kid = "https://acme.example.com/acme/acct/1"
        with patch.object(client._http, "post", side_effect=capture_post):
            await client.get_authorization("https://acme.example.com/acme/authz/1")

        # The nonce embedded in the protected header must be our pre-seeded one
        protected = json.loads(_b64url_decode(captured_jws[0]["protected"]))
        assert protected["nonce"] == "pre-seeded-nonce"

    @pytest.mark.asyncio
    async def test_content_type_is_jose_json(self, client_with_kid: ACMEClient) -> None:
        """JWS POSTs use Content-Type: application/jose+json."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"
        captured_headers: list[dict] = []

        async def capture_post(url: str, *, content: str, headers: dict) -> MagicMock:
            captured_headers.append(dict(headers))
            return _make_mock_response(
                200,
                {"status": "valid", "identifier": {}, "challenges": []},
                headers={"Replay-Nonce": "n2"},
            )

        with patch.object(client_with_kid._http, "post", side_effect=capture_post):
            await client_with_kid.get_authorization("https://acme.example.com/acme/authz/1")

        assert captured_headers[0]["Content-Type"] == "application/jose+json"


# ---------------------------------------------------------------------------
# ACME error response parsing tests
# ---------------------------------------------------------------------------


class TestAcmeErrorParsing:
    """Tests for ACME error response handling."""

    @pytest.mark.asyncio
    async def test_error_message_includes_detail(self, client_with_kid: ACMEClient) -> None:
        """CABackendError message includes ACME 'detail' field."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"

        mock_resp = _make_mock_response(
            403,
            {
                "type": "urn:ietf:params:acme:error:unauthorized",
                "detail": "Account is not authorized",
            },
        )

        with (
            patch.object(client_with_kid._http, "post", return_value=mock_resp),
            pytest.raises(CABackendError, match="Account is not authorized"),
        ):
            await client_with_kid.get_authorization("https://acme.example.com/acme/authz/1")

    @pytest.mark.asyncio
    async def test_error_message_includes_type(self, client_with_kid: ACMEClient) -> None:
        """CABackendError message includes ACME 'type' URN."""
        _seed_directory(client_with_kid)
        client_with_kid._nonce = "n1"

        mock_resp = _make_mock_response(
            400,
            {
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": "bad request",
            },
        )

        with (
            patch.object(client_with_kid._http, "post", return_value=mock_resp),
            pytest.raises(CABackendError, match="malformed"),
        ):
            await client_with_kid.get_authorization("https://acme.example.com/acme/authz/1")


# ---------------------------------------------------------------------------
# Dataclass smoke tests
# ---------------------------------------------------------------------------


class TestDataclasses:
    """Smoke tests for ACME dataclasses."""

    def test_acme_directory_fields(self) -> None:
        """ACMEDirectory stores all five URL fields."""
        d = ACMEDirectory(
            new_nonce="https://a/nonce",
            new_account="https://a/acct",
            new_order="https://a/order",
            revoke_cert="https://a/revoke",
            key_change="https://a/keychange",
        )
        assert d.new_nonce == "https://a/nonce"
        assert d.revoke_cert == "https://a/revoke"

    def test_acme_order_certificate_optional(self) -> None:
        """ACMEOrder.certificate defaults to None."""
        order = ACMEOrder(status="pending", finalize="https://a/fin", authorizations=[])
        assert order.certificate is None

    def test_acme_challenge_fields(self) -> None:
        """ACMEChallenge stores type, url, token, status."""
        ch = ACMEChallenge(type="http-01", url="https://a/chall", token="tok", status="pending")
        assert ch.type == "http-01"
        assert ch.token == "tok"


# ---------------------------------------------------------------------------
# Private test utilities
# ---------------------------------------------------------------------------


def _seed_directory(client: ACMEClient) -> None:
    """Inject a fake directory into client so no HTTP fetch is needed."""
    client._directory = ACMEDirectory(
        new_nonce="https://acme.example.com/acme/new-nonce",
        new_account="https://acme.example.com/acme/new-account",
        new_order="https://acme.example.com/acme/new-order",
        revoke_cert="https://acme.example.com/acme/revoke-cert",
        key_change="https://acme.example.com/acme/key-change",
    )


def _make_nonce_resp(nonce: str) -> MagicMock:
    """Build a mock HEAD response carrying a Replay-Nonce header."""
    return _make_mock_response(200, headers={"Replay-Nonce": nonce})
