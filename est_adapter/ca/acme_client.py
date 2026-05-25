"""Self-contained async ACME client (RFC 8555).

Uses httpx.AsyncClient for HTTP and cryptography for JWS/JWK operations.
Supports EC P-256 account keys and ES256 signatures.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Self

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from est_adapter.exceptions import CABackendError

# ---------------------------------------------------------------------------
# Dataclasses representing ACME protocol objects
# ---------------------------------------------------------------------------


@dataclass
class ACMEDirectory:
    """Parsed ACME directory resource (RFC 8555 §7.1.1)."""

    new_nonce: str
    new_account: str
    new_order: str
    revoke_cert: str
    key_change: str


@dataclass
class ACMEChallenge:
    """Single ACME challenge object."""

    type: str
    url: str
    token: str
    status: str


@dataclass
class ACMEAuthorization:
    """ACME authorization resource."""

    status: str
    identifier: dict[str, str]
    challenges: list[ACMEChallenge]


@dataclass
class ACMEOrder:
    """ACME order resource."""

    status: str
    finalize: str
    authorizations: list[str]
    certificate: str | None = None
    url: str | None = None
    identifiers: list[dict[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    """Base64url-encode bytes without padding (RFC 4648 §5).

    Args:
        data: Raw bytes to encode.

    Returns:
        Base64url-encoded string without trailing '=' padding.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_32bytes(n: int) -> bytes:
    """Encode integer as unsigned big-endian, zero-padded to 32 bytes.

    Required for EC P-256 JWK coordinate encoding (RFC 7518 §6.2.1).

    Args:
        n: Non-negative integer to encode.

    Returns:
        32-byte big-endian representation.
    """
    return n.to_bytes(32, byteorder="big")


# ---------------------------------------------------------------------------
# ACMEClient
# ---------------------------------------------------------------------------


class ACMEClient:
    """Async ACME client implementing RFC 8555.

    Uses EC P-256 account keys and ES256 JWS signatures throughout.
    Maintains a nonce cache — each response's Replay-Nonce is stored and
    consumed by the next POST.

    Args:
        directory_url: URL of the ACME directory endpoint.
        account_key: EC P-256 private key for account signing.
        account_kid: Account URL (KID) if the account already exists.
        verify_tls: Whether to verify TLS certificates.
        ca_cert_path: Path to a custom CA certificate bundle for TLS verification.
    """

    def __init__(
        self,
        directory_url: str,
        account_key: ec.EllipticCurvePrivateKey,
        account_kid: str | None = None,
        verify_tls: bool = True,
        ca_cert_path: str | None = None,
    ) -> None:
        """Initialise the ACME client.

        Args:
            directory_url: ACME directory URL.
            account_key: EC P-256 private key.
            account_kid: Pre-existing account URL / KID.
            verify_tls: Verify server TLS certificate.
            ca_cert_path: Path to custom CA PEM bundle.
        """
        self._directory_url = directory_url
        self._account_key = account_key
        self._account_kid = account_kid
        self._nonce: str | None = None
        self._directory: ACMEDirectory | None = None

        # Build TLS verification argument
        ssl_context: bool | str
        if not verify_tls:
            ssl_context = False
        elif ca_cert_path is not None:
            ssl_context = ca_cert_path
        else:
            ssl_context = True

        self._http = httpx.AsyncClient(verify=ssl_context)

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> Self:
        """Enter async context manager."""
        return self

    async def __aexit__(self, *_: object) -> None:
        """Exit async context manager and close HTTP client."""
        await self.close()

    async def close(self) -> None:
        """Close the underlying httpx client."""
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Public protocol methods
    # ------------------------------------------------------------------

    async def fetch_directory(self) -> ACMEDirectory:
        """Fetch and parse the ACME directory.

        Returns:
            Parsed ACMEDirectory instance.

        Raises:
            CABackendError: On HTTP errors or unexpected response shape.
        """
        resp = await self._http.get(self._directory_url)
        self._capture_nonce(resp)
        _check_response(resp, "fetch directory")
        data = resp.json()
        self._directory = ACMEDirectory(
            new_nonce=data["newNonce"],
            new_account=data["newAccount"],
            new_order=data["newOrder"],
            revoke_cert=data["revokeCert"],
            key_change=data["keyChange"],
        )
        return self._directory

    async def get_nonce(self) -> str:
        """Obtain a fresh nonce via HEAD to newNonce.

        Returns:
            Nonce string.

        Raises:
            CABackendError: If the nonce header is absent.
        """
        directory = await self._ensure_directory()
        resp = await self._http.head(directory.new_nonce)
        nonce_value: str | None = resp.headers.get("Replay-Nonce")
        if not nonce_value:
            msg = "ACME server returned no Replay-Nonce on HEAD /newNonce"
            raise CABackendError(msg)
        nonce_str: str = nonce_value
        self._nonce = nonce_str
        return nonce_str

    async def create_account(self, email: str) -> tuple[str, str]:
        """Create (or retrieve) an ACME account.

        Sends a newAccount request with ``onlyReturnExisting=False``.
        If the account already exists the server responds with 200 and
        returns the same KID.

        Args:
            email: Contact e-mail for the account.

        Returns:
            Tuple of (account_url, kid) — both are the same URL value.

        Raises:
            CABackendError: On ACME protocol errors.
        """
        directory = await self._ensure_directory()
        nonce = await self._fresh_nonce()
        payload = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{email}"],
        }
        resp = await self._jws_post(
            directory.new_account,
            payload,
            nonce,
            use_kid=False,
        )
        self._capture_nonce(resp)
        _check_response(resp, "create account", expected_statuses=(200, 201))

        account_url = resp.headers.get("Location", "")
        if not account_url:
            msg = "ACME server returned no Location header for newAccount"
            raise CABackendError(msg)
        self._account_kid = account_url
        return account_url, account_url

    async def create_order(self, identifiers: list[str]) -> ACMEOrder:
        """Submit a new certificate order.

        Args:
            identifiers: DNS names for the order (e.g. ``["example.com"]``).

        Returns:
            The resulting ACMEOrder.

        Raises:
            CABackendError: On ACME protocol errors.
        """
        directory = await self._ensure_directory()
        nonce = await self._fresh_nonce()
        payload = {
            "identifiers": [{"type": "dns", "value": ident} for ident in identifiers],
        }
        resp = await self._jws_post(directory.new_order, payload, nonce)
        self._capture_nonce(resp)
        _check_response(resp, "create order", expected_statuses=(201,))

        order_url = resp.headers.get("Location")
        return _parse_order(resp.json(), order_url)

    async def get_authorization(self, url: str) -> ACMEAuthorization:
        """Fetch an authorization object (POST-as-GET).

        Args:
            url: Authorization URL from the order.

        Returns:
            Parsed ACMEAuthorization.

        Raises:
            CABackendError: On ACME protocol errors.
        """
        nonce = await self._fresh_nonce()
        resp = await self._jws_post(url, "", nonce)
        self._capture_nonce(resp)
        _check_response(resp, "get authorization")
        return _parse_authorization(resp.json())

    async def respond_to_challenge(self, challenge_url: str) -> None:
        """Signal readiness to complete an HTTP-01 challenge.

        Sends an empty JSON object ``{}`` to the challenge URL, telling the
        ACME server to begin validation.

        Args:
            challenge_url: URL of the specific challenge to respond to.

        Raises:
            CABackendError: On ACME protocol errors.
        """
        nonce = await self._fresh_nonce()
        resp = await self._jws_post(challenge_url, {}, nonce)
        self._capture_nonce(resp)
        _check_response(resp, "respond to challenge")

    async def poll_authorization(
        self,
        url: str,
        timeout: float = 60.0,
        interval: float = 2.0,
    ) -> ACMEAuthorization:
        """Poll an authorization URL until it reaches a terminal state.

        Args:
            url: Authorization URL.
            timeout: Maximum seconds to wait.
            interval: Polling interval in seconds.

        Returns:
            ACMEAuthorization with a terminal status (``valid`` or ``invalid``).

        Raises:
            CABackendError: If authorization fails or times out.
        """
        deadline = time.monotonic() + timeout
        while True:
            auth = await self.get_authorization(url)
            if auth.status == "valid":
                return auth
            if auth.status in ("invalid", "revoked", "deactivated", "expired"):
                msg = f"ACME authorization failed with status: {auth.status}"
                raise CABackendError(msg)
            if time.monotonic() >= deadline:
                msg = f"ACME authorization timed out after {timeout}s (status: {auth.status})"
                raise CABackendError(msg)
            await asyncio.sleep(interval)

    async def finalize_order(self, finalize_url: str, csr_der: bytes) -> ACMEOrder:
        """Submit the CSR to finalize the order.

        Args:
            finalize_url: Finalize URL from the order resource.
            csr_der: DER-encoded CSR bytes.

        Returns:
            Updated ACMEOrder.

        Raises:
            CABackendError: On ACME protocol errors.
        """
        nonce = await self._fresh_nonce()
        payload = {"csr": _b64url(csr_der)}
        resp = await self._jws_post(finalize_url, payload, nonce)
        self._capture_nonce(resp)
        _check_response(resp, "finalize order")
        order_url = resp.headers.get("Location")
        return _parse_order(resp.json(), order_url)

    async def poll_order(
        self,
        order_url: str,
        timeout: float = 120.0,
        interval: float = 2.0,
    ) -> ACMEOrder:
        """Poll an order URL until it becomes ``valid`` (certificate ready).

        Args:
            order_url: URL of the order resource.
            timeout: Maximum seconds to wait.
            interval: Polling interval in seconds.

        Returns:
            ACMEOrder with status ``valid`` and a certificate URL.

        Raises:
            CABackendError: If order fails or times out.
        """
        deadline = time.monotonic() + timeout
        while True:
            nonce = await self._fresh_nonce()
            resp = await self._jws_post(order_url, "", nonce)
            self._capture_nonce(resp)
            _check_response(resp, "poll order")
            order = _parse_order(resp.json(), order_url)
            if order.status == "valid":
                return order
            if order.status in ("invalid", "revoked"):
                msg = f"ACME order failed with status: {order.status}"
                raise CABackendError(msg)
            if time.monotonic() >= deadline:
                msg = f"ACME order timed out after {timeout}s (status: {order.status})"
                raise CABackendError(msg)
            await asyncio.sleep(interval)

    async def download_certificate(self, cert_url: str) -> list[x509.Certificate]:
        """Download the issued certificate chain (POST-as-GET).

        Args:
            cert_url: Certificate URL from the completed order.

        Returns:
            List of parsed X.509 certificates (leaf first, then intermediates).

        Raises:
            CABackendError: On HTTP errors or parse failures.
        """
        nonce = await self._fresh_nonce()
        resp = await self._jws_post(cert_url, "", nonce, accept="application/pem-certificate-chain")
        self._capture_nonce(resp)
        _check_response(resp, "download certificate")

        pem_data = resp.content
        certs: list[x509.Certificate] = []
        # Split on PEM boundaries — each block is one certificate
        pem_blocks = _split_pem(pem_data)
        for block in pem_blocks:
            try:
                cert = x509.load_pem_x509_certificate(block)
                certs.append(cert)
            except Exception as exc:
                msg = f"Failed to parse certificate from chain: {exc}"
                raise CABackendError(msg) from exc

        if not certs:
            msg = "ACME server returned empty certificate chain"
            raise CABackendError(msg)
        return certs

    # ------------------------------------------------------------------
    # Key / JWS helpers
    # ------------------------------------------------------------------

    def key_authorization(self, token: str) -> str:
        """Compute the key authorization for an HTTP-01 challenge.

        RFC 8555 §8.3: ``token || '.' || base64url(SHA-256(JWK-thumbprint))``

        Args:
            token: Challenge token from the ACME server.

        Returns:
            Key authorization string.
        """
        return f"{token}.{self._thumbprint()}"

    def _jwk_dict(self) -> dict[str, str]:
        """Return the JWK representation of the account public key.

        Returns:
            JWK dict suitable for embedding in JWS headers (EC P-256).
        """
        pub_numbers = self._account_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(_int_to_32bytes(pub_numbers.x)),
            "y": _b64url(_int_to_32bytes(pub_numbers.y)),
        }

    def _thumbprint(self) -> str:
        """Compute JWK thumbprint (SHA-256) of the account public key.

        RFC 7638: JSON-serialise the required members in lexicographic order,
        then SHA-256 hash, then base64url-encode.

        Returns:
            Base64url-encoded SHA-256 JWK thumbprint.
        """
        jwk = self._jwk_dict()
        # Required members in lexicographic order (RFC 7638 §3.3)
        thumbprint_input = json.dumps(
            {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        digest = hashlib.sha256(thumbprint_input).digest()
        return _b64url(digest)

    def _build_jws(
        self,
        payload: Any,
        url: str,
        nonce: str,
        use_kid: bool = True,
    ) -> str:
        """Build a RFC 7515 flattened JSON serialisation JWS.

        Args:
            payload: Python object (dict/str) or empty string for POST-as-GET.
            url: Target URL (required ACME header field).
            nonce: Fresh Replay-Nonce value.
            use_kid: If True, use ``kid`` in the protected header (account URL).
                     If False, embed the full JWK (used for newAccount).

        Returns:
            Serialised JWS as a JSON string.

        Raises:
            CABackendError: If account KID is required but not yet set.
        """
        # Protected header
        header: dict[str, Any] = {
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
        }
        if use_kid:
            if self._account_kid is None:
                msg = "Account KID not set; call create_account() first"
                raise CABackendError(msg)
            header["kid"] = self._account_kid
        else:
            header["jwk"] = self._jwk_dict()

        protected_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())

        # Payload — empty string means POST-as-GET (no base64 encoding applied)
        payload_b64 = "" if payload == "" else _b64url(json.dumps(payload, separators=(",", ":")).encode())

        # Sign
        signing_input = f"{protected_b64}.{payload_b64}".encode()
        der_sig = self._account_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

        # Decode DER → raw (r || s), each 32 bytes
        r, s = decode_dss_signature(der_sig)
        raw_sig = _int_to_32bytes(r) + _int_to_32bytes(s)

        return json.dumps(
            {
                "protected": protected_b64,
                "payload": payload_b64,
                "signature": _b64url(raw_sig),
            },
            separators=(",", ":"),
        )

    async def _jws_post(
        self,
        url: str,
        payload: Any,
        nonce: str,
        use_kid: bool = True,
        accept: str = "application/json",
    ) -> httpx.Response:
        """Send a JWS-signed POST request.

        Args:
            url: Target URL.
            payload: Request payload (dict, empty string for POST-as-GET).
            nonce: Fresh Replay-Nonce to embed in the JWS.
            use_kid: Use KID (True) or JWK (False) in protected header.
            accept: Accept header value.

        Returns:
            HTTP response from the server.
        """
        body = self._build_jws(payload, url, nonce, use_kid=use_kid)
        headers = {
            "Content-Type": "application/jose+json",
            "Accept": accept,
        }
        return await self._http.post(url, content=body, headers=headers)

    async def _ensure_directory(self) -> ACMEDirectory:
        """Return cached directory, fetching it first if needed."""
        if self._directory is None:
            await self.fetch_directory()
        return self._directory  # type: ignore[return-value]

    async def _fresh_nonce(self) -> str:
        """Return the cached nonce or fetch a new one."""
        if self._nonce:
            nonce = self._nonce
            self._nonce = None
            return nonce
        return await self.get_nonce()

    def _capture_nonce(self, resp: httpx.Response) -> None:
        """Store the Replay-Nonce from a response for next use."""
        nonce = resp.headers.get("Replay-Nonce")
        if nonce:
            self._nonce = nonce


# ---------------------------------------------------------------------------
# Private parsing helpers
# ---------------------------------------------------------------------------


def _parse_order(data: dict[str, Any], order_url: str | None) -> ACMEOrder:
    """Parse an order JSON dict into ACMEOrder.

    Args:
        data: Raw JSON dict from ACME server.
        order_url: Order URL from Location header (may be None).

    Returns:
        ACMEOrder instance.
    """
    return ACMEOrder(
        status=data.get("status", ""),
        finalize=data.get("finalize", ""),
        authorizations=data.get("authorizations", []),
        certificate=data.get("certificate"),
        url=order_url,
        identifiers=data.get("identifiers", []),
    )


def _parse_authorization(data: dict[str, Any]) -> ACMEAuthorization:
    """Parse an authorization JSON dict into ACMEAuthorization.

    Args:
        data: Raw JSON dict from ACME server.

    Returns:
        ACMEAuthorization instance.
    """
    challenges = [
        ACMEChallenge(
            type=ch.get("type", ""),
            url=ch.get("url", ""),
            token=ch.get("token", ""),
            status=ch.get("status", ""),
        )
        for ch in data.get("challenges", [])
    ]
    return ACMEAuthorization(
        status=data.get("status", ""),
        identifier=data.get("identifier", {}),
        challenges=challenges,
    )


def _check_response(
    resp: httpx.Response,
    operation: str,
    expected_statuses: tuple[int, ...] = (200,),
) -> None:
    """Raise CABackendError if the response status is unexpected.

    Parses ACME error bodies (RFC 8555 §7.3.3) when available.

    Args:
        resp: HTTP response to check.
        operation: Human-readable operation name for error messages.
        expected_statuses: Acceptable HTTP status codes.

    Raises:
        CABackendError: If status not in expected_statuses.
    """
    if resp.status_code in expected_statuses:
        return

    # Try to extract ACME problem detail
    acme_type = ""
    acme_detail = ""
    with contextlib.suppress(Exception):
        body = resp.json()
        acme_type = body.get("type", "")
        acme_detail = body.get("detail", "")

    parts = [f"ACME {operation} failed (HTTP {resp.status_code})"]
    if acme_type:
        parts.append(f"type={acme_type}")
    if acme_detail:
        parts.append(f"detail={acme_detail}")
    msg = ": ".join(parts)
    raise CABackendError(msg)


def _split_pem(pem_data: bytes) -> list[bytes]:
    """Split a PEM bundle into individual certificate blocks.

    Args:
        pem_data: Raw PEM bytes, possibly containing multiple certificates.

    Returns:
        List of individual PEM blocks, each as bytes.
    """
    blocks: list[bytes] = []
    current: list[bytes] = []
    for line in pem_data.splitlines(keepends=True):
        current.append(line)
        if line.strip() == b"-----END CERTIFICATE-----":
            blocks.append(b"".join(current))
            current = []
    return blocks
