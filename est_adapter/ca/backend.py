"""Certificate Authority backend implementations.

Supports four modes:
- AUTO_GENERATE: Creates a self-signed CA on first run
- PROVIDED: Uses externally-provided CA certificate and key
- ACME: Requests certificates from an external ACME CA (RFC 8555)
- SCEP: Forwards CSRs to a SCEP-compatible CA (step-ca, ADCS, EJBCA)
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import APIRouter, FastAPI
from fastapi.responses import PlainTextResponse

from est_adapter.audit.logger import log_ca_initialized, log_certificate_issued
from est_adapter.ca.acme_client import ACMEClient
from est_adapter.ca.scep_client import SCEPClient
from est_adapter.config import ACMEConfig, CAConfig, CAMode, SCEPConfig
from est_adapter.crypto.cert import (
    CertificateSigningKey,
    encode_certificate_pem,
    encode_pkcs7_certs,
    generate_ca_certificate,
    generate_certificate,
)
from est_adapter.exceptions import CABackendError

if TYPE_CHECKING:
    from est_adapter.crypto.csr import CSRInfo


class CABackend(Protocol):
    """Protocol for CA backend implementations."""

    @property
    def ca_certificate(self) -> x509.Certificate:
        """Get the CA certificate."""
        ...

    def sign_csr(
        self,
        csr_info: CSRInfo,
        validity_days: int,
        requestor_identity: str,
    ) -> x509.Certificate:
        """Sign a CSR and return the certificate."""
        ...

    def get_ca_certs_pkcs7(self) -> bytes:
        """Get CA certificate chain as PKCS#7 for /cacerts endpoint."""
        ...


class SelfSignedCABackend:
    """Self-signed CA backend supporting both auto-generate and provided modes."""

    def __init__(
        self,
        ca_cert: x509.Certificate,
        ca_key: CertificateSigningKey,
    ) -> None:
        """Initialize with CA certificate and private key.

        Args:
            ca_cert: CA certificate.
            ca_key: CA private key.
        """
        self._ca_cert = ca_cert
        self._ca_key = ca_key

    @property
    def ca_certificate(self) -> x509.Certificate:
        """Get the CA certificate."""
        return self._ca_cert

    def sign_csr(
        self,
        csr_info: CSRInfo,
        validity_days: int,
        requestor_identity: str,
    ) -> x509.Certificate:
        """Sign a CSR and return the certificate.

        Args:
            csr_info: Parsed CSR information.
            validity_days: Certificate validity period in days.
            requestor_identity: Identity of the requestor for audit.

        Returns:
            Signed X.509 certificate.
        """
        cert = generate_certificate(
            csr=csr_info.csr,
            ca_cert=self._ca_cert,
            ca_key=self._ca_key,
            validity_days=validity_days,
        )

        # Audit log the issuance
        log_certificate_issued(
            subject=csr_info.subject_dn,
            serial_number=cert.serial_number,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            requestor_identity=requestor_identity,
        )

        return cert

    def get_ca_certs_pkcs7(self) -> bytes:
        """Get CA certificate as PKCS#7 for /cacerts endpoint.

        Returns:
            DER-encoded PKCS#7 containing CA certificate.
        """
        return encode_pkcs7_certs([self._ca_cert])


class ACMECABackend:
    """ACME CA backend that requests certificates from an external ACME CA (RFC 8555).

    Uses HTTP-01 challenge validation.  The caller must mount ``challenge_router``
    on the FastAPI application so the ACME server can reach the challenge responses.

    Args:
        config: ACME configuration block.
        ca_cert: Optional pre-loaded CA certificate (from ``config.ca_cert_file``).
    """

    def __init__(
        self,
        config: ACMEConfig,
        ca_cert: x509.Certificate | None = None,
    ) -> None:
        """Initialise the ACME backend.

        Loads or generates the account key and account KID, then stores
        the (optional) CA certificate supplied at construction time.

        Args:
            config: ACMEConfig with directory URL, email, storage paths, etc.
            ca_cert: Pre-loaded CA/root certificate, or None if not yet known.
        """
        self._config = config
        self._ca_cert: x509.Certificate | None = ca_cert
        self._challenge_tokens: dict[str, str] = {}
        self._challenge_lock: threading.Lock = threading.Lock()
        self._challenge_server_thread: threading.Thread | None = None

        # Ensure account storage directory exists
        storage = Path(config.account_storage_path)
        storage.mkdir(parents=True, exist_ok=True)

        # Load or create the ACME account key
        self._account_key: ec.EllipticCurvePrivateKey = self._load_or_create_account_key()

        # Load previously-saved account KID (may be None if first run)
        self._account_kid: str | None = self._load_account_info()

    # ------------------------------------------------------------------
    # CABackend Protocol implementation
    # ------------------------------------------------------------------

    @property
    def ca_certificate(self) -> x509.Certificate:
        """Return the cached CA certificate.

        Returns:
            The CA/root certificate obtained from config or the first ACME order.

        Raises:
            CABackendError: If no CA certificate has been loaded yet.
        """
        if self._ca_cert is None:
            raise CABackendError.not_initialized()
        return self._ca_cert

    def sign_csr(
        self,
        csr_info: CSRInfo,
        validity_days: int,
        requestor_identity: str,
    ) -> x509.Certificate:
        """Sign a CSR via the ACME CA and return the issued certificate.

        Runs the async ACME workflow in a fresh event loop on the calling
        thread to avoid nested-event-loop conflicts with FastAPI.

        Args:
            csr_info: Parsed CSR information.
            validity_days: Requested certificate validity (informational; the
                ACME CA sets the actual validity).
            requestor_identity: Identity of the requestor for audit logging.

        Returns:
            Leaf X.509 certificate issued by the ACME CA.

        Raises:
            CABackendError: On any ACME protocol or network error.
        """

        def _run_in_thread() -> x509.Certificate:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(self._sign_csr_async(csr_info, validity_days, requestor_identity))
            finally:
                loop.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_run_in_thread)
            return future.result(timeout=self._config.order_timeout_seconds + 30)

    def get_ca_certs_pkcs7(self) -> bytes:
        """Return the CA certificate encoded as DER PKCS#7.

        Returns:
            DER-encoded PKCS#7 containing the CA certificate.

        Raises:
            CABackendError: If no CA certificate is available yet.
        """
        if self._ca_cert is None:
            raise CABackendError.not_initialized()
        return encode_pkcs7_certs([self._ca_cert])

    # ------------------------------------------------------------------
    # Challenge router (FastAPI)
    # ------------------------------------------------------------------

    @property
    def challenge_router(self) -> APIRouter:
        """Return a FastAPI router that serves HTTP-01 ACME challenge responses.

        Mount this router on the main application so that challenge tokens
        are also available on the main EST port (useful if the ACME CA can
        reach the proxy on that port).

        Returns:
            APIRouter with a single GET route at
            ``/.well-known/acme-challenge/{token}``.
        """
        return self._build_challenge_router()

    def _build_challenge_router(self) -> APIRouter:
        """Build a challenge router wired to this backend's token store."""
        router = APIRouter()
        backend = self

        @router.get("/.well-known/acme-challenge/{token}", response_class=PlainTextResponse)
        async def serve_challenge(token: str) -> PlainTextResponse:
            with backend._challenge_lock:  # noqa: SLF001
                key_auth = backend._challenge_tokens.get(token)  # noqa: SLF001
            if key_auth is None:
                return PlainTextResponse("Not found", status_code=404)
            return PlainTextResponse(key_auth)

        return router

    # ------------------------------------------------------------------
    # Dedicated HTTP-01 challenge server on port 80
    # ------------------------------------------------------------------

    def start_challenge_server(self) -> None:
        """Start a lightweight HTTP server on the challenge port (default 80).

        Runs in a daemon thread so it doesn't block shutdown.
        The server only serves ``/.well-known/acme-challenge/{token}``
        responses — no EST endpoints, no auth.

        This is needed because ACME HTTP-01 validation always targets port 80.
        """
        if self._challenge_server_thread is not None:
            return  # Already running

        challenge_app = FastAPI()
        challenge_app.include_router(self._build_challenge_router())

        config = uvicorn.Config(
            challenge_app,
            host="0.0.0.0",  # noqa: S104 — challenge server intentionally binds all interfaces for ACME HTTP-01
            port=self._config.challenge_port,
            log_level="warning",
        )
        server = uvicorn.Server(config)

        def _run_server() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(server.serve())

        self._challenge_server_thread = threading.Thread(
            target=_run_server,
            daemon=True,
            name="acme-challenge-server",
        )
        self._challenge_server_thread.start()

    # ------------------------------------------------------------------
    # Async ACME workflow
    # ------------------------------------------------------------------

    async def _sign_csr_async(
        self,
        csr_info: CSRInfo,
        validity_days: int,  # noqa: ARG002 — ACME CA sets validity; arg kept for Protocol compat
        requestor_identity: str,
    ) -> x509.Certificate:
        """Run the full ACME order flow and return the issued leaf certificate.

        Args:
            csr_info: Parsed CSR including the raw CSR object and subject DN.
            validity_days: Informational; the ACME CA determines actual lifetime.
            requestor_identity: For audit logging.

        Returns:
            Leaf X.509 certificate.

        Raises:
            CABackendError: On any ACME protocol error or timeout.
        """
        cfg = self._config

        # Resolve CA cert file path for TLS verification
        ca_cert_path: str | None = None
        if cfg.ca_cert_file is not None:
            ca_cert_path = str(cfg.ca_cert_file)

        async with ACMEClient(
            directory_url=cfg.directory_url,
            account_key=self._account_key,
            account_kid=self._account_kid,
            verify_tls=cfg.verify_tls,
            ca_cert_path=ca_cert_path,
        ) as client:
            # 1. Fetch ACME directory
            await client.fetch_directory()

            # 2. Create or retrieve account
            account_url, _ = await client.create_account(cfg.account_email)
            if self._account_kid != account_url:
                self._account_kid = account_url
                self._save_account_info(account_url)

            # 3. Extract CN from CSR for the order identifier
            cn = csr_info.subject_dn  # Full DN like "CN=device.example.com"
            # Use just the CN value as the DNS identifier
            cn_value = cn.split("CN=")[-1].split(",")[0].strip()

            # 4. Create order
            order = await client.create_order([cn_value])

            # 5. Process each authorization (typically one for HTTP-01)
            for auth_url in order.authorizations:
                auth = await client.get_authorization(auth_url)

                # Find the HTTP-01 challenge
                http01 = next(
                    (ch for ch in auth.challenges if ch.type == "http-01"),
                    None,
                )
                if http01 is None:
                    msg = f"No http-01 challenge found in authorization for {auth.identifier}"
                    raise CABackendError(msg)

                # 6. Compute and register key authorization
                key_auth = client.key_authorization(http01.token)
                with self._challenge_lock:
                    self._challenge_tokens[http01.token] = key_auth

                try:
                    # 7. Signal readiness
                    await client.respond_to_challenge(http01.url)

                    # 8. Poll until authorization is valid
                    await client.poll_authorization(
                        auth_url,
                        timeout=float(cfg.order_timeout_seconds),
                        interval=cfg.poll_interval_seconds,
                    )
                finally:
                    # Always remove token, even on failure
                    with self._challenge_lock:
                        self._challenge_tokens.pop(http01.token, None)

            # 9. Finalize order with CSR DER bytes
            csr_der = csr_info.csr.public_bytes(serialization.Encoding.DER)
            order = await client.finalize_order(order.finalize, csr_der)

            # 10. Poll order until certificate is ready
            if order.url is None:
                msg = "ACME server did not return an order URL"
                raise CABackendError(msg)
            order = await client.poll_order(
                order.url,
                timeout=float(cfg.order_timeout_seconds),
                interval=cfg.poll_interval_seconds,
            )

            # 11. Download certificate chain
            if order.certificate is None:
                msg = "ACME order completed but no certificate URL provided"
                raise CABackendError(msg)
            chain = await client.download_certificate(order.certificate)

        # 12. Extract leaf (first cert) and CA cert (last in chain)
        leaf_cert = chain[0]
        if self._ca_cert is None and len(chain) > 1:
            self._ca_cert = chain[-1]

        # 13. Audit log
        log_certificate_issued(
            subject=csr_info.subject_dn,
            serial_number=leaf_cert.serial_number,
            not_before=leaf_cert.not_valid_before_utc,
            not_after=leaf_cert.not_valid_after_utc,
            requestor_identity=requestor_identity,
        )

        return leaf_cert

    # ------------------------------------------------------------------
    # Account key management
    # ------------------------------------------------------------------

    def _load_or_create_account_key(self) -> ec.EllipticCurvePrivateKey:
        """Load account key from storage, or generate and save a new one.

        Returns:
            EC P-256 account private key.
        """
        key_path = Path(self._config.account_storage_path) / "account.key"
        if key_path.exists():
            key_data = key_path.read_bytes()
            loaded = serialization.load_pem_private_key(key_data, password=None)
            if not isinstance(loaded, ec.EllipticCurvePrivateKey):
                msg = f"Account key at {key_path} is not an EC key; regenerating"
                raise CABackendError(msg)
            return loaded

        # Generate a new EC P-256 key
        key = ec.generate_private_key(ec.SECP256R1())
        self._save_account_key(key)
        return key

    def _save_account_key(self, key: ec.EllipticCurvePrivateKey) -> None:
        """Persist the account key to storage with restrictive permissions.

        Args:
            key: EC P-256 account private key to save.
        """
        key_path = Path(self._config.account_storage_path) / "account.key"
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(pem)
        key_path.chmod(0o600)

    def _load_account_info(self) -> str | None:
        """Load the saved ACME account KID from storage.

        Returns:
            Account URL (KID) string, or None if not yet registered.
        """
        info_path = Path(self._config.account_storage_path) / "account.json"
        if not info_path.exists():
            return None
        try:
            data = json.loads(info_path.read_text())
            kid = data.get("kid")
            return str(kid) if kid else None
        except Exception:
            return None

    def _save_account_info(self, kid: str) -> None:
        """Save the ACME account KID to storage.

        Args:
            kid: Account URL returned by the ACME server.
        """
        info_path = Path(self._config.account_storage_path) / "account.json"
        info_path.write_text(json.dumps({"kid": kid}))


class SCEPCABackend:
    """SCEP CA backend that forwards CSRs to any SCEP-compatible CA.

    Supports step-ca, Microsoft ADCS, EJBCA, and any other RFC 8894
    compliant SCEP server.  The CA certificate is fetched on first access
    and then cached.

    Args:
        config: SCEP configuration block.
        ca_cert: Optional pre-loaded CA certificate (from ``config.ca_cert_file``).
    """

    def __init__(
        self,
        config: SCEPConfig,
        ca_cert: x509.Certificate | None = None,
    ) -> None:
        """Initialise the SCEP backend.

        Generates an ephemeral RSA key pair for SCEP message signing and
        stores the (optional) CA certificate supplied at construction time.

        Args:
            config: SCEPConfig with SCEP URL, challenge password, and TLS options.
            ca_cert: Pre-loaded CA/intermediate certificate, or None if not yet known.
        """
        self._config = config
        self._ca_cert: x509.Certificate | None = ca_cert
        self._encryption_cert: x509.Certificate | None = None

        # Generate an ephemeral RSA key for SCEP message signing.
        # SCEP traditionally requires RSA for the SignedData wrapper.
        self._signing_key: rsa.RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    # ------------------------------------------------------------------
    # CABackend Protocol implementation
    # ------------------------------------------------------------------

    @property
    def ca_certificate(self) -> x509.Certificate:
        """Return the cached CA certificate, fetching it first if necessary.

        On first access, also fetches the encryption/RA cert from the SCEP
        server if one hasn't been discovered yet.

        Returns:
            The CA/intermediate certificate from the SCEP provisioner.

        Raises:
            CABackendError: If GetCACert fails and no cert was pre-loaded.
        """
        if self._ca_cert is None:
            self._ca_cert = self._fetch_ca_cert()
        elif self._encryption_cert is None:
            # CA cert was pre-loaded from file, but we still need to
            # discover the encryption cert from the SCEP server.
            self._fetch_ca_cert()
        return self._ca_cert

    def sign_csr(
        self,
        csr_info: CSRInfo,
        validity_days: int,  # noqa: ARG002 — SCEP CA sets validity; arg kept for Protocol compat
        requestor_identity: str,
    ) -> x509.Certificate:
        """Enroll a CSR via SCEP and return the issued certificate.

        The SCEP CA determines the actual certificate validity; the
        ``validity_days`` argument is accepted for Protocol compatibility
        but is not forwarded to the SCEP CA.

        Args:
            csr_info: Parsed CSR information.
            validity_days: Informational; the SCEP CA sets actual validity.
            requestor_identity: Identity of the requestor for audit logging.

        Returns:
            Issued X.509 certificate from the SCEP CA.

        Raises:
            CABackendError: On SCEP protocol error, connection failure,
                or CA rejection.
        """
        ca_cert = self.ca_certificate  # ensures CA cert is fetched
        csr_der = csr_info.csr.public_bytes(serialization.Encoding.DER)

        ca_cert_path: str | None = None
        if self._config.ca_cert_file is not None:
            ca_cert_path = str(self._config.ca_cert_file)

        with SCEPClient(
            scep_url=self._config.scep_url,
            verify_tls=self._config.verify_tls,
            ca_cert_path=ca_cert_path,
        ) as client:
            cert = client.enroll(
                csr_der=csr_der,
                challenge_password=self._config.challenge_password,
                ca_cert=ca_cert,
                signing_key=self._signing_key,
                encryption_cert=self._encryption_cert,
            )

        log_certificate_issued(
            subject=csr_info.subject_dn,
            serial_number=cert.serial_number,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            requestor_identity=requestor_identity,
        )

        return cert

    def get_ca_certs_pkcs7(self) -> bytes:
        """Return the CA certificate encoded as DER PKCS#7.

        Returns:
            DER-encoded PKCS#7 containing the CA certificate.

        Raises:
            CABackendError: If no CA certificate is available yet.
        """
        return encode_pkcs7_certs([self.ca_certificate])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_ca_cert(self) -> x509.Certificate:
        """Fetch the CA certificate from the SCEP GetCACert endpoint.

        Also caches the encryption/RA cert if the server provides a
        separate RSA decrypter certificate.

        Returns:
            CA X.509 certificate.

        Raises:
            CABackendError: On HTTP error or parse failure.
        """
        ca_cert_path: str | None = None
        if self._config.ca_cert_file is not None:
            ca_cert_path = str(self._config.ca_cert_file)

        with SCEPClient(
            scep_url=self._config.scep_url,
            verify_tls=self._config.verify_tls,
            ca_cert_path=ca_cert_path,
        ) as client:
            ca_cert, encryption_cert = client.get_ca_certs()
            if encryption_cert is not None:
                self._encryption_cert = encryption_cert
            return ca_cert


def create_ca_backend(config: CAConfig) -> SelfSignedCABackend | ACMECABackend | SCEPCABackend:
    """Create CA backend based on configuration.

    Args:
        config: CA configuration.

    Returns:
        Configured CA backend (SelfSignedCABackend, ACMECABackend, or SCEPCABackend).

    Raises:
        CABackendError: If CA initialization fails.
    """
    if config.mode == CAMode.AUTO_GENERATE:
        return _create_auto_generate_backend(config)
    if config.mode == CAMode.PROVIDED:
        return _create_provided_backend(config)
    if config.mode == CAMode.ACME:
        return _create_acme_backend(config)
    if config.mode == CAMode.SCEP:
        return _create_scep_backend(config)
    # Should never reach here due to enum, but be safe
    msg = f"Unknown CA mode: {config.mode}"
    raise CABackendError(msg)


def _create_auto_generate_backend(config: CAConfig) -> SelfSignedCABackend:
    """Create auto-generate CA backend.

    Generates a new CA or loads existing from storage.
    """
    storage_path = Path(config.auto_generate.storage_path)
    cert_path = storage_path / "ca.crt"
    key_path = storage_path / "ca.key"

    # Check if CA already exists
    if cert_path.exists() and key_path.exists():
        return _load_ca_from_files(cert_path, key_path, mode="auto_generate")

    # Generate new CA
    storage_path.mkdir(parents=True, exist_ok=True)

    # Generate RSA key (4096 bits for CA)
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Generate self-signed CA certificate
    ca_cert = generate_ca_certificate(
        ca_key=ca_key,
        subject=config.auto_generate.subject,
        validity_days=config.auto_generate.validity_days,
    )

    # Save to storage
    _save_ca_to_files(ca_cert, ca_key, cert_path, key_path)

    log_ca_initialized(mode="auto_generate", ca_subject=config.auto_generate.subject)

    return SelfSignedCABackend(ca_cert, ca_key)


def _create_provided_backend(config: CAConfig) -> SelfSignedCABackend:
    """Create provided CA backend from external files."""
    if config.provided is None:
        msg = "Provided CA mode requires 'provided' configuration"
        raise CABackendError(msg)

    return _load_ca_from_files(
        config.provided.cert_file,
        config.provided.key_file,
        mode="provided",
    )


def _load_ca_from_files(
    cert_path: Path,
    key_path: Path,
    mode: str,
) -> SelfSignedCABackend:
    """Load CA certificate and key from files.

    Args:
        cert_path: Path to CA certificate (PEM format).
        key_path: Path to CA private key (PEM format).
        mode: CA mode for logging.

    Returns:
        Configured CA backend.

    Raises:
        CABackendError: If files cannot be loaded.
    """
    try:
        cert_data = cert_path.read_bytes()
        ca_cert = x509.load_pem_x509_certificate(cert_data)
    except FileNotFoundError:
        raise CABackendError.not_initialized() from None
    except Exception as e:
        msg = f"Failed to load CA certificate: {e}"
        raise CABackendError(msg) from e

    try:
        key_data = key_path.read_bytes()
        ca_key = serialization.load_pem_private_key(key_data, password=None)
    except FileNotFoundError:
        raise CABackendError.not_initialized() from None
    except Exception as e:
        msg = f"Failed to load CA private key: {e}"
        raise CABackendError(msg) from e

    # Validate key is a signing key type
    if not isinstance(ca_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        msg = f"Unsupported CA key type: {type(ca_key).__name__}"
        raise CABackendError(msg)

    # Extract subject for logging (RFC4514 format)
    subject_str = ca_cert.subject.rfc4514_string()

    log_ca_initialized(mode=mode, ca_subject=subject_str)

    return SelfSignedCABackend(ca_cert, ca_key)


def _create_acme_backend(config: CAConfig) -> ACMECABackend:
    """Create an ACME CA backend.

    Args:
        config: Root CA configuration (must have ``config.acme`` set).

    Returns:
        Configured ACMECABackend instance.

    Raises:
        CABackendError: If ACME configuration is missing or CA cert file cannot be loaded.
    """
    if config.acme is None:
        msg = "ACME CA mode requires 'acme' configuration"
        raise CABackendError(msg)

    # Optionally pre-load the CA cert from file
    ca_cert: x509.Certificate | None = None
    if config.acme.ca_cert_file is not None:
        cert_path = Path(config.acme.ca_cert_file)
        try:
            cert_data = cert_path.read_bytes()
            ca_cert = x509.load_pem_x509_certificate(cert_data)
        except FileNotFoundError:
            raise CABackendError.not_initialized() from None
        except Exception as e:
            msg = f"Failed to load CA certificate from {cert_path}: {e}"
            raise CABackendError(msg) from e

    backend = ACMECABackend(config.acme, ca_cert)

    ca_subject = ca_cert.subject.rfc4514_string() if ca_cert is not None else "(not yet known)"
    log_ca_initialized(mode="acme", ca_subject=ca_subject)

    return backend


def _create_scep_backend(config: CAConfig) -> SCEPCABackend:
    """Create a SCEP CA backend.

    Args:
        config: Root CA configuration (must have ``config.scep`` set).

    Returns:
        Configured SCEPCABackend instance.

    Raises:
        CABackendError: If SCEP configuration is missing or CA cert file cannot be loaded.
    """
    if config.scep is None:
        msg = "SCEP CA mode requires 'scep' configuration"
        raise CABackendError(msg)

    # Optionally pre-load the CA cert from file
    ca_cert: x509.Certificate | None = None
    if config.scep.ca_cert_file is not None:
        cert_path = Path(config.scep.ca_cert_file)
        try:
            cert_data = cert_path.read_bytes()
            ca_cert = x509.load_pem_x509_certificate(cert_data)
        except FileNotFoundError:
            raise CABackendError.not_initialized() from None
        except Exception as e:
            msg = f"Failed to load CA certificate from {cert_path}: {e}"
            raise CABackendError(msg) from e

    backend = SCEPCABackend(config.scep, ca_cert)

    ca_subject = ca_cert.subject.rfc4514_string() if ca_cert is not None else "(will be fetched via GetCACert)"
    log_ca_initialized(mode="scep", ca_subject=ca_subject)

    return backend


def _save_ca_to_files(
    ca_cert: x509.Certificate,
    ca_key: CertificateSigningKey,
    cert_path: Path,
    key_path: Path,
) -> None:
    """Save CA certificate and key to files.

    Args:
        ca_cert: CA certificate.
        ca_key: CA private key.
        cert_path: Path to save certificate.
        key_path: Path to save private key.

    Raises:
        CABackendError: If files cannot be saved.
    """
    try:
        cert_pem = encode_certificate_pem(ca_cert)
        cert_path.write_bytes(cert_pem)

        key_pem = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_pem)

        # Set restrictive permissions on key file
        key_path.chmod(0o600)
    except Exception as e:
        msg = f"Failed to save CA files: {e}"
        raise CABackendError(msg) from e
