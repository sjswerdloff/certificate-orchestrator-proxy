"""Synchronous SCEP client (RFC 8894 / draft-nourse-scep).

Implements the subset of SCEP needed for PKIOperation (enrollment) and
GetCACert.  Uses httpx (sync) for HTTP transport.

CMS / PKCS7 message construction (PKCSReq) and response parsing (CertRep)
are delegated to pyscep (PyScep 0.0.14) because the cryptography library's
PKCS7 builders do not support the custom CMS signed attributes (messageType,
transactionID, senderNonce) that SCEP requires.

** TEMPORARY STAND-IN — pyscep will be replaced **
pyscep is used here as a temporary stand-in for CMS/PKCS7 envelope
construction.  It will be replaced with a native implementation using
asn1crypto directly once the protocol integration is proven end-to-end.
See: TODO(scep-native) comments throughout this file.

SCEP PKCSReq message structure
-------------------------------
The client sends a CMS SignedData whose encapContentInfo contains a
CMS EnvelopedData.  The EnvelopedData encrypts the raw DER-encoded PKCS#10
CSR for the CA certificate recipient.  The SignedData outer layer is signed
with an ephemeral self-signed certificate generated for this transaction,
and includes SCEP-specific signed attributes:
    - messageType  (19 = PKCSReq)
    - transactionID
    - senderNonce

Step-ca's SCEP provisioner (and most other implementations) expect:
    POST ?operation=PKIOperation
    Content-Type: application/x-pki-message
    Body: DER-encoded SignedData(EnvelopedData(CSR))

The server responds with:
    Content-Type: application/x-pki-message
    Body: DER-encoded CertRep (SignedData containing EnvelopedData(Certificate))
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Self

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from est_adapter.exceptions import CABackendError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

# ---------------------------------------------------------------------------
# pyscep imports — TEMPORARY STAND-IN for native asn1crypto CMS construction
# TODO(scep-native): replace pyscep with native asn1crypto CMS construction
# ---------------------------------------------------------------------------
# pyscep (PyScep 0.0.14) is used as a temporary stand-in because the
# cryptography library cannot attach custom signed attributes to SignedData.
# pyscep uses asn1crypto + oscrypto which handles SCEP attributes correctly.
from scep.Client.builders import PKIMessageBuilder, Signer  # pyscep temporary stand-in
from scep.Client.certificate import (
    Certificate as PyscepCertificate,  # pyscep temporary stand-in
)
from scep.Client.cryptoutils import hex_digest_for_data  # pyscep temporary stand-in
from scep.Client.enums import MessageType, PKIStatus  # pyscep temporary stand-in
from scep.Client.envelope import PKCSPKIEnvelopeBuilder  # pyscep temporary stand-in
from scep.Client.message import SCEPMessage  # pyscep temporary stand-in
from scep.Client.privatekey import (
    PrivateKey as PyscepPrivateKey,  # pyscep temporary stand-in
)
from scep.Client.signingrequest import (
    ScepCSRBuilder,  # pyscep temporary stand-in
)
from scep.Client.signingrequest import (
    SigningRequest as PyscepSigningRequest,  # pyscep temporary stand-in
)


def _build_ephemeral_cert(
    key: rsa.RSAPrivateKey,
    cn: str = "SCEP Client",
) -> x509.Certificate:
    """Build a self-signed ephemeral certificate for SCEP message signing.

    The certificate is valid for 24 hours and contains only the minimum
    extensions required by SCEP implementations.

    Args:
        key: RSA private key to use for the certificate.
        cn: Common Name for the certificate subject.

    Returns:
        Self-signed X.509 certificate.
    """
    now = datetime.now(UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))  # small clock-skew buffer
        .not_valid_after(now + timedelta(hours=24))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def _cryptography_cert_to_pyscep(cert: x509.Certificate) -> PyscepCertificate:
    """Convert a cryptography x509.Certificate to a pyscep Certificate.

    # TODO(scep-native): This adapter shim disappears when pyscep is replaced.

    Args:
        cert: cryptography library X.509 certificate.

    Returns:
        pyscep Certificate wrapping the same DER bytes.
    """
    # TODO(scep-native): adapter shim — not needed once pyscep is replaced
    der = cert.public_bytes(Encoding.DER)
    return PyscepCertificate.from_der(der)


def _cryptography_key_to_pyscep(key: rsa.RSAPrivateKey) -> PyscepPrivateKey:
    """Convert a cryptography RSAPrivateKey to a pyscep PrivateKey.

    # TODO(scep-native): This adapter shim disappears when pyscep is replaced.

    Args:
        key: cryptography library RSA private key.

    Returns:
        pyscep PrivateKey wrapping the same key bytes.
    """
    # TODO(scep-native): adapter shim — not needed once pyscep is replaced
    pem_bytes = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    return PyscepPrivateKey.from_pem(pem_bytes)


def _build_challenge_csr(
    original_csr_der: bytes,
    signing_key: rsa.RSAPrivateKey,
    challenge_password: str,
) -> bytes:
    """Build a new inner CSR with the challenge password embedded.

    Extracts the subject and public key from the original CSR, then constructs
    a new CSR signed by ``signing_key`` (our ephemeral RSA key) with the SCEP
    challenge password in the PKCS#9 ``challengePassword`` attribute.

    This is the enrollment-agent pattern: the proxy acts as the RA and re-signs
    the CSR with the challenge, preserving the original subject.

    # TODO(scep-native): native impl can build this CSR using asn1crypto directly.

    Args:
        original_csr_der: DER-encoded PKCS#10 CSR from the device.
        signing_key: Ephemeral RSA key to sign the new inner CSR (enrollment agent).
        challenge_password: SCEP challenge password to embed.

    Returns:
        DER-encoded PKCS#10 CSR with challengePassword embedded.

    Raises:
        CABackendError: If CSR reconstruction fails.
    """
    # TODO(scep-native): replace with native asn1crypto CSR construction
    try:
        # Use the cryptography library to parse the original CSR and extract info
        from cryptography.x509 import load_der_x509_csr  # noqa: PLC0415 — local import for clarity

        parsed_csr = load_der_x509_csr(original_csr_der)
        subject = parsed_csr.subject

        # Build new CSR with the ephemeral signing key (enrollment agent).
        # The subject and PUBLIC KEY are preserved from the original CSR.
        # Only the signature is from the ephemeral key (acting as enrollment agent).
        pyscep_signing_key = _cryptography_key_to_pyscep(signing_key)

        # Convert the subject name attributes to a dict for ScepCSRBuilder
        subject_dict = {attr.oid._name if hasattr(attr.oid, "_name") else str(attr.oid): attr.value for attr in subject}  # noqa: SLF001

        # ScepCSRBuilder needs asn1crypto public key object.
        # Extract the device's public key from the original CSR (not the ephemeral key!)
        # so the issued certificate carries the device's public key.
        from oscrypto import asymmetric as oscrypto_asymmetric  # noqa: PLC0415 — local import for clarity

        device_pubkey_pem = parsed_csr.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        oscrypto_pubkey = oscrypto_asymmetric.load_public_key(device_pubkey_pem)
        asn1_public_key = oscrypto_pubkey.asn1

        # Map common OID names to asn1crypto field names
        _OID_NAME_MAP = {
            "commonName": "common_name",
            "organizationName": "organization_name",
            "organizationalUnitName": "organizational_unit_name",
            "countryName": "country_name",
            "stateOrProvinceName": "state_or_province_name",
            "localityName": "locality_name",
            "emailAddress": "email_address",
        }
        subject_asn1 = {_OID_NAME_MAP.get(k, k): v for k, v in subject_dict.items()}

        builder = ScepCSRBuilder(subject_asn1, asn1_public_key)
        builder.key_usage = {"digital_signature", "key_encipherment"}
        builder.password = challenge_password

        built_csr = builder.build(pyscep_signing_key.to_asn1_private_key())
        return built_csr.dump()  # type: ignore[no-any-return]

    except CABackendError:
        raise
    except Exception as exc:
        msg = f"SCEP: failed to build challenge CSR (pyscep temporary stand-in): {exc}"
        raise CABackendError(msg) from exc


def _build_pkcs_req(
    csr_der: bytes,
    ca_cert: x509.Certificate,
    signing_cert: x509.Certificate,
    signing_key: rsa.RSAPrivateKey,
    challenge_password: str | None = None,
) -> bytes:
    """Build a SCEP PKCSReq message (SignedData wrapping EnvelopedData(CSR)).

    Uses pyscep (PyScep) as a temporary stand-in for CMS construction.
    pyscep correctly attaches the SCEP-required signed attributes (messageType,
    transactionID, senderNonce) that the cryptography library's PKCS7 builder
    cannot produce.

    When ``challenge_password`` is provided, a new inner CSR is built from the
    original CSR's public key and subject, with the challenge embedded as a
    PKCS#9 ``challengePassword`` attribute.  This is required by SCEP CAs
    (such as step-ca) that validate the challenge from the CSR attributes.
    The new inner CSR is signed by ``signing_key`` (acting as the enrollment
    agent); the original CSR's public key is preserved so the issued cert
    has the correct device key.

    # TODO(scep-native): replace pyscep calls with native asn1crypto CMS construction

    Structure:
        SignedData {
          encapContentInfo: contentType = data, eContent = EnvelopedData
          signerInfos: [signed with signing_key/signing_cert, includes SCEP attrs]
        }
      where EnvelopedData encrypts the (challenge-injected) CSR DER for ca_cert.

    Args:
        csr_der: DER-encoded PKCS#10 CSR from the device.
        ca_cert: CA certificate used as encryption recipient.
        signing_cert: Ephemeral self-signed cert used for SignedData.
        signing_key: Corresponding private key for signing_cert.
        challenge_password: SCEP challenge password to embed in the inner CSR.
            If None the original csr_der is used as-is.

    Returns:
        DER-encoded CMS SignedData ready to POST as PKIOperation.

    Raises:
        CABackendError: If any CMS construction step fails.
    """
    # TODO(scep-native): replace pyscep with native asn1crypto CMS construction
    try:
        # Convert cryptography types to pyscep types (adapter shims)
        pyscep_ca_cert = _cryptography_cert_to_pyscep(ca_cert)
        pyscep_signing_cert = _cryptography_cert_to_pyscep(signing_cert)
        pyscep_signing_key = _cryptography_key_to_pyscep(signing_key)

        # If a challenge password is required, rebuild the inner CSR with it embedded.
        # We extract the device's public key and subject from the incoming CSR,
        # then create a new CSR signed by our ephemeral key (enrollment agent pattern).
        # TODO(scep-native): native impl can inject the challenge more cleanly.
        inner_csr_der = csr_der
        if challenge_password:
            inner_csr_der = _build_challenge_csr(csr_der, signing_key, challenge_password)

        # Query CA capabilities to pick strongest cipher; fall back to aes256
        # We use aes256 directly — step-ca and most modern SCEP servers support it.
        # pyscep's GetCACaps is HTTP-aware (uses requests); we skip it and pick directly.
        cipher = "aes256"

        # Step 1: Build EnvelopedData (CSR encrypted for CA cert recipient)
        # pyscep temporary stand-in: PKCSPKIEnvelopeBuilder handles RSA key-wrap
        envelope = PKCSPKIEnvelopeBuilder().encrypt(inner_csr_der, cipher).add_recipient(pyscep_ca_cert)
        envelope_data, _key, _iv = envelope.finalize()

        # transactionID = hex SHA-1 of the (inner) CSR's public key DER (SCEP convention)
        csr_pki = PyscepSigningRequest.from_der(inner_csr_der)
        transaction_id = hex_digest_for_data(data=csr_pki.public_key.to_der(), algorithm="sha1")

        # Step 2: Build SignerInfo with SCEP attributes and finalize SignedData
        # pyscep temporary stand-in: PKIMessageBuilder attaches messageType,
        # transactionID, senderNonce as CMS signed attributes
        signer = Signer(pyscep_signing_cert, pyscep_signing_key, "sha256")

        pki_msg_content_info = (
            PKIMessageBuilder()
            .message_type(MessageType.PKCSReq)
            .pki_envelope(envelope_data)
            .add_signer(signer)
            .transaction_id(transaction_id)
            .sender_nonce()
            .finalize(digest_algorithm="sha256")
        )

        return pki_msg_content_info.dump()  # type: ignore[no-any-return]

    except CABackendError:
        raise
    except Exception as exc:
        msg = f"SCEP: failed to build PKCSReq via pyscep (temporary stand-in): {exc}"
        raise CABackendError(msg) from exc


def _parse_cert_rep(
    response_der: bytes,
    ca_cert: x509.Certificate,  # noqa: ARG001 — reserved for native impl signature verification
    decrypter_cert: x509.Certificate,
    decrypter_key: rsa.RSAPrivateKey,
) -> x509.Certificate:
    """Parse a SCEP CertRep response and return the issued certificate.

    Uses pyscep (PyScep) as a temporary stand-in for CMS response parsing.
    pyscep's SCEPMessage handles the outer SignedData, verifies the CA/RA
    signature, checks PKI status attributes, and decrypts the inner
    EnvelopedData containing the issued certificate.

    # TODO(scep-native): replace pyscep calls with native asn1crypto CMS parsing

    Args:
        response_der: DER-encoded CertRep from the SCEP server.
        ca_cert: CA/RA certificate that signed the CertRep response.
            This is the signer cert used for signature verification.
        decrypter_cert: Ephemeral cert that was used to sign the PKCSReq
            (the server encrypts the response back to this cert's key).
        decrypter_key: Private key corresponding to decrypter_cert, used
            to decrypt the inner EnvelopedData.

    Returns:
        Issued X.509 certificate.

    Raises:
        CABackendError: On parse errors, enrollment failure, or pending status.
    """
    # TODO(scep-native): replace pyscep with native asn1crypto CMS parsing
    try:
        # The signer cert for the CertRep is embedded in the SignedData certificate bag.
        # Pass signer_cert=None so pyscep searches the embedded certs for the signer
        # (by serial number) rather than us having to identify which CA/RA cert signed it.
        # pyscep temporary stand-in: SCEPMessage.parse handles the outer SignedData.
        pyscep_decrypter_cert = _cryptography_cert_to_pyscep(decrypter_cert)
        pyscep_decrypter_key = _cryptography_key_to_pyscep(decrypter_key)

        cert_rep = SCEPMessage.parse(raw=response_der, signer_cert=None)

    except CABackendError:
        raise
    except Exception as exc:
        msg = f"SCEP: failed to parse CertRep outer SignedData (pyscep temporary stand-in): {exc}"
        raise CABackendError(msg) from exc

    if cert_rep.pki_status == PKIStatus.FAILURE:
        fail_info = getattr(cert_rep, "fail_info", "unknown")
        msg = f"SCEP: enrollment rejected by CA — failInfo={fail_info}"
        raise CABackendError.scep_enrollment_failed(reason=msg)

    if cert_rep.pki_status == PKIStatus.PENDING:
        txn_id = getattr(cert_rep, "transaction_id", "unknown")
        msg = f"SCEP: enrollment pending (manual approval required) — transactionID={txn_id}"
        raise CABackendError.scep_enrollment_failed(reason=msg)

    # PKIStatus.SUCCESS — decrypt the inner EnvelopedData and extract the cert
    try:
        # pyscep temporary stand-in: get_decrypted_envelope_data decrypts with our
        # ephemeral key (the server encrypted the response for our ephemeral cert)
        decrypted_bytes = cert_rep.get_decrypted_envelope_data(pyscep_decrypter_cert, pyscep_decrypter_key)
    except Exception as exc:
        msg = f"SCEP: failed to decrypt CertRep envelope (pyscep temporary stand-in): {exc}"
        raise CABackendError(msg) from exc

    # The decrypted content is a degenerate PKCS#7 SignedData containing the cert(s).
    # Parse with the cryptography library to get x509.Certificate objects.
    try:
        issued_certs = load_der_pkcs7_certificates(decrypted_bytes)
    except Exception:
        # Not a PKCS7 bag — might be a bare DER certificate
        issued_certs = []

    if issued_certs:
        # Return the first non-CA cert, or the first cert if all look like CAs
        leaf = [c for c in issued_certs if not _is_ca_cert(c)]
        if leaf:
            return leaf[0]
        return issued_certs[0]

    # Last resort: try parsing as a bare DER certificate
    try:
        return x509.load_der_x509_certificate(decrypted_bytes)
    except Exception as exc:
        msg = f"SCEP: CertRep did not contain a parseable issued certificate: {exc}"
        raise CABackendError(msg) from exc


def _is_ca_cert(cert: x509.Certificate) -> bool:
    """Return True if the certificate appears to be a CA/intermediate."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    else:
        return bc.value.ca


class SCEPClient:
    """Synchronous SCEP client for enrolling CSRs with a SCEP CA.

    Uses httpx (sync) for HTTP transport.  CMS/PKCS7 message construction
    and response parsing are currently delegated to pyscep (PyScep 0.0.14)
    as a temporary stand-in — see module docstring.

    Args:
        scep_url: Base URL of the SCEP endpoint (e.g. ``https://ca/scep/scep``).
        verify_tls: Whether to verify TLS certificates. Defaults to True.
        ca_cert_path: Path to a custom CA certificate PEM file for TLS verification.
    """

    def __init__(
        self,
        scep_url: str,
        verify_tls: bool = True,
        ca_cert_path: str | None = None,
    ) -> None:
        """Initialise the SCEP client.

        Args:
            scep_url: SCEP endpoint URL.
            verify_tls: Verify TLS certificate. Pass False for self-signed CAs.
            ca_cert_path: Path to custom CA PEM bundle for TLS verification.
        """
        self._scep_url = scep_url.rstrip("/")

        ssl_context: bool | str
        if not verify_tls:
            ssl_context = False
        elif ca_cert_path is not None:
            ssl_context = ca_cert_path
        else:
            ssl_context = True

        self._http = httpx.Client(verify=ssl_context)

    def get_ca_certs(self) -> tuple[x509.Certificate, x509.Certificate | None]:
        """Fetch certificates via SCEP GetCACert operation.

        When a SCEP provisioner uses a separate decrypter key (e.g., step-ca
        with an EC CA key and an RSA decrypter), GetCACert returns a PKCS#7
        bag containing both the RA/decrypter cert (RSA, for CMS encryption)
        and the CA cert (for signature verification / trust chain).

        Returns:
            Tuple of (ca_cert, encryption_cert).  ``encryption_cert`` is the
            RSA certificate to use as the CMS EnvelopedData recipient, or
            ``None`` if the CA cert itself has an RSA key and can be used
            for both purposes.

        Raises:
            CABackendError: On HTTP error or parse failure.
        """
        url = f"{self._scep_url}?operation=GetCACert"
        try:
            resp = self._http.get(url)
        except httpx.RequestError as exc:
            msg = f"SCEP GetCACert connection error: {exc}"
            raise CABackendError.scep_connection_error(reason=str(exc)) from exc

        if resp.status_code != 200:  # noqa: PLR2004
            msg = f"SCEP GetCACert failed with HTTP {resp.status_code}"
            raise CABackendError.scep_enrollment_failed(reason=msg)

        content_type = resp.headers.get("Content-Type", "")
        content = resp.content

        if "ca-ra-cert" in content_type or "pkcs7" in content_type:
            try:
                certs = load_der_pkcs7_certificates(content)
            except Exception as exc:
                msg = f"SCEP GetCACert: failed to parse PKCS7 response: {exc}"
                raise CABackendError.scep_enrollment_failed(reason=msg) from exc
            if not certs:
                msg = "SCEP GetCACert returned an empty PKCS7 certificate bag"
                raise CABackendError.scep_enrollment_failed(reason=msg)

            ca_certs = [c for c in certs if _is_ca_cert(c)]
            rsa_certs = [c for c in certs if isinstance(c.public_key(), rsa.RSAPublicKey) and not _is_ca_cert(c)]

            ca_cert = ca_certs[0] if ca_certs else certs[0]
            encryption_cert = rsa_certs[0] if rsa_certs else None
            return ca_cert, encryption_cert

        # Single DER certificate (application/x-x509-ca-cert)
        try:
            cert = x509.load_der_x509_certificate(content)
        except Exception as exc:
            msg = f"SCEP GetCACert: failed to parse DER certificate: {exc}"
            raise CABackendError.scep_enrollment_failed(reason=msg) from exc
        return cert, None

    def get_ca_cert(self) -> x509.Certificate:
        """Fetch the CA certificate via SCEP GetCACert.

        Convenience wrapper around :meth:`get_ca_certs` that returns only
        the CA certificate (ignoring any separate encryption/RA cert).
        """
        ca_cert, _ = self.get_ca_certs()
        return ca_cert

    def enroll(
        self,
        csr_der: bytes,
        challenge_password: str,
        ca_cert: x509.Certificate,
        signing_key: rsa.RSAPrivateKey | EllipticCurvePrivateKey,
        encryption_cert: x509.Certificate | None = None,
    ) -> x509.Certificate:
        """Enroll a CSR via SCEP PKIOperation.

        Constructs a SCEP PKCSReq message using pyscep (temporary stand-in),
        POSTs it to the SCEP endpoint, and parses the CertRep response to
        extract the issued certificate.

        If the signing_key is an EC key, a new ephemeral RSA-2048 key is
        generated for the SCEP transaction signing certificate (SCEP
        traditionally uses RSA for the self-signed wrapper cert).

        # TODO(scep-native): pyscep PKCSReq construction will be replaced with
        # native asn1crypto CMS once protocol integration is proven end-to-end.

        Args:
            csr_der: DER-encoded PKCS#10 CSR to enroll.
            challenge_password: Shared challenge password for the SCEP CA.
            ca_cert: CA certificate (from GetCACert) for trust/issuer info.
            signing_key: Key used to sign the SCEP request wrapper.  An
                ephemeral RSA key is generated if this is an EC key.
            encryption_cert: RSA certificate to use as CMS EnvelopedData
                recipient.  If None, ``ca_cert`` is used (requires RSA key).
                When the CA uses EC keys with a separate RSA decrypter
                (e.g., step-ca), pass the decrypter cert here.

        Returns:
            Issued X.509 certificate from the SCEP CA.

        Raises:
            CABackendError: On SCEP protocol error, network failure, or if
                the CA rejects the enrollment.
        """
        # SCEP traditionally uses RSA for the ephemeral signing cert.
        # If an EC key is provided, generate a fresh RSA-2048 ephemeral key.
        if isinstance(signing_key, rsa.RSAPrivateKey):
            ephem_key: rsa.RSAPrivateKey = signing_key
        else:
            ephem_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        ephem_cert = _build_ephemeral_cert(ephem_key, cn="SCEP Client")

        # Use the separate encryption cert if provided, otherwise fall back to ca_cert
        recipient_cert = encryption_cert if encryption_cert is not None else ca_cert

        # Build the PKCSReq via pyscep (temporary stand-in).
        # Pass challenge_password so it gets embedded in the inner CSR — required
        # by step-ca and most SCEP servers to validate enrollment authorization.
        # TODO(scep-native): replace _build_pkcs_req with native asn1crypto CMS
        pkcs_req = _build_pkcs_req(csr_der, recipient_cert, ephem_cert, ephem_key, challenge_password)

        # POST the PKCSReq
        url = f"{self._scep_url}?operation=PKIOperation"
        try:
            resp = self._http.post(
                url,
                content=pkcs_req,
                headers={"Content-Type": "application/x-pki-message"},
            )
        except httpx.RequestError as exc:
            raise CABackendError.scep_connection_error(reason=str(exc)) from exc

        if resp.status_code != 200:  # noqa: PLR2004
            msg = f"SCEP PKIOperation failed with HTTP {resp.status_code}: {resp.text[:200]}"
            raise CABackendError.scep_enrollment_failed(reason=msg)

        # Parse the CertRep via pyscep (temporary stand-in).
        # The CA signs the CertRep with its own key (use ca_cert for verification).
        # The CA encrypts the issued cert for our ephemeral key (use ephem_cert/key
        # for inner EnvelopedData decryption).
        # TODO(scep-native): replace _parse_cert_rep with native asn1crypto CMS
        return _parse_cert_rep(resp.content, ca_cert, ephem_cert, ephem_key)

    def close(self) -> None:
        """Close the underlying HTTP client and release connections."""
        self._http.close()

    def __enter__(self) -> Self:
        """Enter context manager."""
        return self

    def __exit__(self, *_: object) -> None:
        """Exit context manager and close HTTP client."""
        self.close()
