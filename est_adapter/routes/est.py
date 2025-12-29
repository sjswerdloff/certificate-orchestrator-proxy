"""EST protocol endpoints per RFC 7030.

Implements:
- GET /.well-known/est/cacerts - Get CA certificate chain (PKCS#7)
- POST /.well-known/est/simpleenroll - Enroll with CSR
- POST /.well-known/est/simplereenroll - Re-enroll with CSR
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, Response

from est_adapter.audit.logger import (
    clear_correlation_id,
    log_csr_received,
    log_csr_validation,
    set_correlation_id,
)
from est_adapter.auth.handler import CombinedAuthHandler
from est_adapter.ca.backend import SelfSignedCABackend
from est_adapter.config import Settings
from est_adapter.crypto.cert import encode_pkcs7_certs_base64
from est_adapter.crypto.csr import parse_csr
from est_adapter.exceptions import AuthenticationError, CSRValidationError
from est_adapter.validation.policy import validate_csr

# RFC 7030 content types
CONTENT_TYPE_PKCS7 = "application/pkcs7-mime; smime-type=certs-only"
CONTENT_TYPE_PKCS10 = "application/pkcs10"

# Create router
router = APIRouter(prefix="/.well-known/est")


@dataclass
class RouteState:
    """Mutable state container for route dependencies."""

    ca_backend: SelfSignedCABackend | None = None
    auth_handler: CombinedAuthHandler | None = None
    settings: Settings | None = None


# Module-level state instance
_state = RouteState()


def configure_routes(
    ca_backend: SelfSignedCABackend,
    auth_handler: CombinedAuthHandler,
    settings: Settings,
) -> None:
    """Configure routes with backend instances.

    Called by main.py during startup.
    """
    _state.ca_backend = ca_backend
    _state.auth_handler = auth_handler
    _state.settings = settings


def get_ca_backend() -> SelfSignedCABackend:
    """Dependency to get CA backend."""
    if _state.ca_backend is None:
        msg = "CA backend not configured"
        raise RuntimeError(msg)
    return _state.ca_backend


def get_auth_handler() -> CombinedAuthHandler:
    """Dependency to get auth handler."""
    if _state.auth_handler is None:
        msg = "Auth handler not configured"
        raise RuntimeError(msg)
    return _state.auth_handler


def get_settings() -> Settings:
    """Dependency to get settings."""
    if _state.settings is None:
        msg = "Settings not configured"
        raise RuntimeError(msg)
    return _state.settings


@router.get("/cacerts")
async def get_ca_certs(
    ca_backend: Annotated[SelfSignedCABackend, Depends(get_ca_backend)],
) -> Response:
    """Get CA certificates in PKCS#7 format.

    This endpoint is unauthenticated per RFC 7030.

    Returns:
        Base64-encoded PKCS#7 containing CA certificate chain.
    """
    set_correlation_id()
    try:
        pkcs7_base64 = encode_pkcs7_certs_base64([ca_backend.ca_certificate])
        return Response(
            content=pkcs7_base64,
            media_type=CONTENT_TYPE_PKCS7,
        )
    finally:
        clear_correlation_id()


@router.post("/simpleenroll")
async def simple_enroll(
    request: Request,
    ca_backend: Annotated[SelfSignedCABackend, Depends(get_ca_backend)],
    auth_handler: Annotated[CombinedAuthHandler, Depends(get_auth_handler)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> Response:
    """Enroll by submitting a CSR and receiving a certificate.

    Requires authentication per RFC 7030.

    Args:
        request: FastAPI request object.
        authorization: HTTP Authorization header.

    Returns:
        Base64-encoded PKCS#7 containing the issued certificate.
    """
    set_correlation_id()
    try:
        # Authenticate
        # Note: Client cert would come from request.state if TLS is configured
        client_cert = getattr(request.state, "client_cert", None)
        auth_result = auth_handler.authenticate(
            authorization_header=authorization,
            client_cert=client_cert,
        )
        if not auth_result.authenticated:
            raise AuthenticationError.invalid_credentials()

        # Read and parse CSR
        body = await request.body()
        csr_info = parse_csr(body)

        log_csr_received(
            subject=csr_info.subject_dn,
            key_type=csr_info.key_type,
            key_size=csr_info.key_size,
        )

        # Validate CSR against policy
        validation_result = validate_csr(csr_info, settings.validation)
        if not validation_result.valid:
            log_csr_validation(
                subject=csr_info.subject_dn,
                approved=False,
                reason="; ".join(validation_result.errors),
            )
            raise CSRValidationError.policy_violation(
                reason="; ".join(validation_result.errors),
            )

        log_csr_validation(subject=csr_info.subject_dn, approved=True)

        # Sign the CSR
        cert = ca_backend.sign_csr(
            csr_info=csr_info,
            validity_days=settings.validation.max_validity_days,
            requestor_identity=auth_result.identity,
        )

        # Return certificate in PKCS#7 format
        pkcs7_base64 = encode_pkcs7_certs_base64([cert])
        return Response(
            content=pkcs7_base64,
            media_type=CONTENT_TYPE_PKCS7,
        )

    finally:
        clear_correlation_id()


@router.post("/simplereenroll")
async def simple_reenroll(
    request: Request,
    ca_backend: Annotated[SelfSignedCABackend, Depends(get_ca_backend)],
    auth_handler: Annotated[CombinedAuthHandler, Depends(get_auth_handler)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> Response:
    """Re-enroll by submitting a CSR for certificate renewal.

    Same as simpleenroll, but intended for renewal scenarios.
    Requires authentication (typically with existing certificate).

    Returns:
        Base64-encoded PKCS#7 containing the issued certificate.
    """
    # Re-enrollment uses same logic as initial enrollment
    return await simple_enroll(
        request=request,
        ca_backend=ca_backend,
        auth_handler=auth_handler,
        settings=settings,
        authorization=authorization,
    )
