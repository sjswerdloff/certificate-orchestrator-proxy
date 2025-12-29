"""Audit logging for medical-grade compliance.

Provides structured logging with correlation IDs for tracing requests
through the certificate lifecycle. All security-relevant events are
logged for compliance and forensic analysis.
"""

from __future__ import annotations

import sys
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from est_adapter.config import AuditConfig


# Context variable for request correlation ID
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")


def get_correlation_id() -> str:
    """Get the current correlation ID for request tracing."""
    return _correlation_id.get()


def set_correlation_id(correlation_id: str | None = None) -> str:
    """Set correlation ID for current request context."""
    if correlation_id is None:
        correlation_id = str(uuid.uuid4())
    _correlation_id.set(correlation_id)
    return correlation_id


def clear_correlation_id() -> None:
    """Clear the correlation ID after request completes."""
    _correlation_id.set("")


# Structured format for audit logs
_AUDIT_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS} [{level}] "
    "[{extra[correlation_id]}] <{extra[event]}> {message} | {extra}"
)


def configure_audit_logger(config: AuditConfig) -> None:
    """Configure the audit logger based on settings."""
    logger.remove()

    # Console handler for development
    logger.add(
        sys.stderr,
        level="DEBUG",
        format=_AUDIT_FORMAT,
        filter=lambda r: r["extra"].get("audit", False),
    )

    # File handler for audit trail
    log_path = Path(config.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        str(log_path),
        level=config.log_level.value,
        format=_AUDIT_FORMAT,
        rotation="10 MB",
        retention="90 days",
        compression="gz",
        filter=lambda r: r["extra"].get("audit", False),
    )


def _get_audit_logger() -> Any:
    """Get logger bound with audit context."""
    return logger.bind(
        audit=True,
        correlation_id=get_correlation_id() or "-",
        event="",
    )


def log_auth_attempt(
    *,
    method: str,
    success: bool,
    username: str | None = None,
    client_cert_subject: str | None = None,
    reason: str | None = None,
) -> None:
    """Log an authentication attempt."""
    event = "auth_success" if success else "auth_failure"
    audit = _get_audit_logger().bind(
        event=event,
        auth_method=method,
        username=username,
        cert_subject=client_cert_subject,
        reason=reason,
    )

    result = "succeeded" if success else "failed"
    if success:
        audit.info("Authentication {} via {}", result, method)
    else:
        audit.warning("Authentication {} via {}", result, method)


def log_csr_received(*, subject: str, key_type: str, key_size: int) -> None:
    """Log receipt of a certificate signing request."""
    audit = _get_audit_logger().bind(
        event="csr_received",
        csr_subject=subject,
        key_type=key_type,
        key_size=key_size,
    )
    audit.info("CSR received: {}", subject)


def log_csr_validation(*, subject: str, approved: bool, reason: str | None = None) -> None:
    """Log CSR validation decision."""
    event = "csr_approved" if approved else "csr_rejected"
    audit = _get_audit_logger().bind(
        event=event,
        csr_subject=subject,
        reason=reason,
    )

    result = "passed" if approved else "failed"
    if approved:
        audit.info("CSR validation {}: {}", result, subject)
    else:
        audit.warning("CSR validation {}: {}", result, subject)


def log_certificate_issued(
    *,
    subject: str,
    serial_number: int,
    not_before: datetime,
    not_after: datetime,
    requestor_identity: str,
) -> None:
    """Log certificate issuance."""
    nb = not_before.isoformat() if not_before.tzinfo else not_before.replace(tzinfo=UTC).isoformat()
    na = not_after.isoformat() if not_after.tzinfo else not_after.replace(tzinfo=UTC).isoformat()

    audit = _get_audit_logger().bind(
        event="cert_issued",
        cert_subject=subject,
        serial_number=serial_number,
        not_before=nb,
        not_after=na,
        requestor=requestor_identity,
    )
    audit.info("Certificate issued: {}", subject)


def log_ca_initialized(*, mode: str, ca_subject: str) -> None:
    """Log CA backend initialization."""
    audit = _get_audit_logger().bind(
        event="ca_initialized",
        ca_mode=mode,
        ca_subject=ca_subject,
    )
    audit.info("CA initialized in {} mode", mode)


def log_error(*, error: Exception, context: str) -> None:
    """Log an error with full context."""
    audit = _get_audit_logger().bind(
        event="error",
        error_type=type(error).__name__,
        error_message=str(error),
        context=context,
    )
    audit.exception("Error during {}: {}", context, error)


def log_startup(*, version: str, host: str, port: int) -> None:
    """Log server startup."""
    audit = _get_audit_logger().bind(
        event="startup",
        version=version,
        host=host,
        port=port,
    )
    audit.info("EST Adapter v{} starting", version)


def log_shutdown() -> None:
    """Log server shutdown."""
    audit = _get_audit_logger().bind(event="shutdown")
    audit.info("EST Adapter shutting down")
