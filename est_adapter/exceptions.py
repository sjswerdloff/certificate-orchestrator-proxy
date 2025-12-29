"""Custom exception hierarchy for EST Adapter.

All exceptions inherit from ESTAdapterError for consistent handling.
Each exception maps to an HTTP status code for REST API responses.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


class ESTAdapterError(Exception):
    """Base exception for all EST Adapter errors.

    Attributes:
        message: Human-readable error description.
        http_status: HTTP status code for REST API responses.
        details: Additional context for audit logging.
    """

    http_status: HTTPStatus = HTTPStatus.INTERNAL_SERVER_ERROR

    def __init__(
        self,
        message: str,
        *,
        details: Mapping[str, str | int | bool | None] | None = None,
    ) -> None:
        """Initialize exception.

        Args:
            message: Human-readable error description.
            details: Additional context for audit logging.
        """
        super().__init__(message)
        self.message = message
        self.details = dict(details) if details else {}

    def to_audit_dict(self) -> dict[str, str | int | bool | None]:
        """Return dictionary suitable for audit logging.

        Returns:
            Dictionary with exception type, message, and details.
        """
        return {
            "exception_type": self.__class__.__name__,
            "message": self.message,
            **self.details,
        }


class AuthenticationError(ESTAdapterError):
    """Authentication failed - invalid credentials or certificate.

    HTTP Status: 401 Unauthorized
    """

    http_status = HTTPStatus.UNAUTHORIZED

    @classmethod
    def invalid_credentials(cls, *, username: str | None = None) -> AuthenticationError:
        """Create exception for invalid username/password.

        Args:
            username: Username that failed authentication (for logging).

        Returns:
            AuthenticationError instance.
        """
        details = {"auth_method": "basic"}
        if username:
            details["username"] = username
        return cls("Invalid username or password", details=details)

    @classmethod
    def invalid_certificate(cls, *, reason: str) -> AuthenticationError:
        """Create exception for invalid client certificate.

        Args:
            reason: Why the certificate was rejected.

        Returns:
            AuthenticationError instance.
        """
        return cls(
            f"Client certificate authentication failed: {reason}",
            details={"auth_method": "client_cert", "reason": reason},
        )

    @classmethod
    def missing_credentials(cls, *, expected_method: str) -> AuthenticationError:
        """Create exception for missing authentication.

        Args:
            expected_method: What authentication was expected.

        Returns:
            AuthenticationError instance.
        """
        return cls(
            f"No authentication provided, expected: {expected_method}",
            details={"auth_method": expected_method},
        )


class CSRValidationError(ESTAdapterError):
    """CSR failed policy validation.

    HTTP Status: 400 Bad Request
    """

    http_status = HTTPStatus.BAD_REQUEST

    @classmethod
    def invalid_format(cls, *, reason: str) -> CSRValidationError:
        """Create exception for malformed CSR.

        Args:
            reason: Why the CSR format is invalid.

        Returns:
            CSRValidationError instance.
        """
        return cls(f"Invalid CSR format: {reason}", details={"validation_phase": "parsing", "reason": reason})

    @classmethod
    def invalid_signature(cls) -> CSRValidationError:
        """Create exception for CSR with invalid self-signature.

        Returns:
            CSRValidationError instance.
        """
        return cls("CSR signature verification failed", details={"validation_phase": "signature"})

    @classmethod
    def key_too_small(cls, *, key_size: int, min_size: int) -> CSRValidationError:
        """Create exception for key size below minimum.

        Args:
            key_size: Actual key size in bits.
            min_size: Required minimum key size.

        Returns:
            CSRValidationError instance.
        """
        return cls(
            f"Key size {key_size} bits is below minimum {min_size}",
            details={"validation_phase": "key_policy", "key_size": key_size, "min_size": min_size},
        )

    @classmethod
    def key_type_not_allowed(cls, *, key_type: str, allowed: list[str]) -> CSRValidationError:
        """Create exception for disallowed key type.

        Args:
            key_type: The key type in the CSR.
            allowed: List of allowed key types.

        Returns:
            CSRValidationError instance.
        """
        return cls(
            f"Key type '{key_type}' not allowed, must be one of: {', '.join(allowed)}",
            details={"validation_phase": "key_policy", "key_type": key_type, "allowed_types": ", ".join(allowed)},
        )

    @classmethod
    def ec_curve_not_allowed(cls, *, curve: str, allowed: list[str]) -> CSRValidationError:
        """Create exception for disallowed EC curve.

        Args:
            curve: The EC curve in the CSR.
            allowed: List of allowed curves.

        Returns:
            CSRValidationError instance.
        """
        return cls(
            f"EC curve '{curve}' not allowed, must be one of: {', '.join(allowed)}",
            details={"validation_phase": "key_policy", "curve": curve, "allowed_curves": ", ".join(allowed)},
        )

    @classmethod
    def missing_required_field(cls, *, field: str) -> CSRValidationError:
        """Create exception for missing required subject field.

        Args:
            field: The missing field name.

        Returns:
            CSRValidationError instance.
        """
        return cls(f"Missing required subject field: {field}", details={"validation_phase": "subject", "field": field})

    @classmethod
    def forbidden_field(cls, *, field: str) -> CSRValidationError:
        """Create exception for forbidden subject field.

        Args:
            field: The forbidden field name.

        Returns:
            CSRValidationError instance.
        """
        return cls(f"Forbidden subject field present: {field}", details={"validation_phase": "subject", "field": field})

    @classmethod
    def cn_pattern_mismatch(cls, *, cn: str, pattern: str) -> CSRValidationError:
        """Create exception for CN not matching pattern.

        Args:
            cn: The Common Name value.
            pattern: The required pattern.

        Returns:
            CSRValidationError instance.
        """
        return cls(
            f"Common Name '{cn}' does not match required pattern",
            details={"validation_phase": "subject", "cn": cn, "pattern": pattern},
        )

    @classmethod
    def policy_violation(cls, *, reason: str) -> CSRValidationError:
        """Create exception for generic policy violation.

        Args:
            reason: Description of the policy violation(s).

        Returns:
            CSRValidationError instance.
        """
        return cls(f"CSR policy validation failed: {reason}", details={"validation_phase": "policy", "reason": reason})


class CABackendError(ESTAdapterError):
    """CA backend operation failed.

    HTTP Status: 500 Internal Server Error
    """

    http_status = HTTPStatus.INTERNAL_SERVER_ERROR

    @classmethod
    def not_initialized(cls) -> CABackendError:
        """Create exception for uninitialized CA.

        Returns:
            CABackendError instance.
        """
        return cls("CA backend not initialized", details={"phase": "initialization"})

    @classmethod
    def certificate_generation_failed(cls, *, reason: str) -> CABackendError:
        """Create exception for certificate generation failure.

        Args:
            reason: Why generation failed.

        Returns:
            CABackendError instance.
        """
        return cls(f"Certificate generation failed: {reason}", details={"phase": "generation", "reason": reason})

    @classmethod
    def ca_key_load_failed(cls, *, path: str, reason: str) -> CABackendError:
        """Create exception for CA key loading failure.

        Args:
            path: Path to the key file.
            reason: Why loading failed.

        Returns:
            CABackendError instance.
        """
        return cls(
            f"Failed to load CA private key from {path}: {reason}",
            details={"phase": "initialization", "key_path": path, "reason": reason},
        )

    @classmethod
    def ca_cert_load_failed(cls, *, path: str, reason: str) -> CABackendError:
        """Create exception for CA certificate loading failure.

        Args:
            path: Path to the certificate file.
            reason: Why loading failed.

        Returns:
            CABackendError instance.
        """
        return cls(
            f"Failed to load CA certificate from {path}: {reason}",
            details={"phase": "initialization", "cert_path": path, "reason": reason},
        )


class ConfigurationError(ESTAdapterError):
    """Configuration error.

    HTTP Status: 500 Internal Server Error (startup failure)
    """

    http_status = HTTPStatus.INTERNAL_SERVER_ERROR

    @classmethod
    def invalid_config(cls, *, field: str, reason: str) -> ConfigurationError:
        """Create exception for invalid configuration.

        Args:
            field: The configuration field with the error.
            reason: Why the configuration is invalid.

        Returns:
            ConfigurationError instance.
        """
        return cls(f"Invalid configuration for '{field}': {reason}", details={"field": field, "reason": reason})

    @classmethod
    def missing_required(cls, *, field: str) -> ConfigurationError:
        """Create exception for missing required configuration.

        Args:
            field: The missing configuration field.

        Returns:
            ConfigurationError instance.
        """
        return cls(f"Missing required configuration: {field}", details={"field": field})
