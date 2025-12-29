"""Policy-based CSR validation.

Validates Certificate Signing Requests against configurable policies
for key type, size, subject fields, and naming patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from est_adapter.config import ECCurve, KeyType, ValidationConfig
from est_adapter.crypto.csr import CSRInfo, verify_csr_signature


@dataclass(frozen=True)
class ValidationResult:
    """Result of CSR validation."""

    valid: bool
    errors: tuple[str, ...]

    @classmethod
    def success(cls) -> ValidationResult:
        """Create successful validation result."""
        return cls(valid=True, errors=())

    @classmethod
    def failure(cls, *errors: str) -> ValidationResult:
        """Create failed validation result with errors."""
        return cls(valid=False, errors=errors)


def validate_csr(
    csr_info: CSRInfo,
    config: ValidationConfig,
    *,
    verify_signature: bool = True,
) -> ValidationResult:
    """Validate a CSR against policy configuration.

    Args:
        csr_info: Parsed CSR information.
        config: Validation policy configuration.
        verify_signature: Whether to verify CSR signature (default True).

    Returns:
        ValidationResult with valid flag and any error messages.

    Raises:
        CSRValidationError: If signature verification fails (when verify_signature=True).
    """
    errors: list[str] = []

    # Verify signature first if requested
    if verify_signature:
        verify_csr_signature(csr_info)

    # Check key type
    key_type_error = _validate_key_type(csr_info, config)
    if key_type_error:
        errors.append(key_type_error)

    # Check key size
    key_size_error = _validate_key_size(csr_info, config)
    if key_size_error:
        errors.append(key_size_error)

    # Check EC curve if applicable
    ec_curve_error = _validate_ec_curve(csr_info, config)
    if ec_curve_error:
        errors.append(ec_curve_error)

    # Check required subject fields
    required_errors = _validate_required_fields(csr_info, config)
    errors.extend(required_errors)

    # Check forbidden subject fields
    forbidden_errors = _validate_forbidden_fields(csr_info, config)
    errors.extend(forbidden_errors)

    # Check CN pattern
    cn_error = _validate_cn_pattern(csr_info, config)
    if cn_error:
        errors.append(cn_error)

    if errors:
        return ValidationResult.failure(*errors)
    return ValidationResult.success()


def _validate_key_type(csr_info: CSRInfo, config: ValidationConfig) -> str | None:
    """Validate key type against allowed types."""
    try:
        key_type_enum = KeyType(csr_info.key_type)
    except ValueError:
        return f"Unsupported key type: {csr_info.key_type}"

    if key_type_enum not in config.allowed_key_types:
        allowed = ", ".join(kt.value for kt in config.allowed_key_types)
        return f"Key type {csr_info.key_type} not in allowed types: {allowed}"

    return None


def _validate_key_size(csr_info: CSRInfo, config: ValidationConfig) -> str | None:
    """Validate key size meets minimum requirements."""
    if csr_info.key_size < config.min_key_size:
        return (
            f"Key size {csr_info.key_size} bits below minimum "
            f"{config.min_key_size} bits"
        )
    return None


def _validate_ec_curve(csr_info: CSRInfo, config: ValidationConfig) -> str | None:
    """Validate EC curve is in allowed list."""
    if csr_info.key_type != "EC":
        return None  # Only applies to EC keys

    if csr_info.ec_curve is None:
        return "EC key missing curve information"

    try:
        curve_enum = ECCurve(csr_info.ec_curve)
    except ValueError:
        return f"Unsupported EC curve: {csr_info.ec_curve}"

    if curve_enum not in config.allowed_ec_curves:
        allowed = ", ".join(c.value for c in config.allowed_ec_curves)
        return f"EC curve {csr_info.ec_curve} not in allowed curves: {allowed}"

    return None


def _validate_required_fields(
    csr_info: CSRInfo,
    config: ValidationConfig,
) -> list[str]:
    """Check that all required subject fields are present."""
    errors: list[str] = []
    for field in config.required_subject_fields:
        if field not in csr_info.subject_fields:
            errors.append(f"Required subject field missing: {field}")
    return errors


def _validate_forbidden_fields(
    csr_info: CSRInfo,
    config: ValidationConfig,
) -> list[str]:
    """Check that no forbidden subject fields are present."""
    errors: list[str] = []
    for field in config.forbidden_subject_fields:
        if field in csr_info.subject_fields:
            errors.append(f"Forbidden subject field present: {field}")
    return errors


def _validate_cn_pattern(csr_info: CSRInfo, config: ValidationConfig) -> str | None:
    """Validate Common Name matches required pattern."""
    if not csr_info.common_name:
        # CN presence is handled by required_subject_fields if needed
        return None

    pattern = re.compile(config.subject_cn_pattern)
    if not pattern.match(csr_info.common_name):
        return (
            f"Common Name '{csr_info.common_name}' does not match "
            f"required pattern: {config.subject_cn_pattern}"
        )

    return None
