"""Configuration management for EST Adapter.

Loads configuration from YAML file and validates with Pydantic models.
"""

from __future__ import annotations

import os
import re
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class TLSConfig(BaseModel):
    """TLS configuration for server."""

    model_config = ConfigDict(frozen=True)

    cert_file: Path
    key_file: Path


class ServerConfig(BaseModel):
    """HTTP/S server configuration."""

    model_config = ConfigDict(frozen=True)

    host: str = "0.0.0.0"  # noqa: S104 - binding to all interfaces is intentional for server
    port: Annotated[int, Field(ge=1, le=65535)] = 8443
    tls: TLSConfig | None = None


class CAAutoGenerateConfig(BaseModel):
    """Configuration for auto-generated CA."""

    model_config = ConfigDict(frozen=True)

    subject: str = "CN=EST Adapter CA,O=Healthcare Organization"
    validity_days: Annotated[int, Field(ge=1, le=36500)] = 3650
    storage_path: Path = Path("./ca_data/")


class CAProvidedConfig(BaseModel):
    """Configuration for externally-provided CA."""

    model_config = ConfigDict(frozen=True)

    cert_file: Path
    key_file: Path


class ACMEConfig(BaseModel):
    """Configuration for ACME (RFC 8555) CA backend.

    Enables certificate issuance through any ACME-compatible CA
    (e.g., step-ca, Let's Encrypt, EJBCA).
    """

    model_config = ConfigDict(frozen=True)

    directory_url: str
    account_email: str
    account_storage_path: Path = Path("./acme_account/")
    ca_cert_file: Path | None = None
    verify_tls: bool = True
    challenge_port: Annotated[int, Field(ge=1, le=65535)] = 80
    order_timeout_seconds: Annotated[int, Field(ge=10, le=600)] = 120
    poll_interval_seconds: Annotated[float, Field(ge=0.5, le=30.0)] = 2.0
    eab_kid: str | None = None
    eab_hmac_key: str | None = None


class SCEPConfig(BaseModel):
    """Configuration for SCEP (RFC 8894) CA backend.

    Enables certificate issuance through any SCEP-compatible CA
    (e.g., step-ca, Microsoft ADCS, EJBCA).
    """

    model_config = ConfigDict(frozen=True)

    scep_url: str  # e.g., "https://localhost/scep/scep"
    challenge_password: str  # shared secret configured on the SCEP provisioner
    ca_cert_file: Path | None = None
    verify_tls: bool = True
    timeout_seconds: Annotated[int, Field(ge=1, le=600)] = 60


class CAMode(StrEnum):
    """CA operation mode."""

    AUTO_GENERATE = "auto_generate"
    PROVIDED = "provided"
    ACME = "acme"
    SCEP = "scep"


class CAConfig(BaseModel):
    """Certificate Authority backend configuration."""

    model_config = ConfigDict(frozen=True)

    mode: CAMode = CAMode.AUTO_GENERATE
    auto_generate: CAAutoGenerateConfig = CAAutoGenerateConfig()
    provided: CAProvidedConfig | None = None
    acme: ACMEConfig | None = None
    scep: SCEPConfig | None = None


class BasicAuthUser(BaseModel):
    """Single user for HTTP Basic authentication."""

    model_config = ConfigDict(frozen=True)

    username: str
    password_hash: str


class BasicAuthConfig(BaseModel):
    """HTTP Basic authentication configuration."""

    model_config = ConfigDict(frozen=True)

    users: list[BasicAuthUser] = []


class ClientCertAuthConfig(BaseModel):
    """Client certificate authentication configuration."""

    model_config = ConfigDict(frozen=True)

    trust_anchors: Path


class AuthMethod(StrEnum):
    """Authentication method."""

    BASIC = "basic"
    CLIENT_CERT = "client_cert"
    BOTH = "both"


class AuthConfig(BaseModel):
    """Authentication configuration."""

    model_config = ConfigDict(frozen=True)

    method: AuthMethod = AuthMethod.BASIC
    basic: BasicAuthConfig = BasicAuthConfig()
    client_cert: ClientCertAuthConfig | None = None


class KeyType(StrEnum):
    """Allowed key types for CSR validation."""

    RSA = "RSA"
    EC = "EC"


class ECCurve(StrEnum):
    """Allowed elliptic curves for CSR validation."""

    SECP256R1 = "secp256r1"
    SECP384R1 = "secp384r1"
    SECP521R1 = "secp521r1"


class ValidationConfig(BaseModel):
    """CSR policy validation configuration."""

    model_config = ConfigDict(frozen=True)

    min_key_size: Annotated[int, Field(ge=1024, le=16384)] = 2048
    allowed_key_types: list[KeyType] = [KeyType.RSA, KeyType.EC]
    allowed_ec_curves: list[ECCurve] = [ECCurve.SECP256R1, ECCurve.SECP384R1]
    max_validity_days: Annotated[int, Field(ge=1, le=3650)] = 365
    required_subject_fields: list[str] = ["CN"]
    forbidden_subject_fields: list[str] = []
    subject_cn_pattern: str = r"^[a-zA-Z0-9._-]+$"

    @field_validator("subject_cn_pattern")
    @classmethod
    def validate_regex(cls, v: str) -> str:
        """Validate that subject_cn_pattern is valid regex."""
        try:
            re.compile(v)
        except re.error as e:
            msg = f"Invalid regex pattern: {e}"
            raise ValueError(msg) from e
        return v


class LogLevel(StrEnum):
    """Log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class AuditConfig(BaseModel):
    """Audit logging configuration."""

    model_config = ConfigDict(frozen=True)

    log_file: Path = Path("./logs/audit.log")
    log_level: LogLevel = LogLevel.INFO


class AdminAPIConfig(BaseModel):
    """Admin API configuration."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    port: Annotated[int, Field(ge=1, le=65535)] = 8080
    host: str = "0.0.0.0"  # noqa: S104


class AdminWebConfig(BaseModel):
    """Admin Web UI configuration."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    port: Annotated[int, Field(ge=1, le=65535)] = 8501
    host: str = "0.0.0.0"  # noqa: S104


class DatabaseConfig(BaseModel):
    """Database configuration."""

    model_config = ConfigDict(frozen=True)

    url: str | None = None
    pool_size: int = 10
    max_overflow: int = 20


class AdminConfig(BaseModel):
    """Admin configuration (API + Web UI)."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    api: AdminAPIConfig = AdminAPIConfig()
    web: AdminWebConfig = AdminWebConfig()
    database: DatabaseConfig = DatabaseConfig()


class Settings(BaseModel):
    """Root configuration model for EST Adapter."""

    model_config = ConfigDict(frozen=True)

    server: ServerConfig = ServerConfig()
    ca: CAConfig = CAConfig()
    auth: AuthConfig = AuthConfig()
    validation: ValidationConfig = ValidationConfig()
    audit: AuditConfig = AuditConfig()
    admin: AdminConfig = AdminConfig()


def load_config(config_path: Path | str) -> Settings:
    """Load configuration from YAML file.

    Args:
        config_path: Path to configuration YAML file.

    Returns:
        Validated Settings instance.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        yaml.YAMLError: If YAML parsing fails.
        pydantic.ValidationError: If configuration validation fails.
    """
    path = Path(config_path)
    with path.open("r") as f:
        data = yaml.safe_load(f)

    return Settings.model_validate(data or {})


def load_config_from_env(
    env_var: str = "EST_ADAPTER_CONFIG",
    default_paths: list[Path] | None = None,
) -> Settings:
    """Load configuration from environment variable or default paths.

    Args:
        env_var: Environment variable name containing config path.
        default_paths: List of default paths to try if env var not set.

    Returns:
        Validated Settings instance.

    Raises:
        FileNotFoundError: If no config file found.
    """
    # Try environment variable first
    config_path = os.environ.get(env_var)
    if config_path:
        return load_config(config_path)

    # Try default paths
    if default_paths is None:
        default_paths = [
            Path("config.yaml"),
            Path("config.yml"),
            Path("/etc/est-adapter/config.yaml"),
        ]

    for path in default_paths:
        if path.exists():
            return load_config(path)

    # Return defaults if no config found
    return Settings()


# Type alias for config keys
ConfigMode = Literal["auto_generate", "provided"]
