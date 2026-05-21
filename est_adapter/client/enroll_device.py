"""CLI tool for EST device enrollment from a YAML configuration file.

Usage:
    uv run python -m est_adapter.client.enroll_device enrollment.yaml
    uv run python -m est_adapter.client.enroll_device enrollment.yaml --output-dir ./certs
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

from est_adapter.client.est_client import (
    ESTClient,
    ESTClientError,
    KryptonianDeviceIdentity,
)


def load_config(config_path: Path) -> dict[str, Any]:
    """Load and validate enrollment YAML configuration."""
    with config_path.open() as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        msg = f"Invalid config: expected a YAML mapping, got {type(config).__name__}"
        raise TypeError(msg)

    # Required fields
    for field in ("server_url", "device"):
        if field not in config:
            msg = f"Missing required field: {field}"
            raise ValueError(msg)

    device = config["device"]
    if "common_name" not in device:
        msg = "Missing required field: device.common_name"
        raise ValueError(msg)

    return config


def _build_kryptonian_identity(config: dict[str, Any], device: dict[str, Any]) -> KryptonianDeviceIdentity | None:
    """Build Kryptonian device identity from config if activation section present."""
    kryptonian_cfg = config.get("kryptonian_activation")
    if not kryptonian_cfg:
        return None
    return KryptonianDeviceIdentity(
        activation_code=kryptonian_cfg["activation_code"],
        manufacturer=device.get("manufacturer", ""),
        model=device.get("model", ""),
        serial_number=device.get("serial_number", ""),
    )


def _resolve_tls_settings(tls: dict[str, Any]) -> tuple[Path | bool, Path | None, Path | None]:
    """Resolve TLS paths and verification settings from config."""
    ca_bundle: Path | bool = True
    if tls.get("ca_bundle"):
        ca_bundle = Path(tls["ca_bundle"])
    elif tls.get("verify") is False:
        ca_bundle = False

    client_cert = Path(tls["client_cert"]) if tls.get("client_cert") else None
    client_key = Path(tls["client_key"]) if tls.get("client_key") else None
    return ca_bundle, client_cert, client_key


def _print_mode(
    is_renewal: bool,
    client_cert: Path | None,
    kryptonian_device: KryptonianDeviceIdentity | None,
    server_url: str,
    common_name: str,
) -> None:
    """Print enrollment mode summary."""
    print(f"Connecting to EST server: {server_url}")
    print(f"Device CN: {common_name}")
    if is_renewal:
        print(f"Mode: RENEWAL (authenticating with {client_cert})")
    elif kryptonian_device:
        print(
            f"Mode: Kryptonian activation: manufacturer={kryptonian_device.manufacturer}, "
            f"model={kryptonian_device.model}, serial={kryptonian_device.serial_number}"
        )
    else:
        print("Mode: Initial enrollment")


def _save_results(result: Any, output_dir: Path) -> None:
    """Save certificate, key, and optional CA chain to output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)

    cert_path = output_dir / "device.cert.pem"
    key_path = output_dir / "device.key.pem"

    result.save_certificate_pem(cert_path)
    result.save_private_key_pem(key_path)

    print("\nEnrollment successful!")
    print(f"  Certificate: {cert_path}")
    print(f"  Private key: {key_path}")
    print(f"  Subject:     {result.certificate.subject}")
    print(f"  Issuer:      {result.certificate.issuer}")
    print(f"  Serial:      {result.certificate.serial_number:#x}")
    print(f"  Not before:  {result.certificate.not_valid_before_utc}")
    print(f"  Not after:   {result.certificate.not_valid_after_utc}")

    if result.ca_chain:
        from cryptography.hazmat.primitives.serialization import Encoding  # noqa: PLC0415

        ca_path = output_dir / "ca-chain.pem"
        ca_pem = b"".join(c.public_bytes(Encoding.PEM) for c in result.ca_chain)
        ca_path.write_bytes(ca_pem)
        print(f"  CA chain:    {ca_path}")


def run_enrollment(config: dict[str, Any], output_dir: Path) -> None:
    """Execute enrollment from parsed config."""
    server_url = config["server_url"]
    device = config["device"]
    auth = config.get("auth", {})
    tls = config.get("tls", {})

    kryptonian_device = _build_kryptonian_identity(config, device)
    ca_bundle, client_cert, client_key = _resolve_tls_settings(tls)

    # Detect renewal: mTLS client cert present, no activation code
    is_renewal = client_cert is not None and kryptonian_device is None
    # Some gateways (e.g., Kryptonian on Azure) don't support simplereenroll
    # because TLS terminates at the ingress. Use simpleenroll with mTLS instead.
    use_reenroll_endpoint = config.get("use_reenroll_endpoint", False)

    _print_mode(is_renewal, client_cert, kryptonian_device, server_url, device["common_name"])

    with ESTClient(
        server_url,
        username=auth.get("username"),
        password=auth.get("password"),
        client_cert=client_cert,
        client_key=client_key,
        ca_bundle=ca_bundle,
        timeout=config.get("timeout", 30.0),
    ) as client:
        print("Retrieving CA certificates...")
        try:
            ca_certs = client.get_ca_certs()
            print(f"  CA subject: {ca_certs[0].subject}")
        except ESTClientError as e:
            print(f"  Warning: could not retrieve CA certs: {e}")

        action = "renewal" if is_renewal else "enrollment"
        print(f"Submitting {action} request...")
        result = client.enroll(
            common_name=device["common_name"],
            key_size=device.get("key_size", 2048),
            organization=device.get("organization"),
            san_dns_names=device.get("san_dns_names"),
            kryptonian_device=kryptonian_device,
            renewal=is_renewal and use_reenroll_endpoint,
        )

    _save_results(result, output_dir)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="EST device enrollment from YAML configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See enrollment.example.yaml for configuration format.",
    )
    parser.add_argument("config", type=Path, help="Path to enrollment YAML file")
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("./certs"),
        help="Directory for output certificate and key files (default: ./certs)",
    )
    args = parser.parse_args()

    if not args.config.exists():
        print(f"Error: config file not found: {args.config}", file=sys.stderr)
        sys.exit(1)

    try:
        config = load_config(args.config)
        run_enrollment(config, args.output_dir)
    except ESTClientError as e:
        print(f"\nEnrollment failed: {e}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, KeyError) as e:
        print(f"\nConfiguration error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
