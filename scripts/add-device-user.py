#!/usr/bin/env python3
"""Generate EST device credentials for a new device.

Creates a username/password pair and outputs:
1. The YAML config block to add to config.yaml (with bcrypt hash)
2. The enrollment YAML for the device operator
3. The cleartext credentials (give to the device operator securely)

Usage:
    uv run scripts/add-device-user.py linac-01.radonc.hospital.org
    uv run scripts/add-device-user.py linac-01.radonc.hospital.org --server https://est.example.com
    uv run scripts/add-device-user.py linac-01.radonc.hospital.org --password mysecret
"""

from __future__ import annotations

import argparse
import secrets
import string

from est_adapter.auth.handler import hash_password_for_config


def generate_password(length: int = 24) -> str:
    """Generate a random password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate EST device credentials")
    parser.add_argument("device_name", help="Device CN (e.g., linac-01.radonc.hospital.org)")
    parser.add_argument("--server", default="https://localhost:8443", help="EST server URL")
    parser.add_argument("--password", default=None, help="Use specific password instead of random")
    parser.add_argument("--organization", default=None, help="Organization for the certificate")
    args = parser.parse_args()

    password = args.password or generate_password()
    password_hash = hash_password_for_config(password)
    username = args.device_name

    print("=" * 60)
    print("ADD TO config.yaml (under auth.basic.users):")
    print("=" * 60)
    print(f"      - username: {username}")
    print(f'        password_hash: "{password_hash}"')
    print()

    print("=" * 60)
    print("GIVE TO DEVICE OPERATOR (enrollment.yaml):")
    print("=" * 60)
    org_line = f'\n  organization: "{args.organization}"' if args.organization else ""
    print(f"""server_url: "{args.server}"

device:
  common_name: "{args.device_name}"{org_line}
  key_size: 2048

auth:
  username: "{username}"
  password: "{password}"

timeout: 30.0""")
    print()

    print("=" * 60)
    print("CREDENTIALS (deliver securely):")
    print("=" * 60)
    print(f"  Device:   {args.device_name}")
    print(f"  Username: {username}")
    print(f"  Password: {password}")
    print(f"  Server:   {args.server}")
    print()
    print("After first enrollment, renewal uses the issued certificate (mTLS).")
    print("See renewal.example.yaml for renewal configuration.")


if __name__ == "__main__":
    main()
