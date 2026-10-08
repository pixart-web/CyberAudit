#!/usr/bin/env python3
"""VENDOR-SIDE tool: sign an offline CyberAudit license. Never ships on customer servers.

  python issue_license.py keygen --out vendor-private.key       # prints the public key to trust
  python issue_license.py sign --key vendor-private.key --org <organization-id> \
      --edition professional --days 30 --id EVAL-ACME-001

Put the printed public key in the server's LICENSE_TRUSTED_PUBLIC_KEYS (JSON array). The signed
document is bound to ONE organization id and an expiry; there is no universal license.
"""

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")  # noqa: E731


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("keygen")
    gen.add_argument("--out", required=True)
    sign = sub.add_parser("sign")
    sign.add_argument("--key", required=True)
    sign.add_argument("--org", required=True)
    sign.add_argument("--edition", choices=["professional", "enterprise"], required=True)
    sign.add_argument("--days", type=int, required=True)
    sign.add_argument("--grace-days", type=int, default=7)
    sign.add_argument("--id", required=True)
    args = parser.parse_args()
    if args.cmd == "keygen":
        key = Ed25519PrivateKey.generate()
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        print("Public key (trust this on servers):", b64(key.public_key().public_bytes_raw()))
        return
    with open(args.key, "rb") as handle:
        key = serialization.load_pem_private_key(handle.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("Not an Ed25519 key")
    now = datetime.now(timezone.utc)
    document = {
        "license_id": args.id, "organization_id": args.org, "edition": args.edition,
        "issued_at": now.isoformat(), "expires_at": (now + timedelta(days=args.days)).isoformat(),
        "grace_days": args.grace_days,
    }
    raw = json.dumps(document, sort_keys=True).encode()
    print(json.dumps({"payload": b64(raw), "signature": b64(key.sign(raw))}, indent=2))


if __name__ == "__main__":
    main()
