import argparse
import base64
import hashlib
import json
import os
import platform
import re
import sys
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from dotenv import load_dotenv

LICENSE_RE = re.compile(r"^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3}$")
KEY_SIZE_BYTES = 64


def parse_license(value: str) -> str:
    normalized = value.strip().upper()
    if not LICENSE_RE.fullmatch(normalized):
        raise argparse.ArgumentTypeError(
            "license must look like XXXX-XXXX-XXXX-XXXX (A-Z and 0-9)"
        )
    return normalized


def mac_address() -> str:
    node = uuid.getnode()
    if not 0 < node < (1 << 48) or node & 0x010000000000:
        raise RuntimeError("no stable hardware MAC address")
    return node.to_bytes(6, "big").hex(":")


def canonical_json(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def load_key() -> bytes:
    raw = os.environ.get("DEVICE_ENCRYPTION_KEY")
    if not raw:
        raise RuntimeError("DEVICE_ENCRYPTION_KEY is not set")
    try:
        key = base64.b64decode(raw.strip(), validate=True)
    except ValueError as exc:
        raise RuntimeError("DEVICE_ENCRYPTION_KEY must be valid base64") from exc
    if len(key) != KEY_SIZE_BYTES:
        raise RuntimeError(
            f"DEVICE_ENCRYPTION_KEY must decode to {KEY_SIZE_BYTES} bytes"
        )
    return key


def get_info(license_number: str) -> dict[str, object]:
    base = {
        "schema": 1,
        "license": license_number,
        "system": platform.system() or "unknown",
        "release": platform.release() or "unknown",
        "version": platform.version() or "unknown",
        "arch": platform.machine() or "unknown",
        "cpu_count": os.cpu_count() or 0,
        "mac": mac_address(),
    }
    checksum = hashlib.sha256(canonical_json(base)).hexdigest()
    return {**base, "checksum": checksum}


def encrypt(payload: dict[str, object], key: bytes) -> str:
    ciphertext = AESSIV(key).encrypt(canonical_json(payload), None)
    return base64.b64encode(ciphertext).decode("ascii")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Collect stable device parameters and encrypt the fingerprint.",
        epilog="Example: main.py ABCD-EFGH-IJKL-MNOP",
    )
    parser.add_argument(
        "license",
        type=parse_license,
        metavar="LICENSE",
        help="license number in the form XXXX-XXXX-XXXX-XXXX",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_dotenv()

    try:
        key = load_key()
        info = get_info(args.license)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    token = encrypt(info, key)

    print(json.dumps(info, indent=2, sort_keys=True))
    print()
    print("Ciphertext (base64):")
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
