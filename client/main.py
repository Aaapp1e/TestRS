import argparse
import base64
import hashlib
import json
import os
import platform
import re
import sys
import uuid

import requests
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


def load_server_config() -> tuple[str, float]:
    url = os.environ.get("LICENSE_SERVER_URL")
    if not url:
        raise RuntimeError("LICENSE_SERVER_URL is not set")

    raw_timeout = os.environ.get("LICENSE_TIMEOUT")
    if raw_timeout is None:
        raise RuntimeError("LICENSE_TIMEOUT is not set")

    try:
        timeout = float(raw_timeout)
    except ValueError as exc:
        raise RuntimeError("LICENSE_TIMEOUT must be a number") from exc

    if timeout <= 0:
        raise RuntimeError("LICENSE_TIMEOUT must be positive")

    return url, timeout


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


def send_payload(url: str, token: str, timeout: float) -> str:
    try:
        response = requests.post(
            url,
            json={"payload": token},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"failed to reach {url}: {exc}") from exc

    if not response.ok:
        detail = " ".join(response.text.split())
        if len(detail) > 300:
            detail = detail[:300] + "..."
        message = f"server responded with {response.status_code}"
        raise RuntimeError(f"{message}: {detail}" if detail else message)

    return response.text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Collect device parameters, encrypt the fingerprint and send it.",
        epilog="Example: main.py ABCD-EFGH-IJKL-MNOP --dry-run",
    )
    parser.add_argument(
        "license",
        type=parse_license,
        metavar="LICENSE",
        help="license number in the form XXXX-XXXX-XXXX-XXXX",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print payload and token without sending",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_dotenv()

    try:
        key = load_key()
        info = get_info(args.license)
        token = encrypt(info, key)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(json.dumps(info, indent=2, sort_keys=True))
        print()
        print("Ciphertext (base64):")
        print(token)
        return 0

    try:
        url, timeout = load_server_config()
        reply = send_payload(url, token, timeout)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Sent fingerprint for license {args.license} to {url}")
    if reply.strip():
        print(reply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
