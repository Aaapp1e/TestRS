import argparse
import json
import os
import platform
import re
import sys
import uuid

LICENSE_RE = re.compile(r"^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3}$")


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


def get_info(license_number: str) -> dict[str, object]:
    return {
        "schema": 1,
        "license": license_number,
        "system": platform.system() or "unknown",
        "release": platform.release() or "unknown",
        "version": platform.version() or "unknown",
        "arch": platform.machine() or "unknown",
        "cpu_count": os.cpu_count() or 0,
        "mac": mac_address(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Collect stable device parameters for the license fingerprint.",
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

    try:
        info = get_info(args.license)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
