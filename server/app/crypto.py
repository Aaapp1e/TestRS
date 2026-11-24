import base64
import hashlib
import json

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

FIELDS = (
    "schema",
    "license",
    "system",
    "release",
    "version",
    "arch",
    "cpu_count",
    "mac",
)


def decrypt_token(token: str, key: bytes) -> dict:
    ciphertext = base64.b64decode(token.strip(), validate=True)
    payload = json.loads(AESSIV(key).decrypt(ciphertext, None))

    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    return payload


def verify_checksum(payload: dict) -> None:
    base = {field: payload.get(field) for field in FIELDS}
    canonical = json.dumps(
        base,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    expected = hashlib.sha256(canonical.encode()).hexdigest()
    if payload.get("checksum") != expected:
        raise ValueError("checksum mismatch")


def device_fingerprint(mac: str) -> str:
    return hashlib.sha256(mac.lower().encode()).hexdigest()
