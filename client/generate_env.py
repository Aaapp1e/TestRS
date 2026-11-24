import base64
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

env_path = Path(__file__).with_name(".env")
if env_path.exists():
    raise SystemExit(f"{env_path} already exists; delete it to regenerate")

key = base64.b64encode(AESSIV.generate_key(512)).decode()
env_path.write_text(f"DEVICE_ENCRYPTION_KEY={key}\n", encoding="utf-8")
env_path.chmod(0o600)
print(f"Wrote {env_path}")
