import base64
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

DEFAULT_URL = "http://127.0.0.1:8000/api/v1/licenses/activate"
DEFAULT_TIMEOUT = 10

env_path = Path(__file__).with_name(".env")
if env_path.exists():
    raise SystemExit(f"{env_path} already exists; delete it to regenerate")

key = base64.b64encode(AESSIV.generate_key(512)).decode()
content = (
    f"DEVICE_ENCRYPTION_KEY={key}\n"
    f"LICENSE_SERVER_URL={DEFAULT_URL}\n"
    f"LICENSE_TIMEOUT={DEFAULT_TIMEOUT}\n"
)
env_path.write_text(content, encoding="utf-8")
env_path.chmod(0o600)
print(f"Wrote {env_path}")
