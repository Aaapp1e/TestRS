import base64
import os

from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

_raw_key = os.getenv("DEVICE_ENCRYPTION_KEY")
if not _raw_key:
    raise RuntimeError("DEVICE_ENCRYPTION_KEY is not set")

DEVICE_ENCRYPTION_KEY = base64.b64decode(_raw_key, validate=True)
if len(DEVICE_ENCRYPTION_KEY) != 64:
    raise RuntimeError("DEVICE_ENCRYPTION_KEY must be 64 bytes")
