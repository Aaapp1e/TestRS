import base64
import hashlib
import json
import os
from collections.abc import AsyncIterator

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"
os.environ["DEVICE_ENCRYPTION_KEY"] = base64.b64encode(b"t" * 64).decode()

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models.license import License  # noqa: E402,F401

KEY = b"t" * 64
URL = "/api/v1/licenses/activate"


def canonical(data: dict[str, object]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def make_token(**overrides: object) -> str:
    fields: dict[str, object] = {
        "schema": 1,
        "license": "ABCD-EFGH-IJKL-MNOP",
        "system": "Darwin",
        "release": "24.6.0",
        "version": "test",
        "arch": "x86_64",
        "cpu_count": 12,
        "mac": "ac:de:48:00:11:22",
    }
    checksum = overrides.pop("checksum", None)
    fields.update(overrides)
    if checksum is None:
        checksum = hashlib.sha256(canonical(fields)).hexdigest()

    payload = {**fields, "checksum": checksum}
    ciphertext = AESSIV(KEY).encrypt(canonical(payload), None)
    return base64.b64encode(ciphertext).decode("ascii")


@pytest.fixture(autouse=True)
async def clean_db() -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def count_licenses() -> int:
    async with SessionLocal() as session:
        return await session.scalar(select(func.count()).select_from(License)) or 0
