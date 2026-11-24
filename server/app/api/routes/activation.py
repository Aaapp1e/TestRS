import json
from binascii import Error as Base64Error
from datetime import timezone

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import DEVICE_ENCRYPTION_KEY
from app.crypto import decrypt_token, verify_checksum
from app.db import get_session
from app.schemas.activation import ActivationPayload, ActivationResponse
from app.services.activation import LicenseConflict, activate_license

router = APIRouter()

MAX_BODY_BYTES = 16 * 1024


async def read_token(request: Request) -> str:
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="request body is too large")

    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()

    if content_type == "application/json":
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc

        if isinstance(data, dict):
            token = data.get("payload") or data.get("ciphertext")
        elif isinstance(data, str):
            token = data
        else:
            token = None

        if not isinstance(token, str) or not token.strip():
            raise HTTPException(
                status_code=400,
                detail="JSON body must contain a non-empty 'payload'",
            )
        return token.strip()

    if content_type in ("", "text/plain"):
        try:
            token = body.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="token must be UTF-8") from exc
        if not token:
            raise HTTPException(status_code=400, detail="empty token")
        return token

    raise HTTPException(
        status_code=415,
        detail="use Content-Type: text/plain or application/json",
    )


@router.post("/activate", response_model=ActivationResponse)
async def activate(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> ActivationResponse:
    token = await read_token(request)

    try:
        raw_payload = decrypt_token(token, DEVICE_ENCRYPTION_KEY)
    except (Base64Error, ValueError, InvalidTag) as exc:
        raise HTTPException(status_code=400, detail="cannot decrypt payload") from exc

    try:
        verify_checksum(raw_payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="checksum mismatch") from exc

    try:
        payload = ActivationPayload.model_validate(raw_payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    try:
        license_row, already_activated = await activate_license(session, payload)
    except LicenseConflict as exc:
        raise HTTPException(
            status_code=409,
            detail="license is already activated on another device",
        ) from exc

    activated_at = license_row.activated_at
    if activated_at.tzinfo is None:
        activated_at = activated_at.replace(tzinfo=timezone.utc)

    return ActivationResponse(
        already_activated=already_activated,
        activation_id=license_row.id,
        license=license_row.license_key,
        activated_at=activated_at,
    )
