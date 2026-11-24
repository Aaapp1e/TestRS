from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto import device_fingerprint
from app.models.license import License
from app.schemas.activation import ActivationPayload


class LicenseConflict(Exception):
    pass


async def activate_license(
    session: AsyncSession,
    payload: ActivationPayload,
) -> tuple[License, bool]:
    fingerprint = device_fingerprint(payload.mac)

    existing = await session.scalar(
        select(License).where(License.license_key == payload.license)
    )
    if existing is not None:
        if existing.device_fingerprint != fingerprint:
            raise LicenseConflict
        return existing, True

    row = License(
        license_key=payload.license,
        device_fingerprint=fingerprint,
    )
    session.add(row)

    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        existing = await session.scalar(
            select(License).where(License.license_key == payload.license)
        )
        if existing is None:
            raise
        if existing.device_fingerprint != fingerprint:
            raise LicenseConflict
        return existing, True

    return row, False
