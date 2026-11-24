from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

LICENSE_PATTERN = r"^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3}$"
MAC_PATTERN = r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$"


class ActivationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: int = Field(alias="schema")
    license: str = Field(pattern=LICENSE_PATTERN)
    system: str = Field(min_length=1, max_length=255)
    release: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=512)
    arch: str = Field(min_length=1, max_length=64)
    cpu_count: int = Field(ge=0, le=1024)
    mac: str = Field(pattern=MAC_PATTERN)
    checksum: str = Field(pattern=r"^[0-9a-f]{64}$")


class ActivationResponse(BaseModel):
    status: Literal["activated"] = "activated"
    already_activated: bool
    activation_id: UUID
    license: str
    activated_at: datetime
