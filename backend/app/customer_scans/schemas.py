"""Customer assessment request and response contracts."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class CustomerScanStatusRead(BaseModel):
    enabled: bool
    max_upload_bytes: int
    timeout_seconds: int


class CustomerScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_type: Literal["iac", "container"]
    source_filename: str
    status: str
    finding_count: int
    scanner_version: str | None
    error_code: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    expires_at: datetime


class CustomerScanPage(BaseModel):
    items: list[CustomerScanRead]
    total: int
    offset: int
    limit: int


class CustomerScanFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    title: str
    severity: str
    category: str
    resource: str | None
    details: dict[str, Any]


class CustomerScanFindingPage(BaseModel):
    items: list[CustomerScanFindingRead]
    total: int
    offset: int
    limit: int

