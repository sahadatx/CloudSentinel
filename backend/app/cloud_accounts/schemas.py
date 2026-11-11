"""Request and response contracts for cloud account administration."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CloudAccountCreate(BaseModel):
    """Register AWS account access metadata and enabled scan regions."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=2, max_length=160)
    environment: str | None = Field(default=None, min_length=2, max_length=80)
    account_id: str = Field(pattern=r"^\d{12}$")
    primary_region: str | None = Field(default=None, max_length=40)
    role_arn: str | None = Field(default=None, min_length=30, max_length=512)
    regions: list[str] = Field(min_length=1, max_length=100)


class CloudAccountUpdate(BaseModel):
    """Update account label, assumed role, or configured regions."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str | None = Field(default=None, min_length=2, max_length=160)
    environment: str | None = Field(default=None, min_length=2, max_length=80)
    role_arn: str | None = Field(default=None, min_length=30, max_length=512)
    primary_region: str | None = Field(default=None, max_length=40)
    regions: list[str] | None = Field(default=None, min_length=1, max_length=100)

    @model_validator(mode="after")
    def require_non_null_changes(self) -> "CloudAccountUpdate":
        """Require at least one concrete field; null is not an update value."""
        invalid_null_fields = self.model_fields_set - {"environment"}
        if not self.model_fields_set or any(
            getattr(self, field) is None for field in invalid_null_fields
        ):
            raise ValueError("Provide at least one non-null account field to update.")
        return self


class CloudRegionRead(BaseModel):
    """Configured AWS region; configuration does not imply resource discovery."""

    model_config = ConfigDict(from_attributes=True)

    region_code: str
    is_enabled: bool


class CloudRegionInventoryRead(CloudRegionRead):
    """Configured AWS region with counts derived from normalized inventory."""

    asset_count: int


class CloudAccountRead(BaseModel):
    """Safe cloud-account metadata; never contains ExternalId or credentials."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    environment: str | None
    provider: str = "AWS"
    account_id: str
    primary_region: str | None
    role_arn: str | None
    connection_status: str
    validation_mode: Literal["real", "mock"] | None
    created_at: datetime
    last_validated_at: datetime | None
    last_error_code: str | None
    last_scan_at: datetime | None = None
    regions: list[CloudRegionRead]


class CloudAccountCreated(CloudAccountRead):
    """Initial provisioning response includes its generated ExternalId once."""

    external_id: str


class CloudAccountValidation(BaseModel):
    """Sanitized connection validation result."""

    account_id: str
    connection_status: str
    validated_at: datetime
    validation_mode: Literal["real", "mock"]
    baseline_permissions_status: Literal["not_checked", "simulated_passed", "simulated_failed"]


class CloudAccountValidationMode(BaseModel):
    """Current server-selected AWS validation mode, without secrets."""

    mode: Literal["real", "mock"]


class CloudAccountExternalId(BaseModel):
    """One-time External ID setup response; never persisted in audit payloads."""

    external_id: str
