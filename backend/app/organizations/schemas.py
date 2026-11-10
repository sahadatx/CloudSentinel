"""Organization profile API schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class OrganizationRead(BaseModel):
    """Organization data visible to its active members."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    is_active: bool
    description: str | None
    default_environment: str | None
    default_region: str | None
    timezone: str
    date_time_format: str
    created_at: datetime
    updated_at: datetime


class OrganizationUpdate(BaseModel):
    """Fields an organization administrator may change."""

    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=1000)
    default_environment: str | None = Field(default=None, max_length=80)
    default_region: str | None = Field(default=None, max_length=40)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    date_time_format: str | None = Field(default=None, min_length=1, max_length=32)

    @field_validator("name", mode="before")
    @classmethod
    def normalize_name(cls, value: object) -> object:
        if value is None:
            raise ValueError("organization name cannot be null")
        if isinstance(value, str):
            value = value.strip()
            if len(value) < 2:
                raise ValueError("organization name must contain at least 2 characters")
        return value

    @field_validator("description", "default_environment", "default_region", mode="before")
    @classmethod
    def normalize_optional_text(cls, value: object) -> object:
        return value.strip() or None if isinstance(value, str) else value

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip()
            if not value:
                raise ValueError("timezone cannot be blank")
            from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

            try:
                ZoneInfo(value)
            except ZoneInfoNotFoundError as exc:
                raise ValueError("timezone must be a valid IANA timezone") from exc
        return value

    @field_validator("timezone", mode="before")
    @classmethod
    def require_timezone_when_supplied(cls, value: object) -> object:
        if value is None:
            raise ValueError("timezone cannot be null")
        return value

    @field_validator("date_time_format")
    @classmethod
    def validate_date_time_format(cls, value: str | None) -> str | None:
        supported = {"YYYY-MM-DD HH:mm", "MM/DD/YYYY hh:mm A", "DD/MM/YYYY HH:mm"}
        if value is not None and value not in supported:
            raise ValueError("date_time_format must be one of the supported organization formats")
        return value

    @field_validator("date_time_format", mode="before")
    @classmethod
    def require_date_time_format_when_supplied(cls, value: object) -> object:
        if value is None:
            raise ValueError("date_time_format cannot be null")
        return value

    @model_validator(mode="after")
    def require_change(self) -> "OrganizationUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one organization field must be provided")
        return self


class OrganizationSummary(BaseModel):
    """Live organization administration counts from tenant-owned records."""

    total_users: int
    active_users: int
    locked_users: int
    pending_invitations: int
    teams: int
    cloud_accounts: int


class OrganizationSecuritySettings(BaseModel):
    """Persisted password and refresh-session policy for the active tenant."""

    password_min_length: int = Field(ge=12, le=128)
    session_ttl_days: int = Field(ge=1, le=30)
    remembered_session_ttl_days: int = Field(ge=1, le=90)
    max_concurrent_sessions: int = Field(ge=1, le=50)


class OrganizationSecuritySettingsUpdate(BaseModel):
    """Partial updates for organization security policy, with bounded values."""

    password_min_length: int | None = Field(default=None, ge=12, le=128)
    session_ttl_days: int | None = Field(default=None, ge=1, le=30)
    remembered_session_ttl_days: int | None = Field(default=None, ge=1, le=90)
    max_concurrent_sessions: int | None = Field(default=None, ge=1, le=50)

    @model_validator(mode="after")
    def validate_policy(self) -> "OrganizationSecuritySettingsUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one security setting must be provided")
        if self.session_ttl_days is not None and self.remembered_session_ttl_days is not None:
            if self.remembered_session_ttl_days < self.session_ttl_days:
                raise ValueError(
                    "Remembered session lifetime cannot be shorter than the standard lifetime"
                )
        return self


class OrganizationRetentionSettings(BaseModel):
    """Tenant audit retention policy used for new audit events."""

    audit_retention_days: int = Field(ge=30, le=3650)


class OrganizationRetentionSettingsUpdate(BaseModel):
    """Bounded audit retention policy change."""

    audit_retention_days: int = Field(ge=30, le=3650)


class OffboardingRequest(BaseModel):
    """Explicit organization-key confirmation for irreversible offboarding."""

    confirm_slug: str = Field(min_length=2, max_length=100)
