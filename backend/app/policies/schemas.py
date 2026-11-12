"""Validated contracts for organization policy management and assessment views."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cloudsentinel_scanner.collectors.aws_inventory import AWS_RESOURCE_TYPES

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
PolicyStatus = Literal["enabled", "disabled"]


class PolicyCreate(BaseModel):
    rule_id: str | None = Field(default=None, max_length=100)
    name: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=2000)
    provider: Literal["AWS"] = "AWS"
    resource_types: list[str] = Field(min_length=1, max_length=20)
    category: str = Field(min_length=1, max_length=100)
    severity: Severity
    status: PolicyStatus = "enabled"
    detection_logic: dict[str, Any]
    evidence_logic: dict[str, Any] = Field(default_factory=dict)
    remediation: str = Field(min_length=1, max_length=2000)
    compliance_controls: list[dict[str, str]] = Field(default_factory=list, max_length=50)

    @field_validator("resource_types")
    @classmethod
    def supported_resource_types(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or not set(value).issubset(AWS_RESOURCE_TYPES):
            raise ValueError(
                "Choose unique resource types supported by the AWS inventory collector."
            )
        return value


class PolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, min_length=1, max_length=2000)
    provider: Literal["AWS"] | None = None
    resource_types: list[str] | None = Field(default=None, min_length=1, max_length=20)
    category: str | None = Field(default=None, min_length=1, max_length=100)
    severity: Severity | None = None
    detection_logic: dict[str, Any] | None = None
    evidence_logic: dict[str, Any] | None = None
    remediation: str | None = Field(default=None, min_length=1, max_length=2000)
    compliance_controls: list[dict[str, str]] | None = Field(default=None, max_length=50)

    @field_validator("resource_types")
    @classmethod
    def supported_resource_types(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and (
            len(set(value)) != len(value) or not set(value).issubset(AWS_RESOURCE_TYPES)
        ):
            raise ValueError(
                "Choose unique resource types supported by the AWS inventory collector."
            )
        return value

    @model_validator(mode="after")
    def reject_empty_update(self) -> "PolicyUpdate":
        if not self.model_fields_set:
            raise ValueError("Provide at least one policy field to update.")
        return self


class PolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    name: str
    description: str
    provider: str
    resource_types: list[str]
    category: str
    severity: str
    status: str
    version: int
    detection_logic: dict[str, Any]
    evidence_logic: dict[str, Any]
    remediation: str
    compliance_controls: list[dict[str, str]]
    is_builtin: bool
    created_at: datetime
    updated_at: datetime


class PolicyPage(BaseModel):
    items: list[PolicyRead]
    total: int
    offset: int
    limit: int


class PolicySummary(BaseModel):
    total: int
    enabled: int
    disabled: int
    critical: int
    compliance_mapped: int


class PolicyFilterOptions(BaseModel):
    providers: list[str]
    severities: list[str]
    categories: list[str]
    statuses: list[str]
    resource_types: list[str]
    frameworks: list[str]


class PolicyVersionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    version: int
    snapshot: dict[str, Any]
    changed_by_user_id: UUID | None
    created_at: datetime


class PolicyAssessmentRead(BaseModel):
    assessment_id: UUID
    asset_id: UUID
    asset_name: str | None
    resource_id: str
    resource_type: str
    account_name: str
    region_code: str
    result: Literal["PASS", "FAIL", "NOT_APPLICABLE", "ERROR"]
    error_code: str | None
    policy_version: int
    scan_job_id: UUID
    evaluated_at: datetime


class PolicyAssessmentPage(BaseModel):
    items: list[PolicyAssessmentRead]
    total: int
    offset: int
    limit: int
    assessed: int
    passed: int
    failed: int
    not_applicable: int
    errors: int
