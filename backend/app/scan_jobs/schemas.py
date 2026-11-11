"""Validated scan-job API request and response contracts."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cloudsentinel_scanner.collectors.aws_inventory import AWS_RESOURCE_TYPES

ResourceType = Literal[
    "vpc",
    "subnet",
    "security_group",
    "network_interface",
    "ec2_instance",
    "ebs_volume",
    "rds_instance",
    "lambda_function",
    "s3_bucket",
    "iam_user",
    "iam_role",
    "iam_policy",
    "cloudtrail",
    "cloudwatch_alarm",
    "kms_key",
    "ecr_repository",
    "ecs_cluster",
    "ecs_service",
    "eks_cluster",
]


class ScanCreate(BaseModel):
    """Request an asynchronous scan of an already registered AWS account."""

    cloud_account_id: UUID
    regions: list[str] | None = Field(default=None, min_length=1, max_length=100)
    resource_types: list[ResourceType] | None = Field(default=None, min_length=1, max_length=30)

    @field_validator("regions")
    @classmethod
    def reject_duplicate_regions(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and len(set(value)) != len(value):
            raise ValueError("Regions must be unique.")
        return value

    @field_validator("resource_types")
    @classmethod
    def reject_duplicate_resource_types(
        cls, value: list[ResourceType] | None
    ) -> list[ResourceType] | None:
        if value is not None and len(set(value)) != len(value):
            raise ValueError("Resource types must be unique.")
        if value is not None and not set(value).issubset(AWS_RESOURCE_TYPES):
            raise ValueError("One or more resource types are not supported.")
        return value


class ScanJobRead(BaseModel):
    """Tenant-safe current state and bounded error codes for a scan job."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    cloud_account_id: UUID
    cloud_account_name: str | None = None
    environment: str | None = None
    status: str
    requested_regions: list[str]
    requested_resource_types: list[str]
    progress_total: int
    progress_completed: int
    resources_discovered: int
    errors_count: int
    error_codes: list[dict[str, str]]
    progress_percent: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ScanJobPage(BaseModel):
    """Bounded scan history response."""

    items: list[ScanJobRead]
    total: int
    offset: int
    limit: int
    status_counts: dict[str, int]


class AssetRead(BaseModel):
    """Normalized cloud resource fields safe for tenant inventory APIs."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    cloud_account_id: UUID
    cloud_account_name: str | None = None
    environment: str | None = None
    last_scan_job_id: UUID | None
    provider: str
    resource_type: str
    resource_id: str
    resource_arn: str | None
    region_code: str
    name: str | None
    tags: dict[str, str]
    owner_metadata: dict[str, str] | None
    attributes: dict[str, object]
    status: str
    missed_scan_count: int
    risk_score: int | None = None
    compliance_status: Literal[
        "PASS", "FAIL", "PARTIAL", "NOT_ASSESSED", "NOT_APPLICABLE"
    ] | None = None
    compliance_last_assessed_at: datetime | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


class AssetSummary(BaseModel):
    """Inventory lifecycle counts derived from tenant-owned assets."""

    total: int
    new: int
    active: int
    stale: int
    removed: int
    critical: int | None = None
    high_risk: int | None = None


class AssetPage(BaseModel):
    """Bounded asset list response."""

    items: list[AssetRead]
    total: int
    offset: int
    limit: int


class AssetFilterOptions(BaseModel):
    """Filter values drawn from assets visible in the active tenant."""

    regions: list[str]
    resource_types: list[str]
    environments: list[str]
    providers: list[str]
    accounts: list[dict[str, str]]


class AssetRelationshipRead(BaseModel):
    """Safe relationship edge and its target inventory identity."""

    relationship_type: str
    target: AssetRead


class AssetEvidenceRead(BaseModel):
    """Redacted rule evidence attached to an asset, when findings are enabled."""

    id: UUID
    finding_id: UUID
    scan_job_id: UUID
    rule_version: str
    scanner_version: str
    source: str
    expected_state: dict[str, object]
    detected_condition: dict[str, object]
    configuration: dict[str, object]
    collected_at: datetime
