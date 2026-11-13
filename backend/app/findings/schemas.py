"""Bounded API representations for policy rules, findings, and evidence."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PolicyRuleRead(BaseModel):
    """Safe display projection of a bundled versioned policy rule."""

    id: str
    name: str
    description: str
    version: str
    severity: str
    category: str
    resource_types: tuple[str, ...]
    remediation: str


class FindingRead(BaseModel):
    """Tenant-safe finding identity and lifecycle state."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    cloud_account_id: UUID
    asset_id: UUID
    asset_name: str | None = None
    asset_type: str | None = None
    account_name: str | None = None
    data_origin: str | None = None
    scan_job_id: UUID
    rule_id: str
    rule_version: str
    category: str
    title: str
    description: str
    remediation: str
    severity: str
    region_code: str
    status: str
    assigned_to_user_id: UUID | None
    due_at: datetime | None = None
    risk_score: int | None = None
    assignee_name: str | None = None
    assignee_role: str | None = None
    suppression_reason: str | None
    suppression_expires_at: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    verified_at: datetime | None
    verified_by_user_id: UUID | None
    closed_at: datetime | None


class FindingPage(BaseModel):
    items: list[FindingRead]
    total: int
    offset: int
    limit: int


class FindingFilterOptions(BaseModel):
    """Filter values drawn only from current-tenant finding records."""

    categories: list[str]
    regions: list[str]
    asset_types: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)


class FindingKpis(BaseModel):
    open: int
    critical: int
    high: int
    medium: int
    low: int
    overdue: int
    suppressed: int
    resolved: int


class FindingDetail(FindingRead):
    risk_score: int | None
    risk_level: str | None
    risk_factors: dict[str, int]
    risk_model: str | None = None
    risk_model_version: str | None = None
    risk_calculated_at: datetime | None = None
    asset_name: str
    asset_type: str
    asset_arn: str | None = None
    account_name: str
    evidence: list["FindingEvidenceRead"]
    compliance_controls: list["FindingControlRead"]
    events: list["FindingEventRead"]


class FindingEvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID
    scan_job_id: UUID
    rule_version: str
    scanner_version: str
    source: str
    expected_state: dict[str, object]
    detected_condition: dict[str, object]
    configuration: dict[str, object]
    collected_at: datetime


class FindingEvidencePage(BaseModel):
    items: list[FindingEvidenceRead]
    total: int
    offset: int
    limit: int


class FindingControlRead(BaseModel):
    framework_code: str
    framework_name: str
    framework_version: str
    control_code: str
    title: str


class FindingEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    actor_user_id: UUID
    action: str
    from_status: str | None
    to_status: str | None
    reason: str | None
    details: dict[str, object]
    created_at: datetime


class FindingTransitionRequest(BaseModel):
    status: Literal["TRIAGED", "IN_PROGRESS", "RESOLVED", "VERIFIED", "CLOSED"]
    reason: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def require_verification_reason(self) -> "FindingTransitionRequest":
        if self.status == "VERIFIED" and (self.reason is None or len(self.reason.strip()) < 3):
            raise ValueError("A verification note is required.")
        return self


class FindingAssignRequest(BaseModel):
    assignee_user_id: UUID
    due_at: datetime | None = None


class FindingAssigneeRead(BaseModel):
    id: UUID
    display_name: str


class FindingSuppressRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)
    expires_at: datetime

    @model_validator(mode="after")
    def validate_reason(self) -> "FindingSuppressRequest":
        if len(self.reason.strip()) < 3:
            raise ValueError("Suppression reason must contain at least three non-space characters.")
        return self


class RiskRead(BaseModel):
    subject_type: str
    subject_id: UUID
    score: int | None
    level: str | None
    factors: dict[str, object]
    calculated_at: datetime | None
    risk_model: str | None = None
    risk_model_version: str | None = None


class RiskFindingItem(BaseModel):
    id: UUID
    title: str
    severity: str
    status: str
    asset_id: UUID
    asset_name: str | None
    account_name: str | None
    score: int
    level: str


class RiskFindingPage(BaseModel):
    items: list[RiskFindingItem]
    total: int
    offset: int
    limit: int


class RiskAssetItem(BaseModel):
    id: UUID
    name: str
    resource_type: str
    account_name: str
    score: int
    level: str
    finding_count: int


class RiskSummary(BaseModel):
    organization_score: int | None
    organization_level: str | None
    critical: int
    high: int
    medium: int
    low: int
    informational: int
    at_risk_assets: int = 0
    open_critical_findings: int = 0


class ComplianceFrameworkRead(BaseModel):
    code: str
    name: str
    version: str
    coverage_status: str = "UNVERIFIED"
    source_url: str | None = None
    controls_total: int
    assessed: int
    passed: int
    failed: int
    not_assessed: int
    partial: int = 0
    not_applicable: int = 0
    compliance_score: int | None = None


class ComplianceControlRead(BaseModel):
    id: UUID | None = None
    code: str
    title: str
    domain: str | None
    description: str | None = None
    category: str | None = None
    severity: str = "MEDIUM"
    version: str = "1.0"
    framework_code: str | None = None
    framework_name: str | None = None
    framework_version: str | None = None
    guidance: dict[str, object] = Field(default_factory=dict)
    status: Literal["PASS", "FAIL", "PARTIAL", "NOT_ASSESSED", "NOT_APPLICABLE"]
    assessed_assets: int
    passed_assets: int
    failed_assets: int
    finding_ids: list[UUID]
    not_assessed_assets: int = 0
    not_applicable_assets: int = 0
    partial_assets: int = 0
    compliance_score: int | None = None
    last_assessed_at: datetime | None = None


class ComplianceCategoryRead(BaseModel):
    category: str
    total: int
    passed: int
    failed: int
    partial: int
    not_assessed: int
    not_applicable: int = 0
    compliance_score: int | None


class ComplianceSummaryRead(BaseModel):
    frameworks: int
    compliance_score: int | None
    passing_controls: int
    failing_controls: int
    partial_controls: int
    not_assessed_controls: int
    not_applicable_controls: int = 0
    critical_failures: int


class ComplianceAssessmentRead(BaseModel):
    id: UUID
    asset_id: UUID
    asset_name: str
    resource_type: str
    account_id: UUID
    account_name: str
    region: str
    status: str
    observed: dict[str, object] | None
    expected: dict[str, object] | None
    evidence_id: UUID | None
    policy_version: str | None
    assessed_at: datetime


class ComplianceAssessmentRecordRead(BaseModel):
    """Recorded control evaluation without claiming verified framework coverage."""

    assessment_id: UUID
    framework_code: str
    framework_name: str
    framework_version: str
    coverage_status: str
    control_code: str
    control_title: str
    status: str
    asset_name: str
    resource_type: str
    account_name: str
    region: str
    assessed_at: datetime
    synthetic: bool


class ComplianceAssessmentRecordPage(BaseModel):
    items: list[ComplianceAssessmentRecordRead]
    total: int
    offset: int
    limit: int


class ComplianceFindingRead(BaseModel):
    id: UUID
    title: str
    remediation: str
    severity: str
    status: str
    asset_id: UUID
    asset_name: str
    risk_score: int | None


class ComplianceActivityRead(BaseModel):
    action: str
    detail: str
    created_at: datetime


class ComplianceEvidenceRead(BaseModel):
    id: UUID
    asset_id: UUID
    asset_name: str
    source: str
    expected_state: dict[str, object]
    observed_state: dict[str, object]
    configuration: dict[str, object]
    collected_at: datetime


FindingDetail.model_rebuild()
