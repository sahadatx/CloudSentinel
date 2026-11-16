"""Public contracts for reports, remediation approvals, notifications, and audit."""

from datetime import date, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ReportFilters(BaseModel):
    environment: str | None = Field(default=None, max_length=80)
    cloud_account_id: UUID | None = None
    region: str | None = Field(default=None, max_length=40)
    asset_type: str | None = Field(default=None, max_length=80)
    compliance_framework: str | None = Field(default=None, max_length=80)
    severities: list[Literal["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]] = Field(
        default_factory=list, max_length=5
    )
    finding_statuses: list[str] = Field(default_factory=list, max_length=8)
    date_from: date | None = None
    date_to: date | None = None

    @model_validator(mode="after")
    def validate_dates(self) -> "ReportFilters":
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValueError("date_from must be on or before date_to")
        return self


class ReportCreate(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    report_type: Literal[
        "executive_security",
        "security_assessment",
        "security_posture",
        "findings",
        "compliance",
        "risk",
        "assets",
        "scans",
        "remediation",
        "accounts",
    ]
    file_format: Literal["PDF", "CSV", "JSON"] = "PDF"
    filters: ReportFilters = Field(default_factory=ReportFilters)


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    report_type: str
    status: str
    file_format: str
    report_version: int
    generator_version: str
    created_by_user_id: UUID
    created_by_name: str | None = None
    created_by_role: str | None = None
    filters: dict[str, object]
    checksum: str | None
    snapshot_checksum: str | None
    file_size: int | None
    data_snapshot_at: datetime | None
    generated_at: datetime | None
    retention_until: datetime | None
    parent_report_id: UUID | None
    error_code: str | None
    error_message: str | None
    created_at: datetime


class ReportDetail(ReportRead):
    snapshot: dict[str, object] | None


class ReportPage(BaseModel):
    items: list[ReportRead]
    total: int
    offset: int
    limit: int


class ReportSummary(BaseModel):
    total: int
    queued: int
    generating: int
    completed: int
    failed: int
    expired: int


class RemediationCreate(BaseModel):
    request_note: str = Field(min_length=3, max_length=1000)


class RemediationDecision(BaseModel):
    decision: Literal["APPROVED", "REJECTED"]
    decision_note: str = Field(min_length=3, max_length=1000)


class RemediationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID
    requested_by_user_id: UUID
    decided_by_user_id: UUID | None
    status: str
    request_note: str
    decision_note: str | None
    action_definition: dict[str, object]
    evidence_id: UUID | None
    verification_status: str
    requested_at: datetime
    decided_at: datetime | None


class RemediationPage(BaseModel):
    items: list[RemediationRead]
    total: int
    offset: int
    limit: int


class RemediationSummary(BaseModel):
    pending_approval: int
    approved: int
    verification_pending: int
    completed: int
    failed: int
    rejected: int
    cancelled: int


class RemediationVerify(BaseModel):
    scan_job_id: UUID
    result: Literal["PASSED", "FAILED"]
    note: str = Field(min_length=3, max_length=1000)


class RemediationCancel(BaseModel):
    decision_note: str = Field(min_length=3, max_length=1000)


class RemediationEvidenceRead(BaseModel):
    id: UUID
    source: str
    expected_state: dict[str, object]
    detected_condition: dict[str, object]
    collected_at: datetime


class RemediationFindingRead(BaseModel):
    id: UUID
    title: str
    severity: str
    status: str
    asset_id: UUID
    asset_name: str
    resource_id: str
    account_id: UUID
    account_name: str
    aws_account_id: str
    region_code: str
    risk_score: int | None


class RemediationDetail(BaseModel):
    request: RemediationRead
    finding: RemediationFindingRead
    evidence: RemediationEvidenceRead | None


class NotificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    category: str
    title: str
    message: str
    resource_type: str | None
    resource_id: str | None
    read_at: datetime | None
    created_at: datetime


class NotificationPage(BaseModel):
    items: list[NotificationRead]
    total: int
    unread: int
    offset: int
    limit: int


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    actor_user_id: UUID | None
    actor_type: str
    actor_name: str
    actor_role: str | None
    action: str
    resource_type: str
    resource_id: str | None
    target_type: str | None
    target_id: str | None
    status: str
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    before: dict[str, object] | None
    after: dict[str, object] | None
    details: dict[str, object]
    retention_until: datetime | None
    created_at: datetime


class AuditEventPage(BaseModel):
    items: list[AuditEventRead]
    total: int
    offset: int
    limit: int


class AuditSummary(BaseModel):
    events_today: int
    security_events: int
    failed_actions: int
    administrative_actions: int
