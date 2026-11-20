"""Tenant alert and rule API contracts."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_rule_id: UUID | None
    alert_type: str
    source_type: str
    source_id: str
    source_href: str | None = None
    account_name: str | None = None
    region_code: str | None = None
    title: str
    description: str
    severity: str
    status: str
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    acknowledged_by_user_id: UUID | None
    acknowledged_at: datetime | None
    resolved_by_user_id: UUID | None
    resolved_at: datetime | None
    dismissed_by_user_id: UUID | None
    dismissed_at: datetime | None
    created_at: datetime


class AlertPage(BaseModel):
    items: list[AlertRead]
    total: int
    offset: int
    limit: int


class AlertSummary(BaseModel):
    active: int
    critical: int
    high: int
    acknowledged: int
    resolved: int
    dismissed: int


class AlertReconcileResult(BaseModel):
    evaluated_findings: int
    evaluated_scans: int
    created_alerts: int


class AlertRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    code: str
    name: str
    description: str
    event_type: str
    severity: str
    enabled: bool
    threshold_score: int | None
    updated_at: datetime


class AlertRulePatch(BaseModel):
    enabled: bool | None = None
    threshold_score: int | None = Field(default=None, ge=0, le=100)
