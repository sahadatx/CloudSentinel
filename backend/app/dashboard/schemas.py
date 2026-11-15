"""Tenant-scoped dashboard overview response contracts."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class DashboardSummary(BaseModel):
    """Current metrics derived from tenant-owned records and permission grants."""

    cloud_accounts: int | None = None
    connected_accounts: int | None = None
    local_mock_accounts: int | None = None
    assets: int | None = None
    high_risk_assets: int | None = None
    open_findings: int | None = None
    critical_findings: int | None = None
    organization_risk_score: int | None = None
    organization_risk_level: str | None = None
    compliance_score: int | None = None
    unread_notifications: int | None = None
    active_alerts: int | None = None


class DashboardRiskyAsset(BaseModel):
    id: UUID
    name: str
    resource_type: str
    account_name: str
    region: str
    score: int
    level: str


class DashboardCriticalFinding(BaseModel):
    id: UUID
    title: str
    severity: str
    status: str
    asset_id: UUID
    asset_name: str
    risk_score: int | None
    risk_level: str | None


class DashboardActivity(BaseModel):
    id: UUID
    action: str
    resource_type: str
    resource_id: str | None
    details: dict[str, Any]
    created_at: datetime
    href: str | None


class DashboardScan(BaseModel):
    id: UUID
    account_name: str
    status: str
    progress_percent: int
    created_at: datetime
    finished_at: datetime | None


class DashboardOverview(BaseModel):
    organization_id: UUID
    organization_name: str
    environment: str | None
    region: str | None
    available_environments: list[str]
    available_regions: list[str]
    last_updated_at: datetime | None = None
    security_score: int | None
    security_score_level: str | None
    security_score_model_version: str
    cloud_accounts: int | None = None
    connected_accounts: int | None = None
    local_mock_accounts: int | None = None
    assets: int | None = None
    open_findings: int | None = None
    open_by_severity: dict[str, int] | None = None
    critical_findings: int | None = None
    high_risk_assets: int | None = None
    organization_risk_score: int | None = None
    organization_risk_level: str | None = None
    risk_distribution: dict[str, int] | None = None
    compliance_score: int | None = None
    passing_controls: int | None = None
    failing_controls: int | None = None
    partial_controls: int | None = None
    not_assessed_controls: int | None = None
    top_risky_assets: list[DashboardRiskyAsset] = Field(default_factory=list)
    critical_findings_list: list[DashboardCriticalFinding] = Field(default_factory=list)
    recent_activity: list[DashboardActivity] = Field(default_factory=list)
    scan_status_counts: dict[str, int] | None = None
    recent_scans: list[DashboardScan] = Field(default_factory=list)
    remediation_counts: dict[str, int] | None = None
    unread_notifications: int | None = None
    active_alerts: int | None = None
    trend_available: bool = False
    trend: list[dict[str, Any]] = Field(default_factory=list)
