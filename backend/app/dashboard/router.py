"""Permission-aware, tenant-scoped operations dashboard aggregation."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.compliance.service import control_status
from app.core.models import (
    Alert,
    Asset,
    AuditEvent,
    CloudAccount,
    ComplianceControl,
    ComplianceFramework,
    Finding,
    Notification,
    Organization,
    RemediationRequest,
    RiskScore,
    ScanJob,
)
from app.dashboard.schemas import (
    DashboardActivity,
    DashboardCriticalFinding,
    DashboardOverview,
    DashboardRiskyAsset,
    DashboardScan,
    DashboardSummary,
)
from app.risk.service import aggregate_scores, is_risk_active, risk_level

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
OPEN_STATUSES = {"OPEN", "TRIAGED", "ASSIGNED", "IN_PROGRESS"}
SECURITY_SCORE_MODEL_VERSION = "1.0"


def _is_open(finding: Finding, now: datetime) -> bool:
    return finding.status in OPEN_STATUSES or (
        finding.status == "SUPPRESSED" and is_risk_active(finding, now)
    )


def calculate_security_score(
    risk_score: int | None, compliance_score: int | None
) -> tuple[int | None, str | None]:
    """Apply the versioned posture model only when both source assessments exist."""
    if risk_score is None or compliance_score is None:
        return None, None
    score = round(0.4 * (100 - risk_score) + 0.6 * compliance_score)
    level = (
        "STRONG"
        if score >= 80
        else "GUARDED"
        if score >= 60
        else "ELEVATED"
        if score >= 40
        else "HIGH RISK"
        if score >= 20
        else "CRITICAL"
    )
    return score, level


def _context_account_ids(
    session: Session, organization_id: UUID, environment: str | None
) -> list[UUID]:
    query = select(CloudAccount.id).where(CloudAccount.organization_id == organization_id)
    if environment:
        query = query.where(CloudAccount.environment == environment)
    return list(session.scalars(query).all())


def _audit_href(resource_type: str, resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    routes = {
        "finding": "findings",
        "asset": "assets",
        "cloud_account": "cloud-accounts",
        "scan_job": "scans",
        "policy": "policies",
        "report": "reports",
    }
    if resource_type.lower() == "remediation_request":
        return "/remediation"
    route = routes.get(resource_type.lower())
    return f"/{route}/{resource_id}" if route else None


def _build_overview(
    session: Session,
    principal: Principal,
    *,
    environment: str | None,
    region: str | None,
) -> DashboardOverview:
    org_id = principal.organization_id
    grants = principal.permissions
    organization = session.get(Organization, org_id)
    if organization is None:
        # Principal is only issued for an active organization; keep response safe if it
        # is removed between token validation and aggregation.
        from app.core.domain_errors import NotFoundError

        raise NotFoundError("Organization")

    env_options = list(
        session.scalars(
            select(CloudAccount.environment)
            .where(
                CloudAccount.organization_id == org_id,
                CloudAccount.environment.is_not(None),
            )
            .distinct()
            .order_by(CloudAccount.environment)
        ).all()
    )
    region_query = select(Asset.region_code).where(Asset.organization_id == org_id)
    if environment:
        region_query = region_query.join(
            CloudAccount, CloudAccount.id == Asset.cloud_account_id
        ).where(CloudAccount.environment == environment)
    regions = list(session.scalars(region_query.distinct().order_by(Asset.region_code)).all())
    account_ids = _context_account_ids(session, org_id, environment)

    result = DashboardOverview(
        organization_id=org_id,
        organization_name=organization.name,
        environment=environment,
        region=region,
        available_environments=env_options,
        available_regions=regions,
        security_score=None,
        security_score_level=None,
        security_score_model_version=SECURITY_SCORE_MODEL_VERSION,
        top_risky_assets=[],
        critical_findings_list=[],
        recent_activity=[],
        recent_scans=[],
    )

    if "cloud_accounts:read" in grants:
        account_query = select(func.count(CloudAccount.id)).where(
            CloudAccount.organization_id == org_id
        )
        connected_query = select(func.count(CloudAccount.id)).where(
            CloudAccount.organization_id == org_id,
            CloudAccount.connection_status == "connected",
        )
        mock_query = select(func.count(CloudAccount.id)).where(
            CloudAccount.organization_id == org_id,
            CloudAccount.connection_status == "connected",
            CloudAccount.validation_mode == "mock",
        )
        if environment:
            account_query = account_query.where(CloudAccount.environment == environment)
            connected_query = connected_query.where(CloudAccount.environment == environment)
            mock_query = mock_query.where(CloudAccount.environment == environment)
        result.cloud_accounts = session.scalar(account_query) or 0
        result.connected_accounts = session.scalar(connected_query) or 0
        result.local_mock_accounts = session.scalar(mock_query) or 0

    asset_ids: list[UUID] | None = None
    if "assets:read" in grants or "findings:read" in grants:
        asset_query = select(Asset.id).where(Asset.organization_id == org_id)
        if account_ids:
            asset_query = asset_query.where(Asset.cloud_account_id.in_(account_ids))
        elif environment:
            asset_query = asset_query.where(Asset.id == UUID(int=0))
        if region:
            asset_query = asset_query.where(Asset.region_code == region)
        asset_ids = list(session.scalars(asset_query).all())
        if "assets:read" in grants:
            result.assets = len(asset_ids)

    finding_rows: list[tuple[Finding, RiskScore | None, Asset, CloudAccount]] = []
    if "findings:read" in grants:
        statement = (
            select(Finding, RiskScore, Asset, CloudAccount)
            .join(
                Asset,
                (Asset.id == Finding.asset_id) & (Asset.organization_id == Finding.organization_id),
            )
            .join(
                CloudAccount,
                (CloudAccount.id == Finding.cloud_account_id)
                & (CloudAccount.organization_id == Finding.organization_id),
            )
            .outerjoin(
                RiskScore,
                (RiskScore.finding_id == Finding.id)
                & (RiskScore.organization_id == Finding.organization_id),
            )
            .where(Finding.organization_id == org_id)
        )
        if environment:
            if account_ids:
                statement = statement.where(Finding.cloud_account_id.in_(account_ids))
            else:
                statement = statement.where(Finding.id == UUID(int=0))
        if region:
            statement = statement.where(Finding.region_code == region)
        finding_rows = [
            (finding, risk, asset, account)
            for finding, risk, asset, account in session.execute(statement).all()
        ]
        now = datetime.now(UTC)
        active_rows = [row for row in finding_rows if _is_open(row[0], now)]
        active_scores = [score.score for _finding, score, _asset, _account in active_rows if score]
        score_bands = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for finding, score_row, _asset, _account in active_rows:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            if score_row:
                score_bands[score_row.level] = score_bands.get(score_row.level, 0) + 1
        result.open_findings = len(active_rows)
        result.open_by_severity = by_severity
        result.critical_findings = by_severity["CRITICAL"]
        result.risk_distribution = score_bands
        result.organization_risk_score = aggregate_scores(active_scores) if active_scores else None
        result.organization_risk_level = (
            risk_level(result.organization_risk_score)
            if result.organization_risk_score is not None
            else None
        )

        asset_findings: dict[UUID, list[int]] = {}
        asset_context: dict[UUID, tuple[Asset, CloudAccount]] = {}
        for _finding, score_row, asset, account in active_rows:
            if score_row:
                asset_findings.setdefault(asset.id, []).append(score_row.score)
                asset_context[asset.id] = (asset, account)
        asset_scores = [
            (asset_id, aggregate_scores(scores)) for asset_id, scores in asset_findings.items()
        ]
        if "assets:read" in grants:
            result.high_risk_assets = sum(value >= 60 for _asset_id, value in asset_scores)
            for asset_id, value in sorted(asset_scores, key=lambda item: (-item[1], str(item[0])))[
                :5
            ]:
                asset, account = asset_context[asset_id]
                result.top_risky_assets.append(
                    DashboardRiskyAsset(
                        id=asset.id,
                        name=asset.name or asset.resource_id,
                        resource_type=asset.resource_type,
                        account_name=account.name,
                        region=asset.region_code,
                        score=value,
                        level=risk_level(value),
                    )
                )

        critical = [row for row in active_rows if row[0].severity == "CRITICAL"]
        critical.sort(key=lambda row: (-(row[1].score if row[1] else -1), row[0].id.hex))
        result.critical_findings_list = [
            DashboardCriticalFinding(
                id=finding.id,
                title=finding.title,
                severity=finding.severity,
                status=finding.status,
                asset_id=asset.id,
                asset_name=asset.name or asset.resource_id,
                risk_score=score.score if score else None,
                risk_level=score.level if score else None,
            )
            for finding, score, asset, _account in critical[:5]
        ]

        if "compliance:read" in grants or "findings:read" in grants:
            frameworks = session.scalars(
                select(ComplianceFramework).where(ComplianceFramework.is_active.is_(True))
            ).all()
            control_results: list[tuple[str, int]] = []
            for framework in frameworks:
                controls = session.scalars(
                    select(ComplianceControl).where(ComplianceControl.framework_id == framework.id)
                ).all()
                for control in controls:
                    status, assessed, passed, _failed, partial, _na, _napp = control_status(
                        session, org_id, control, asset_ids=asset_ids
                    )
                    if status in {"PASS", "FAIL", "PARTIAL"} and assessed:
                        control_results.append((status, round(passed * 100 / assessed)))
            assessed = len(control_results)
            result.compliance_score = (
                round(sum(score for _status, score in control_results) / assessed)
                if assessed
                else None
            )
            result.passing_controls = sum(status == "PASS" for status, _score in control_results)
            result.failing_controls = sum(status == "FAIL" for status, _score in control_results)
            result.partial_controls = sum(status == "PARTIAL" for status, _score in control_results)
            result.not_assessed_controls = sum(
                control_status(session, org_id, control, asset_ids=asset_ids)[0] == "NOT_ASSESSED"
                for framework in frameworks
                for control in session.scalars(
                    select(ComplianceControl).where(ComplianceControl.framework_id == framework.id)
                ).all()
            )

        # This posture score has a separate, explicit backend model from risk score.
        # It is withheld unless both risk and compliance have real assessments.
        result.security_score, result.security_score_level = calculate_security_score(
            result.organization_risk_score, result.compliance_score
        )

    if "scans:read" in grants:
        scan_query = (
            select(ScanJob, CloudAccount.name)
            .join(
                CloudAccount,
                (CloudAccount.id == ScanJob.cloud_account_id)
                & (CloudAccount.organization_id == ScanJob.organization_id),
            )
            .where(ScanJob.organization_id == org_id)
        )
        if account_ids:
            scan_query = scan_query.where(ScanJob.cloud_account_id.in_(account_ids))
        elif environment:
            scan_query = scan_query.where(ScanJob.id == UUID(int=0))
        counts = {
            key: 0 for key in ("queued", "running", "completed", "partial", "failed", "cancelled")
        }
        scan_rows: list[tuple[ScanJob, str]]
        if region:
            scan_rows = [
                (job, name)
                for job, name in session.execute(
                    scan_query.order_by(ScanJob.created_at.desc())
                ).all()
                if region in job.requested_regions
            ]
            for job, _name in scan_rows:
                counts[job.status] = counts.get(job.status, 0) + 1
        else:
            group_query = select(ScanJob.status, func.count(ScanJob.id)).where(
                ScanJob.organization_id == org_id
            )
            if environment:
                group_query = group_query.where(ScanJob.cloud_account_id.in_(account_ids))
            grouped = session.execute(group_query.group_by(ScanJob.status)).all()
            counts.update({status: count for status, count in grouped})
            scan_rows = [
                (job, name)
                for job, name in session.execute(
                    scan_query.order_by(ScanJob.created_at.desc()).limit(5)
                ).all()
            ]
        result.scan_status_counts = counts
        result.recent_scans = [
            DashboardScan(
                id=job.id,
                account_name=name,
                status=job.status,
                progress_percent=(
                    round(job.progress_completed * 100 / job.progress_total)
                    if job.progress_total
                    else (100 if job.status == "completed" else 0)
                ),
                created_at=job.created_at,
                finished_at=job.finished_at,
            )
            for job, name in scan_rows[:5]
        ]

    if "remediation:read" in grants:
        remediation_query = select(RemediationRequest.status, func.count(RemediationRequest.id))
        remediation_query = remediation_query.join(
            Finding, Finding.id == RemediationRequest.finding_id
        ).where(RemediationRequest.organization_id == org_id)
        if region:
            remediation_query = remediation_query.where(Finding.region_code == region)
        if environment and account_ids:
            remediation_query = remediation_query.where(Finding.cloud_account_id.in_(account_ids))
        elif environment:
            remediation_query = remediation_query.where(Finding.id == UUID(int=0))
        result.remediation_counts = {
            status: count
            for status, count in session.execute(
                remediation_query.group_by(RemediationRequest.status)
            ).all()
        }

    if "alerts:read" in grants:
        alert_rows = session.execute(
            select(Alert.status, Alert.severity, func.count(Alert.id))
            .where(
                Alert.organization_id == org_id,
                Alert.status.in_(("OPEN", "ACKNOWLEDGED")),
            )
            .group_by(Alert.status, Alert.severity)
        ).all()
        result.active_alerts = sum(count for _status, _severity, count in alert_rows)

    result.unread_notifications = (
        session.scalar(
            select(func.count(Notification.id)).where(
                Notification.organization_id == org_id,
                Notification.recipient_user_id == principal.user_id,
                Notification.read_at.is_(None),
            )
        )
        or 0
    )

    if "audit:read" in grants:
        activity_rows = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.organization_id == org_id)
            .order_by(AuditEvent.created_at.desc())
            .limit(10)
        ).all()
        result.recent_activity = [
            DashboardActivity(
                id=event.id,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                details={},
                created_at=event.created_at,
                href=_audit_href(event.resource_type, event.resource_id),
            )
            for event in activity_rows
        ]

    timestamps: list[datetime] = []
    if account_ids:
        latest_account = session.scalar(
            select(func.max(CloudAccount.updated_at)).where(CloudAccount.id.in_(account_ids))
        )
        if latest_account:
            timestamps.append(latest_account)
    if "scans:read" in grants and account_ids:
        latest_scan = session.scalar(
            select(func.max(ScanJob.updated_at)).where(ScanJob.cloud_account_id.in_(account_ids))
        )
        if latest_scan:
            timestamps.append(latest_scan)
    if asset_ids:
        latest_asset = session.scalar(
            select(func.max(Asset.updated_at)).where(Asset.id.in_(asset_ids))
        )
        if latest_asset:
            timestamps.append(latest_asset)
    if "findings:read" in grants and finding_rows:
        latest_finding = max(row[0].last_seen_at for row in finding_rows)
        timestamps.append(latest_finding)
    if result.recent_activity:
        timestamps.append(result.recent_activity[0].created_at)
    result.last_updated_at = max(timestamps) if timestamps else None
    return result


@router.get("/overview", response_model=DashboardOverview)
def dashboard_overview(
    principal: Annotated[Principal, Depends(require_permission("organizations:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    environment: Annotated[str | None, Query(max_length=80)] = None,
    region: Annotated[str | None, Query(max_length=40)] = None,
) -> DashboardOverview:
    """Return a single permission-aware current-organization operations view."""
    return _build_overview(session, principal, environment=environment, region=region)


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    principal: Annotated[Principal, Depends(require_permission("organizations:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    environment: Annotated[str | None, Query(max_length=80)] = None,
    region: Annotated[str | None, Query(max_length=40)] = None,
) -> DashboardSummary:
    """Compatibility summary endpoint backed by the canonical overview aggregation."""
    overview = _build_overview(session, principal, environment=environment, region=region)
    return DashboardSummary(
        cloud_accounts=overview.cloud_accounts,
        connected_accounts=overview.connected_accounts,
        local_mock_accounts=overview.local_mock_accounts,
        assets=overview.assets,
        high_risk_assets=overview.high_risk_assets,
        open_findings=overview.open_findings,
        critical_findings=overview.critical_findings,
        organization_risk_score=overview.organization_risk_score,
        organization_risk_level=overview.organization_risk_level,
        compliance_score=overview.compliance_score,
        unread_notifications=overview.unread_notifications,
        active_alerts=overview.active_alerts,
    )
