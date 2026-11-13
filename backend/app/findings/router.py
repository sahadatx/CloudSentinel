"""Policy catalog and tenant-scoped findings lifecycle and investigation API."""

import csv
import io
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import String, func, or_, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.core.domain_errors import NotFoundError
from app.core.models import (
    Asset,
    CloudAccount,
    ComplianceControl,
    ComplianceFramework,
    Finding,
    FindingComplianceControl,
    FindingEvent,
    FindingEvidence,
    Membership,
    RiskScore,
    Role,
    User,
)
from app.findings.schemas import (
    FindingAssigneeRead,
    FindingAssignRequest,
    FindingControlRead,
    FindingDetail,
    FindingEventRead,
    FindingEvidencePage,
    FindingEvidenceRead,
    FindingFilterOptions,
    FindingKpis,
    FindingPage,
    FindingRead,
    FindingSuppressRequest,
    FindingTransitionRequest,
)
from app.findings.service import assign_finding, suppress_finding, transition_finding

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/export")
def export_findings(
    principal: Annotated[Principal, Depends(require_permission("findings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    severity: Annotated[str | None, Query(max_length=20)] = None,
    status: Annotated[str | None, Query(max_length=20)] = None,
) -> Response:
    """Export a bounded tenant-owned finding snapshot as formula-safe CSV."""
    criteria = [Finding.organization_id == principal.organization_id]
    if severity:
        criteria.append(Finding.severity == severity.upper())
    if status:
        criteria.append(Finding.status == status.upper())
    rows = session.execute(
        select(Finding, Asset, CloudAccount, RiskScore.score)
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
        .where(*criteria)
        .order_by(Finding.last_seen_at.desc(), Finding.id)
        .limit(10000)
    ).all()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        (
            "Finding ID",
            "Severity",
            "Title",
            "Asset",
            "Asset Type",
            "Account",
            "Region",
            "Policy",
            "Status",
            "Risk Score",
            "Assignee",
            "Detected",
            "Last Seen",
            "Due",
        )
    )
    for finding, asset, account, risk_score in rows:
        values = (
            str(finding.id),
            finding.severity,
            finding.title,
            asset.name or asset.resource_id,
            asset.resource_type,
            account.name,
            finding.region_code,
            finding.rule_id,
            finding.status,
            risk_score if risk_score is not None else "Not assessed",
            str(finding.assigned_to_user_id or ""),
            finding.first_seen_at.isoformat(),
            finding.last_seen_at.isoformat(),
            finding.due_at.isoformat() if finding.due_at else "",
        )
        writer.writerow(
            tuple(
                "'" + str(value)
                if str(value).lstrip().startswith(("=", "+", "-", "@"))
                else value
                for value in values
            )
        )
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="cloudsentinel-findings.csv"',
            "Cache-Control": "no-store",
        },
    )


@router.get("", response_model=FindingPage)
def list_findings(
    principal: Annotated[Principal, Depends(require_permission("findings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    severity: Annotated[str | None, Query(max_length=20)] = None,
    status: Annotated[str | None, Query(max_length=20)] = None,
    category: Annotated[str | None, Query(max_length=100)] = None,
    region: Annotated[str | None, Query(max_length=40)] = None,
    cloud_account_id: UUID | None = None,
    asset_id: UUID | None = None,
    assigned_to_user_id: UUID | None = None,
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    page: Annotated[int | None, Query(ge=1)] = None,
    page_size: Annotated[int | None, Query(ge=1, le=100)] = None,
    policy: Annotated[str | None, Query(max_length=100)] = None,
    asset_type: Annotated[str | None, Query(max_length=100)] = None,
    framework: Annotated[str | None, Query(max_length=80)] = None,
    compliance_control: Annotated[str | None, Query(max_length=80)] = None,
    detected_from: datetime | None = None,
    detected_to: datetime | None = None,
    overdue: bool | None = None,
    risk_min: Annotated[int | None, Query(ge=0, le=100)] = None,
) -> FindingPage:
    """Return bounded finding results filtered inside the active tenant."""
    if page is not None:
        offset = (page - 1) * (page_size or limit)
    if page_size is not None:
        limit = page_size
    criteria = [Finding.organization_id == principal.organization_id]
    if severity is not None:
        criteria.append(Finding.severity == severity.upper())
    if status is not None:
        criteria.append(Finding.status == status.upper())
    if category is not None:
        criteria.append(Finding.category == category)
    if region is not None:
        criteria.append(Finding.region_code == region)
    if cloud_account_id is not None:
        criteria.append(Finding.cloud_account_id == cloud_account_id)
    if asset_id is not None:
        criteria.append(Finding.asset_id == asset_id)
    if assigned_to_user_id is not None:
        criteria.append(Finding.assigned_to_user_id == assigned_to_user_id)
    if policy is not None:
        criteria.append(Finding.rule_id == policy)
    if asset_type is not None:
        criteria.append(Asset.resource_type == asset_type)
    if detected_from is not None:
        criteria.append(Finding.first_seen_at >= detected_from)
    if detected_to is not None:
        criteria.append(Finding.first_seen_at <= detected_to)
    if overdue is True:
        criteria.extend(
            (
                Finding.due_at < datetime.now(UTC),
                Finding.status.not_in(("VERIFIED", "CLOSED", "SUPPRESSED")),
            )
        )
    elif overdue is False:
        criteria.append(or_(Finding.due_at.is_(None), Finding.due_at >= datetime.now(UTC)))
    if risk_min is not None:
        criteria.append(
            Finding.id.in_(
                select(RiskScore.finding_id).where(
                    RiskScore.organization_id == principal.organization_id,
                    RiskScore.score >= risk_min,
                )
            )
        )
    if framework is not None:
        criteria.append(
            Finding.id.in_(
                select(FindingComplianceControl.finding_id)
                .join(
                    ComplianceControl, ComplianceControl.id == FindingComplianceControl.control_id
                )
                .join(ComplianceFramework, ComplianceFramework.id == ComplianceControl.framework_id)
                .where(
                    FindingComplianceControl.organization_id == principal.organization_id,
                    ComplianceFramework.code == framework,
                )
            )
        )
    if compliance_control is not None:
        criteria.append(
            Finding.id.in_(
                select(FindingComplianceControl.finding_id)
                .join(
                    ComplianceControl, ComplianceControl.id == FindingComplianceControl.control_id
                )
                .where(
                    FindingComplianceControl.organization_id == principal.organization_id,
                    ComplianceControl.control_code == compliance_control,
                )
            )
        )
    if search is not None:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        criteria.append(
            or_(
                Finding.rule_id.ilike(pattern),
                Finding.title.ilike(pattern),
                Finding.description.ilike(pattern),
                Asset.name.ilike(pattern),
                Asset.resource_id.ilike(pattern),
                Asset.resource_arn.ilike(pattern),
                Finding.asset_id.cast(String).ilike(pattern),
            )
        )
    total = (
        session.scalar(
            select(func.count(Finding.id))
            .join(
                Asset,
                (Asset.id == Finding.asset_id) & (Asset.organization_id == Finding.organization_id),
            )
            .where(*criteria)
        )
        or 0
    )
    rows = list(
        session.execute(
            select(
                Finding,
                RiskScore.score,
                User.display_name,
                Role.code,
                Asset.attributes,
                Asset.name,
                Asset.resource_id,
                Asset.resource_type,
                CloudAccount.name,
            )
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
            .outerjoin(User, User.id == Finding.assigned_to_user_id)
            .outerjoin(
                Membership,
                (Membership.user_id == User.id)
                & (Membership.organization_id == Finding.organization_id),
            )
            .outerjoin(Role, Role.id == Membership.role_id)
            .where(*criteria)
            .order_by(Finding.last_seen_at.desc(), Finding.id)
            .offset(offset)
            .limit(limit)
        ).all()
    )
    return FindingPage(
        items=[
            FindingRead.model_validate(finding).model_copy(
                update={
                    "data_origin": "local_mock"
                    if attributes.get("cloudsentinel_data_origin") == "local_mock"
                    else None,
                    "asset_name": asset_name or resource_id,
                    "asset_type": resource_type,
                    "account_name": account_name,
                    "risk_score": risk_score,
                    "assignee_name": assignee_name,
                    "assignee_role": assignee_role,
                }
            )
            for (
                finding,
                risk_score,
                assignee_name,
                assignee_role,
                attributes,
                asset_name,
                resource_id,
                resource_type,
                account_name,
            ) in rows
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/kpis", response_model=FindingKpis)
def finding_kpis(
    principal: Annotated[Principal, Depends(require_permission("findings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> FindingKpis:
    """Return server-calculated finding totals for the active tenant."""
    org_id = principal.organization_id
    active = Finding.status.not_in(("VERIFIED", "CLOSED", "SUPPRESSED"))
    counts: dict[str, int] = {}
    for key, criterion in (
        ("open", active),
        ("critical", (Finding.severity == "CRITICAL") & active),
        ("high", (Finding.severity == "HIGH") & active),
        ("medium", (Finding.severity == "MEDIUM") & active),
        ("low", (Finding.severity == "LOW") & active),
        ("overdue", (Finding.due_at < datetime.now(UTC)) & active),
        ("suppressed", Finding.status == "SUPPRESSED"),
        ("resolved", Finding.status.in_(("RESOLVED", "VERIFIED", "CLOSED"))),
    ):
        counts[key] = (
            session.scalar(
                select(func.count(Finding.id)).where(Finding.organization_id == org_id, criterion)
            )
            or 0
        )
    return FindingKpis(**counts)


@router.get("/assignees", response_model=list[FindingAssigneeRead])
def list_finding_assignees(
    principal: Annotated[Principal, Depends(require_permission("findings:assign"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[FindingAssigneeRead]:
    """List active tenant members available for finding assignment."""
    from app.core.models import Membership, User

    rows = session.execute(
        select(User.id, User.display_name)
        .join(Membership, Membership.user_id == User.id)
        .where(
            Membership.organization_id == principal.organization_id,
            Membership.is_active.is_(True),
            User.is_active.is_(True),
        )
        .order_by(User.display_name, User.id)
    ).all()
    return [FindingAssigneeRead(id=row.id, display_name=row.display_name) for row in rows]


@router.get("/filter-options", response_model=FindingFilterOptions)
def finding_filter_options(
    principal: Annotated[Principal, Depends(require_permission("findings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> FindingFilterOptions:
    """Return category and region values that exist in the active organization."""
    org_id = principal.organization_id
    categories = session.scalars(
        select(Finding.category)
        .where(Finding.organization_id == org_id)
        .distinct()
        .order_by(Finding.category)
    ).all()
    regions = session.scalars(
        select(Finding.region_code)
        .where(Finding.organization_id == org_id)
        .distinct()
        .order_by(Finding.region_code)
    ).all()
    asset_types = session.scalars(
        select(Asset.resource_type)
        .join(
            Finding,
            (Finding.asset_id == Asset.id) & (Finding.organization_id == Asset.organization_id),
        )
        .where(Finding.organization_id == org_id)
        .distinct()
        .order_by(Asset.resource_type)
    ).all()
    frameworks = session.scalars(
        select(ComplianceFramework.code)
        .join(ComplianceControl, ComplianceControl.framework_id == ComplianceFramework.id)
        .join(FindingComplianceControl, FindingComplianceControl.control_id == ComplianceControl.id)
        .where(FindingComplianceControl.organization_id == org_id)
        .distinct()
        .order_by(ComplianceFramework.code)
    ).all()
    return FindingFilterOptions(
        categories=list(categories),
        regions=list(regions),
        asset_types=list(asset_types),
        frameworks=list(frameworks),
    )


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding_detail(
    finding_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("findings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> FindingDetail:
    """Return investigation context including risk, evidence, mappings, and lifecycle events."""
    finding = _get_finding(session, principal.organization_id, finding_id)
    asset_row = session.execute(
        select(Asset).where(
            Asset.id == finding.asset_id,
            Asset.organization_id == principal.organization_id,
        )
    ).scalar_one()
    account_name = (
        session.scalar(
            select(CloudAccount.name).where(
                CloudAccount.id == finding.cloud_account_id,
                CloudAccount.organization_id == principal.organization_id,
            )
        )
        or "Cloud account"
    )
    assignee_name = (
        session.scalar(select(User.display_name).where(User.id == finding.assigned_to_user_id))
        if finding.assigned_to_user_id
        else None
    )
    assignee_role = (
        session.scalar(
            select(Role.code)
            .join(Membership, Membership.role_id == Role.id)
            .where(
                Membership.user_id == finding.assigned_to_user_id,
                Membership.organization_id == principal.organization_id,
            )
        )
        if finding.assigned_to_user_id
        else None
    )
    risk = session.scalar(
        select(RiskScore).where(
            RiskScore.organization_id == principal.organization_id,
            RiskScore.finding_id == finding.id,
        )
    )
    evidence = list(
        session.scalars(
            select(FindingEvidence)
            .where(
                FindingEvidence.organization_id == principal.organization_id,
                FindingEvidence.finding_id == finding.id,
            )
            .order_by(FindingEvidence.collected_at.desc())
            .limit(1)
        ).all()
    )
    controls = session.execute(
        select(ComplianceFramework, ComplianceControl)
        .join(ComplianceControl, ComplianceControl.framework_id == ComplianceFramework.id)
        .join(
            FindingComplianceControl,
            FindingComplianceControl.control_id == ComplianceControl.id,
        )
        .where(
            FindingComplianceControl.organization_id == principal.organization_id,
            FindingComplianceControl.finding_id == finding.id,
        )
        .order_by(ComplianceFramework.code, ComplianceControl.control_code)
    ).all()
    events = list(
        session.scalars(
            select(FindingEvent)
            .where(
                FindingEvent.organization_id == principal.organization_id,
                FindingEvent.finding_id == finding.id,
            )
            .order_by(FindingEvent.created_at.desc(), FindingEvent.id.desc())
            .limit(100)
        ).all()
    )
    events.reverse()
    finding_data = FindingRead.model_validate(finding).model_dump()
    finding_data.update(
        data_origin=(
            "local_mock"
            if asset_row.attributes.get("cloudsentinel_data_origin") == "local_mock"
            else None
        ),
        asset_name=asset_row.name or asset_row.resource_id,
        asset_type=asset_row.resource_type,
        asset_arn=asset_row.resource_arn,
        account_name=account_name,
        assignee_name=assignee_name,
        assignee_role=assignee_role,
        risk_score=risk.score if risk else None,
    )
    return FindingDetail(
        **finding_data,
        risk_level=risk.level if risk else None,
        risk_factors=risk.factors if risk else {},
        risk_model=risk.risk_model if risk else None,
        risk_model_version=risk.risk_model_version if risk else None,
        risk_calculated_at=risk.calculated_at if risk else None,
        evidence=[FindingEvidenceRead.model_validate(row) for row in evidence],
        compliance_controls=[
            FindingControlRead(
                framework_code=framework.code,
                framework_name=framework.name,
                framework_version=framework.version,
                control_code=control.control_code,
                title=control.title,
            )
            for framework, control in controls
        ],
        events=[FindingEventRead.model_validate(row) for row in events],
    )


@router.post("/{finding_id}/transition", response_model=FindingRead)
@router.post("/{finding_id}/status", response_model=FindingRead, include_in_schema=False)
def transition_finding_status(
    finding_id: UUID,
    payload: FindingTransitionRequest,
    principal: Annotated[Principal, Depends(require_permission("findings:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Finding:
    """Apply only a canonical finding lifecycle transition."""
    finding = _get_finding(session, principal.organization_id, finding_id, lock=True)
    return transition_finding(
        session,
        finding,
        actor_user_id=principal.user_id,
        status=payload.status,
        reason=payload.reason,
    )


@router.post("/{finding_id}/assign", response_model=FindingRead)
def assign_finding_to_member(
    finding_id: UUID,
    payload: FindingAssignRequest,
    principal: Annotated[Principal, Depends(require_permission("findings:assign"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Finding:
    """Assign a finding to an active user membership in this organization."""
    finding = _get_finding(session, principal.organization_id, finding_id, lock=True)
    return assign_finding(
        session,
        finding,
        actor_user_id=principal.user_id,
        assignee_user_id=payload.assignee_user_id,
        due_at=payload.due_at,
    )


@router.post("/{finding_id}/suppress", response_model=FindingRead)
def suppress_finding_with_approval(
    finding_id: UUID,
    payload: FindingSuppressRequest,
    principal: Annotated[Principal, Depends(require_permission("findings:suppress"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Finding:
    """Suppress with mandatory reason, authenticated approver, expiry, and event record."""
    finding = _get_finding(session, principal.organization_id, finding_id, lock=True)
    return suppress_finding(
        session,
        finding,
        actor_user_id=principal.user_id,
        reason=payload.reason,
        expires_at=payload.expires_at,
    )


@router.get("/{finding_id}/evidence", response_model=FindingEvidencePage)
def list_finding_evidence(
    finding_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("findings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> FindingEvidencePage:
    """Read secret-filtered evidence only after resolving the tenant-owned finding."""
    _get_finding(session, principal.organization_id, finding_id)
    criteria = [
        FindingEvidence.organization_id == principal.organization_id,
        FindingEvidence.finding_id == finding_id,
    ]
    total = session.scalar(select(func.count(FindingEvidence.id)).where(*criteria)) or 0
    rows = list(
        session.scalars(
            select(FindingEvidence)
            .where(*criteria)
            .order_by(FindingEvidence.collected_at.desc())
            .offset(offset)
            .limit(limit)
        ).all()
    )
    return FindingEvidencePage(
        items=[FindingEvidenceRead.model_validate(row) for row in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


def _get_finding(
    session: Session, organization_id: UUID, finding_id: UUID, *, lock: bool = False
) -> Finding:
    statement = select(Finding).where(
        Finding.organization_id == organization_id,
        Finding.id == finding_id,
    )
    if lock:
        statement = statement.with_for_update()
    finding = session.scalar(statement)
    if finding is None:
        raise NotFoundError("Finding")
    return finding
