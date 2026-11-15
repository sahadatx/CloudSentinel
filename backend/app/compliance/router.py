"""Tenant-scoped compliance summaries, controls, assessments, and evidence links."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.compliance.service import control_status
from app.core.domain_errors import NotFoundError
from app.core.models import (
    Asset,
    CloudAccount,
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    Finding,
    FindingComplianceControl,
    FindingEvidence,
    RiskScore,
)
from app.findings.schemas import (
    ComplianceActivityRead,
    ComplianceAssessmentRead,
    ComplianceAssessmentRecordPage,
    ComplianceAssessmentRecordRead,
    ComplianceCategoryRead,
    ComplianceControlRead,
    ComplianceEvidenceRead,
    ComplianceFindingRead,
    ComplianceFrameworkRead,
    ComplianceSummaryRead,
)

router = APIRouter(prefix="/compliance", tags=["compliance"])
READ = "findings:read"


def _framework(session: Session, code: str) -> ComplianceFramework:
    row = session.scalar(
        select(ComplianceFramework).where(
            ComplianceFramework.code == code, ComplianceFramework.is_active.is_(True)
        )
    )
    if row is None:
        raise NotFoundError("Compliance framework")
    return row


def _control(
    session: Session, framework_code: str, control_code: str
) -> tuple[ComplianceFramework, ComplianceControl]:
    row = session.execute(
        select(ComplianceFramework, ComplianceControl)
        .join(ComplianceControl, ComplianceControl.framework_id == ComplianceFramework.id)
        .where(
            ComplianceFramework.code == framework_code,
            ComplianceFramework.is_active.is_(True),
            ComplianceControl.control_code == control_code,
        )
    ).first()
    if row is None:
        raise NotFoundError("Compliance control")
    return row[0], row[1]


def _findings(session: Session, organization_id: UUID, control_id: UUID) -> list[Finding]:
    return list(
        session.scalars(
            select(Finding)
            .join(FindingComplianceControl, FindingComplianceControl.finding_id == Finding.id)
            .where(
                FindingComplianceControl.organization_id == organization_id,
                FindingComplianceControl.control_id == control_id,
                Finding.status.notin_({"VERIFIED", "CLOSED"}),
            )
            .order_by(Finding.severity, Finding.id)
        ).all()
    )


def _read_control(
    session: Session,
    organization_id: UUID,
    framework: ComplianceFramework,
    control: ComplianceControl,
) -> ComplianceControlRead:
    (
        status,
        assessed,
        passed,
        failed,
        partial,
        not_assessed,
        not_applicable,
    ) = control_status(session, organization_id, control)
    latest = session.scalar(
        select(func.max(ComplianceAssessment.checked_at)).where(
            ComplianceAssessment.organization_id == organization_id,
            ComplianceAssessment.control_id == control.id,
        )
    )
    ids = [row.id for row in _findings(session, organization_id, control.id)]
    score = round(passed * 100 / assessed) if assessed else None
    return ComplianceControlRead(
        id=control.id,
        code=control.control_code,
        title=control.title,
        domain=control.domain,
        description=control.description,
        category=control.category or control.domain,
        severity=control.severity,
        version=control.control_version,
        framework_code=framework.code,
        framework_name=framework.name,
        framework_version=framework.version,
        status=status,
        assessed_assets=assessed,
        passed_assets=passed,
        failed_assets=failed,
        partial_assets=partial,
        not_assessed_assets=not_assessed,
        not_applicable_assets=not_applicable,
        finding_ids=ids,
        compliance_score=score,
        last_assessed_at=latest,
        guidance=control.guidance,
    )


def _framework_controls(
    session: Session, organization_id: UUID, framework: ComplianceFramework
) -> list[ComplianceControlRead]:
    controls = session.scalars(
        select(ComplianceControl)
        .where(ComplianceControl.framework_id == framework.id)
        .order_by(ComplianceControl.control_code)
    ).all()
    return [_read_control(session, organization_id, framework, item) for item in controls]


@router.get("/summary", response_model=ComplianceSummaryRead)
def summary(
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> ComplianceSummaryRead:
    """Aggregate backend control assessments; unassessed controls do not gain scores."""
    frameworks = session.scalars(
        select(ComplianceFramework).where(ComplianceFramework.is_active.is_(True))
    ).all()
    controls = [
        item
        for framework in frameworks
        for item in _framework_controls(session, principal.organization_id, framework)
    ]
    assessed = [item for item in controls if item.compliance_score is not None]
    total = len(assessed)
    passed = sum(item.status == "PASS" for item in controls)
    failed = sum(item.status == "FAIL" for item in controls)
    partial = sum(item.status == "PARTIAL" for item in controls)
    not_assessed = sum(item.status == "NOT_ASSESSED" for item in controls)
    not_applicable = sum(item.status == "NOT_APPLICABLE" for item in controls)
    score = round(sum(item.compliance_score or 0 for item in assessed) / total) if total else None
    critical = sum(
        item.status in {"FAIL", "PARTIAL"} and item.severity == "CRITICAL" for item in controls
    )
    return ComplianceSummaryRead(
        frameworks=len(frameworks),
        compliance_score=score,
        passing_controls=passed,
        failing_controls=failed,
        partial_controls=partial,
        not_assessed_controls=not_assessed,
        not_applicable_controls=not_applicable,
        critical_failures=critical,
    )


@router.get("/assessment-records", response_model=ComplianceAssessmentRecordPage)
def assessment_records(
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    status: str | None = None,
) -> ComplianceAssessmentRecordPage:
    """List raw tenant-scoped evaluations, including mappings not enabled for compliance."""
    filters = [ComplianceAssessment.organization_id == principal.organization_id]
    if status:
        filters.append(ComplianceAssessment.status == status.upper())

    joins = (
        select(
            ComplianceAssessment,
            ComplianceFramework,
            ComplianceControl,
            Asset,
            CloudAccount,
        )
        .join(ComplianceControl, ComplianceControl.id == ComplianceAssessment.control_id)
        .join(ComplianceFramework, ComplianceFramework.id == ComplianceControl.framework_id)
        .join(Asset, Asset.id == ComplianceAssessment.asset_id)
        .join(CloudAccount, CloudAccount.id == Asset.cloud_account_id)
        .where(*filters)
    )
    total = session.scalar(
        select(func.count(ComplianceAssessment.id))
        .join(ComplianceControl, ComplianceControl.id == ComplianceAssessment.control_id)
        .join(ComplianceFramework, ComplianceFramework.id == ComplianceControl.framework_id)
        .join(Asset, Asset.id == ComplianceAssessment.asset_id)
        .join(CloudAccount, CloudAccount.id == Asset.cloud_account_id)
        .where(*filters)
    ) or 0
    rows = session.execute(
        joins.order_by(
            ComplianceAssessment.checked_at.desc(), ComplianceAssessment.id.desc()
        )
        .offset(offset)
        .limit(limit)
    ).all()
    items = []
    for assessment, framework, control, asset, account in rows:
        attributes = asset.attributes if isinstance(asset.attributes, dict) else {}
        synthetic = (
            attributes.get("cloudsentinel_data_origin") == "local_mock"
            or (asset.name or "").startswith("DEMO ONLY")
            or account.name.startswith("DEMO ONLY")
        )
        items.append(
            ComplianceAssessmentRecordRead(
                assessment_id=assessment.id,
                framework_code=framework.code,
                framework_name=framework.name,
                framework_version=framework.version,
                coverage_status=framework.coverage_status,
                control_code=control.control_code,
                control_title=control.title,
                status=assessment.status,
                asset_name=asset.name or asset.resource_id,
                resource_type=asset.resource_type,
                account_name=account.name,
                region=asset.region_code,
                assessed_at=assessment.checked_at,
                synthetic=synthetic,
            )
        )
    return ComplianceAssessmentRecordPage(
        items=items,
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/frameworks", response_model=list[ComplianceFrameworkRead])
def list_framework_assessments(
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[ComplianceFrameworkRead]:
    frameworks = session.scalars(
        select(ComplianceFramework)
        .where(ComplianceFramework.is_active.is_(True))
        .order_by(ComplianceFramework.code)
    ).all()
    result = []
    for framework in frameworks:
        rows = _framework_controls(session, principal.organization_id, framework)
        scored = [row for row in rows if row.compliance_score is not None]
        result.append(
            ComplianceFrameworkRead(
                code=framework.code,
                name=framework.name,
                version=framework.version,
                coverage_status=framework.coverage_status,
                source_url=framework.source_url,
                controls_total=len(rows),
                assessed=len(scored),
                passed=sum(row.status == "PASS" for row in rows),
                failed=sum(row.status == "FAIL" for row in rows),
                not_assessed=sum(row.status == "NOT_ASSESSED" for row in rows),
                not_applicable=sum(row.status == "NOT_APPLICABLE" for row in rows),
                partial=sum(row.status == "PARTIAL" for row in rows),
                compliance_score=round(
                    sum(row.compliance_score or 0 for row in scored) / len(scored)
                )
                if scored
                else None,
            )
        )
    return result


@router.get("/frameworks/{framework_code}/categories", response_model=list[ComplianceCategoryRead])
def categories(
    framework_code: str,
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[ComplianceCategoryRead]:
    framework = _framework(session, framework_code)
    rows = _framework_controls(session, principal.organization_id, framework)
    grouped: dict[str, list[ComplianceControlRead]] = {}
    for row in rows:
        grouped.setdefault(row.category or "Uncategorized", []).append(row)
    return [
        ComplianceCategoryRead(
            category=name,
            total=len(items),
            passed=sum(i.status == "PASS" for i in items),
            failed=sum(i.status == "FAIL" for i in items),
            partial=sum(i.status == "PARTIAL" for i in items),
            not_assessed=sum(i.status == "NOT_ASSESSED" for i in items),
            not_applicable=sum(i.status == "NOT_APPLICABLE" for i in items),
            compliance_score=round(
                sum(i.compliance_score or 0 for i in items if i.compliance_score is not None)
                / sum(i.compliance_score is not None for i in items)
            )
            if any(i.compliance_score is not None for i in items)
            else None,
        )
        for name, items in sorted(grouped.items())
    ]


@router.get("/frameworks/{framework_code}/controls", response_model=list[ComplianceControlRead])
def list_framework_controls(
    framework_code: str,
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
    status: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    provider: str | None = None,
    cloud_account_id: UUID | None = None,
    region: str | None = None,
    environment: str | None = None,
    assessed_after: datetime | None = None,
    assessed_before: datetime | None = None,
) -> list[ComplianceControlRead]:
    framework = _framework(session, framework_code)
    rows = _framework_controls(session, principal.organization_id, framework)
    if status:
        rows = [row for row in rows if row.status == status.upper()]
    if category:
        rows = [row for row in rows if (row.category or "").casefold() == category.casefold()]
    if severity:
        rows = [row for row in rows if row.severity == severity.upper()]
    if any((provider, cloud_account_id, region, environment, assessed_after, assessed_before)):
        criteria = [ComplianceAssessment.organization_id == principal.organization_id]
        if assessed_after:
            criteria.append(ComplianceAssessment.checked_at >= assessed_after)
        if assessed_before:
            criteria.append(ComplianceAssessment.checked_at <= assessed_before)
        if provider:
            criteria.append(Asset.provider == provider.upper())
        if cloud_account_id:
            criteria.append(CloudAccount.id == cloud_account_id)
        if region:
            criteria.append(Asset.region_code == region)
        if environment:
            criteria.append(CloudAccount.environment == environment)
        ids = set(
            session.scalars(
                select(ComplianceAssessment.control_id)
                .join(Asset, Asset.id == ComplianceAssessment.asset_id)
                .join(CloudAccount, CloudAccount.id == Asset.cloud_account_id)
                .where(*criteria)
            ).all()
        )
        rows = [row for row in rows if row.id in ids]
    return rows


@router.get("/controls/{control_id}", response_model=ComplianceControlRead)
def get_control_by_id(
    control_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> ComplianceControlRead:
    found = session.execute(
        select(ComplianceFramework, ComplianceControl)
        .join(ComplianceControl, ComplianceControl.framework_id == ComplianceFramework.id)
        .where(ComplianceControl.id == control_id, ComplianceFramework.is_active.is_(True))
    ).first()
    if not found:
        raise NotFoundError("Compliance control")
    framework, control = found
    return _read_control(session, principal.organization_id, framework, control)


@router.get(
    "/frameworks/{framework_code}/controls/{control_code}", response_model=ComplianceControlRead
)
def get_control_assessment(
    framework_code: str,
    control_code: str,
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> ComplianceControlRead:
    framework, control = _control(session, framework_code, control_code)
    return _read_control(session, principal.organization_id, framework, control)


def _detail_control(
    session: Session, framework_code: str, control_code: str, organization_id: UUID
) -> tuple[ComplianceFramework, ComplianceControl]:
    framework, control = _control(session, framework_code, control_code)
    # Verify assessment context through tenant-scoped shared helper before returning.
    control_status(session, organization_id, control)
    return framework, control


@router.get(
    "/frameworks/{framework_code}/controls/{control_code}/assessments",
    response_model=list[ComplianceAssessmentRead],
)
def assessments(
    framework_code: str,
    control_code: str,
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
    status: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[ComplianceAssessmentRead]:
    _framework, control = _detail_control(
        session, framework_code, control_code, principal.organization_id
    )
    query = (
        select(ComplianceAssessment, Asset, CloudAccount)
        .join(Asset, Asset.id == ComplianceAssessment.asset_id)
        .join(CloudAccount, CloudAccount.id == Asset.cloud_account_id)
        .where(
            ComplianceAssessment.organization_id == principal.organization_id,
            ComplianceAssessment.control_id == control.id,
        )
        .order_by(ComplianceAssessment.checked_at.desc(), ComplianceAssessment.id.desc())
    )
    latest: dict[UUID, tuple[ComplianceAssessment, Asset, CloudAccount]] = {}
    for item, asset, account in session.execute(query).all():
        latest.setdefault(asset.id, (item, asset, account))
    rows = list(latest.values())
    if status:
        rows = [row for row in rows if row[0].status == status.upper()]
    return [
        ComplianceAssessmentRead(
            id=item.id,
            asset_id=asset.id,
            asset_name=asset.name or asset.resource_id,
            resource_type=asset.resource_type,
            account_id=account.id,
            account_name=account.name,
            region=asset.region_code,
            status=item.status,
            observed=item.observed,
            expected=item.expected,
            evidence_id=item.evidence_id,
            policy_version=item.policy_version,
            assessed_at=item.checked_at,
        )
        for item, asset, account in rows[:limit]
    ]


@router.get(
    "/frameworks/{framework_code}/controls/{control_code}/findings",
    response_model=list[ComplianceFindingRead],
)
def related_findings(
    framework_code: str,
    control_code: str,
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[ComplianceFindingRead]:
    _framework, control = _detail_control(
        session, framework_code, control_code, principal.organization_id
    )
    rows = session.execute(
        select(Finding, Asset, RiskScore)
        .join(FindingComplianceControl, FindingComplianceControl.finding_id == Finding.id)
        .join(Asset, Asset.id == Finding.asset_id)
        .outerjoin(
            RiskScore,
            (RiskScore.finding_id == Finding.id)
            & (RiskScore.organization_id == Finding.organization_id),
        )
        .where(
            FindingComplianceControl.organization_id == principal.organization_id,
            FindingComplianceControl.control_id == control.id,
        )
        .order_by(Finding.severity, Finding.id)
    ).all()
    return [
        ComplianceFindingRead(
            id=f.id,
            title=f.title,
            remediation=f.remediation,
            severity=f.severity,
            status=f.status,
            asset_id=asset.id,
            asset_name=asset.name or asset.resource_id,
            risk_score=risk.score if risk else None,
        )
        for f, asset, risk in rows
    ]


@router.get(
    "/frameworks/{framework_code}/controls/{control_code}/evidence",
    response_model=list[ComplianceEvidenceRead],
)
def evidence(
    framework_code: str,
    control_code: str,
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[ComplianceEvidenceRead]:
    _framework, control = _detail_control(
        session, framework_code, control_code, principal.organization_id
    )
    rows = session.execute(
        select(FindingEvidence, Asset)
        .join(
            ComplianceAssessment,
            (ComplianceAssessment.evidence_id == FindingEvidence.id)
            & (ComplianceAssessment.organization_id == FindingEvidence.organization_id),
        )
        .join(Asset, Asset.id == ComplianceAssessment.asset_id)
        .where(
            ComplianceAssessment.organization_id == principal.organization_id,
            ComplianceAssessment.control_id == control.id,
        )
        .order_by(FindingEvidence.collected_at.desc())
        .limit(200)
    ).all()
    return [
        ComplianceEvidenceRead(
            id=item.id,
            asset_id=asset.id,
            asset_name=asset.name or asset.resource_id,
            source=item.source,
            expected_state=item.expected_state,
            observed_state=item.detected_condition,
            configuration=item.configuration,
            collected_at=item.collected_at,
        )
        for item, asset in rows
    ]


@router.get(
    "/frameworks/{framework_code}/controls/{control_code}/activity",
    response_model=list[ComplianceActivityRead],
)
def activity(
    framework_code: str,
    control_code: str,
    principal: Annotated[Principal, Depends(require_permission(READ))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[ComplianceActivityRead]:
    _framework, control = _detail_control(
        session, framework_code, control_code, principal.organization_id
    )
    rows = session.execute(
        select(ComplianceAssessment, Asset)
        .join(Asset, Asset.id == ComplianceAssessment.asset_id)
        .where(
            ComplianceAssessment.organization_id == principal.organization_id,
            ComplianceAssessment.control_id == control.id,
        )
        .order_by(ComplianceAssessment.checked_at.desc())
        .limit(100)
    ).all()
    return [
        ComplianceActivityRead(
            action=f"ASSESSMENT_{item.status}",
            detail=f"{asset.name or asset.resource_id} assessed as {item.status}",
            created_at=item.checked_at,
        )
        for item, asset in rows
    ]
