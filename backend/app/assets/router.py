"""Read-only tenant-scoped normalized asset inventory endpoints."""

import csv
import io
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.core.domain_errors import NotFoundError
from app.core.models import (
    Asset,
    AssetRelationship,
    CloudAccount,
    ComplianceAssessment,
    Finding,
    FindingEvidence,
    RiskScore,
)
from app.risk.service import is_risk_active
from app.scan_jobs.schemas import (
    AssetEvidenceRead,
    AssetFilterOptions,
    AssetPage,
    AssetRead,
    AssetRelationshipRead,
    AssetSummary,
)

router = APIRouter(prefix="/assets", tags=["assets"])


def _asset_compliance_summaries(
    session: Session, organization_id: UUID, asset_ids: list[UUID]
) -> dict[UUID, tuple[str, datetime | None]]:
    """Aggregate each asset's latest per-control compliance outcomes."""
    if not asset_ids:
        return {}
    latest_assessments = (
        select(
            ComplianceAssessment.asset_id,
            ComplianceAssessment.control_id,
            ComplianceAssessment.status,
            ComplianceAssessment.checked_at,
            func.row_number()
            .over(
                partition_by=(ComplianceAssessment.asset_id, ComplianceAssessment.control_id),
                order_by=(ComplianceAssessment.checked_at.desc(), ComplianceAssessment.id.desc()),
            )
            .label("assessment_rank"),
        )
        .where(
            ComplianceAssessment.organization_id == organization_id,
            ComplianceAssessment.asset_id.in_(asset_ids),
        )
        .subquery()
    )
    latest_rows = session.execute(
        select(
            latest_assessments.c.asset_id,
            latest_assessments.c.control_id,
            latest_assessments.c.status,
            latest_assessments.c.checked_at,
        ).where(latest_assessments.c.assessment_rank == 1)
    ).tuples()

    outcomes_by_asset: dict[UUID, list[tuple[str, datetime]]] = {}
    for asset_id, _control_id, status, checked_at in latest_rows:
        outcomes_by_asset.setdefault(asset_id, []).append((status, checked_at))

    summaries: dict[UUID, tuple[str, datetime | None]] = {}
    for asset_id in asset_ids:
        outcomes = outcomes_by_asset.get(asset_id, [])
        if not outcomes:
            summaries[asset_id] = ("NOT_ASSESSED", None)
            continue
        statuses = [status for status, _checked_at in outcomes]
        passed = "PASS" in statuses
        failed = "FAIL" in statuses
        partial = "PARTIAL" in statuses
        assessed = passed or failed or partial
        if not assessed:
            overall = (
                "NOT_APPLICABLE"
                if "NOT_APPLICABLE" in statuses and "NOT_ASSESSED" not in statuses
                else "NOT_ASSESSED"
            )
        elif partial or (passed and failed):
            overall = "PARTIAL"
        elif failed:
            overall = "FAIL"
        else:
            overall = "PASS"
        last_assessed = max(checked_at for _status, checked_at in outcomes)
        summaries[asset_id] = (overall, last_assessed)
    return summaries


def _asset_risk_scores(
    session: Session, organization_id: UUID, asset_ids: list[UUID]
) -> dict[UUID, int]:
    """Return the highest active finding risk score for each requested asset."""
    if not asset_ids:
        return {}
    rows = session.execute(
        select(Finding, RiskScore)
        .join(
            RiskScore,
            (RiskScore.organization_id == Finding.organization_id)
            & (RiskScore.finding_id == Finding.id),
        )
        .where(Finding.organization_id == organization_id, Finding.asset_id.in_(asset_ids))
    ).all()
    now = datetime.now(UTC)
    scores: dict[UUID, int] = {}
    for finding, risk in rows:
        if is_risk_active(finding, now):
            scores[finding.asset_id] = max(scores.get(finding.asset_id, 0), risk.score)
    return scores


def _csv_cell(value: object) -> str:
    """Prevent spreadsheet formula execution in exported user-controlled text."""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return f"'{text}"
    return text


@router.get("/export")
def export_assets(
    principal: Annotated[Principal, Depends(require_permission("assets:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    cloud_account_id: UUID | None = None,
    region: Annotated[str | None, Query(max_length=40)] = None,
    resource_type: Annotated[str | None, Query(max_length=100)] = None,
    provider: Annotated[str | None, Query(max_length=20)] = None,
    status: Annotated[str | None, Query(pattern="^(active|stale|removed)$")] = None,
    environment: Annotated[str | None, Query(max_length=80)] = None,
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
) -> Response:
    """Export a bounded tenant-scoped inventory CSV with formula-safe cells."""
    criteria = [Asset.organization_id == principal.organization_id]
    if cloud_account_id is not None:
        criteria.append(Asset.cloud_account_id == cloud_account_id)
    if region is not None:
        criteria.append(Asset.region_code == region)
    if resource_type is not None:
        criteria.append(Asset.resource_type == resource_type)
    if provider is not None:
        criteria.append(Asset.provider == provider.upper())
    if status is not None:
        criteria.append(Asset.status == status)
    if environment is not None:
        criteria.append(CloudAccount.environment == environment)
    if search is not None:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        criteria.append(
            or_(
                Asset.resource_id.ilike(pattern),
                Asset.name.ilike(pattern),
                Asset.resource_arn.ilike(pattern),
                CloudAccount.name.ilike(pattern),
            )
        )
    account_join = (CloudAccount.id == Asset.cloud_account_id) & (
        CloudAccount.organization_id == principal.organization_id
    )
    rows = session.execute(
        select(Asset, CloudAccount.name, CloudAccount.environment)
        .join(CloudAccount, account_join)
        .where(*criteria)
        .order_by(Asset.name, Asset.resource_id)
        .limit(10_000)
    ).all()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "asset_id",
            "name",
            "resource_type",
            "provider",
            "cloud_account",
            "environment",
            "resource_id",
            "arn",
            "region",
            "status",
            "first_seen_at",
            "last_seen_at",
        ]
    )
    for asset, account_name, account_environment in rows:
        writer.writerow(
            [
                _csv_cell(value)
                for value in [
                    str(asset.id),
                    asset.name or "",
                    asset.resource_type,
                    asset.provider,
                    account_name,
                    account_environment or "",
                    asset.resource_id,
                    asset.resource_arn or "",
                    asset.region_code,
                    asset.status,
                    asset.first_seen_at.isoformat(),
                    asset.last_seen_at.isoformat(),
                ]
            ]
        )
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="cloudsentinel-assets.csv"'},
    )


@router.get("", response_model=AssetPage)
def list_assets(
    principal: Annotated[Principal, Depends(require_permission("assets:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cloud_account_id: UUID | None = None,
    region: Annotated[str | None, Query(max_length=40)] = None,
    resource_type: Annotated[str | None, Query(max_length=100)] = None,
    provider: Annotated[str | None, Query(max_length=20)] = None,
    status: Annotated[str | None, Query(pattern="^(active|stale|removed)$")] = None,
    environment: Annotated[str | None, Query(max_length=80)] = None,
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
) -> AssetPage:
    """List discovered assets with bounded filters and trusted tenant scope."""
    criteria = [Asset.organization_id == principal.organization_id]
    if cloud_account_id is not None:
        criteria.append(Asset.cloud_account_id == cloud_account_id)
    if region is not None:
        criteria.append(Asset.region_code == region)
    if resource_type is not None:
        criteria.append(Asset.resource_type == resource_type)
    if provider is not None:
        criteria.append(Asset.provider == provider.upper())
    if status is not None:
        criteria.append(Asset.status == status)
    if environment is not None:
        criteria.append(CloudAccount.environment == environment)
    if search is not None:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        criteria.append(
            or_(
                Asset.resource_id.ilike(pattern),
                Asset.name.ilike(pattern),
                Asset.resource_arn.ilike(pattern),
                CloudAccount.name.ilike(pattern),
            )
        )
    account_join = (CloudAccount.id == Asset.cloud_account_id) & (
        CloudAccount.organization_id == principal.organization_id
    )
    total = (
        session.scalar(
            select(func.count(Asset.id)).join(CloudAccount, account_join).where(*criteria)
        )
        or 0
    )
    rows = list(
        session.execute(
            select(Asset, CloudAccount.name, CloudAccount.environment)
            .join(CloudAccount, account_join)
            .where(*criteria)
            .order_by(Asset.last_seen_at.desc(), Asset.id)
            .offset(offset)
            .limit(limit)
        ).all()
    )
    asset_ids = [asset.id for asset, _name, _environment in rows]
    compliance_by_asset = _asset_compliance_summaries(
        session, principal.organization_id, asset_ids
    )
    risk_by_asset = _asset_risk_scores(session, principal.organization_id, asset_ids)
    return AssetPage(
        items=[
            AssetRead.model_validate(asset).model_copy(
                update={
                    "cloud_account_name": name,
                    "environment": environment,
                    "risk_score": risk_by_asset.get(asset.id),
                    "compliance_status": compliance_by_asset[asset.id][0],
                    "compliance_last_assessed_at": compliance_by_asset[asset.id][1],
                }
            )
            for asset, name, environment in rows
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/summary", response_model=AssetSummary)
def asset_summary(
    principal: Annotated[Principal, Depends(require_permission("assets:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AssetSummary:
    """Return inventory and lifecycle counts from persisted tenant assets."""
    org_id = principal.organization_id
    total = session.scalar(select(func.count(Asset.id)).where(Asset.organization_id == org_id)) or 0
    statuses: dict[str, int] = {
        str(status): int(count)
        for status, count in session.execute(
            select(Asset.status, func.count(Asset.id))
            .where(Asset.organization_id == org_id)
            .group_by(Asset.status)
        ).tuples()
    }
    new_assets = (
        session.scalar(
            select(func.count(Asset.id)).where(
                Asset.organization_id == org_id,
                Asset.first_seen_at >= datetime.now(UTC) - timedelta(hours=24),
            )
        )
        or 0
    )
    critical: int | None = None
    high_risk: int | None = None
    if "findings:read" in principal.permissions:
        critical = (
            session.scalar(
                select(func.count(func.distinct(Finding.asset_id))).where(
                    Finding.organization_id == org_id,
                    Finding.severity == "CRITICAL",
                    Finding.status.not_in(("VERIFIED", "CLOSED", "SUPPRESSED")),
                )
            )
            or 0
        )
        high_risk = (
            session.scalar(
                select(func.count(func.distinct(Finding.asset_id)))
                .join(
                    RiskScore,
                    (RiskScore.finding_id == Finding.id)
                    & (RiskScore.organization_id == Finding.organization_id),
                )
                .where(
                    Finding.organization_id == org_id,
                    Finding.status.not_in(("VERIFIED", "CLOSED", "SUPPRESSED")),
                    RiskScore.score >= 60,
                )
            )
            or 0
        )
    return AssetSummary(
        total=total,
        new=new_assets,
        active=statuses.get("active", 0),
        stale=statuses.get("stale", 0),
        removed=statuses.get("removed", 0),
        critical=critical,
        high_risk=high_risk,
    )


@router.get("/filter-options", response_model=AssetFilterOptions)
def asset_filter_options(
    principal: Annotated[Principal, Depends(require_permission("assets:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AssetFilterOptions:
    """Return regions and resource types actually present for this tenant."""
    org_id = principal.organization_id
    regions = session.scalars(
        select(Asset.region_code)
        .where(Asset.organization_id == org_id)
        .distinct()
        .order_by(Asset.region_code)
    ).all()
    resource_types = session.scalars(
        select(Asset.resource_type)
        .where(Asset.organization_id == org_id)
        .distinct()
        .order_by(Asset.resource_type)
    ).all()
    environments = session.scalars(
        select(CloudAccount.environment)
        .join(Asset, Asset.cloud_account_id == CloudAccount.id)
        .where(
            Asset.organization_id == org_id,
            CloudAccount.organization_id == org_id,
            CloudAccount.environment.is_not(None),
        )
        .distinct()
        .order_by(CloudAccount.environment)
    ).all()
    providers = session.scalars(
        select(Asset.provider)
        .where(Asset.organization_id == org_id)
        .distinct()
        .order_by(Asset.provider)
    ).all()
    accounts = session.execute(
        select(CloudAccount.id, CloudAccount.name)
        .join(Asset, Asset.cloud_account_id == CloudAccount.id)
        .where(
            Asset.organization_id == org_id,
            CloudAccount.organization_id == org_id,
        )
        .distinct()
        .order_by(CloudAccount.name)
    ).all()
    return AssetFilterOptions(
        regions=list(regions),
        resource_types=list(resource_types),
        environments=[value for value in environments if value],
        providers=list(providers),
        accounts=[{"id": str(account_id), "name": name} for account_id, name in accounts],
    )


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(
    asset_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("assets:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AssetRead:
    """Return one asset only when it belongs to the active organization."""
    row = session.execute(
        select(Asset, CloudAccount.name, CloudAccount.environment)
        .join(
            CloudAccount,
            (CloudAccount.id == Asset.cloud_account_id)
            & (CloudAccount.organization_id == Asset.organization_id),
        )
        .where(
            Asset.id == asset_id,
            Asset.organization_id == principal.organization_id,
        )
    ).one_or_none()
    if row is None:
        raise NotFoundError("Asset")
    asset, name, environment = row
    compliance_status, compliance_last_assessed_at = _asset_compliance_summaries(
        session, principal.organization_id, [asset.id]
    )[asset.id]
    risk_score = _asset_risk_scores(session, principal.organization_id, [asset.id]).get(
        asset.id
    )
    return AssetRead.model_validate(asset).model_copy(
        update={
            "cloud_account_name": name,
            "environment": environment,
            "risk_score": risk_score,
            "compliance_status": compliance_status,
            "compliance_last_assessed_at": compliance_last_assessed_at,
        }
    )


@router.get("/{asset_id}/relationships", response_model=list[AssetRelationshipRead])
def get_asset_relationships(
    asset_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("assets:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[AssetRelationshipRead]:
    """Return known relationship edges and target metadata for a tenant-owned asset."""
    source_exists = session.scalar(
        select(Asset.id).where(
            Asset.id == asset_id,
            Asset.organization_id == principal.organization_id,
        )
    )
    if source_exists is None:
        raise NotFoundError("Asset")
    rows = session.execute(
        select(
            AssetRelationship.relationship_type,
            Asset,
            CloudAccount.name,
            CloudAccount.environment,
        )
        .join(Asset, Asset.id == AssetRelationship.target_asset_id)
        .join(
            CloudAccount,
            (CloudAccount.id == Asset.cloud_account_id)
            & (CloudAccount.organization_id == Asset.organization_id),
        )
        .where(
            AssetRelationship.organization_id == principal.organization_id,
            AssetRelationship.source_asset_id == asset_id,
        )
        .order_by(Asset.resource_type, Asset.resource_id)
    ).all()
    return [
        AssetRelationshipRead(
            relationship_type=relationship_type,
            target=AssetRead.model_validate(asset).model_copy(
                update={"cloud_account_name": name, "environment": environment}
            ),
        )
        for relationship_type, asset, name, environment in rows
    ]


@router.get("/{asset_id}/evidence", response_model=list[AssetEvidenceRead])
def get_asset_evidence(
    asset_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("findings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[AssetEvidenceRead]:
    """List sanitized policy evidence only after resolving the tenant-owned asset."""
    exists = session.scalar(
        select(Asset.id).where(
            Asset.id == asset_id,
            Asset.organization_id == principal.organization_id,
        )
    )
    if exists is None:
        raise NotFoundError("Asset")
    rows = session.scalars(
        select(FindingEvidence)
        .where(
            FindingEvidence.organization_id == principal.organization_id,
            FindingEvidence.asset_id == asset_id,
        )
        .order_by(FindingEvidence.collected_at.desc(), FindingEvidence.id)
        .limit(100)
    ).all()
    return [AssetEvidenceRead.model_validate(row) for row in rows]
