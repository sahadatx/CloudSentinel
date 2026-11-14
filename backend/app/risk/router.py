"""Tenant-scoped risk summary and subject score API."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.core.domain_errors import NotFoundError
from app.core.models import Asset, CloudAccount, Finding, RiskScore
from app.findings.schemas import (
    RiskAssetItem,
    RiskFindingItem,
    RiskFindingPage,
    RiskRead,
    RiskSummary,
)
from app.risk.service import aggregate_risk, aggregate_scores, get_finding_score, is_risk_active

router = APIRouter(prefix="/risk", tags=["risk"])
RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")


@router.get("/summary", response_model=RiskSummary)
def get_risk_summary(
    principal: Annotated[Principal, Depends(require_permission("findings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> RiskSummary:
    """Summarize current organization risk without exposing other tenant records."""
    score, level, _factors = aggregate_risk(
        session,
        organization_id=principal.organization_id,
        subject_type="organization",
        subject_id=principal.organization_id,
    )
    active_rows = _active_finding_rows(session, principal.organization_id)
    active = [score for score, _finding in active_rows]
    counts = {name: sum(row.level == name for row in active) for name in RISK_LEVELS}
    open_critical = sum(
        score.level == "CRITICAL"
        and finding.status in {"OPEN", "TRIAGED", "ASSIGNED", "IN_PROGRESS"}
        for score, finding in active_rows
    )
    asset_scores: dict[UUID, list[int]] = {}
    for score_row, finding in active_rows:
        asset_scores.setdefault(finding.asset_id, []).append(score_row.score)
    at_risk = sum(aggregate_scores(scores) >= 60 for scores in asset_scores.values())
    return RiskSummary(
        organization_score=score if active else None,
        organization_level=level if active else None,
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
        informational=counts["INFORMATIONAL"],
        at_risk_assets=at_risk,
        open_critical_findings=open_critical,
    )


@router.get("/findings", response_model=RiskFindingPage)
def list_risky_findings(
    principal: Annotated[Principal, Depends(require_permission("findings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    risk_min: int = 0,
    risk_band: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    cloud_account_id: UUID | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 30,
) -> RiskFindingPage:
    """Return tenant scoped, ranked active finding assessments with server filters."""
    statement = (
        select(Finding, RiskScore, Asset, CloudAccount)
        .join(
            RiskScore,
            (RiskScore.finding_id == Finding.id)
            & (RiskScore.organization_id == Finding.organization_id),
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
        .where(
            Finding.organization_id == principal.organization_id,
            RiskScore.score >= max(0, min(risk_min, 100)),
        )
        .order_by(RiskScore.score.desc(), Finding.id)
    )
    band_ranges = {
        "INFORMATIONAL": (0, 19),
        "LOW": (20, 39),
        "MEDIUM": (40, 59),
        "HIGH": (60, 79),
        "CRITICAL": (80, 100),
    }
    if risk_band and risk_band.upper() in band_ranges:
        lower, upper = band_ranges[risk_band.upper()]
        statement = statement.where(RiskScore.score.between(lower, upper))
    if severity:
        statement = statement.where(Finding.severity == severity.upper())
    if status:
        statement = statement.where(Finding.status == status.upper())
    if cloud_account_id:
        statement = statement.where(Finding.cloud_account_id == cloud_account_id)
    now = datetime.now(UTC)
    active_items = [
        RiskFindingItem(
            id=finding.id,
            title=finding.title,
            severity=finding.severity,
            status=finding.status,
            asset_id=asset.id,
            asset_name=asset.name or asset.resource_id,
            account_name=account.name,
            score=score.score,
            level=score.level,
        )
        for finding, score, asset, account in session.execute(statement).all()
        if is_risk_active(finding, now)
    ]
    return RiskFindingPage(
        items=active_items[offset : offset + limit],
        total=len(active_items),
        offset=offset,
        limit=limit,
    )


@router.get("/assets", response_model=list[RiskAssetItem])
def list_risky_assets(
    principal: Annotated[Principal, Depends(require_permission("assets:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    risk_min: int = 0,
    risk_band: str | None = None,
    cloud_account_id: UUID | None = None,
    limit: int = 100,
) -> list[RiskAssetItem]:
    """Return assets ranked by cumulative active finding risk."""
    statement = (
        select(Asset, CloudAccount)
        .join(
            CloudAccount,
            (CloudAccount.id == Asset.cloud_account_id)
            & (CloudAccount.organization_id == Asset.organization_id),
        )
        .where(Asset.organization_id == principal.organization_id)
    )
    if cloud_account_id:
        statement = statement.where(Asset.cloud_account_id == cloud_account_id)
    output = []
    band_ranges = {
        "INFORMATIONAL": (0, 19),
        "LOW": (20, 39),
        "MEDIUM": (40, 59),
        "HIGH": (60, 79),
        "CRITICAL": (80, 100),
    }
    for asset, account in session.execute(statement).all():
        score, level, _factors = aggregate_risk(
            session,
            organization_id=principal.organization_id,
            subject_type="asset",
            subject_id=asset.id,
        )
        in_band = score > 0 and (
            risk_band is None
            or risk_band.upper() not in band_ranges
            or band_ranges[risk_band.upper()][0] <= score <= band_ranges[risk_band.upper()][1]
        )
        if score >= max(0, min(risk_min, 100)) and in_band:
            output.append(
                RiskAssetItem(
                    id=asset.id,
                    name=asset.name or asset.resource_id,
                    resource_type=asset.resource_type,
                    account_name=account.name,
                    score=score,
                    level=level,
                    finding_count=len(
                        _active_asset_findings(session, principal.organization_id, asset.id)
                    ),
                )
            )
    return sorted(output, key=lambda item: (-item.score, str(item.id)))[: max(1, min(limit, 100))]


@router.get("/findings/{finding_id}", response_model=RiskRead)
def get_finding_risk(
    finding_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("findings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> RiskRead:
    _require_finding(session, principal.organization_id, finding_id)
    row = get_finding_score(session, principal.organization_id, finding_id)
    return _risk_read(
        "finding",
        finding_id,
        row.score if row else None,
        row.level if row else None,
        row.factors if row else {},
        row.calculated_at if row else None,
        row.risk_model if row else None,
        row.risk_model_version if row else None,
    )


@router.get("/assets/{asset_id}", response_model=RiskRead)
def get_asset_risk(
    asset_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("assets:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> RiskRead:
    _require_asset(session, principal.organization_id, asset_id)
    score, level, factors = aggregate_risk(
        session,
        organization_id=principal.organization_id,
        subject_type="asset",
        subject_id=asset_id,
    )
    assessed = bool(_active_asset_findings(session, principal.organization_id, asset_id))
    timestamp, model, version = _aggregate_metadata(
        session, principal.organization_id, "asset_id", asset_id
    )
    return _risk_read(
        "asset",
        asset_id,
        score if assessed else None,
        level if assessed else None,
        factors,
        timestamp,
        model,
        version,
    )


@router.get("/cloud-accounts/{account_id}", response_model=RiskRead)
def get_account_risk(
    account_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> RiskRead:
    account = session.scalar(
        select(CloudAccount).where(
            CloudAccount.id == account_id,
            CloudAccount.organization_id == principal.organization_id,
        )
    )
    if account is None:
        raise NotFoundError("Cloud account")
    score, level, factors = aggregate_risk(
        session,
        organization_id=principal.organization_id,
        subject_type="cloud_account",
        subject_id=account_id,
    )
    assessed = bool(_active_account_findings(session, principal.organization_id, account_id))
    timestamp, model, version = _aggregate_metadata(
        session, principal.organization_id, "cloud_account_id", account_id
    )
    return _risk_read(
        "cloud_account",
        account_id,
        score if assessed else None,
        level if assessed else None,
        factors,
        timestamp,
        model,
        version,
    )


def _active_finding_rows(
    session: Session, organization_id: UUID
) -> list[tuple[RiskScore, Finding]]:
    rows = session.execute(
        select(RiskScore, Finding)
        .join(
            Finding,
            (Finding.id == RiskScore.finding_id)
            & (Finding.organization_id == RiskScore.organization_id),
        )
        .where(RiskScore.organization_id == organization_id)
    ).all()
    now = datetime.now(UTC)
    return [(score, finding) for score, finding in rows if is_risk_active(finding, now)]


def _active_asset_findings(
    session: Session, organization_id: UUID, asset_id: UUID
) -> list[Finding]:
    rows = session.execute(
        select(Finding, RiskScore)
        .join(
            RiskScore,
            (RiskScore.finding_id == Finding.id)
            & (RiskScore.organization_id == Finding.organization_id),
        )
        .where(Finding.organization_id == organization_id, Finding.asset_id == asset_id)
    ).all()
    now = datetime.now(UTC)
    return [finding for finding, _score in rows if is_risk_active(finding, now)]


def _active_account_findings(
    session: Session, organization_id: UUID, account_id: UUID
) -> list[Finding]:
    rows = session.execute(
        select(Finding, RiskScore)
        .join(
            RiskScore,
            (RiskScore.finding_id == Finding.id)
            & (RiskScore.organization_id == Finding.organization_id),
        )
        .where(Finding.organization_id == organization_id, Finding.cloud_account_id == account_id)
    ).all()
    now = datetime.now(UTC)
    return [finding for finding, _score in rows if is_risk_active(finding, now)]


def _aggregate_metadata(
    session: Session, organization_id: UUID, subject_column: str, subject_id: UUID
) -> tuple[datetime | None, str | None, str | None]:
    column = Finding.asset_id if subject_column == "asset_id" else Finding.cloud_account_id
    rows = session.execute(
        select(Finding, RiskScore)
        .join(
            RiskScore,
            (RiskScore.finding_id == Finding.id)
            & (RiskScore.organization_id == Finding.organization_id),
        )
        .where(Finding.organization_id == organization_id, column == subject_id)
    ).all()
    now = datetime.now(UTC)
    scores = [score for finding, score in rows if is_risk_active(finding, now)]
    if not scores:
        return None, None, None
    model_pairs = {(score.risk_model, score.risk_model_version) for score in scores}
    model, version = (
        next(iter(model_pairs)) if len(model_pairs) == 1 else ("Mixed models", "Multiple")
    )
    return max(score.calculated_at for score in scores), model, version


def _risk_read(
    subject_type: str,
    subject_id: UUID,
    score: int | None,
    level: str | None,
    factors: dict[str, object],
    calculated_at: datetime | None = None,
    risk_model: str | None = None,
    risk_model_version: str | None = None,
) -> RiskRead:
    return RiskRead(
        subject_type=subject_type,
        subject_id=subject_id,
        score=score,
        level=level,
        factors=factors,
        calculated_at=calculated_at,
        risk_model=risk_model,
        risk_model_version=risk_model_version,
    )


def _require_finding(session: Session, organization_id: UUID, finding_id: UUID) -> Finding:
    row = session.scalar(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == organization_id,
        )
    )
    if row is None:
        raise NotFoundError("Finding")
    return row


def _require_asset(session: Session, organization_id: UUID, asset_id: UUID) -> Asset:
    row = session.scalar(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.organization_id == organization_id,
        )
    )
    if row is None:
        raise NotFoundError("Asset")
    return row
