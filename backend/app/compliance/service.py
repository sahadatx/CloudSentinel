"""Shared tenant-scoped compliance aggregation helpers."""

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.models import ComplianceAssessment, ComplianceControl


def control_status(
    session: Session,
    organization_id: UUID,
    control: ComplianceControl,
    *,
    asset_ids: Sequence[UUID] | None = None,
) -> tuple[str, int, int, int, int, int, int]:
    """Return latest per-asset outcomes for one control in the active tenant."""
    statement = select(
        ComplianceAssessment.asset_id,
        ComplianceAssessment.status,
        ComplianceAssessment.checked_at,
    ).where(
        ComplianceAssessment.organization_id == organization_id,
        ComplianceAssessment.control_id == control.id,
    )
    if asset_ids is not None:
        if not asset_ids:
            return "NOT_ASSESSED", 0, 0, 0, 0, 0, 0
        statement = statement.where(ComplianceAssessment.asset_id.in_(asset_ids))
    rows = session.execute(
        statement.order_by(ComplianceAssessment.checked_at.desc(), ComplianceAssessment.id.desc())
    ).all()
    latest: dict[UUID, str] = {}
    for asset_id, status, _checked_at in rows:
        latest.setdefault(asset_id, status)
    passed = sum(status == "PASS" for status in latest.values())
    failed = sum(status == "FAIL" for status in latest.values())
    partial = sum(status == "PARTIAL" for status in latest.values())
    not_assessed = sum(status == "NOT_ASSESSED" for status in latest.values())
    not_applicable = sum(status == "NOT_APPLICABLE" for status in latest.values())
    assessed = passed + failed + partial
    if not assessed:
        overall = "NOT_APPLICABLE" if not_applicable and not not_assessed else "NOT_ASSESSED"
    elif partial or (passed and failed):
        overall = "PARTIAL"
    elif failed:
        overall = "FAIL"
    else:
        overall = "PASS"
    return overall, assessed, passed, failed, partial, not_assessed, not_applicable
