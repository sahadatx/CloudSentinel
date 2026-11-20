"""Tenant-isolated alerts, lifecycle actions, and organization alert rules."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.alerts.schemas import (
    AlertPage,
    AlertRead,
    AlertReconcileResult,
    AlertRulePatch,
    AlertRuleRead,
    AlertSummary,
)
from app.alerts.service import ensure_alert_rules, reconcile_alerts, update_alert_status
from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.core.domain_errors import ConflictError, NotFoundError
from app.core.models import Alert, AlertRule, CloudAccount, Finding, ScanJob
from app.operations.service import record_audit

router = APIRouter(tags=["alerts"])


@router.post("/alerts/reconcile", response_model=AlertReconcileResult)
def reconcile_current_alerts(
    principal: Annotated[Principal, Depends(require_permission("alerts:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AlertReconcileResult:
    """Backfill missing alerts from this organization's canonical current records."""
    result = reconcile_alerts(session, principal.organization_id)
    audit_details: dict[str, object] = dict(result)
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="alerts.reconciled",
        resource_type="alert_collection",
        resource_id=principal.organization_id,
        details=audit_details,
    )
    session.commit()
    return AlertReconcileResult(**result)


def _source_href(source_type: str, source_id: str) -> str | None:
    routes = {"FINDING": "findings", "SCAN": "scans"}
    route = routes.get(source_type)
    return f"/{route}/{source_id}" if route else None


def _read_alert(session: Session, row: Alert) -> AlertRead:
    account_name: str | None = None
    region_code: str | None = None
    try:
        source_uuid = UUID(row.source_id)
    except ValueError:
        source_uuid = None
    if source_uuid and row.source_type == "FINDING":
        source = session.execute(
            select(CloudAccount.name, Finding.region_code)
            .join(CloudAccount, CloudAccount.id == Finding.cloud_account_id)
            .where(
                Finding.organization_id == row.organization_id,
                Finding.id == source_uuid,
                CloudAccount.organization_id == row.organization_id,
            )
        ).first()
        if source:
            account_name, region_code = source
    elif source_uuid and row.source_type == "SCAN":
        scan_source = session.execute(
            select(CloudAccount.name, ScanJob.requested_regions)
            .join(CloudAccount, CloudAccount.id == ScanJob.cloud_account_id)
            .where(
                ScanJob.organization_id == row.organization_id,
                ScanJob.id == source_uuid,
                CloudAccount.organization_id == row.organization_id,
            )
        ).first()
        if scan_source:
            account_name = scan_source[0]
            region_code = ", ".join(scan_source[1]) if scan_source[1] else "All regions"
    return AlertRead.model_validate(row).model_copy(
        update={
            "source_href": _source_href(row.source_type, row.source_id),
            "account_name": account_name,
            "region_code": region_code,
        }
    )


@router.get("/alerts/summary", response_model=AlertSummary)
def alert_summary(
    principal: Annotated[Principal, Depends(require_permission("alerts:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AlertSummary:
    rows = session.execute(
        select(Alert.status, Alert.severity, func.count(Alert.id))
        .where(Alert.organization_id == principal.organization_id)
        .group_by(Alert.status, Alert.severity)
    ).all()
    counts = {(status, severity): count for status, severity, count in rows}
    active = sum(
        count for (status, _severity), count in counts.items() if status in {"OPEN", "ACKNOWLEDGED"}
    )
    return AlertSummary(
        active=active,
        critical=sum(
            count
            for (status, severity), count in counts.items()
            if status in {"OPEN", "ACKNOWLEDGED"} and severity == "CRITICAL"
        ),
        high=sum(
            count
            for (status, severity), count in counts.items()
            if status in {"OPEN", "ACKNOWLEDGED"} and severity == "HIGH"
        ),
        acknowledged=sum(
            count for (status, _severity), count in counts.items() if status == "ACKNOWLEDGED"
        ),
        resolved=sum(
            count for (status, _severity), count in counts.items() if status == "RESOLVED"
        ),
        dismissed=sum(
            count for (status, _severity), count in counts.items() if status == "DISMISSED"
        ),
    )


@router.get("/alerts", response_model=AlertPage)
def list_alerts(
    principal: Annotated[Principal, Depends(require_permission("alerts:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    status: Annotated[str | None, Query(max_length=20)] = None,
    severity: Annotated[str | None, Query(max_length=20)] = None,
    source_type: Annotated[str | None, Query(max_length=40)] = None,
    search: Annotated[str | None, Query(max_length=160)] = None,
) -> AlertPage:
    criteria = [Alert.organization_id == principal.organization_id]
    if status:
        criteria.append(Alert.status == status.upper())
    if severity:
        criteria.append(Alert.severity == severity.upper())
    if source_type:
        criteria.append(Alert.source_type == source_type.upper())
    if search:
        escaped = search.replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        criteria.append(Alert.title.ilike(pattern, escape="\\"))
    total = session.scalar(select(func.count(Alert.id)).where(*criteria)) or 0
    rows = session.scalars(
        select(Alert)
        .where(*criteria)
        .order_by(Alert.created_at.desc(), Alert.id)
        .offset(offset)
        .limit(limit)
    ).all()
    return AlertPage(
        items=[_read_alert(session, row) for row in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/alerts/{alert_id}", response_model=AlertRead)
def get_alert(
    alert_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("alerts:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AlertRead:
    row = session.scalar(
        select(Alert).where(
            Alert.organization_id == principal.organization_id, Alert.id == alert_id
        )
    )
    if row is None:
        raise NotFoundError("Alert")
    return _read_alert(session, row)


def _change_status(
    alert_id: UUID,
    status: str,
    principal: Principal,
    session: Session,
) -> AlertRead:
    row = session.scalar(
        select(Alert)
        .where(Alert.organization_id == principal.organization_id, Alert.id == alert_id)
        .with_for_update()
    )
    if row is None:
        raise NotFoundError("Alert")
    return _read_alert(
        session, update_alert_status(session, row, actor_user_id=principal.user_id, status=status)
    )


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertRead)
def acknowledge_alert(
    alert_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("alerts:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AlertRead:
    return _change_status(alert_id, "ACKNOWLEDGED", principal, session)


@router.post("/alerts/{alert_id}/resolve", response_model=AlertRead)
def resolve_alert(
    alert_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("alerts:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AlertRead:
    return _change_status(alert_id, "RESOLVED", principal, session)


@router.post("/alerts/{alert_id}/dismiss", response_model=AlertRead)
def dismiss_alert(
    alert_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("alerts:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AlertRead:
    return _change_status(alert_id, "DISMISSED", principal, session)


@router.get("/alert-rules", response_model=list[AlertRuleRead])
def list_alert_rules(
    principal: Annotated[Principal, Depends(require_permission("alerts:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[AlertRuleRead]:
    rows = ensure_alert_rules(session, principal.organization_id)
    session.commit()
    return [AlertRuleRead.model_validate(row) for row in rows]


@router.patch("/alert-rules/{rule_id}", response_model=AlertRuleRead)
def update_alert_rule(
    rule_id: UUID,
    payload: AlertRulePatch,
    principal: Annotated[Principal, Depends(require_permission("alerts:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AlertRuleRead:
    ensure_alert_rules(session, principal.organization_id)
    row = session.scalar(
        select(AlertRule)
        .where(AlertRule.organization_id == principal.organization_id, AlertRule.id == rule_id)
        .with_for_update()
    )
    if row is None:
        raise NotFoundError("Alert rule")
    if "enabled" in payload.model_fields_set:
        row.enabled = bool(payload.enabled)
    if "threshold_score" in payload.model_fields_set:
        if row.event_type == "HIGH_RISK_FINDING" and payload.threshold_score is None:
            raise ConflictError("The high-risk finding rule requires a risk score threshold.")
        row.threshold_score = payload.threshold_score
    session.flush()
    from app.operations.service import record_audit

    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action=(
            "alert_rule.enabled"
            if "enabled" in payload.model_fields_set and row.enabled
            else "alert_rule.disabled"
            if "enabled" in payload.model_fields_set
            else "alert_rule.updated"
        ),
        resource_type="alert_rule",
        resource_id=row.id,
        details={"enabled": row.enabled, "threshold_score": row.threshold_score},
    )
    session.commit()
    session.refresh(row)
    return AlertRuleRead.model_validate(row)
