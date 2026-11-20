"""Evaluate canonical findings, risk assessments, and scan outcomes into alerts."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.models import (
    Alert,
    AlertRule,
    Finding,
    Membership,
    Permission,
    RiskScore,
    RolePermission,
    ScanJob,
    User,
)
from app.operations.service import notify_user, record_audit

DEFAULT_ALERT_RULES = (
    (
        "CRITICAL_FINDING",
        "Critical finding",
        "Create an alert when a critical severity finding is detected.",
        "CRITICAL_FINDING",
        "CRITICAL",
        None,
    ),
    (
        "HIGH_RISK_FINDING",
        "High risk finding",
        "Create an alert when finding risk reaches the configured score threshold.",
        "HIGH_RISK_FINDING",
        "HIGH",
        80,
    ),
    (
        "SCAN_FAILED",
        "Scan failed",
        "Create an alert when a cloud scan ends in a failed state.",
        "SCAN_FAILED",
        "CRITICAL",
        None,
    ),
    (
        "SCAN_COMPLETED_WITH_ERRORS",
        "Scan completed with errors",
        "Create an alert when a scan completes partially with collection errors.",
        "SCAN_COMPLETED_WITH_ERRORS",
        "HIGH",
        None,
    ),
    (
        "FINDING_CREATED",
        "Finding created",
        "Optional alert for each newly detected finding.",
        "FINDING_CREATED",
        "MEDIUM",
        None,
    ),
)


def ensure_alert_rules(session: Session, organization_id: UUID) -> list[AlertRule]:
    """Materialize the versioned default rule set once for an organization."""
    rows = list(
        session.scalars(
            select(AlertRule)
            .where(AlertRule.organization_id == organization_id)
            .order_by(AlertRule.code)
        ).all()
    )
    existing = {row.code for row in rows}
    for code, name, description, event_type, severity, threshold in DEFAULT_ALERT_RULES:
        if code in existing:
            continue
        rule = AlertRule(
            organization_id=organization_id,
            code=code,
            name=name,
            description=description,
            event_type=event_type,
            severity=severity,
            enabled=code != "FINDING_CREATED",
            threshold_score=threshold,
        )
        try:
            with session.begin_nested():
                session.add(rule)
                session.flush()
        except IntegrityError:
            existing_rule = session.scalar(
                select(AlertRule).where(
                    AlertRule.organization_id == organization_id, AlertRule.code == code
                )
            )
            if existing_rule is None:
                raise
            rule = existing_rule
        rows.append(rule)
    session.flush()
    return rows


def _create_or_update_alert(
    session: Session,
    *,
    organization_id: UUID,
    rule_code: str,
    source_type: str,
    source_id: UUID,
    title: str,
    description: str,
    severity: str | None = None,
    score: int | None = None,
    increment_occurrence: bool = True,
) -> Alert | None:
    rules = ensure_alert_rules(session, organization_id)
    rule = next((row for row in rules if row.code == rule_code), None)
    if rule is None or not rule.enabled:
        return None
    if rule.threshold_score is not None and (score is None or score < rule.threshold_score):
        return None
    deduplication_key = f"{rule.code}:{source_type}:{source_id}"
    alert = session.scalar(
        select(Alert)
        .where(
            Alert.organization_id == organization_id,
            Alert.deduplication_key == deduplication_key,
        )
        .with_for_update()
    )
    now = datetime.now(UTC)
    if alert is not None:
        if increment_occurrence:
            alert.occurrence_count += 1
            alert.last_seen_at = now
            alert.description = description[:1000]
        return alert

    alert = Alert(
        organization_id=organization_id,
        alert_rule_id=rule.id,
        deduplication_key=deduplication_key,
        alert_type=rule.event_type,
        source_type=source_type,
        source_id=str(source_id),
        title=title[:200],
        description=description[:1000],
        severity=severity or rule.severity,
        status="OPEN",
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
    )
    try:
        with session.begin_nested():
            session.add(alert)
            session.flush()
    except IntegrityError:
        existing = session.scalar(
            select(Alert)
            .where(
                Alert.organization_id == organization_id,
                Alert.deduplication_key == deduplication_key,
            )
            .with_for_update()
        )
        if existing is None:
            raise
        existing.occurrence_count += 1
        existing.last_seen_at = now
        existing.description = description[:1000]
        return existing
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=None,
        action="alert.created",
        resource_type="alert",
        resource_id=alert.id,
        details={"alert_type": alert.alert_type, "source_type": source_type},
    )
    _notify_alert_readers(session, organization_id=organization_id, alert=alert)
    return alert


def _notify_alert_readers(session: Session, *, organization_id: UUID, alert: Alert) -> None:
    user_ids = session.scalars(
        select(Membership.user_id)
        .join(User, User.id == Membership.user_id)
        .join(RolePermission, RolePermission.role_id == Membership.role_id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(
            Membership.organization_id == organization_id,
            Membership.is_active.is_(True),
            User.is_active.is_(True),
            Permission.code == "alerts:read",
        )
        .distinct()
    ).all()
    for user_id in user_ids:
        notify_user(
            session,
            organization_id=organization_id,
            recipient_user_id=user_id,
            category="security_alert",
            title=alert.title,
            message=alert.description,
            resource_type=alert.source_type.lower(),
            resource_id=alert.source_id,
        )


def emit_finding_alerts(
    session: Session,
    finding: Finding,
    risk_score: int | None,
    *,
    is_new: bool,
    increment_occurrence: bool = True,
) -> None:
    """Evaluate finding and risk rules after canonical assessments have been saved."""
    source_id = finding.id
    if is_new:
        _create_or_update_alert(
            session,
            organization_id=finding.organization_id,
            rule_code="FINDING_CREATED",
            source_type="FINDING",
            source_id=source_id,
            title=f"Finding created: {finding.title}",
            description=f"{finding.title} was detected on asset {finding.asset_id}.",
            severity="MEDIUM",
        )
    if finding.severity == "CRITICAL":
        _create_or_update_alert(
            session,
            organization_id=finding.organization_id,
            rule_code="CRITICAL_FINDING",
            source_type="FINDING",
            source_id=source_id,
            title=f"Critical finding: {finding.title}",
            description=f"{finding.title} affects asset {finding.asset_id}.",
            severity="CRITICAL",
            increment_occurrence=increment_occurrence,
        )
    _create_or_update_alert(
        session,
        organization_id=finding.organization_id,
        rule_code="HIGH_RISK_FINDING",
        source_type="FINDING",
        source_id=source_id,
        title=f"High risk finding: {finding.title}",
        description=(
            f"Finding risk score is {risk_score if risk_score is not None else 'not assessed'}."
        ),
        severity="HIGH",
        score=risk_score,
        increment_occurrence=increment_occurrence,
    )


def emit_scan_alert(
    session: Session, job: ScanJob, *, increment_occurrence: bool = True
) -> None:
    """Evaluate terminal scan state within the worker's database transaction."""
    if job.status == "failed":
        _create_or_update_alert(
            session,
            organization_id=job.organization_id,
            rule_code="SCAN_FAILED",
            source_type="SCAN",
            source_id=job.id,
            title="Cloud scan failed",
            description=f"Scan {job.id} failed with {job.errors_count} collection error(s).",
            increment_occurrence=increment_occurrence,
        )
    elif job.status == "partial" and job.errors_count:
        _create_or_update_alert(
            session,
            organization_id=job.organization_id,
            rule_code="SCAN_COMPLETED_WITH_ERRORS",
            source_type="SCAN",
            source_id=job.id,
            title="Cloud scan completed with errors",
            description=f"Scan {job.id} completed with {job.errors_count} collection error(s).",
            increment_occurrence=increment_occurrence,
        )


def reconcile_alerts(session: Session, organization_id: UUID) -> dict[str, int]:
    """Create missing alerts from current canonical findings and terminal scan outcomes."""
    ensure_alert_rules(session, organization_id)
    before = session.scalar(
        select(func.count(Alert.id)).where(Alert.organization_id == organization_id)
    ) or 0
    active_findings = session.scalars(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.status.in_(("OPEN", "TRIAGED", "ASSIGNED", "IN_PROGRESS")),
        )
    ).all()
    scores = {
        finding_id: score
        for finding_id, score in session.execute(
            select(RiskScore.finding_id, RiskScore.score).where(
                RiskScore.organization_id == organization_id
            )
        ).all()
    }
    for finding in active_findings:
        emit_finding_alerts(
            session,
            finding,
            scores.get(finding.id),
            is_new=False,
            increment_occurrence=False,
        )

    terminal_scans = session.scalars(
        select(ScanJob).where(
            ScanJob.organization_id == organization_id,
            ScanJob.status.in_(("failed", "partial")),
        )
    ).all()
    for job in terminal_scans:
        emit_scan_alert(session, job, increment_occurrence=False)

    session.flush()
    after = session.scalar(
        select(func.count(Alert.id)).where(Alert.organization_id == organization_id)
    ) or 0
    return {
        "evaluated_findings": len(active_findings),
        "evaluated_scans": len(terminal_scans),
        "created_alerts": max(after - before, 0),
    }


def update_alert_status(
    session: Session,
    alert: Alert,
    *,
    actor_user_id: UUID,
    status: str,
    note: str | None = None,
) -> Alert:
    """Apply an allowed alert lifecycle action and append an audit record."""
    allowed = {
        "ACKNOWLEDGED": {"OPEN"},
        "RESOLVED": {"OPEN", "ACKNOWLEDGED"},
        "DISMISSED": {"OPEN", "ACKNOWLEDGED"},
    }
    from app.core.domain_errors import ConflictError

    if alert.status not in allowed.get(status, set()):
        raise ConflictError("This alert can no longer receive that action.")
    now = datetime.now(UTC)
    alert.status = status
    actor_field = {
        "ACKNOWLEDGED": "acknowledged_by_user_id",
        "RESOLVED": "resolved_by_user_id",
        "DISMISSED": "dismissed_by_user_id",
    }[status]
    time_field = {
        "ACKNOWLEDGED": "acknowledged_at",
        "RESOLVED": "resolved_at",
        "DISMISSED": "dismissed_at",
    }[status]
    setattr(alert, actor_field, actor_user_id)
    setattr(alert, time_field, now)
    record_audit(
        session,
        organization_id=alert.organization_id,
        actor_user_id=actor_user_id,
        action=f"alert.{status.lower()}",
        resource_type="alert",
        resource_id=alert.id,
        details={"source_type": alert.source_type, "note": note[:200] if note else None},
    )
    session.commit()
    session.refresh(alert)
    return alert
