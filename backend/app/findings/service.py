"""Finding discovery, lifecycle transitions, suppression, evidence, and compliance links."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.alerts.service import emit_finding_alerts
from app.core.models import (
    Asset,
    CloudAccount,
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    Finding,
    FindingComplianceControl,
    FindingEvent,
    FindingEvidence,
    PolicyDefinition,
    RiskScore,
    ScanJob,
)
from app.operations.service import record_audit
from app.risk.service import RISK_MODEL, RISK_MODEL_VERSION, calculate_risk
from cloudsentinel_policy.engine import PolicyEvaluation, evaluate_asset, evaluate_rule
from cloudsentinel_scanner.normalizers.aws import sanitize_evidence

SCANNER_VERSION = "0.1.0"
TRANSITIONS = {
    "OPEN": {"TRIAGED"},
    "TRIAGED": {"IN_PROGRESS"},
    "ASSIGNED": {"IN_PROGRESS"},
    "IN_PROGRESS": {"RESOLVED"},
    "RESOLVED": {"VERIFIED"},
    "VERIFIED": {"CLOSED"},
}


def record_policy_evaluations(
    session: Session,
    *,
    job: ScanJob,
    account: CloudAccount,
    asset: Asset,
    asset_data: dict[str, Any],
    policies: list[PolicyDefinition] | None = None,
) -> None:
    """Persist canonical findings from the same enabled policy registry used by scans."""

    now = datetime.now(UTC)
    if policies is None:
        evaluations = evaluate_asset(asset_data)
    else:
        from app.policies.service import validate_policy_definition

        evaluations = tuple(
            evaluation
            for policy in policies
            if (evaluation := evaluate_rule(validate_policy_definition(policy), asset_data))
            is not None
        )
    for evaluation in evaluations:
        rule = evaluation.rule
        controls = [
            _get_or_create_control(
                session,
                reference.framework,
                reference.control,
                reference.title,
                severity=rule.severity,
                category=rule.category,
            )
            for reference in rule.compliance_controls
        ]
        for control in controls:
            assessment = session.scalar(
                select(ComplianceAssessment).where(
                    ComplianceAssessment.organization_id == job.organization_id,
                    ComplianceAssessment.scan_job_id == job.id,
                    ComplianceAssessment.asset_id == asset.id,
                    ComplianceAssessment.control_id == control.id,
                )
            )
            if assessment is None:
                assessment = ComplianceAssessment(
                    organization_id=job.organization_id,
                    scan_job_id=job.id,
                    asset_id=asset.id,
                    control_id=control.id,
                    status="FAIL" if evaluation.matched else "PASS",
                    checked_at=now,
                    observed=sanitize_evidence(evaluation.observed),
                    expected=sanitize_evidence(rule.condition),
                    policy_version=rule.version,
                )
                session.add(assessment)
            else:
                assessment.status = "FAIL" if evaluation.matched else "PASS"
                assessment.checked_at = now
                assessment.observed = sanitize_evidence(evaluation.observed)
                assessment.expected = sanitize_evidence(rule.condition)
                assessment.policy_version = rule.version

        if evaluation.matched:
            risk_score: int | None = None
            finding, is_new = _upsert_finding(session, job, account, asset, evaluation, now)
            for control in controls:
                link = session.get(
                    FindingComplianceControl,
                    {
                        "finding_id": finding.id,
                        "control_id": control.id,
                    },
                )
                if link is None:
                    session.add(
                        FindingComplianceControl(
                            organization_id=job.organization_id,
                            finding_id=finding.id,
                            control_id=control.id,
                        )
                    )
            _upsert_evidence(session, job, asset, finding, evaluation, now)
            evidence = session.scalar(
                select(FindingEvidence).where(
                    FindingEvidence.organization_id == job.organization_id,
                    FindingEvidence.finding_id == finding.id,
                    FindingEvidence.scan_job_id == job.id,
                )
            )
            for control in controls:
                assessment = session.scalar(
                    select(ComplianceAssessment).where(
                        ComplianceAssessment.organization_id == job.organization_id,
                        ComplianceAssessment.scan_job_id == job.id,
                        ComplianceAssessment.asset_id == asset.id,
                        ComplianceAssessment.control_id == control.id,
                    )
                )
                if assessment is not None and evidence is not None:
                    assessment.evidence_id = evidence.id
            if rule.risk is not None:
                risk_score, level, factors = calculate_risk(rule.severity, rule.risk)
                _upsert_finding_risk(
                    session, job.organization_id, finding.id, risk_score, level, factors
                )
            emit_finding_alerts(session, finding, risk_score, is_new=is_new)

    session.flush()


def transition_finding(
    session: Session, finding: Finding, *, actor_user_id: UUID, status: str, reason: str | None
) -> Finding:
    """Apply one canonical lifecycle edge and append its immutable event."""
    if status not in TRANSITIONS.get(finding.status, set()):
        from app.core.domain_errors import ConflictError

        raise ConflictError("The requested finding lifecycle transition is not allowed.")
    previous = finding.status
    finding.status = status
    now = datetime.now(UTC)
    if status == "RESOLVED":
        finding.resolved_at = now
    if status == "VERIFIED":
        finding.verified_at = now
        finding.verified_by_user_id = actor_user_id
    if status == "CLOSED":
        finding.closed_at = now
    session.add(
        FindingEvent(
            organization_id=finding.organization_id,
            finding_id=finding.id,
            actor_user_id=actor_user_id,
            action="status_changed",
            from_status=previous,
            to_status=status,
            reason=reason,
        )
    )
    record_audit(
        session,
        organization_id=finding.organization_id,
        actor_user_id=actor_user_id,
        action="finding.status_changed",
        resource_type="finding",
        resource_id=finding.id,
        details={"from_status": previous, "to_status": status},
    )
    session.commit()
    session.refresh(finding)
    return finding


def assign_finding(
    session: Session,
    finding: Finding,
    *,
    actor_user_id: UUID,
    assignee_user_id: UUID,
    due_at: datetime | None = None,
) -> Finding:
    """Assign to a verified active member of the finding's organization."""
    from app.core.domain_errors import InvalidOperationError
    from app.core.models import Membership, User

    member = session.scalar(
        select(Membership.id)
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.organization_id == finding.organization_id,
            Membership.user_id == assignee_user_id,
            Membership.is_active.is_(True),
            User.is_active.is_(True),
        )
    )
    if member is None:
        raise InvalidOperationError("The assignee must be an active member of this organization.")
    if finding.status not in {"TRIAGED", "ASSIGNED"}:
        from app.core.domain_errors import ConflictError

        raise ConflictError("Only triaged or assigned findings can be assigned.")
    previous = finding.status
    finding.assigned_to_user_id = assignee_user_id
    finding.due_at = due_at
    finding.status = "ASSIGNED"
    session.add(
        FindingEvent(
            organization_id=finding.organization_id,
            finding_id=finding.id,
            actor_user_id=actor_user_id,
            action="assigned",
            from_status=previous,
            to_status="ASSIGNED",
            details={"assignee_user_id": str(assignee_user_id)},
        )
    )
    record_audit(
        session,
        organization_id=finding.organization_id,
        actor_user_id=actor_user_id,
        action="finding.assigned",
        resource_type="finding",
        resource_id=finding.id,
        details={"assignee_user_id": str(assignee_user_id)},
    )
    session.commit()
    session.refresh(finding)
    return finding


def suppress_finding(
    session: Session,
    finding: Finding,
    *,
    actor_user_id: UUID,
    reason: str,
    expires_at: datetime,
) -> Finding:
    """Suppress with a reason, acting approver, expiration, and lifecycle record."""
    from app.core.domain_errors import ConflictError, InvalidOperationError

    now = datetime.now(UTC)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= now:
        raise InvalidOperationError("Suppression expiration must be in the future.")
    if finding.status not in {"OPEN", "TRIAGED", "ASSIGNED", "IN_PROGRESS"}:
        raise ConflictError("Only active findings can be suppressed.")
    previous = finding.status
    finding.status = "SUPPRESSED"
    finding.suppression_reason = reason
    finding.suppressed_by_user_id = actor_user_id
    finding.suppression_expires_at = expires_at
    session.add(
        FindingEvent(
            organization_id=finding.organization_id,
            finding_id=finding.id,
            actor_user_id=actor_user_id,
            action="suppressed",
            from_status=previous,
            to_status="SUPPRESSED",
            reason=reason,
            details={"expires_at": expires_at.isoformat()},
        )
    )
    record_audit(
        session,
        organization_id=finding.organization_id,
        actor_user_id=actor_user_id,
        action="finding.suppressed",
        resource_type="finding",
        resource_id=finding.id,
        details={"expires_at": expires_at.isoformat()},
    )
    session.commit()
    session.refresh(finding)
    return finding


def _upsert_finding(
    session: Session,
    job: ScanJob,
    account: CloudAccount,
    asset: Asset,
    evaluation: PolicyEvaluation,
    now: datetime,
) -> tuple[Finding, bool]:
    rule = evaluation.rule
    finding = session.scalar(
        select(Finding)
        .where(
            Finding.organization_id == job.organization_id,
            Finding.asset_id == asset.id,
            Finding.rule_id == rule.id,
        )
        .with_for_update()
    )
    is_new = finding is None
    if finding is None:
        finding = Finding(
            organization_id=job.organization_id,
            cloud_account_id=account.id,
            asset_id=asset.id,
            scan_job_id=job.id,
            rule_id=rule.id,
            rule_version=rule.version,
            category=rule.category,
            title=rule.name,
            description=rule.description,
            remediation=rule.remediation,
            severity=rule.severity,
            region_code=asset.region_code,
            status="OPEN",
            first_seen_at=now,
            last_seen_at=now,
        )
        session.add(finding)
        session.flush()
        session.add(
            FindingEvent(
                organization_id=job.organization_id,
                finding_id=finding.id,
                actor_user_id=job.requested_by_user_id,
                action="discovered",
                to_status="OPEN",
                details={"rule_id": rule.id, "rule_version": rule.version},
            )
        )
    else:
        finding.scan_job_id = job.id
        finding.rule_version = rule.version
        finding.category = rule.category
        finding.title = rule.name
        finding.description = rule.description
        finding.remediation = rule.remediation
        finding.severity = rule.severity
        finding.region_code = asset.region_code
        finding.last_seen_at = now
        if finding.status == "SUPPRESSED":
            expires_at = finding.suppression_expires_at
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at is not None and expires_at <= now:
                finding.status = "OPEN"
                finding.suppression_reason = None
                finding.suppressed_by_user_id = None
                finding.suppression_expires_at = None
                session.add(
                    FindingEvent(
                        organization_id=job.organization_id,
                        finding_id=finding.id,
                        actor_user_id=job.requested_by_user_id,
                        action="suppression_expired_reopened",
                        from_status="SUPPRESSED",
                        to_status="OPEN",
                    )
                )
        elif finding.status in {"RESOLVED", "VERIFIED", "CLOSED"}:
            old_status = finding.status
            finding.status = "OPEN"
            finding.resolved_at = None
            finding.verified_at = None
            finding.verified_by_user_id = None
            finding.closed_at = None
            session.add(
                FindingEvent(
                    organization_id=job.organization_id,
                    finding_id=finding.id,
                    actor_user_id=job.requested_by_user_id,
                    action="reopened_on_detection",
                    from_status=old_status,
                    to_status="OPEN",
                )
            )
    return finding, is_new


def _upsert_evidence(
    session: Session,
    job: ScanJob,
    asset: Asset,
    finding: Finding,
    evaluation: PolicyEvaluation,
    now: datetime,
) -> None:
    evidence = session.scalar(
        select(FindingEvidence).where(
            FindingEvidence.organization_id == job.organization_id,
            FindingEvidence.finding_id == finding.id,
            FindingEvidence.scan_job_id == job.id,
        )
    )
    values = {
        "rule_version": evaluation.rule.version,
        "scanner_version": SCANNER_VERSION,
        "source": "Local sample inventory"
        if asset.attributes.get("cloudsentinel_data_origin") == "local_mock"
        else "AWS API",
        "expected_state": sanitize_evidence(evaluation.rule.condition),
        "detected_condition": sanitize_evidence(evaluation.observed),
        "configuration": sanitize_evidence(asset.attributes),
        "collected_at": now,
    }
    if evidence is None:
        session.add(
            FindingEvidence(
                organization_id=job.organization_id,
                finding_id=finding.id,
                asset_id=asset.id,
                scan_job_id=job.id,
                **values,
            )
        )
    else:
        for key, value in values.items():
            setattr(evidence, key, value)


def _get_or_create_control(
    session: Session,
    framework_code: str,
    control_code: str,
    title: str,
    *,
    severity: str = "MEDIUM",
    category: str | None = None,
) -> ComplianceControl:
    cache = session.info.setdefault("compliance_control_cache", {})
    cache_key = (framework_code, control_code)
    cached = cache.get(cache_key)
    if isinstance(cached, ComplianceControl):
        return cached
    framework = session.scalar(
        select(ComplianceFramework).where(ComplianceFramework.code == framework_code)
    )
    if framework is None:
        framework = ComplianceFramework(
            code=framework_code,
            name="CIS AWS Foundations",
            version="UNRESOLVED",
            is_active=True,
        )
        session.add(framework)
        session.flush()
    control = session.scalar(
        select(ComplianceControl).where(
            ComplianceControl.framework_id == framework.id,
            ComplianceControl.control_code == control_code,
        )
    )
    if control is None:
        control = ComplianceControl(
            framework_id=framework.id,
            control_code=control_code,
            title=title,
            description=None,
            domain=category or "Uncategorized",
            category=category or "Uncategorized",
            severity=severity,
        )
        session.add(control)
        session.flush()
    cache[cache_key] = control
    return control


def _upsert_finding_risk(
    session: Session,
    organization_id: UUID,
    finding_id: UUID,
    score: int,
    level: str,
    factors: dict[str, object],
) -> None:
    row = session.scalar(
        select(RiskScore).where(
            RiskScore.organization_id == organization_id,
            RiskScore.finding_id == finding_id,
        )
    )
    if row is None:
        session.add(
            RiskScore(
                organization_id=organization_id,
                finding_id=finding_id,
                score=score,
                level=level,
                factors=factors,
                calculated_at=datetime.now(UTC),
            )
        )
    else:
        row.score = score
        row.level = level
        row.factors = factors
        row.calculated_at = datetime.now(UTC)
        row.risk_model = RISK_MODEL
        row.risk_model_version = RISK_MODEL_VERSION
