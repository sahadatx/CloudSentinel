"""Tenant-scoped policy registry, version snapshots, and rule evaluation."""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.domain_errors import ConflictError, NotFoundError
from app.core.models import (
    Asset,
    PolicyAssessment,
    PolicyAssessmentEvidence,
    PolicyDefinition,
    PolicyVersion,
    ScanJob,
)
from app.operations.service import record_audit
from app.policies.schemas import PolicyCreate, PolicyUpdate
from cloudsentinel_policy.engine import RuleDefinition, evaluate_rule, load_aws_rules
from cloudsentinel_scanner.normalizers.aws import sanitize_evidence


def ensure_builtin_policies(session: Session, organization_id: UUID) -> list[PolicyDefinition]:
    """Provision bundled AWS rule definitions once for a tenant, then return its registry."""
    rows = list(
        session.scalars(
            select(PolicyDefinition)
            .where(PolicyDefinition.organization_id == organization_id)
            .order_by(PolicyDefinition.rule_id)
        ).all()
    )
    present = {row.rule_id for row in rows}
    for rule in load_aws_rules():
        if rule.id in present:
            continue
        policy = PolicyDefinition(
            organization_id=organization_id,
            rule_id=rule.id,
            name=rule.name,
            description=rule.description,
            provider="AWS",
            resource_types=list(rule.resource_types),
            category=rule.category,
            severity=rule.severity,
            status="enabled",
            version=_initial_version(rule.version),
            detection_logic=rule.condition,
            evidence_logic={"observed_fields": _condition_paths(rule.condition)},
            remediation=rule.remediation,
            compliance_controls=[item.model_dump() for item in rule.compliance_controls],
            is_builtin=True,
        )
        session.add(policy)
        session.flush()
        session.add(
            PolicyVersion(
                organization_id=organization_id,
                policy_id=policy.id,
                version=policy.version,
                snapshot=policy_snapshot(policy),
                changed_by_user_id=None,
            )
        )
        rows.append(policy)
    if len(rows) != len(present):
        session.commit()
    return sorted(rows, key=lambda row: row.rule_id)


def policy_snapshot(policy: PolicyDefinition) -> dict[str, Any]:
    """Return the immutable definition fields that determine future evaluations."""
    return {
        "rule_id": policy.rule_id,
        "name": policy.name,
        "description": policy.description,
        "provider": policy.provider,
        "resource_types": list(policy.resource_types),
        "category": policy.category,
        "severity": policy.severity,
        "detection_logic": policy.detection_logic,
        "evidence_logic": policy.evidence_logic,
        "remediation": policy.remediation,
        "compliance_controls": list(policy.compliance_controls),
    }


def validate_policy_definition(policy: PolicyDefinition) -> RuleDefinition:
    """Validate all policy metadata and constrained DSL fields before persistence/use."""
    try:
        return RuleDefinition.model_validate(
            {
                "id": policy.rule_id,
                "name": policy.name,
                "description": policy.description,
                "version": str(policy.version),
                "severity": policy.severity,
                "category": policy.category,
                "resource_types": policy.resource_types,
                "condition": policy.detection_logic,
                "remediation": policy.remediation,
                "compliance_controls": policy.compliance_controls,
                "risk": None,
            }
        )
    except ValidationError as error:
        raise ConflictError(
            "Policy definition is invalid. Check the supported rule logic."
        ) from error


def create_policy(
    session: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID,
    payload: PolicyCreate,
) -> PolicyDefinition:
    rule_id = payload.rule_id or f"CUSTOM-{uuid4().hex[:12].upper()}"
    rule_id = rule_id.strip().upper()
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9_.-]{1,99}", rule_id):
        raise ConflictError(
            "Rule ID must use uppercase letters, numbers, dots, underscores, or hyphens."
        )
    if session.scalar(
        select(PolicyDefinition.id).where(
            PolicyDefinition.organization_id == organization_id,
            PolicyDefinition.rule_id == rule_id,
        )
    ):
        raise ConflictError("A policy with this Rule ID already exists.")
    policy = PolicyDefinition(
        organization_id=organization_id,
        rule_id=rule_id,
        name=payload.name,
        description=payload.description,
        provider=payload.provider,
        resource_types=payload.resource_types,
        category=payload.category,
        severity=payload.severity,
        status=payload.status,
        version=1,
        detection_logic=payload.detection_logic,
        evidence_logic=payload.evidence_logic,
        remediation=payload.remediation,
        compliance_controls=payload.compliance_controls,
        is_builtin=False,
    )
    validate_policy_definition(policy)
    session.add(policy)
    session.flush()
    _record_version(session, policy, actor_user_id)
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="policy.created",
        resource_type="policy",
        resource_id=policy.id,
        details={"rule_id": rule_id, "version": policy.version},
    )
    session.commit()
    return policy


def update_policy(
    session: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID,
    policy_id: UUID,
    payload: PolicyUpdate,
) -> PolicyDefinition:
    policy = get_policy(session, organization_id, policy_id, lock=True)
    before = policy_snapshot(policy)
    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(policy, field, value)
    validate_policy_definition(policy)
    after = policy_snapshot(policy)
    changed = before != after
    if changed:
        policy.version += 1
        session.flush()
        _record_version(session, policy, actor_user_id)
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="policy.updated",
        resource_type="policy",
        resource_id=policy.id,
        details={
            "rule_id": policy.rule_id,
            "version": policy.version,
            "definition_changed": changed,
        },
    )
    session.commit()
    return policy


def get_policy(
    session: Session, organization_id: UUID, policy_id: UUID, *, lock: bool = False
) -> PolicyDefinition:
    statement = select(PolicyDefinition).where(
        PolicyDefinition.organization_id == organization_id,
        PolicyDefinition.id == policy_id,
    )
    if lock:
        statement = statement.with_for_update()
    policy = session.scalar(statement)
    if policy is None:
        raise NotFoundError("Policy")
    return policy


def set_policy_status(
    session: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID,
    policy_id: UUID,
    status: str,
) -> PolicyDefinition:
    policy = get_policy(session, organization_id, policy_id, lock=True)
    if status not in {"enabled", "disabled"}:
        raise ConflictError("Unsupported policy state.")
    previous = policy.status
    policy.status = status
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="policy.enabled" if status == "enabled" else "policy.disabled",
        resource_type="policy",
        resource_id=policy.id,
        details={"rule_id": policy.rule_id, "before": previous, "after": status},
    )
    session.commit()
    return policy


def duplicate_policy(
    session: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID,
    policy_id: UUID,
) -> PolicyDefinition:
    source = get_policy(session, organization_id, policy_id)
    new_id = f"CUSTOM-{uuid4().hex[:12].upper()}"
    copy = PolicyDefinition(
        organization_id=organization_id,
        rule_id=new_id,
        name=f"{source.name} (Copy)",
        description=source.description,
        provider=source.provider,
        resource_types=list(source.resource_types),
        category=source.category,
        severity=source.severity,
        status="disabled",
        version=1,
        detection_logic=source.detection_logic,
        evidence_logic=source.evidence_logic,
        remediation=source.remediation,
        compliance_controls=list(source.compliance_controls),
        is_builtin=False,
    )
    session.add(copy)
    session.flush()
    _record_version(session, copy, actor_user_id)
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="policy.duplicated",
        resource_type="policy",
        resource_id=copy.id,
        details={"source_policy_id": str(source.id), "rule_id": new_id},
    )
    session.commit()
    return copy


def record_asset_assessments(
    session: Session,
    *,
    job: ScanJob,
    asset: Asset,
    policies: list[PolicyDefinition],
) -> None:
    """Persist PASS/FAIL/N/A/ERROR for each enabled rule and canonical asset."""
    canonical = {
        "resource_type": asset.resource_type,
        "resource_id": asset.resource_id,
        "resource_arn": asset.resource_arn,
        "region_code": asset.region_code,
        "tags": asset.tags,
        "attributes": asset.attributes,
    }
    for policy in policies:
        if policy.provider != asset.provider or asset.resource_type not in policy.resource_types:
            result = "NOT_APPLICABLE"
            observed: dict[str, object] = {}
            error_code = None
        else:
            try:
                rule = validate_policy_definition(policy)
                evaluation = evaluate_rule(rule, canonical)
                if evaluation is None:
                    result, observed, error_code = "NOT_APPLICABLE", {}, None
                else:
                    result = "FAIL" if evaluation.matched else "PASS"
                    observed = sanitize_evidence(evaluation.observed)
                    error_code = None
            except Exception:
                result, observed, error_code = "ERROR", {}, "rule_evaluation_error"

        assessment = PolicyAssessment(
            organization_id=job.organization_id,
            policy_id=policy.id,
            asset_id=asset.id,
            scan_job_id=job.id,
            policy_version=policy.version,
            result=result,
            error_code=error_code,
        )
        session.add(assessment)
        session.flush()
        if result in {"PASS", "FAIL"}:
            session.add(
                PolicyAssessmentEvidence(
                    organization_id=job.organization_id,
                    assessment_id=assessment.id,
                    expected_state={"condition": policy.detection_logic},
                    observed_state=observed,
                )
            )


def policy_counts(session: Session, organization_id: UUID) -> dict[str, int]:
    rows = list(
        session.scalars(
            select(PolicyDefinition).where(PolicyDefinition.organization_id == organization_id)
        ).all()
    )
    return {
        "total": len(rows),
        "enabled": sum(row.status == "enabled" for row in rows),
        "disabled": sum(row.status == "disabled" for row in rows),
        "critical": sum(row.severity == "CRITICAL" for row in rows),
        "compliance_mapped": sum(bool(row.compliance_controls) for row in rows),
    }


def _record_version(session: Session, policy: PolicyDefinition, actor_user_id: UUID | None) -> None:
    session.add(
        PolicyVersion(
            organization_id=policy.organization_id,
            policy_id=policy.id,
            version=policy.version,
            snapshot=policy_snapshot(policy),
            changed_by_user_id=actor_user_id,
        )
    )


def _initial_version(value: str) -> int:
    try:
        return max(1, int(value.split(".", maxsplit=1)[0]))
    except ValueError:
        return 1


def _condition_paths(condition: dict[str, Any]) -> list[str]:
    if set(condition) in ({"all"}, {"any"}):
        paths: list[str] = []
        for item in condition[next(iter(condition))]:
            paths.extend(_condition_paths(item))
        return list(dict.fromkeys(paths))
    path = condition.get("path")
    return [path] if isinstance(path, str) else []
