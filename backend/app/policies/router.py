"""Tenant-scoped policy registry, lifecycle actions, and assessment investigation APIs."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.core.domain_errors import NotFoundError
from app.core.models import (
    Asset,
    CloudAccount,
    PolicyAssessment,
    PolicyAssessmentEvidence,
    PolicyDefinition,
    PolicyVersion,
)
from app.findings.schemas import PolicyRuleRead
from app.policies.schemas import (
    PolicyAssessmentPage,
    PolicyAssessmentRead,
    PolicyCreate,
    PolicyFilterOptions,
    PolicyPage,
    PolicyRead,
    PolicySummary,
    PolicyUpdate,
    PolicyVersionRead,
)
from app.policies.service import (
    create_policy,
    duplicate_policy,
    ensure_builtin_policies,
    get_policy,
    policy_counts,
    set_policy_status,
    update_policy,
)

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("/summary", response_model=PolicySummary)
def get_policy_summary(
    principal: Annotated[Principal, Depends(require_permission("policies:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> PolicySummary:
    ensure_builtin_policies(session, principal.organization_id)
    return PolicySummary(**policy_counts(session, principal.organization_id))


@router.get("/filter-options", response_model=PolicyFilterOptions)
def get_policy_filter_options(
    principal: Annotated[Principal, Depends(require_permission("policies:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> PolicyFilterOptions:
    policies = ensure_builtin_policies(session, principal.organization_id)
    return PolicyFilterOptions(
        providers=sorted({policy.provider for policy in policies}),
        severities=sorted({policy.severity for policy in policies}),
        categories=sorted({policy.category for policy in policies}),
        statuses=["enabled", "disabled"],
        resource_types=sorted({kind for policy in policies for kind in policy.resource_types}),
        frameworks=sorted(
            {
                str(mapping.get("framework"))
                for policy in policies
                for mapping in policy.compliance_controls
                if mapping.get("framework")
            }
        ),
    )


@router.get("", response_model=PolicyPage)
def list_policies(
    principal: Annotated[Principal, Depends(require_permission("policies:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    provider: Annotated[str | None, Query(max_length=20)] = None,
    severity: Annotated[str | None, Query(max_length=20)] = None,
    category: Annotated[str | None, Query(max_length=100)] = None,
    status: Annotated[str | None, Query(pattern="^(enabled|disabled)$")] = None,
    resource_type: Annotated[str | None, Query(max_length=100)] = None,
    framework: Annotated[str | None, Query(max_length=100)] = None,
    sort_by: Annotated[
        str, Query(pattern="^(rule_id|name|severity|category|provider|status|version)$")
    ] = "rule_id",
    sort_direction: Annotated[str, Query(pattern="^(asc|desc)$")] = "asc",
) -> PolicyPage:
    ensure_builtin_policies(session, principal.organization_id)
    criteria = [PolicyDefinition.organization_id == principal.organization_id]
    if provider:
        criteria.append(PolicyDefinition.provider == provider.upper())
    if severity:
        criteria.append(PolicyDefinition.severity == severity.upper())
    if category:
        criteria.append(PolicyDefinition.category == category)
    if status:
        criteria.append(PolicyDefinition.status == status)
    if search:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        criteria.append(
            PolicyDefinition.rule_id.ilike(pattern)
            | PolicyDefinition.name.ilike(pattern)
            | PolicyDefinition.description.ilike(pattern)
        )
    column = getattr(PolicyDefinition, sort_by)
    ordering = column.desc() if sort_direction == "desc" else column.asc()
    policies = list(
        session.scalars(
            select(PolicyDefinition).where(*criteria).order_by(ordering, PolicyDefinition.rule_id)
        ).all()
    )
    # JSON containment differs between PostgreSQL JSON and JSONB operators. The
    # registry is intentionally small, so apply these two optional filters after
    # tenant-scoped retrieval and keep pagination/counts deterministic.
    if resource_type:
        policies = [policy for policy in policies if resource_type in policy.resource_types]
    if framework:
        policies = [
            policy
            for policy in policies
            if any(mapping.get("framework") == framework for mapping in policy.compliance_controls)
        ]
    total = len(policies)
    policies = policies[offset : offset + limit]
    return PolicyPage(
        items=[PolicyRead.model_validate(policy) for policy in policies],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/rules", response_model=list[PolicyRuleRead])
def list_rules_compatibility(
    principal: Annotated[Principal, Depends(require_permission("policies:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[PolicyRuleRead]:
    """Keep the catalog projection used by cross-module global search clients."""
    policies = ensure_builtin_policies(session, principal.organization_id)
    return [
        PolicyRuleRead(
            id=policy.rule_id,
            name=policy.name,
            description=policy.description,
            version=str(policy.version),
            severity=policy.severity,
            category=policy.category,
            resource_types=tuple(policy.resource_types),
            remediation=policy.remediation,
        )
        for policy in policies
    ]


@router.post("", response_model=PolicyRead, status_code=201)
def post_policy(
    payload: PolicyCreate,
    principal: Annotated[Principal, Depends(require_permission("policies:create"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> PolicyRead:
    policy = create_policy(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        payload=payload,
    )
    return PolicyRead.model_validate(policy)


@router.get("/{policy_id}", response_model=PolicyRead)
def get_policy_details(
    policy_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("policies:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> PolicyRead:
    ensure_builtin_policies(session, principal.organization_id)
    return PolicyRead.model_validate(get_policy(session, principal.organization_id, policy_id))


@router.patch("/{policy_id}", response_model=PolicyRead)
def patch_policy(
    policy_id: UUID,
    payload: PolicyUpdate,
    principal: Annotated[Principal, Depends(require_permission("policies:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> PolicyRead:
    policy = update_policy(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        policy_id=policy_id,
        payload=payload,
    )
    return PolicyRead.model_validate(policy)


@router.post("/{policy_id}/enable", response_model=PolicyRead)
def enable_policy(
    policy_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("policies:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> PolicyRead:
    policy = set_policy_status(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        policy_id=policy_id,
        status="enabled",
    )
    return PolicyRead.model_validate(policy)


@router.post("/{policy_id}/disable", response_model=PolicyRead)
def disable_policy(
    policy_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("policies:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> PolicyRead:
    policy = set_policy_status(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        policy_id=policy_id,
        status="disabled",
    )
    return PolicyRead.model_validate(policy)


@router.post("/{policy_id}/duplicate", response_model=PolicyRead, status_code=201)
def duplicate_policy_route(
    policy_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("policies:create"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> PolicyRead:
    policy = duplicate_policy(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        policy_id=policy_id,
    )
    return PolicyRead.model_validate(policy)


@router.get("/{policy_id}/versions", response_model=list[PolicyVersionRead])
def list_policy_versions(
    policy_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("policies:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[PolicyVersionRead]:
    get_policy(session, principal.organization_id, policy_id)
    versions = session.scalars(
        select(PolicyVersion)
        .where(
            PolicyVersion.organization_id == principal.organization_id,
            PolicyVersion.policy_id == policy_id,
        )
        .order_by(PolicyVersion.version.desc())
    ).all()
    return [PolicyVersionRead.model_validate(version) for version in versions]


@router.get("/{policy_id}/versions/{version}", response_model=PolicyVersionRead)
def get_policy_version(
    policy_id: UUID,
    version: int,
    principal: Annotated[Principal, Depends(require_permission("policies:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> PolicyVersionRead:
    get_policy(session, principal.organization_id, policy_id)
    row = session.scalar(
        select(PolicyVersion).where(
            PolicyVersion.organization_id == principal.organization_id,
            PolicyVersion.policy_id == policy_id,
            PolicyVersion.version == version,
        )
    )
    if row is None:
        raise NotFoundError("Policy version")
    return PolicyVersionRead.model_validate(row)


@router.get("/{policy_id}/assessments", response_model=PolicyAssessmentPage)
def list_policy_assessments(
    policy_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("policies:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    result: Annotated[str | None, Query(pattern="^(PASS|FAIL|NOT_APPLICABLE|ERROR)$")] = None,
) -> PolicyAssessmentPage:
    get_policy(session, principal.organization_id, policy_id)
    criteria = [
        PolicyAssessment.organization_id == principal.organization_id,
        PolicyAssessment.policy_id == policy_id,
    ]
    ranked = (
        select(
            PolicyAssessment.id.label("assessment_id"),
            func.row_number()
            .over(
                partition_by=PolicyAssessment.asset_id,
                order_by=(PolicyAssessment.evaluated_at.desc(), PolicyAssessment.id.desc()),
            )
            .label("rank"),
        )
        .where(*criteria)
        .subquery()
    )
    latest_ids = select(ranked.c.assessment_id).where(ranked.c.rank == 1).subquery()
    latest_criteria = [
        PolicyAssessment.organization_id == principal.organization_id,
        PolicyAssessment.policy_id == policy_id,
    ]
    if result:
        latest_criteria.append(PolicyAssessment.result == result)
    latest_query = (
        select(PolicyAssessment, Asset, CloudAccount)
        .join(latest_ids, latest_ids.c.assessment_id == PolicyAssessment.id)
        .join(
            Asset,
            (Asset.id == PolicyAssessment.asset_id)
            & (Asset.organization_id == PolicyAssessment.organization_id),
        )
        .join(
            CloudAccount,
            (CloudAccount.id == Asset.cloud_account_id)
            & (CloudAccount.organization_id == Asset.organization_id),
        )
        .where(*latest_criteria)
    )
    total = session.scalar(select(func.count()).select_from(latest_query.subquery())) or 0
    result_counts: dict[str, int] = {
        str(result): int(count)
        for result, count in session.execute(
            select(PolicyAssessment.result, func.count(PolicyAssessment.id))
            .join(latest_ids, latest_ids.c.assessment_id == PolicyAssessment.id)
            .where(
                PolicyAssessment.organization_id == principal.organization_id,
                PolicyAssessment.policy_id == policy_id,
            )
            .group_by(PolicyAssessment.result)
        ).tuples()
    }
    rows = session.execute(
        latest_query.order_by(PolicyAssessment.evaluated_at.desc(), Asset.name)
        .offset(offset)
        .limit(limit)
    ).all()
    return PolicyAssessmentPage(
        items=[
            PolicyAssessmentRead(
                assessment_id=assessment.id,
                asset_id=asset.id,
                asset_name=asset.name,
                resource_id=asset.resource_id,
                resource_type=asset.resource_type,
                account_name=account.name,
                region_code=asset.region_code,
                result=assessment.result,
                error_code=assessment.error_code,
                policy_version=assessment.policy_version,
                scan_job_id=assessment.scan_job_id,
                evaluated_at=assessment.evaluated_at,
            )
            for assessment, asset, account in rows
        ],
        total=total,
        offset=offset,
        limit=limit,
        assessed=result_counts.get("PASS", 0) + result_counts.get("FAIL", 0),
        passed=result_counts.get("PASS", 0),
        failed=result_counts.get("FAIL", 0),
        not_applicable=result_counts.get("NOT_APPLICABLE", 0),
        errors=result_counts.get("ERROR", 0),
    )


@router.get("/{policy_id}/assessments/{assessment_id}/evidence")
def get_assessment_evidence(
    policy_id: UUID,
    assessment_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("policies:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> dict[str, object]:
    get_policy(session, principal.organization_id, policy_id)
    row = session.execute(
        select(PolicyAssessment, PolicyAssessmentEvidence, Asset)
        .join(
            PolicyAssessmentEvidence,
            (PolicyAssessmentEvidence.assessment_id == PolicyAssessment.id)
            & (PolicyAssessmentEvidence.organization_id == PolicyAssessment.organization_id),
        )
        .join(
            Asset,
            (Asset.id == PolicyAssessment.asset_id)
            & (Asset.organization_id == PolicyAssessment.organization_id),
        )
        .where(
            PolicyAssessment.organization_id == principal.organization_id,
            PolicyAssessment.policy_id == policy_id,
            PolicyAssessment.id == assessment_id,
        )
    ).one_or_none()
    if row is None:
        raise NotFoundError("Policy assessment evidence")
    assessment, evidence, asset = row
    return {
        "assessment_id": str(assessment.id),
        "result": assessment.result,
        "asset_id": str(asset.id),
        "asset_name": asset.name,
        "resource_id": asset.resource_id,
        "region": asset.region_code,
        "policy_version": assessment.policy_version,
        "scan_job_id": str(assessment.scan_job_id),
        "expected_state": evidence.expected_state,
        "observed_state": evidence.observed_state,
        "evaluated_at": assessment.evaluated_at.isoformat(),
    }
