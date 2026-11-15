"""Permission-aware tenant search over canonical product records."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, or_, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_current_principal, get_tenant_session
from app.core.models import (
    Asset,
    CloudAccount,
    ComplianceControl,
    ComplianceFramework,
    Finding,
    Membership,
    PolicyDefinition,
    Report,
    ScanJob,
    Team,
    User,
)
from app.search.schemas import SearchResponse, SearchResult
from cloudsentinel_policy.engine import load_aws_rules

router = APIRouter(prefix="/search", tags=["search"])
SEARCH_TYPES = {
    "asset",
    "finding",
    "cloud_account",
    "policy",
    "compliance_control",
    "scan",
    "user",
    "team",
    "report",
}
MAX_CANDIDATES_PER_TYPE = 100


def _rank(term: str, identifier: str, title: str, text: str) -> int:
    """Rank exact IDs and names above prefixes, tokens, and descriptive matches."""
    query = term.casefold().strip()
    if identifier.casefold() == query:
        return 1000
    if title.casefold() == query:
        return 900
    if identifier.casefold().startswith(query) or title.casefold().startswith(query):
        return 700
    words = query.split()
    title_words = title.casefold()
    if words and all(word in title_words for word in words):
        return 500
    return 200 if query in text.casefold() else 0


@router.get("", response_model=SearchResponse)
def search(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_tenant_session)],
    q: Annotated[str, Query(min_length=2, max_length=100)],
    entity_types: Annotated[str | None, Query(alias="type", max_length=200)] = None,
    severity: Annotated[str | None, Query(max_length=20)] = None,
    status: Annotated[str | None, Query(max_length=30)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=50)] = 20,
) -> SearchResponse:
    """Search permitted entity types, enforce tenant scope, rank, then paginate."""
    term = q.strip()
    if len(term) < 2:
        raise HTTPException(
            status_code=422, detail="Search query must contain at least two characters."
        )
    selected = set(entity_types.split(",")) if entity_types else SEARCH_TYPES
    unknown = selected - SEARCH_TYPES
    if unknown:
        raise HTTPException(status_code=422, detail="One or more entity types are unsupported.")
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped}%"
    org_id = principal.organization_id
    grants = principal.permissions
    found: list[SearchResult] = []

    def include(entity_type: str) -> bool:
        return entity_type in selected

    def append(
        entity_type: str, identifier: str, title: str, subtitle: str, href: str, searchable: str
    ) -> None:
        rank = _rank(term, identifier, title, searchable)
        if rank:
            found.append(
                SearchResult(
                    type=entity_type,
                    id=identifier,
                    title=title,
                    subtitle=subtitle,
                    href=href,
                    rank=rank,
                )
            )

    if "assets:read" in grants and include("asset"):
        asset_query = select(Asset).where(
            Asset.organization_id == org_id,
            or_(
                Asset.name.ilike(pattern),
                Asset.resource_id.ilike(pattern),
                Asset.resource_arn.ilike(pattern),
                cast(Asset.id, String).ilike(pattern),
            ),
        )
        asset_rows = session.scalars(
            asset_query.order_by(Asset.name, Asset.id).limit(MAX_CANDIDATES_PER_TYPE)
        ).all()
        for asset in asset_rows:
            title = asset.name or asset.resource_id
            append(
                "asset",
                str(asset.id),
                title,
                f"{asset.resource_type} · {asset.provider} · {asset.region_code} · {asset.status}",
                f"/assets/{asset.id}",
                f"{asset.resource_id} {asset.resource_arn or ''} {asset.tags}",
            )

    if "findings:read" in grants and include("finding"):
        criteria = [
            Finding.organization_id == org_id,
            or_(
                Finding.title.ilike(pattern),
                Finding.rule_id.ilike(pattern),
                Finding.description.ilike(pattern),
                cast(Finding.id, String).ilike(pattern),
            ),
        ]
        if severity:
            criteria.append(Finding.severity == severity.upper())
        if status:
            criteria.append(Finding.status == status.upper())
        finding_rows = session.scalars(
            select(Finding)
            .where(*criteria)
            .order_by(Finding.severity, Finding.last_seen_at.desc())
            .limit(MAX_CANDIDATES_PER_TYPE)
        ).all()
        for finding in finding_rows:
            append(
                "finding",
                str(finding.id),
                finding.title or finding.rule_id,
                f"{finding.severity} · {finding.status} · {finding.rule_id}",
                f"/findings/{finding.id}",
                f"{finding.rule_id} {finding.description}",
            )

    if "cloud_accounts:read" in grants and include("cloud_account"):
        account_rows = session.scalars(
            select(CloudAccount)
            .where(
                CloudAccount.organization_id == org_id,
                or_(
                    CloudAccount.name.ilike(pattern),
                    CloudAccount.account_id.ilike(pattern),
                    cast(CloudAccount.id, String).ilike(pattern),
                ),
            )
            .order_by(CloudAccount.name)
            .limit(MAX_CANDIDATES_PER_TYPE)
        ).all()
        for account in account_rows:
            append(
                "cloud_account",
                str(account.id),
                account.name or account.account_id,
                f"AWS · {account.connection_status} · {account.account_id}",
                f"/cloud-accounts/{account.id}",
                f"{account.account_id} {account.environment or ''}",
            )

    if "policies:read" in grants and include("policy"):
        policy_rows = session.scalars(
            select(PolicyDefinition)
            .where(
                PolicyDefinition.organization_id == org_id,
                or_(
                    PolicyDefinition.rule_id.ilike(pattern),
                    PolicyDefinition.name.ilike(pattern),
                    PolicyDefinition.description.ilike(pattern),
                    cast(PolicyDefinition.id, String).ilike(pattern),
                ),
            )
            .order_by(PolicyDefinition.rule_id)
            .limit(MAX_CANDIDATES_PER_TYPE)
        ).all()
        for policy in policy_rows:
            append(
                "policy",
                str(policy.id),
                policy.name or policy.rule_id,
                f"{policy.severity} · {policy.status} · v{policy.version} · {policy.rule_id}",
                f"/policies/{policy.id}",
                f"{policy.rule_id} {policy.description}",
            )
        # Bundled definitions are canonical even before another endpoint has lazily
        # materialized the tenant's editable policy registry rows.
        present_rule_ids = {row.rule_id for row in policy_rows}
        for rule in load_aws_rules():
            if rule.id not in present_rule_ids:
                append(
                    "policy",
                    rule.id,
                    rule.name,
                    f"{rule.severity} · bundled definition · v{rule.version}",
                    f"/policies?search={rule.id}",
                    f"{rule.id} {rule.description}",
                )

    if "findings:read" in grants and include("compliance_control"):
        control_rows = session.execute(
            select(ComplianceControl, ComplianceFramework)
            .join(ComplianceFramework, ComplianceFramework.id == ComplianceControl.framework_id)
            .where(
                ComplianceFramework.is_active.is_(True),
                or_(
                    ComplianceControl.control_code.ilike(pattern),
                    ComplianceControl.title.ilike(pattern),
                    cast(ComplianceControl.id, String).ilike(pattern),
                ),
            )
            .order_by(ComplianceControl.control_code)
            .limit(MAX_CANDIDATES_PER_TYPE)
        ).all()
        for control, framework in control_rows:
            append(
                "compliance_control",
                str(control.id),
                control.title,
                f"{framework.name} · {control.control_code}",
                f"/compliance/{control.id}",
                control.control_code,
            )

    if "scans:read" in grants and include("scan"):
        scan_query = (
            select(ScanJob, CloudAccount.name)
            .join(
                CloudAccount,
                (CloudAccount.id == ScanJob.cloud_account_id)
                & (CloudAccount.organization_id == ScanJob.organization_id),
            )
            .where(
                ScanJob.organization_id == org_id,
                or_(
                    cast(ScanJob.id, String).ilike(pattern),
                    CloudAccount.name.ilike(pattern),
                    ScanJob.status.ilike(pattern),
                ),
            )
        )
        scan_rows = session.execute(
            scan_query.order_by(ScanJob.created_at.desc()).limit(MAX_CANDIDATES_PER_TYPE)
        ).all()
        for scan, account_name in scan_rows:
            append(
                "scan",
                str(scan.id),
                account_name or "Cloud account",
                f"{scan.status} · {scan.progress_completed}/{scan.progress_total} resources",
                f"/scans/{scan.id}",
                scan.status,
            )

    if "users:read" in grants and include("user"):
        user_rows = session.execute(
            select(User, Membership)
            .join(Membership, Membership.user_id == User.id)
            .where(
                Membership.organization_id == org_id,
                or_(
                    User.email.ilike(pattern),
                    User.display_name.ilike(pattern),
                    cast(User.id, String).ilike(pattern),
                ),
            )
            .order_by(User.display_name)
            .limit(MAX_CANDIDATES_PER_TYPE)
        ).all()
        for user, membership in user_rows:
            state = "active" if membership.is_active and user.is_active else "inactive"
            append(
                "user",
                str(user.id),
                user.display_name or user.email,
                f"{user.email} · {state}",
                f"/administration/users/{user.id}",
                user.email,
            )

    if "teams:read" in grants and include("team"):
        team_rows = session.scalars(
            select(Team)
            .where(
                Team.organization_id == org_id,
                or_(
                    Team.name.ilike(pattern),
                    Team.description.ilike(pattern),
                    cast(Team.id, String).ilike(pattern),
                ),
            )
            .order_by(Team.name)
            .limit(MAX_CANDIDATES_PER_TYPE)
        ).all()
        for team in team_rows:
            append(
                "team",
                str(team.id),
                team.name or "Organization team",
                team.description or "Organization team",
                f"/administration/teams/{team.id}",
                team.description or "",
            )

    if "reports:read" in grants and include("report"):
        report_rows = session.scalars(
            select(Report)
            .where(
                Report.organization_id == org_id,
                or_(
                    Report.name.ilike(pattern),
                    Report.report_type.ilike(pattern),
                    cast(Report.id, String).ilike(pattern),
                ),
            )
            .order_by(Report.created_at.desc())
            .limit(MAX_CANDIDATES_PER_TYPE)
        ).all()
        for report in report_rows:
            title = report.name
            append(
                "report",
                str(report.id),
                title,
                (
                    f"{report.report_type.replace('_', ' ')} · "
                    f"{report.status} · v{report.report_version}"
                ),
                f"/reports/{report.id}",
                report.report_type,
            )

    found.sort(key=lambda item: (-item.rank, item.type, item.title.casefold(), item.id))
    total = len(found)
    start = (page - 1) * page_size
    page_results = found[start : start + page_size]
    return SearchResponse(
        query=term,
        results=page_results,
        total=total,
        page=page,
        page_size=page_size,
        has_more=start + page_size < total,
    )
