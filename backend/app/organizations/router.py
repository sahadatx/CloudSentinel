"""Authenticated organization profile endpoints."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.core.config import get_settings
from app.core.domain_errors import NotFoundError
from app.core.models import (
    CloudAccount,
    CustomerScanJob,
    Membership,
    Organization,
    Report,
    ScanJob,
    RefreshSession,
    SamlIdentityProvider,
    ScimToken,
    Team,
    User,
    UserInvitation,
    TaskOutbox,
)
from app.operations.service import record_audit
from app.organizations.schemas import (
    OrganizationRead,
    OrganizationSecuritySettings,
    OrganizationSecuritySettingsUpdate,
    OrganizationRetentionSettings,
    OrganizationRetentionSettingsUpdate,
    OffboardingRequest,
    OrganizationSummary,
    OrganizationUpdate,
)

router = APIRouter(prefix="/organizations", tags=["organizations"])

SECURITY_SETTING_FIELDS = (
    "password_min_length",
    "session_ttl_days",
    "remembered_session_ttl_days",
    "max_concurrent_sessions",
)
RETENTION_UPDATE_PERMISSION = "organization:retention:update"


@router.get("/current", response_model=OrganizationRead)
def get_current_organization(
    principal: Annotated[Principal, Depends(require_permission("organizations:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Organization:
    """Return only the organization selected by the authenticated membership."""
    organization = session.get(Organization, principal.organization_id)
    if organization is None or not organization.is_active:
        raise NotFoundError("Organization")
    return organization


@router.patch("/current", response_model=OrganizationRead)
def update_current_organization(
    payload: OrganizationUpdate,
    principal: Annotated[Principal, Depends(require_permission("organizations:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Organization:
    """Update the active organization's display name without changing its tenant key."""
    organization = session.get(Organization, principal.organization_id)
    if organization is None or not organization.is_active:
        raise NotFoundError("Organization")
    changes = payload.model_dump(exclude_unset=True)
    before = {field: getattr(organization, field) for field in changes}
    for field, value in changes.items():
        setattr(organization, field, value.strip() if isinstance(value, str) else value)
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="organization.updated",
        resource_type="organization",
        resource_id=organization.id,
        details={
            "before": before,
            "after": {field: getattr(organization, field) for field in changes},
        },
    )
    session.commit()
    return organization


@router.post("/current/offboard", status_code=202)
def request_organization_offboarding(
    payload: OffboardingRequest,
    principal: Annotated[
        Principal, Depends(require_permission("organization:offboard"))
    ],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> dict[str, str]:
    """Disable the tenant immediately and schedule deletion after its audit retention."""
    organization = session.get(Organization, principal.organization_id)
    if organization is None:
        raise NotFoundError("Organization")
    if payload.confirm_slug != organization.slug:
        from app.core.domain_errors import InvalidOperationError

        raise InvalidOperationError("Type the exact organization slug to confirm offboarding.")
    if organization.offboarding_at is not None:
        return {
            "status": "offboarding_scheduled",
            "purge_after": organization.purge_after.isoformat()
            if organization.purge_after
            else "",
        }

    now = datetime.now(UTC)
    organization.is_active = False
    organization.offboarding_at = now
    organization.offboarding_requested_by = principal.user_id
    memberships = session.scalars(
        select(Membership).where(Membership.organization_id == principal.organization_id)
    ).all()
    for membership in memberships:
        membership.is_active = False
    sessions = session.scalars(
        select(RefreshSession).where(
            RefreshSession.organization_id == principal.organization_id,
            RefreshSession.revoked_at.is_(None),
        )
    ).all()
    for auth_session in sessions:
        auth_session.revoked_at = now
    invitations = session.scalars(
        select(UserInvitation).where(
            UserInvitation.organization_id == principal.organization_id,
            UserInvitation.revoked_at.is_(None),
        )
    ).all()
    for invitation in invitations:
        invitation.revoked_at = now
    scim_tokens = session.scalars(
        select(ScimToken).where(
            ScimToken.organization_id == principal.organization_id,
            ScimToken.revoked_at.is_(None),
        )
    ).all()
    for token in scim_tokens:
        token.revoked_at = now
    saml = session.scalar(
        select(SamlIdentityProvider).where(
            SamlIdentityProvider.organization_id == principal.organization_id
        )
    )
    if saml is not None:
        saml.is_active = False
        saml.enforce_sso = False
    scans = session.scalars(
        select(CustomerScanJob)
        .where(
            CustomerScanJob.organization_id == principal.organization_id,
            CustomerScanJob.status.in_(("queued", "running", "cancelling")),
        )
        .with_for_update()
    ).all()
    for scan in scans:
        if scan.status == "queued":
            scan.status = "cancelled"
            scan.finished_at = now
        else:
            scan.status = "cancelling"
    scans_to_cancel = session.scalars(
        select(ScanJob)
        .where(
            ScanJob.organization_id == principal.organization_id,
            ScanJob.status.in_(("queued", "running", "cancelling")),
        )
        .with_for_update()
    ).all()
    for scan in scans_to_cancel:
        if scan.status == "queued":
            scan.status = "cancelled"
            scan.finished_at = now
        else:
            scan.status = "cancelling"
            scan.cancel_requested_at = now
    for report in session.scalars(
        select(Report)
        .where(
            Report.organization_id == principal.organization_id,
            Report.status.in_(("QUEUED", "GENERATING")),
        )
        .with_for_update()
    ).all():
        report.status = "CANCELLED"
        report.error_code = "organization_offboarding"
        report.error_message = "Report generation was cancelled because this organization is offboarding."
        report.updated_at = now
    pending_scan_events = session.scalars(
        select(TaskOutbox).where(
            TaskOutbox.organization_id == principal.organization_id,
            TaskOutbox.status.in_(("pending", "dispatching")),
        )
    ).all()
    for event in pending_scan_events:
        event.status = "dead"
        event.dead_lettered_at = now
        event.claimed_until = None
        event.claim_token = None
        event.last_error_code = "organization_offboarding"
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="organization.offboarding_requested",
        resource_type="organization",
        resource_id=organization.id,
        details={
            "audit_retention_days": organization.audit_retention_days,
            "customer_scan_jobs_cancelled": len(scans),
            "scan_jobs_cancelled": len(scans_to_cancel),
            "saml_disabled": saml is not None,
        },
    )
    session.flush()
    from app.retention import retention_deadline

    retention_deadline_with_grace = max(
        now + timedelta(days=30), retention_deadline(session, principal.organization_id)
    )
    organization.purge_after = retention_deadline_with_grace + timedelta(
        days=get_settings().offboarding_backup_retention_days
    )
    session.commit()
    return {
        "status": "offboarding_scheduled",
        "purge_after": organization.purge_after.isoformat(),
    }


@router.get("/current/settings/retention", response_model=OrganizationRetentionSettings)
def get_current_retention_settings(
    principal: Annotated[Principal, Depends(require_permission("organizations:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Organization:
    organization = session.get(Organization, principal.organization_id)
    if organization is None or not organization.is_active:
        raise NotFoundError("Organization")
    return organization


@router.patch("/current/settings/retention", response_model=OrganizationRetentionSettings)
def update_current_retention_settings(
    payload: OrganizationRetentionSettingsUpdate,
    principal: Annotated[Principal, Depends(require_permission(RETENTION_UPDATE_PERMISSION))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Organization:
    organization = session.get(Organization, principal.organization_id)
    if organization is None or not organization.is_active:
        raise NotFoundError("Organization")
    before = organization.audit_retention_days
    organization.audit_retention_days = payload.audit_retention_days
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="organization.retention_policy_updated",
        resource_type="organization",
        resource_id=organization.id,
        details={"before_days": before, "after_days": payload.audit_retention_days},
    )
    session.commit()
    return organization


@router.get(
    "/current/settings/security",
    response_model=OrganizationSecuritySettings,
)
def get_current_security_settings(
    principal: Annotated[Principal, Depends(require_permission("security_settings:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Organization:
    """Return the active tenant's persisted password and session policy."""
    organization = session.get(Organization, principal.organization_id)
    if organization is None or not organization.is_active:
        raise NotFoundError("Organization")
    return organization


@router.patch(
    "/current/settings/security",
    response_model=OrganizationSecuritySettings,
)
def update_current_security_settings(
    payload: OrganizationSecuritySettingsUpdate,
    principal: Annotated[Principal, Depends(require_permission("security_settings:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Organization:
    """Update and audit security policy used by authentication flows."""
    organization = session.get(Organization, principal.organization_id)
    if organization is None or not organization.is_active:
        raise NotFoundError("Organization")
    changes = payload.model_dump(exclude_unset=True)
    resulting = {field: getattr(organization, field) for field in SECURITY_SETTING_FIELDS}
    resulting.update(changes)
    if resulting["remembered_session_ttl_days"] < resulting["session_ttl_days"]:
        from app.core.domain_errors import InvalidOperationError

        raise InvalidOperationError(
            "Remembered session lifetime cannot be shorter than the standard lifetime."
        )
    before = {field: getattr(organization, field) for field in changes}
    for field, value in changes.items():
        setattr(organization, field, value)
    after = {field: getattr(organization, field) for field in changes}
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="organization.security_settings_updated",
        resource_type="organization",
        resource_id=organization.id,
        details={"before": before, "after": after},
    )
    session.commit()
    return organization


@router.get("/current/summary", response_model=OrganizationSummary)
def get_current_organization_summary(
    principal: Annotated[Principal, Depends(require_permission("organizations:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> OrganizationSummary:
    """Return counts derived from the active organization only."""
    organization_id = principal.organization_id
    total_users = (
        session.scalar(
            select(func.count(Membership.id)).where(Membership.organization_id == organization_id)
        )
        or 0
    )
    active_users = (
        session.scalar(
            select(func.count(Membership.id))
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.organization_id == organization_id,
                Membership.is_active.is_(True),
                Membership.is_locked.is_(False),
                User.is_active.is_(True),
            )
        )
        or 0
    )
    locked_users = (
        session.scalar(
            select(func.count(Membership.id))
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.organization_id == organization_id,
                Membership.is_locked.is_(True),
                Membership.is_active.is_(True),
                User.is_active.is_(True),
            )
        )
        or 0
    )
    pending_invitations = (
        session.scalar(
            select(func.count(UserInvitation.id)).where(
                UserInvitation.organization_id == organization_id,
                UserInvitation.accepted_at.is_(None),
                UserInvitation.revoked_at.is_(None),
                UserInvitation.expires_at > func.now(),
            )
        )
        or 0
    )
    teams = (
        session.scalar(
            select(func.count(Team.id)).where(
                Team.organization_id == organization_id,
                Team.is_active.is_(True),
            )
        )
        or 0
    )
    cloud_accounts = (
        session.scalar(
            select(func.count(CloudAccount.id)).where(
                CloudAccount.organization_id == organization_id,
                CloudAccount.connection_status != "disabled",
            )
        )
        or 0
    )
    return OrganizationSummary(
        total_users=total_users,
        active_users=active_users,
        locked_users=locked_users,
        pending_invitations=pending_invitations,
        teams=teams,
        cloud_accounts=cloud_accounts,
    )
