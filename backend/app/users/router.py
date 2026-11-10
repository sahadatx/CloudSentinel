"""Tenant-scoped member, access, session, invitation, and activity endpoints."""

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, Response, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.auth.dependencies import (
    Principal,
    get_current_principal,
    get_tenant_session,
    require_permission,
)
from app.auth.recovery import RecoveryDelivery, send_recovery_email
from app.core.config import Settings
from app.core.domain_errors import ConflictError, NotFoundError, ServiceUnavailableError
from app.core.models import (
    AuditEvent,
    Membership,
    Organization,
    Permission,
    RefreshSession,
    Role,
    RolePermission,
    Team,
    TeamMembership,
    User,
    UserInvitation,
    utc_now,
)
from app.operations.service import record_audit
from app.users.email import send_invitation_email
from app.users.schemas import (
    InvitationCreate,
    InvitationCreated,
    RoleRead,
    RoleUpdate,
    UserActivityList,
    UserActivityRead,
    UserDetail,
    UserList,
    UserLockRequest,
    UserMembershipRead,
    UserSessionList,
    UserSessionRead,
    UserSummary,
    UserUpdate,
)
from app.users.service import (
    create_invitation,
    create_user_password_reset,
    set_membership_active,
    update_membership_role,
)

router = APIRouter(prefix="/users", tags=["users"])
ADMIN_ROLES = ("SUPER_ADMIN", "ORG_ADMIN", "SECURITY_ADMIN")


@router.get("/me", response_model=UserDetail)
def get_my_profile(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> UserDetail:
    """Return the authenticated user's profile without requiring user admin grants."""
    return _user_detail(session, principal, principal.user_id)


@router.patch("/me", response_model=UserDetail)
def update_my_profile(
    payload: UserUpdate,
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> UserDetail:
    display_name = payload.display_name.strip()
    if not display_name:
        raise ConflictError("Display name cannot be blank.")
    user = session.get(User, principal.user_id)
    if user is None:
        raise NotFoundError("User")
    user.display_name = display_name
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="user.profile_updated",
        resource_type="user",
        resource_id=principal.user_id,
        details={"changed_fields": ["display_name"]},
    )
    session.commit()
    session.refresh(user)
    return _user_detail(session, principal, principal.user_id)


@router.get("/summary", response_model=UserSummary)
def user_summary(
    principal: Annotated[Principal, Depends(require_permission("users:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> UserSummary:
    organization_id = principal.organization_id
    total = (
        session.scalar(
            select(func.count(Membership.id)).where(Membership.organization_id == organization_id)
        )
        or 0
    )
    active = (
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
    locked = (
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
    disabled = max(total - active - locked, 0)
    pending = (
        session.scalar(
            select(func.count(UserInvitation.id)).where(
                UserInvitation.organization_id == organization_id,
                UserInvitation.accepted_at.is_(None),
                UserInvitation.revoked_at.is_(None),
                UserInvitation.expires_at > utc_now(),
            )
        )
        or 0
    )
    return UserSummary(
        total=total, active=active, disabled=disabled, locked=locked, pending=pending
    )


@router.get("/roles", response_model=list[RoleRead])
def list_roles(
    _principal: Annotated[Principal, Depends(require_permission("users:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[RoleRead]:
    rows = (
        session.execute(
            select(Role.code, Role.description, Permission.code)
            .select_from(Role)
            .outerjoin(RolePermission, RolePermission.role_id == Role.id)
            .outerjoin(Permission, Permission.id == RolePermission.permission_id)
            .order_by(Role.code, Permission.code)
        )
        .tuples()
        .all()
    )
    role_map: dict[str, RoleRead] = {}
    for role_code, description, permission_code in rows:
        role = role_map.setdefault(
            role_code,
            RoleRead(code=role_code, description=description, permissions=[]),
        )
        if permission_code is not None:
            role.permissions.append(permission_code)
    return list(role_map.values())


@router.get("", response_model=UserList)
def list_users(
    principal: Annotated[Principal, Depends(require_permission("users:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    search: Annotated[str | None, Query(max_length=320)] = None,
    role: Annotated[str | None, Query(max_length=40)] = None,
    user_id: UUID | None = None,
    state: Annotated[Literal["active", "disabled", "locked", "all"], Query(alias="status")] = "all",
    team_id: UUID | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> UserList:
    filters = [Membership.organization_id == principal.organization_id]
    if search and search.strip():
        term = f"%{search.strip()}%"
        filters.append(or_(User.email.ilike(term), User.display_name.ilike(term)))
    if role:
        filters.append(Role.code == role)
    if user_id is not None:
        filters.append(Membership.user_id == user_id)
    if date_from is not None:
        filters.append(Membership.created_at >= date_from)
    if date_to is not None:
        filters.append(Membership.created_at <= date_to)
    if state == "active":
        filters.extend(
            [
                User.is_active.is_(True),
                Membership.is_active.is_(True),
                Membership.is_locked.is_(False),
            ]
        )
    elif state == "disabled":
        filters.append(or_(User.is_active.is_(False), Membership.is_active.is_(False)))
    elif state == "locked":
        filters.append(Membership.is_locked.is_(True))
    if team_id is not None:
        filters.append(
            Membership.user_id.in_(
                select(TeamMembership.user_id).where(
                    TeamMembership.organization_id == principal.organization_id,
                    TeamMembership.team_id == team_id,
                )
            )
        )
    total = (
        session.scalar(
            select(func.count(Membership.id))
            .join(User, User.id == Membership.user_id)
            .join(Role, Role.id == Membership.role_id)
            .where(*filters)
        )
        or 0
    )
    rows = [
        row._tuple()
        for row in session.execute(
            select(User, Membership, Role)
            .join(Membership, Membership.user_id == User.id)
            .join(Role, Role.id == Membership.role_id)
            .where(*filters)
            .order_by(User.display_name, User.email)
            .offset(offset)
            .limit(limit)
        ).all()
    ]
    items = _membership_reads(session, principal.organization_id, rows)
    return UserList(items=items, total=total, offset=offset, limit=limit)


@router.post("/invitations", response_model=InvitationCreated, status_code=status.HTTP_201_CREATED)
def invite_user(
    payload: InvitationCreate,
    request: Request,
    principal: Annotated[Principal, Depends(require_permission("users:invite"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> InvitationCreated:
    """Create a tenant-bound invitation and email its one-time acceptance link."""
    invitation, token = create_invitation(
        session,
        organization_id=principal.organization_id,
        invited_by_user_id=principal.user_id,
        email=str(payload.email).strip().lower(),
        display_name=payload.display_name.strip(),
        role_code=payload.role_code,
    )
    settings = cast(Settings, request.app.state.settings)
    organization = session.get(Organization, principal.organization_id)
    email_sent = send_invitation_email(
        settings,
        recipient=invitation.email,
        display_name=invitation.display_name,
        organization_name=organization.name if organization else "your organization",
        organization_slug=organization.slug if organization else "",
        role_code=payload.role_code,
        token=token,
    )
    return InvitationCreated(
        email=invitation.email,
        organization_id=invitation.organization_id,
        role_code=payload.role_code,
        token=token,
        invitation_url=(
            f"{settings.frontend_base_url.rstrip('/')}/accept-invitation?token={token}"
        ),
        expires_at=invitation.expires_at,
        email_delivery="sent" if email_sent else "failed",
    )


@router.get("/{user_id}", response_model=UserDetail)
def get_user(
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("users:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> UserDetail:
    return _user_detail(session, principal, user_id)


def _user_detail(session: Session, principal: Principal, user_id: UUID) -> UserDetail:
    user, membership, role = _get_user_membership(session, principal.organization_id, user_id)
    permissions = session.scalars(
        select(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role.id)
        .order_by(Permission.code)
    ).all()
    base = _membership_reads(session, principal.organization_id, [(user, membership, role)])[0]
    active_sessions = (
        session.scalar(
            select(func.count(RefreshSession.id)).where(
                RefreshSession.organization_id == principal.organization_id,
                RefreshSession.user_id == user_id,
                RefreshSession.revoked_at.is_(None),
                RefreshSession.expires_at > utc_now(),
            )
        )
        or 0
    )
    organization = session.get(Organization, principal.organization_id)
    if organization is None:
        raise NotFoundError("Organization")
    return UserDetail(
        **base.model_dump(),
        organization_id=organization.id,
        organization_name=organization.name,
        permissions=list(permissions),
        active_sessions=active_sessions,
        updated_at=user.updated_at,
    )


@router.patch("/{user_id}", response_model=UserDetail)
def update_user(
    user_id: UUID,
    payload: UserUpdate,
    principal: Annotated[Principal, Depends(require_permission("users:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> UserDetail:
    user, _membership, _role = _get_user_membership(session, principal.organization_id, user_id)
    display_name = payload.display_name.strip()
    if not display_name:
        raise ConflictError("Display name cannot be blank.")
    user.display_name = display_name
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="user.updated",
        resource_type="user",
        resource_id=user_id,
        details={"changed_fields": ["display_name"]},
    )
    session.commit()
    session.refresh(user)
    return get_user(user_id, principal, session)


@router.patch("/{user_id}/role", status_code=status.HTTP_204_NO_CONTENT)
def change_user_role(
    user_id: UUID,
    payload: RoleUpdate,
    principal: Annotated[Principal, Depends(require_permission("users:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> None:
    _user, membership, current_role = _get_user_membership(
        session, principal.organization_id, user_id
    )
    if current_role.code in ADMIN_ROLES and payload.role_code not in ADMIN_ROLES:
        _ensure_another_active_admin(session, principal.organization_id, user_id)
    update_membership_role(
        session,
        organization_id=principal.organization_id,
        user_id=user_id,
        role_code=payload.role_code,
        actor_user_id=principal.user_id,
    )


@router.post("/{user_id}/enable", status_code=status.HTTP_204_NO_CONTENT)
def enable_user(
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("users:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    set_membership_active(
        session,
        organization_id=principal.organization_id,
        user_id=user_id,
        is_active=True,
        actor_user_id=principal.user_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{user_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable_user(
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("users:disable"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    if user_id == principal.user_id:
        raise ConflictError("You cannot disable your own organization membership.")
    _user, membership, role = _get_user_membership(session, principal.organization_id, user_id)
    if membership.is_active and role.code in ADMIN_ROLES:
        _ensure_another_active_admin(session, principal.organization_id, user_id)
    membership.is_active = False
    session.execute(
        update(RefreshSession)
        .where(
            RefreshSession.organization_id == principal.organization_id,
            RefreshSession.user_id == user_id,
            RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=utc_now())
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="user.disabled",
        resource_type="membership",
        resource_id=membership.id,
        details={"is_active": False},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def disable_user_legacy(
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("users:disable"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    """Compatibility alias for disabling a membership; accounts are not deleted."""
    return disable_user(user_id, principal, session)


@router.post("/{user_id}/lock", status_code=status.HTTP_204_NO_CONTENT)
def lock_user(
    user_id: UUID,
    payload: UserLockRequest,
    principal: Annotated[Principal, Depends(require_permission("users:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    if user_id == principal.user_id:
        raise ConflictError("You cannot lock your own organization membership.")
    _user, membership, role = _get_user_membership(session, principal.organization_id, user_id)
    if role.code in ADMIN_ROLES and not membership.is_locked:
        _ensure_another_active_admin(session, principal.organization_id, user_id)
    membership.is_locked = True
    membership.locked_at = utc_now()
    membership.lock_reason = payload.reason.strip() if payload.reason else None
    session.execute(
        update(RefreshSession)
        .where(
            RefreshSession.organization_id == principal.organization_id,
            RefreshSession.user_id == user_id,
            RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=utc_now())
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="user.locked",
        resource_type="user",
        resource_id=user_id,
        details={"reason": membership.lock_reason or ""},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{user_id}/unlock", status_code=status.HTTP_204_NO_CONTENT)
def unlock_user(
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("users:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    _user, membership, _role = _get_user_membership(session, principal.organization_id, user_id)
    if membership.is_locked:
        membership.is_locked = False
        membership.locked_at = None
        membership.lock_reason = None
        record_audit(
            session,
            organization_id=principal.organization_id,
            actor_user_id=principal.user_id,
            action="user.unlocked",
            resource_type="user",
            resource_id=user_id,
        )
        session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{user_id}/force-password-change", status_code=status.HTTP_204_NO_CONTENT)
def require_password_change(
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("users:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    user, _membership, _role = _get_user_membership(session, principal.organization_id, user_id)
    user.force_password_change = True
    session.execute(
        update(RefreshSession)
        .where(RefreshSession.user_id == user_id, RefreshSession.revoked_at.is_(None))
        .values(revoked_at=utc_now())
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="user.force_password_change",
        resource_type="user",
        resource_id=user_id,
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{user_id}/password-reset", status_code=status.HTTP_202_ACCEPTED)
def request_password_reset(
    user_id: UUID,
    background_tasks: BackgroundTasks,
    request: Request,
    principal: Annotated[Principal, Depends(require_permission("users:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> dict[str, str]:
    user, _membership, _role = _get_user_membership(session, principal.organization_id, user_id)
    settings = cast(Settings, request.app.state.settings)
    if not settings.smtp_host or not settings.smtp_from_email:
        raise ServiceUnavailableError("Password reset email is not configured.")
    token = create_user_password_reset(
        session, user, ttl_minutes=settings.password_reset_token_ttl_minutes
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="user.password_reset_requested",
        resource_type="user",
        resource_id=user_id,
    )
    session.commit()
    background_tasks.add_task(
        send_recovery_email, settings, RecoveryDelivery(recipient=user.email, token=token)
    )
    return {"status": "password_reset_email_queued"}


@router.get("/{user_id}/sessions", response_model=UserSessionList)
def list_user_sessions(
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("users:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> UserSessionList:
    _get_user_membership(session, principal.organization_id, user_id)
    filters = [
        RefreshSession.organization_id == principal.organization_id,
        RefreshSession.user_id == user_id,
    ]
    total = session.scalar(select(func.count(RefreshSession.id)).where(*filters)) or 0
    rows = session.scalars(
        select(RefreshSession)
        .where(*filters)
        .order_by(RefreshSession.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return UserSessionList(
        items=[
            UserSessionRead(
                id=row.id,
                created_at=row.created_at,
                last_used_at=row.last_used_at,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
                ip_address=row.ip_address,
                user_agent=row.user_agent,
                current=row.id == principal.session_id,
            )
            for row in rows
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.delete("/{user_id}/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_user_session(
    user_id: UUID,
    session_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("users:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    _get_user_membership(session, principal.organization_id, user_id)
    auth_session = session.scalar(
        select(RefreshSession).where(
            RefreshSession.id == session_id,
            RefreshSession.organization_id == principal.organization_id,
            RefreshSession.user_id == user_id,
            RefreshSession.revoked_at.is_(None),
        )
    )
    if auth_session is None:
        raise NotFoundError("User session")
    auth_session.revoked_at = utc_now()
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="user.session_revoked",
        resource_type="auth_session",
        resource_id=session_id,
        details={"user_id": str(user_id)},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{user_id}/sessions/revoke-all", status_code=status.HTTP_204_NO_CONTENT)
def revoke_user_sessions(
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("users:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    _get_user_membership(session, principal.organization_id, user_id)
    session.execute(
        update(RefreshSession)
        .where(
            RefreshSession.organization_id == principal.organization_id,
            RefreshSession.user_id == user_id,
            RefreshSession.id != principal.session_id,
            RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=utc_now())
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="user.sessions_revoked",
        resource_type="user",
        resource_id=user_id,
        details={"scope": "other_sessions"},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{user_id}/activity", response_model=UserActivityList)
def list_user_activity(
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("audit:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> UserActivityList:
    _get_user_membership(session, principal.organization_id, user_id)
    filters = [
        AuditEvent.organization_id == principal.organization_id,
        or_(
            AuditEvent.actor_user_id == user_id,
            (AuditEvent.resource_type == "user") & (AuditEvent.resource_id == str(user_id)),
        ),
    ]
    total = session.scalar(select(func.count(AuditEvent.id)).where(*filters)) or 0
    rows = session.scalars(
        select(AuditEvent)
        .where(*filters)
        .order_by(AuditEvent.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return UserActivityList(
        items=[
            UserActivityRead(
                id=row.id,
                actor_user_id=row.actor_user_id,
                action=row.action,
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                details=row.details,
                created_at=row.created_at,
            )
            for row in rows
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


def _get_user_membership(
    session: Session, organization_id: UUID, user_id: UUID
) -> tuple[User, Membership, Role]:
    row = (
        session.execute(
            select(User, Membership, Role)
            .join(Membership, Membership.user_id == User.id)
            .join(Role, Role.id == Membership.role_id)
            .where(Membership.organization_id == organization_id, User.id == user_id)
        )
        .tuples()
        .first()
    )
    if row is None:
        raise NotFoundError("Organization user")
    return row


def _membership_reads(
    session: Session,
    organization_id: UUID,
    rows: Sequence[tuple[User, Membership, Role]],
) -> list[UserMembershipRead]:
    if not rows:
        return []
    user_ids = [user.id for user, _membership, _role in rows]
    last_login_rows = session.execute(
        select(RefreshSession.user_id, func.max(RefreshSession.created_at))
        .where(
            RefreshSession.organization_id == organization_id,
            RefreshSession.user_id.in_(user_ids),
        )
        .group_by(RefreshSession.user_id)
    ).all()
    last_logins = {user_id: created for user_id, created in last_login_rows}
    team_rows = session.execute(
        select(TeamMembership.user_id, Team.name)
        .join(Team, Team.id == TeamMembership.team_id)
        .where(
            TeamMembership.organization_id == organization_id,
            TeamMembership.user_id.in_(user_ids),
            Team.is_active.is_(True),
        )
        .order_by(Team.name)
    ).all()
    teams_by_user: dict[UUID, list[str]] = {}
    for user_id, team_name in team_rows:
        teams_by_user.setdefault(user_id, []).append(team_name)
    return [
        UserMembershipRead(
            user_id=user.id,
            email=user.email,
            display_name=user.display_name,
            role_code=role.code,
            is_active=user.is_active and membership.is_active,
            is_locked=membership.is_locked,
            force_password_change=user.force_password_change,
            created_at=membership.created_at,
            last_login_at=last_logins.get(user.id),
            team_names=teams_by_user.get(user.id, []),
        )
        for user, membership, role in rows
    ]


def _ensure_another_active_admin(
    session: Session, organization_id: UUID, excluded_user_id: UUID
) -> None:
    remaining = (
        session.scalar(
            select(func.count(Membership.id))
            .join(Role, Role.id == Membership.role_id)
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.organization_id == organization_id,
                Membership.user_id != excluded_user_id,
                Membership.is_active.is_(True),
                Membership.is_locked.is_(False),
                User.is_active.is_(True),
                Role.code.in_(ADMIN_ROLES),
            )
        )
        or 0
    )
    if remaining < 1:
        raise ConflictError("The last active organization administrator cannot be removed.")
