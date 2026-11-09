"""Database-backed authentication and refresh-session operations."""

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.auth.mfa import verify_and_consume_mfa_code
from app.auth.schemas import AuthenticatedUser, TokenResponse
from app.auth.security import (
    create_access_token,
    create_refresh_token,
    digest_refresh_token,
    hash_password,
    verify_password,
)
from app.core.config import Settings
from app.core.models import (
    AuditEvent,
    Membership,
    Organization,
    PasswordResetToken,
    Permission,
    RefreshSession,
    RefreshToken,
    Role,
    RolePermission,
    SamlIdentityProvider,
    User,
    UserMfa,
)


class AuthenticationFailure(Exception):
    """Raised for all credential/membership failures with one public response."""


class MultiFactorChallengeRequired(Exception):
    """Raised after valid password verification when the user needs an MFA factor."""


def authenticate(
    session: Session,
    settings: Settings,
    *,
    email: str,
    organization_slug: str | None = None,
    password: str,
    mfa_code: str | None = None,
    remember_session: bool = False,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[TokenResponse, str, str]:
    """Verify one unambiguous membership and create a scoped revocable session."""
    identity_query = (
        select(User, Membership, Organization, Role)
        .join(Membership, Membership.user_id == User.id)
        .join(Organization, Organization.id == Membership.organization_id)
        .join(Role, Role.id == Membership.role_id)
        .where(
            User.email == email.lower(),
            User.is_active.is_(True),
            Membership.is_active.is_(True),
            Membership.is_locked.is_(False),
            Organization.is_active.is_(True),
        )
    )
    if organization_slug is not None:
        identity_query = identity_query.where(Organization.slug == organization_slug)
    # An email identifies a global user, not necessarily a single tenant. Never
    # infer an arbitrary organization when that identity has several valid memberships.
    rows = session.execute(identity_query.limit(2)).all()
    if len(rows) != 1:
        verify_password(password, "invalid-password-hash")
        raise AuthenticationFailure
    user, membership, organization, role = rows[0]
    enforced_sso = session.scalar(
        select(SamlIdentityProvider.id).where(
            SamlIdentityProvider.organization_id == organization.id,
            SamlIdentityProvider.is_active.is_(True),
            SamlIdentityProvider.enforce_sso.is_(True),
        )
    )
    if enforced_sso is not None:
        verify_password(password, user.password_hash)
        raise AuthenticationFailure
    if not verify_password(password, user.password_hash):
        raise AuthenticationFailure

    mfa_enrollment = session.scalar(
        select(UserMfa).where(UserMfa.user_id == user.id).with_for_update()
    )
    if mfa_enrollment is not None and mfa_enrollment.is_enabled:
        if not mfa_code:
            raise MultiFactorChallengeRequired
        if not verify_and_consume_mfa_code(session, settings, mfa_enrollment, mfa_code):
            raise AuthenticationFailure
    elif mfa_code:
        raise AuthenticationFailure

    user = session.scalar(select(User).where(User.id == user.id).with_for_update())
    if user is None or not user.is_active:
        raise AuthenticationFailure

    permissions = _permissions_for_role(session, role.id)
    now = datetime.now(UTC)
    ttl_days = (
        organization.remembered_session_ttl_days
        if remember_session
        else organization.session_ttl_days
    )
    active_sessions = session.scalars(
        select(RefreshSession)
        .where(
            RefreshSession.organization_id == organization.id,
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
            RefreshSession.expires_at > now,
        )
        .order_by(RefreshSession.created_at.asc())
        .with_for_update()
    ).all()
    excess = len(active_sessions) - organization.max_concurrent_sessions + 1
    if excess > 0:
        for old_session in active_sessions[:excess]:
            old_session.revoked_at = now
        session.add(
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                action="auth.session_limit_enforced",
                resource_type="user",
                resource_id=str(user.id),
                details={"revoked_sessions": excess},
            )
        )
    session_id = uuid4()
    expires_at = now + timedelta(days=ttl_days)
    auth_session = RefreshSession(
        id=session_id,
        organization_id=organization.id,
        user_id=user.id,
        membership_id=membership.id,
        expires_at=expires_at,
        remember_session=remember_session,
        ip_address=ip_address,
        user_agent=user_agent[:512] if user_agent else None,
    )
    session.add(auth_session)
    refresh_token, csrf_token = _rotate_refresh_token(session, auth_session, expires_at)
    access = create_access_token(
        settings,
        user_id=user.id,
        membership_id=membership.id,
        organization_id=organization.id,
        role_code=role.code,
        permissions=permissions,
        session_id=session_id,
        now=now,
    )
    session.commit()
    return (
        TokenResponse(
            access_token=access,
            expires_in=settings.access_token_ttl_minutes * 60,
            remember_session=auth_session.remember_session,
            refresh_expires_in=ttl_days * 24 * 60 * 60,
            user=_user_response(user, organization.id, membership.id, role.code, permissions),
        ),
        refresh_token,
        csrf_token,
    )


def issue_federated_session(
    session: Session,
    settings: Settings,
    *,
    user_id: UUID,
    membership_id: UUID,
    organization_id: UUID,
    ip_address: str | None,
    user_agent: str | None,
) -> tuple[TokenResponse, str, str]:
    """Create a regular revocable app session after an external SAML assertion is verified."""
    row = session.execute(
        select(User, Membership, Organization, Role)
        .join(Membership, Membership.user_id == User.id)
        .join(Organization, Organization.id == Membership.organization_id)
        .join(Role, Role.id == Membership.role_id)
        .where(
            User.id == user_id,
            Membership.id == membership_id,
            Membership.organization_id == organization_id,
            Membership.user_id == user_id,
            User.is_active.is_(True),
            Membership.is_active.is_(True),
            Membership.is_locked.is_(False),
            Organization.is_active.is_(True),
        )
        .with_for_update()
    ).first()
    if row is None:
        raise AuthenticationFailure
    user, membership, organization, role = row
    now = datetime.now(UTC)
    active_sessions = session.scalars(
        select(RefreshSession)
        .where(
            RefreshSession.organization_id == organization.id,
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
            RefreshSession.expires_at > now,
        )
        .order_by(RefreshSession.created_at.asc())
        .with_for_update()
    ).all()
    excess = len(active_sessions) - organization.max_concurrent_sessions + 1
    if excess > 0:
        for old_session in active_sessions[:excess]:
            old_session.revoked_at = now
    session_id = uuid4()
    expires_at = now + timedelta(days=organization.session_ttl_days)
    auth_session = RefreshSession(
        id=session_id,
        organization_id=organization.id,
        user_id=user.id,
        membership_id=membership.id,
        expires_at=expires_at,
        remember_session=False,
        ip_address=ip_address,
        user_agent=user_agent[:512] if user_agent else None,
    )
    session.add(auth_session)
    refresh_token, csrf_token = _rotate_refresh_token(session, auth_session, expires_at)
    permissions = _permissions_for_role(session, role.id)
    access = create_access_token(
        settings,
        user_id=user.id,
        membership_id=membership.id,
        organization_id=organization.id,
        role_code=role.code,
        permissions=permissions,
        session_id=session_id,
        now=now,
    )
    session.commit()
    return (
        TokenResponse(
            access_token=access,
            expires_in=settings.access_token_ttl_minutes * 60,
            remember_session=False,
            refresh_expires_in=organization.session_ttl_days * 24 * 60 * 60,
            user=_user_response(user, organization.id, membership.id, role.code, permissions),
        ),
        refresh_token,
        csrf_token,
    )


def rotate_session(
    session: Session,
    settings: Settings,
    *,
    refresh_token: str,
) -> tuple[TokenResponse, str, str]:
    """Consume a refresh token once and issue a replacement within its session."""
    digest = digest_refresh_token(refresh_token)
    token_row = session.scalar(
        select(RefreshToken).where(RefreshToken.token_digest == digest).with_for_update()
    )
    now = datetime.now(UTC)
    if token_row is None:
        raise AuthenticationFailure
    auth_session = session.scalar(
        select(RefreshSession).where(RefreshSession.id == token_row.session_id).with_for_update()
    )
    if auth_session is None:
        raise AuthenticationFailure
    if token_row.consumed_at is not None:
        auth_session.revoked_at = now
        session.commit()
        raise AuthenticationFailure
    if (
        auth_session.revoked_at is not None
        or _as_utc(token_row.expires_at) <= now
        or _as_utc(auth_session.expires_at) <= now
    ):
        raise AuthenticationFailure

    membership = session.get(Membership, auth_session.membership_id)
    user = session.get(User, auth_session.user_id)
    if (
        membership is None
        or not membership.is_active
        or membership.is_locked
        or membership.organization_id != auth_session.organization_id
        or membership.user_id != auth_session.user_id
        or user is None
        or not user.is_active
    ):
        auth_session.revoked_at = now
        session.commit()
        raise AuthenticationFailure
    organization = session.get(Organization, membership.organization_id)
    role = session.get(Role, membership.role_id)
    if organization is None or not organization.is_active or role is None:
        auth_session.revoked_at = now
        session.commit()
        raise AuthenticationFailure

    token_row.consumed_at = now
    auth_session.last_used_at = now
    permissions = _permissions_for_role(session, role.id)
    replacement, csrf_token = _rotate_refresh_token(session, auth_session, auth_session.expires_at)
    access = create_access_token(
        settings,
        user_id=user.id,
        membership_id=membership.id,
        organization_id=organization.id,
        role_code=role.code,
        permissions=permissions,
        session_id=auth_session.id,
        now=now,
    )
    session.commit()
    return (
        TokenResponse(
            access_token=access,
            expires_in=settings.access_token_ttl_minutes * 60,
            remember_session=auth_session.remember_session,
            refresh_expires_in=max(
                0, int((_as_utc(auth_session.expires_at) - now).total_seconds())
            ),
            user=_user_response(user, organization.id, membership.id, role.code, permissions),
        ),
        replacement,
        csrf_token,
    )


def revoke_refresh_session(session: Session, refresh_token: str) -> None:
    """Revoke the refresh-token session addressed by the presented cookie."""
    token_row = session.scalar(
        select(RefreshToken).where(RefreshToken.token_digest == digest_refresh_token(refresh_token))
    )
    if token_row is None:
        return
    auth_session = session.get(RefreshSession, token_row.session_id)
    if auth_session is not None and auth_session.revoked_at is None:
        auth_session.revoked_at = datetime.now(UTC)
        session.commit()


def validate_password_reset_token(session: Session, token: str) -> bool:
    """Return whether an opaque reset token exists and is live and unused."""
    now = datetime.now(UTC)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = session.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_digest == digest)
    )
    return bool(
        row is not None
        and row.used_at is None
        and row.revoked_at is None
        and _as_utc(row.expires_at) > now
    )


def password_minimum_for_user(session: Session, user_id: UUID) -> int:
    """Use the strictest active-tenant password minimum for this global identity."""
    values = session.scalars(
        select(Organization.password_min_length)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(
            Membership.user_id == user_id,
            Membership.is_active.is_(True),
            Organization.is_active.is_(True),
        )
    ).all()
    return max(values, default=12)


def password_minimum_for_reset_token(session: Session, token: str) -> int:
    """Return password policy metadata only after a valid reset token is verified."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    token_row = session.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_digest == digest)
    )
    if token_row is None or not validate_password_reset_token(session, token):
        raise AuthenticationFailure
    return password_minimum_for_user(session, token_row.user_id)


def validate_password_minimum(password: str, minimum: int) -> None:
    """Reject passwords that do not meet the active canonical tenant policy."""
    if len(password) < minimum:
        raise ValueError(f"Password must contain at least {minimum} characters.")


def reset_password(session: Session, token: str, new_password: str) -> None:
    """Consume one live recovery token, update the password, and revoke all sessions."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(UTC)
    token_identity = session.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_digest == digest)
    )
    if token_identity is None:
        raise AuthenticationFailure
    # Lock the user first to serialize simultaneous resets issued for different tokens.
    user = session.scalar(select(User).where(User.id == token_identity.user_id).with_for_update())
    if user is None or not user.is_active:
        raise AuthenticationFailure
    reset_row = session.scalar(
        select(PasswordResetToken)
        .where(
            PasswordResetToken.id == token_identity.id,
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.token_digest == digest,
        )
        .with_for_update()
    )
    if (
        reset_row is None
        or reset_row.used_at is not None
        or reset_row.revoked_at is not None
        or _as_utc(reset_row.expires_at) <= now
    ):
        raise AuthenticationFailure
    validate_password_minimum(
        new_password, password_minimum_for_user(session, user.id)
    )
    user.password_hash = hash_password(new_password)
    user.password_changed_at = now
    user.force_password_change = False
    reset_row.used_at = now
    session.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.id != reset_row.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    session.execute(
        update(RefreshSession)
        .where(RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    _record_password_change_audit(session, user.id, "auth.password_reset")
    session.commit()


def force_change_password(
    session: Session,
    *,
    user_id: UUID,
    session_id: UUID,
    current_password: str,
    new_password: str,
) -> None:
    """Require the current password, update identity, and retain only this session."""
    user = session.scalar(select(User).where(User.id == user_id).with_for_update())
    auth_session = session.scalar(
        select(RefreshSession).where(RefreshSession.id == session_id).with_for_update()
    )
    if (
        user is None
        or not user.is_active
        or not user.force_password_change
        or auth_session is None
        or auth_session.user_id != user_id
        or auth_session.revoked_at is not None
        or not verify_password(current_password, user.password_hash)
    ):
        raise AuthenticationFailure
    if current_password == new_password:
        raise ValueError("The new password must differ from the current password.")
    validate_password_minimum(
        new_password, password_minimum_for_user(session, user_id)
    )
    now = datetime.now(UTC)
    user.password_hash = hash_password(new_password)
    user.password_changed_at = now
    user.force_password_change = False
    session.execute(
        update(RefreshSession)
        .where(
            RefreshSession.user_id == user_id,
            RefreshSession.id != session_id,
            RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    _record_password_change_audit(session, user_id, "auth.password_changed")
    session.commit()


def _record_password_change_audit(session: Session, user_id: UUID, action: str) -> None:
    """Record secret-free password-change events for each organization membership."""
    for membership in session.scalars(
        select(Membership).where(Membership.user_id == user_id)
    ).all():
        session.add(
            AuditEvent(
                organization_id=membership.organization_id,
                actor_user_id=user_id,
                action=action,
                resource_type="user",
                resource_id=str(user_id),
                details={},
            )
        )


def _permissions_for_role(session: Session, role_id: UUID) -> list[str]:
    return list(
        session.scalars(
            select(Permission.code)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id == role_id)
            .order_by(Permission.code)
        ).all()
    )


def _rotate_refresh_token(
    session: Session, auth_session: RefreshSession, expires_at: datetime
) -> tuple[str, str]:
    value = create_refresh_token()
    session.add(
        RefreshToken(
            organization_id=auth_session.organization_id,
            session_id=auth_session.id,
            token_digest=digest_refresh_token(value),
            expires_at=expires_at,
        )
    )
    return value, create_refresh_token()


def _user_response(
    user: User,
    organization_id: UUID,
    membership_id: UUID,
    role_code: str,
    permissions: list[str],
) -> AuthenticatedUser:
    return AuthenticatedUser(
        id=str(user.id),
        email=user.email,
        display_name=user.display_name,
        organization_id=str(organization_id),
        membership_id=str(membership_id),
        role=role_code,
        permissions=permissions,
        force_password_change=user.force_password_change,
    )


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
