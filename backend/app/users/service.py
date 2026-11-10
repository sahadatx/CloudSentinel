"""User invitation acceptance and organization membership operations."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.core.domain_errors import ConflictError, InvalidOperationError, NotFoundError
from app.core.models import (
    Membership,
    Organization,
    PasswordResetToken,
    Role,
    User,
    UserInvitation,
)
from app.operations.service import record_audit

INVITATION_TTL = timedelta(hours=72)


def invitation_password_minimum(session: Session, token: str) -> int:
    """Return password policy only for a currently valid invitation token."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    invitation = session.scalar(select(UserInvitation).where(UserInvitation.token_digest == digest))
    now = datetime.now(UTC)
    if (
        invitation is None
        or invitation.accepted_at is not None
        or invitation.revoked_at is not None
        or _as_utc(invitation.expires_at) <= now
    ):
        raise InvalidOperationError("The invitation is invalid or has expired.")
    organization = session.get(Organization, invitation.organization_id)
    if organization is None or not organization.is_active:
        raise InvalidOperationError("The invitation is invalid or has expired.")
    existing_user = session.scalar(select(User).where(User.email == invitation.email))
    if existing_user is None:
        return organization.password_min_length
    minima = session.scalars(
        select(Organization.password_min_length)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(
            Membership.user_id == existing_user.id,
            Membership.is_active.is_(True),
            Organization.is_active.is_(True),
        )
    ).all()
    return max([organization.password_min_length, *minima])


def create_user_password_reset(session: Session, user: User, *, ttl_minutes: int) -> str:
    """Create a one-time hashed reset token for an authorized tenant admin action."""
    now = datetime.now(UTC)
    session.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.revoked_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(revoked_at=now)
    )
    token = secrets.token_urlsafe(32)
    session.add(
        PasswordResetToken(
            user_id=user.id,
            token_digest=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            expires_at=now + timedelta(minutes=ttl_minutes),
        )
    )
    return token


def create_invitation(
    session: Session,
    *,
    organization_id: UUID,
    invited_by_user_id: UUID,
    email: str,
    display_name: str,
    role_code: str,
) -> tuple[UserInvitation, str]:
    """Create or rotate a pending invitation and return its plaintext token once."""
    email = email.lower()
    organization = session.scalar(
        select(Organization).where(Organization.id == organization_id).with_for_update()
    )
    role = session.scalar(select(Role).where(Role.code == role_code))
    if organization is None or not organization.is_active:
        raise NotFoundError("Organization")
    if role is None:
        raise InvalidOperationError("The requested role is not available.")

    user = session.scalar(select(User).where(User.email == email))
    if user is not None:
        membership = session.scalar(
            select(Membership).where(
                Membership.organization_id == organization_id,
                Membership.user_id == user.id,
            )
        )
        if membership is not None:
            raise ConflictError("This email already has an organization membership.")
        if not user.is_active:
            raise ConflictError("This user account is inactive.")

    now = datetime.now(UTC)
    previous = session.scalar(
        select(UserInvitation)
        .where(UserInvitation.organization_id == organization_id, UserInvitation.email == email)
        .with_for_update()
    )
    if previous is not None:
        if previous.accepted_at is not None:
            raise ConflictError("This invitation has already been accepted.")
        # Reissuing an invitation revokes the previous token, so an admin can
        # retry delivery while only the newest email link remains usable.
        session.delete(previous)
        session.flush()

    token = secrets.token_urlsafe(48)
    invitation = UserInvitation(
        organization_id=organization_id,
        email=email,
        display_name=display_name,
        role_id=role.id,
        invited_by_user_id=invited_by_user_id,
        token_digest=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        expires_at=now + INVITATION_TTL,
    )
    session.add(invitation)
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=invited_by_user_id,
        action="user.invitation_created",
        resource_type="user_invitation",
        resource_id=invitation.id,
        details={"role": role_code},
    )
    session.commit()
    return invitation, token


def accept_invitation(session: Session, *, token: str, password: str) -> None:
    """Consume a single-use invitation and create/attach the user membership."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    invitation = session.scalar(
        select(UserInvitation).where(UserInvitation.token_digest == digest).with_for_update()
    )
    now = datetime.now(UTC)
    if (
        invitation is None
        or invitation.accepted_at is not None
        or invitation.revoked_at is not None
        or _as_utc(invitation.expires_at) <= now
    ):
        raise InvalidOperationError("The invitation is invalid or has expired.")

    organization = session.get(Organization, invitation.organization_id)
    role = session.get(Role, invitation.role_id)
    if organization is None or not organization.is_active or role is None:
        raise InvalidOperationError("The invitation is invalid or has expired.")
    user = session.scalar(select(User).where(User.email == invitation.email).with_for_update())
    existing_policy_values = (
        session.scalars(
            select(Organization.password_min_length)
            .join(Membership, Membership.organization_id == Organization.id)
            .where(
                Membership.user_id == user.id,
                Membership.is_active.is_(True),
                Organization.is_active.is_(True),
            )
        ).all()
        if user is not None
        else []
    )
    required_length = max([organization.password_min_length, *existing_policy_values])
    if len(password) < required_length:
        raise InvalidOperationError(f"Password must contain at least {required_length} characters.")

    if user is None:
        user = User(
            email=invitation.email,
            display_name=invitation.display_name,
            password_hash=hash_password(password),
        )
        session.add(user)
        session.flush()
    elif not user.is_active:
        raise InvalidOperationError("The invitation is invalid or has expired.")

    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == invitation.organization_id,
            Membership.user_id == user.id,
        )
    )
    if membership is not None:
        raise ConflictError("This user already has an organization membership.")

    membership = Membership(
        organization_id=invitation.organization_id,
        user_id=user.id,
        role_id=invitation.role_id,
    )
    session.add(membership)
    session.flush()
    invitation.accepted_at = now
    record_audit(
        session,
        organization_id=invitation.organization_id,
        actor_user_id=user.id,
        action="user.invitation_accepted",
        resource_type="membership",
        resource_id=membership.id,
        details={"role": role.code},
    )
    session.commit()


def update_membership_role(
    session: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    role_code: str,
    actor_user_id: UUID | None = None,
) -> None:
    _lock_organization(session, organization_id)
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == user_id,
        )
    )
    role = session.scalar(select(Role).where(Role.code == role_code))
    if membership is None:
        raise NotFoundError("Organization user")
    if role is None:
        raise InvalidOperationError("The requested role is not available.")
    if (
        membership.is_active
        and _is_admin_role(membership.role_id, session)
        and not _is_admin_role(role.id, session)
    ):
        _ensure_another_active_admin(session, organization_id, excluding_user_id=user_id)
    membership.role_id = role.id
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="user.role_changed",
        resource_type="membership",
        resource_id=membership.id,
        details={"role": role_code},
    )
    session.commit()


def set_membership_active(
    session: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    is_active: bool,
    actor_user_id: UUID | None = None,
) -> None:
    _lock_organization(session, organization_id)
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == user_id,
        )
    )
    if membership is None:
        raise NotFoundError("Organization user")
    if not is_active and membership.is_active and _is_admin_role(membership.role_id, session):
        _ensure_another_active_admin(session, organization_id, excluding_user_id=user_id)
    membership.is_active = is_active
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="user.enabled" if is_active else "user.disabled",
        resource_type="membership",
        resource_id=membership.id,
        details={"is_active": is_active},
    )
    session.commit()


def _is_admin_role(role_id: UUID, session: Session) -> bool:
    role = session.get(Role, role_id)
    return role is not None and role.code in {"ORG_ADMIN", "SUPER_ADMIN", "SECURITY_ADMIN"}


def _ensure_another_active_admin(
    session: Session, organization_id: UUID, *, excluding_user_id: UUID
) -> None:
    count = session.scalar(
        select(Membership.id)
        .join(User, User.id == Membership.user_id)
        .join(Role, Role.id == Membership.role_id)
        .where(
            Membership.organization_id == organization_id,
            Membership.user_id != excluding_user_id,
            Membership.is_active.is_(True),
            Membership.is_locked.is_(False),
            User.is_active.is_(True),
            Role.code.in_(("ORG_ADMIN", "SUPER_ADMIN", "SECURITY_ADMIN")),
        )
        .limit(1)
    )
    if count is None:
        raise InvalidOperationError(
            "An organization must retain at least one active administrator."
        )


def _lock_organization(session: Session, organization_id: UUID) -> None:
    """Serialize administrator demotions/deactivations within one organization."""
    organization = session.scalar(
        select(Organization).where(Organization.id == organization_id).with_for_update()
    )
    if organization is None:
        raise NotFoundError("Organization")


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
