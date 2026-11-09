"""Bearer authentication and permission dependencies."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, cast
from uuid import UUID, uuid4

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.security import decode_access_token
from app.core.config import Settings
from app.core.database import get_system_session
from app.core.models import (
    Membership,
    Organization,
    Permission,
    RefreshSession,
    Role,
    RolePermission,
    User,
)

bearer = HTTPBearer(auto_error=False)


class Principal:
    """Authenticated principal bound to one active organization membership."""

    def __init__(self, claims: dict[str, Any], permissions: set[str]) -> None:
        self.user_id = UUID(claims["sub"])
        self.membership_id = UUID(claims["mid"])
        self.organization_id = UUID(claims["org"])
        self.session_id = UUID(claims["sid"])
        self.role_code = str(claims["role"])
        self.permissions = frozenset(permissions)
        self.force_password_change = False


def get_current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    """Decode token claims and revalidate user, membership, session, and current grants."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()
    try:
        claims = decode_access_token(
            cast(Settings, request.app.state.settings), credentials.credentials
        )
        user_id = UUID(claims["sub"])
        membership_id = UUID(claims["mid"])
        organization_id = UUID(claims["org"])
        session_id = UUID(claims["sid"])
    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError, RuntimeError):
        raise _unauthorized() from None

    factory = request.app.state.session_factory
    if factory is None:
        raise HTTPException(status_code=503, detail="Service unavailable")
    with cast(Any, factory)(info={"allow_unscoped": True}) as session:
        row = session.execute(
            select(Membership, User, Role, RefreshSession, Organization)
            .join(User, User.id == Membership.user_id)
            .join(Role, Role.id == Membership.role_id)
            .join(RefreshSession, RefreshSession.membership_id == Membership.id)
            .join(Organization, Organization.id == Membership.organization_id)
            .where(
                Membership.id == membership_id,
                Membership.organization_id == organization_id,
                Membership.user_id == user_id,
                Membership.is_active.is_(True),
                Membership.is_locked.is_(False),
                User.is_active.is_(True),
                Role.code == claims.get("role"),
                Organization.id == organization_id,
                Organization.is_active.is_(True),
                RefreshSession.id == session_id,
                RefreshSession.user_id == user_id,
                RefreshSession.organization_id == organization_id,
                RefreshSession.revoked_at.is_(None),
            )
        ).first()
        if row is None:
            raise _unauthorized()
        membership, user, role, auth_session, _organization = row
        expiry = auth_session.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        if expiry <= datetime.now(UTC):
            raise _unauthorized()
        force_password_change = user.force_password_change
        permissions = set(
            session.scalars(
                select(Permission.code)
                .join(RolePermission, RolePermission.permission_id == Permission.id)
                .where(RolePermission.role_id == membership.role_id)
            ).all()
        )
        if not set(claims.get("permissions", [])).issuperset(permissions):
            raise _unauthorized()
    principal = Principal(claims, permissions)
    principal.force_password_change = force_password_change
    request.state.audit_principal = principal
    return principal


def require_permission(permission: str) -> Callable[..., Principal]:
    """Build a deny-by-default permission dependency."""

    def dependency(
        principal: Annotated[Principal, Depends(get_current_principal)],
    ) -> Principal:
        if principal.force_password_change:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Password update required",
            )
        if permission not in principal.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied",
            )
        return principal

    return dependency


def get_tenant_session(
    request: Request,
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_system_session)],
) -> Session:
    """Bind the request's SQLAlchemy session to its authenticated organization."""
    if principal.force_password_change:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password update required",
        )
    session.info.pop("allow_unscoped", None)
    session.info["tenant_id"] = principal.organization_id
    session.info["audit_ip_address"] = request.client.host if request.client else None
    session.info["audit_user_agent"] = request.headers.get("user-agent", "")[:512] or None
    request_id = request.headers.get("x-request-id", "")
    if (
        not request_id
        or len(request_id) > 100
        or any(ord(char) < 33 or ord(char) > 126 for char in request_id)
    ):
        request_id = str(uuid4())
    session.info["audit_request_id"] = request_id
    request.state.audit_db_session = session
    return session


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )
