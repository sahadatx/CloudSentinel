"""Trusted operator provisioning for a tenant and its initial administrator."""

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.core.domain_errors import ConflictError, InvalidOperationError
from app.core.models import Membership, Organization, Role, User

_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")


def bootstrap_organization(
    session: Session,
    *,
    name: str,
    slug: str,
    email: str,
    display_name: str,
    password: str | None,
) -> Organization:
    """Create an organization and assign the initial user an organization-scoped role."""
    normalized_email = email.strip().lower()
    if not name.strip() or len(name) > 200 or not _SLUG_PATTERN.fullmatch(slug):
        raise InvalidOperationError("Organization name or slug is invalid.")
    if session.scalar(select(Organization.id).where(Organization.slug == slug)) is not None:
        raise ConflictError("An organization with this slug already exists.")

    role = session.scalar(select(Role).where(Role.code == "SUPER_ADMIN"))
    if role is None:
        raise InvalidOperationError("The role catalog must be migrated before provisioning.")
    user = session.scalar(select(User).where(User.email == normalized_email).with_for_update())
    if user is None:
        if password is None or len(password) < 12:
            raise InvalidOperationError(
                "A new administrator password must contain at least 12 characters."
            )
        user = User(
            email=normalized_email,
            display_name=display_name.strip(),
            password_hash=hash_password(password),
        )
        session.add(user)
        session.flush()
    elif not user.is_active:
        raise ConflictError("The selected administrator account is inactive.")

    organization = Organization(name=name.strip(), slug=slug)
    session.add(organization)
    session.flush()
    existing = session.scalar(
        select(Membership.id).where(
            Membership.organization_id == organization.id,
            Membership.user_id == user.id,
        )
    )
    if existing is not None:
        raise ConflictError("The user already belongs to this organization.")
    session.add(Membership(organization_id=organization.id, user_id=user.id, role_id=role.id))
    session.commit()
    return organization
