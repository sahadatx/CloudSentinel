"""Organization user, access, and invitation API schemas."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class UserMembershipRead(BaseModel):
    """Safe identity and membership view for an organization user."""

    user_id: UUID
    # Stored identities can include non-deliverable reserved addresses such as
    # the .invalid addresses used by disabled demo memberships.
    email: str
    display_name: str
    role_code: str
    is_active: bool
    is_locked: bool
    force_password_change: bool
    created_at: datetime
    last_login_at: datetime | None
    team_names: list[str]


class UserList(BaseModel):
    """Bounded users response for the active organization."""

    items: list[UserMembershipRead]
    total: int
    offset: int
    limit: int


class UserSummary(BaseModel):
    """Live counts from organization memberships and invitations."""

    total: int
    active: int
    disabled: int
    locked: int
    pending: int


class UserDetail(UserMembershipRead):
    """User detail with effective permissions and organization context."""

    organization_id: UUID
    organization_name: str
    permissions: list[str]
    active_sessions: int
    updated_at: datetime


class UserUpdate(BaseModel):
    """Editable organization identity fields."""

    display_name: str = Field(min_length=2, max_length=200)


class RoleUpdate(BaseModel):
    """Select one of the specification-locked organization roles."""

    role_code: str = Field(
        pattern=r"^(SUPER_ADMIN|ORG_ADMIN|SECURITY_ADMIN|SECURITY_ANALYST|CLOUD_ENGINEER|AUDITOR|VIEWER)$"
    )


class UserLockRequest(BaseModel):
    """Administrative reason recorded with a membership lock event."""

    reason: str | None = Field(default=None, max_length=500)


class RoleRead(BaseModel):
    code: str
    description: str
    permissions: list[str] = Field(default_factory=list)


class InvitationCreate(BaseModel):
    """Issue an invitation for an organization membership."""

    email: EmailStr
    display_name: str = Field(min_length=1, max_length=200)
    role_code: str = Field(min_length=1, max_length=40)


class InvitationCreated(BaseModel):
    """Invitation delivery state and one-time acceptance URL."""

    email: EmailStr
    organization_id: UUID
    role_code: str
    token: str
    invitation_url: str
    expires_at: datetime
    email_delivery: Literal["sent", "failed"]


class UserSessionRead(BaseModel):
    id: UUID
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None
    ip_address: str | None
    user_agent: str | None
    current: bool


class UserSessionList(BaseModel):
    items: list[UserSessionRead]
    total: int
    offset: int
    limit: int


class UserActivityRead(BaseModel):
    id: UUID
    actor_user_id: UUID | None
    action: str
    resource_type: str
    resource_id: str | None
    details: dict[str, object]
    created_at: datetime


class UserActivityList(BaseModel):
    items: list[UserActivityRead]
    total: int
    offset: int
    limit: int
