"""Organization team and membership API contracts."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TeamCreate(BaseModel):
    """Create an organization team."""

    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)


class TeamUpdate(BaseModel):
    """Update an organization's team metadata."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)


class TeamRead(BaseModel):
    """Organization-scoped team metadata."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    member_count: int
    is_active: bool
    created_at: datetime
    updated_at: datetime


class TeamPage(BaseModel):
    """Bounded team collection."""

    items: list[TeamRead]
    total: int
    offset: int
    limit: int


class TeamSummary(BaseModel):
    """Current tenant team counts."""

    total: int
    active: int
    archived: int
    members: int


class TeamMemberRead(BaseModel):
    """Safe organization user data for a team membership."""

    user_id: UUID
    display_name: str
    email: str
    role_code: str
    is_active: bool
    is_locked: bool


class TeamMemberList(BaseModel):
    """Paginated team member results."""

    team_id: UUID
    items: list[TeamMemberRead]
    total: int
    offset: int
    limit: int
