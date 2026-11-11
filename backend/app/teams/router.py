"""Tenant-scoped team and team-membership administration endpoints."""

from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.core.domain_errors import ConflictError, NotFoundError
from app.core.models import AuditEvent, Membership, Role, Team, TeamMembership, User
from app.operations.service import record_audit
from app.teams.schemas import (
    TeamCreate,
    TeamMemberList,
    TeamMemberRead,
    TeamPage,
    TeamRead,
    TeamSummary,
    TeamUpdate,
)
from app.users.schemas import UserActivityList, UserActivityRead

router = APIRouter(prefix="/teams", tags=["teams"])


@router.get("/summary", response_model=TeamSummary)
def team_summary(
    principal: Annotated[Principal, Depends(require_permission("teams:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> TeamSummary:
    organization_id = principal.organization_id
    total = (
        session.scalar(select(func.count(Team.id)).where(Team.organization_id == organization_id))
        or 0
    )
    active = (
        session.scalar(
            select(func.count(Team.id)).where(
                Team.organization_id == organization_id, Team.is_active.is_(True)
            )
        )
        or 0
    )
    members = (
        session.scalar(
            select(func.count(func.distinct(TeamMembership.user_id))).where(
                TeamMembership.organization_id == organization_id
            )
        )
        or 0
    )
    return TeamSummary(total=total, active=active, archived=total - active, members=members)


@router.get("", response_model=TeamPage)
def list_teams(
    principal: Annotated[Principal, Depends(require_permission("teams:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    search: Annotated[str | None, Query(max_length=120)] = None,
    state: Annotated[Literal["active", "archived", "all"], Query(alias="status")] = "active",
    team_id: UUID | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> TeamPage:
    filters = [Team.organization_id == principal.organization_id]
    if state != "all":
        filters.append(Team.is_active.is_(state == "active"))
    if search and search.strip():
        filters.append(Team.name.ilike(f"%{search.strip()}%"))
    if team_id:
        filters.append(Team.id == team_id)
    if date_from:
        filters.append(Team.created_at >= datetime.combine(date_from, time.min, tzinfo=UTC))
    if date_to:
        filters.append(
            Team.created_at < datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=UTC)
        )
    total = session.scalar(select(func.count(Team.id)).where(*filters)) or 0
    rows = session.execute(
        select(Team, func.count(TeamMembership.id))
        .outerjoin(
            TeamMembership,
            (TeamMembership.team_id == Team.id)
            & (TeamMembership.organization_id == principal.organization_id),
        )
        .where(*filters)
        .group_by(Team.id)
        .order_by(Team.name)
        .offset(offset)
        .limit(limit)
    ).all()
    return TeamPage(
        items=[_team_read(team, count) for team, count in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("", response_model=TeamRead, status_code=status.HTTP_201_CREATED)
def create_team(
    payload: TeamCreate,
    principal: Annotated[Principal, Depends(require_permission("teams:create"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> TeamRead:
    name = payload.name.strip()
    if not name:
        raise ConflictError("Team name cannot be blank.")
    if (
        session.scalar(
            select(Team.id).where(
                Team.organization_id == principal.organization_id,
                func.lower(Team.name) == name.lower(),
            )
        )
        is not None
    ):
        raise ConflictError("A team with this name already exists.")
    team = Team(
        organization_id=principal.organization_id,
        name=name,
        description=_normalize_description(payload.description),
    )
    session.add(team)
    session.flush()
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="team.created",
        resource_type="team",
        resource_id=team.id,
    )
    session.commit()
    session.refresh(team)
    return _team_read(team, 0)


@router.get("/{team_id}", response_model=TeamRead)
def get_team(
    team_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("teams:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> TeamRead:
    team = _get_team(session, principal.organization_id, team_id)
    count = (
        session.scalar(
            select(func.count(TeamMembership.id)).where(
                TeamMembership.organization_id == principal.organization_id,
                TeamMembership.team_id == team.id,
            )
        )
        or 0
    )
    return _team_read(team, count)


@router.get("/{team_id}/members", response_model=TeamMemberList)
def list_team_members(
    team_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("teams:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> TeamMemberList:
    _get_team(session, principal.organization_id, team_id)
    filters = [
        TeamMembership.organization_id == principal.organization_id,
        TeamMembership.team_id == team_id,
    ]
    total = session.scalar(select(func.count(TeamMembership.id)).where(*filters)) or 0
    rows = session.execute(
        select(User, Membership, Role)
        .join(TeamMembership, TeamMembership.user_id == User.id)
        .join(
            Membership,
            (Membership.user_id == User.id)
            & (Membership.organization_id == TeamMembership.organization_id),
        )
        .join(Role, Role.id == Membership.role_id)
        .where(*filters)
        .order_by(User.display_name, User.email)
        .offset(offset)
        .limit(limit)
    ).all()
    return TeamMemberList(
        team_id=team_id,
        items=[
            TeamMemberRead(
                user_id=user.id,
                display_name=user.display_name,
                email=user.email,
                role_code=role.code,
                is_active=user.is_active and membership.is_active,
                is_locked=membership.is_locked,
            )
            for user, membership, role in rows
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/{team_id}/activity", response_model=UserActivityList)
def list_team_activity(
    team_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("audit:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> UserActivityList:
    """Read canonical audit events related to a tenant-scoped team."""
    _get_team(session, principal.organization_id, team_id)
    filters = [
        AuditEvent.organization_id == principal.organization_id,
        AuditEvent.resource_type == "team",
        AuditEvent.resource_id == str(team_id),
    ]
    total = session.scalar(select(func.count(AuditEvent.id)).where(*filters)) or 0
    events = session.scalars(
        select(AuditEvent)
        .where(*filters)
        .order_by(AuditEvent.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return UserActivityList(
        items=[
            UserActivityRead(
                id=event.id,
                actor_user_id=event.actor_user_id,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                details=event.details,
                created_at=event.created_at,
            )
            for event in events
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/{team_id}/available-members", response_model=list[TeamMemberRead])
def available_team_members(
    team_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("teams:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[TeamMemberRead]:
    team = _get_team(session, principal.organization_id, team_id)
    if not team.is_active:
        return []
    current_ids = select(TeamMembership.user_id).where(
        TeamMembership.organization_id == principal.organization_id,
        TeamMembership.team_id == team_id,
    )
    rows = session.execute(
        select(User, Membership, Role)
        .join(Membership, Membership.user_id == User.id)
        .join(Role, Role.id == Membership.role_id)
        .where(
            Membership.organization_id == principal.organization_id,
            Membership.is_active.is_(True),
            Membership.is_locked.is_(False),
            User.is_active.is_(True),
            User.id.not_in(current_ids),
        )
        .order_by(User.display_name, User.email)
        .limit(100)
    ).all()
    return [
        TeamMemberRead(
            user_id=user.id,
            display_name=user.display_name,
            email=user.email,
            role_code=role.code,
            is_active=True,
            is_locked=False,
        )
        for user, _membership, role in rows
    ]


@router.put("/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def add_team_member(
    team_id: UUID,
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("teams:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    team = _get_team(session, principal.organization_id, team_id)
    if not team.is_active:
        raise ConflictError("Members cannot be added to an archived team.")
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == principal.organization_id,
            Membership.user_id == user_id,
            Membership.is_active.is_(True),
            Membership.is_locked.is_(False),
        )
    )
    if membership is None:
        raise NotFoundError("Organization user")
    link = session.scalar(
        select(TeamMembership).where(
            TeamMembership.organization_id == principal.organization_id,
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == user_id,
        )
    )
    if link is not None:
        raise ConflictError("This user is already a member of the team.")
    session.add(
        TeamMembership(
            organization_id=principal.organization_id,
            team_id=team_id,
            user_id=user_id,
        )
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="team.member_added",
        resource_type="team",
        resource_id=team_id,
        details={"user_id": str(user_id)},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_team_member(
    team_id: UUID,
    user_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("teams:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    _get_team(session, principal.organization_id, team_id)
    link = session.scalar(
        select(TeamMembership)
        .join(Team, Team.id == TeamMembership.team_id)
        .where(
            Team.id == team_id,
            Team.organization_id == principal.organization_id,
            TeamMembership.organization_id == principal.organization_id,
            TeamMembership.user_id == user_id,
        )
    )
    if link is None:
        raise NotFoundError("Team membership")
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="team.member_removed",
        resource_type="team",
        resource_id=team_id,
        details={"user_id": str(user_id)},
    )
    session.delete(link)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.patch("/{team_id}", response_model=TeamRead)
def update_team(
    team_id: UUID,
    payload: TeamUpdate,
    principal: Annotated[Principal, Depends(require_permission("teams:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> TeamRead:
    team = _get_team(session, principal.organization_id, team_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise ConflictError("At least one team field must be provided.")
    if "name" in changes:
        changes["name"] = changes["name"].strip()
        if not changes["name"]:
            raise ConflictError("Team name cannot be blank.")
        duplicate = session.scalar(
            select(Team.id).where(
                Team.organization_id == principal.organization_id,
                func.lower(Team.name) == changes["name"].lower(),
                Team.id != team.id,
            )
        )
        if duplicate is not None:
            raise ConflictError("A team with this name already exists.")
    if "description" in changes:
        changes["description"] = _normalize_description(changes["description"])
    for field, value in changes.items():
        setattr(team, field, value)
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="team.updated",
        resource_type="team",
        resource_id=team.id,
        details={"changed_fields": sorted(changes)},
    )
    session.commit()
    session.refresh(team)
    count = (
        session.scalar(
            select(func.count(TeamMembership.id)).where(
                TeamMembership.organization_id == principal.organization_id,
                TeamMembership.team_id == team.id,
            )
        )
        or 0
    )
    return _team_read(team, count)


@router.delete("/{team_id}", status_code=status.HTTP_204_NO_CONTENT)
def archive_team(
    team_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("teams:delete"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    team = _get_team(session, principal.organization_id, team_id)
    if team.is_active:
        team.is_active = False
        record_audit(
            session,
            organization_id=principal.organization_id,
            actor_user_id=principal.user_id,
            action="team.archived",
            resource_type="team",
            resource_id=team.id,
        )
        session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{team_id}/restore", response_model=TeamRead)
def restore_team(
    team_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("teams:delete"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> TeamRead:
    team = _get_team(session, principal.organization_id, team_id)
    if not team.is_active:
        team.is_active = True
        record_audit(
            session,
            organization_id=principal.organization_id,
            actor_user_id=principal.user_id,
            action="team.restored",
            resource_type="team",
            resource_id=team.id,
        )
        session.commit()
        session.refresh(team)
    count = (
        session.scalar(
            select(func.count(TeamMembership.id)).where(
                TeamMembership.organization_id == principal.organization_id,
                TeamMembership.team_id == team.id,
            )
        )
        or 0
    )
    return _team_read(team, count)


def _get_team(session: Session, organization_id: UUID, team_id: UUID) -> Team:
    team = session.scalar(
        select(Team).where(Team.id == team_id, Team.organization_id == organization_id)
    )
    if team is None:
        raise NotFoundError("Team")
    return team


def _team_read(team: Team, member_count: int) -> TeamRead:
    return TeamRead(
        id=team.id,
        name=team.name,
        description=team.description,
        member_count=member_count,
        is_active=team.is_active,
        created_at=team.created_at,
        updated_at=team.updated_at,
    )


def _normalize_description(value: str | None) -> str | None:
    normalized = value.strip() if value is not None else None
    return normalized or None
