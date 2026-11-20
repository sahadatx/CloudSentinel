"""Tenant-isolated SCIM 2.0 Users and Groups provisioning endpoints."""

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.auth.security import hash_password
from app.core.config import Settings
from app.core.database import get_system_session
from app.core.models import (
    Membership,
    Organization,
    RefreshSession,
    Role,
    RolePermission,
    ScimGroup,
    ScimGroupMembership,
    ScimToken,
    User,
    utc_now,
)
from app.identity.schemas import ScimGroupMappingWrite, ScimTokenCreate, ScimTokenCreated
from app.operations.service import record_audit
from app.scim.errors import ScimProtocolError

router = APIRouter(tags=["SCIM 2.0"])
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
EMAIL_ADAPTER = TypeAdapter(EmailStr)
ROLE_ORDER = {
    "VIEWER": 0,
    "AUDITOR": 1,
    "SECURITY_ANALYST": 2,
    "CLOUD_ENGINEER": 3,
    "SECURITY_ADMIN": 4,
    "ORG_ADMIN": 5,
}
MAX_SCIM_BODY_BYTES = 64_000


@dataclass(frozen=True)
class ScimContext:
    organization: Organization
    token: ScimToken
    session: Session


def get_scim_context(
    organization_slug: str,
    authorization: Annotated[str | None, Header()] = None,
    session: Session = Depends(get_system_session),
) -> ScimContext:
    organization = session.scalar(
        select(Organization).where(
            Organization.slug == organization_slug,
            Organization.is_active.is_(True),
        )
    )
    if organization is None or authorization is None:
        raise _scim_error(401, "Invalid or expired SCIM credential.", "invalidToken")
    scheme, separator, token_value = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or len(token_value) < 40:
        raise _scim_error(401, "Invalid or expired SCIM credential.", "invalidToken")
    digest = hashlib.sha256(token_value.encode()).hexdigest()
    token = session.scalar(
        select(ScimToken).where(
            ScimToken.organization_id == organization.id,
            ScimToken.token_digest == digest,
            ScimToken.revoked_at.is_(None),
        )
    )
    now = datetime.now(UTC)
    if token is None or (token.expires_at is not None and _as_utc(token.expires_at) <= now):
        raise _scim_error(401, "Invalid or expired SCIM credential.", "invalidToken")
    token.last_used_at = now
    session.commit()
    return ScimContext(organization=organization, token=token, session=session)


@router.post("/organizations/current/scim-token", response_model=ScimTokenCreated)
def create_scim_token(
    payload: ScimTokenCreate,
    request: Request,
    principal: Annotated[Principal, Depends(require_permission("identity:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> ScimTokenCreated:
    organization = session.get(Organization, principal.organization_id)
    if organization is None or not organization.is_active:
        raise HTTPException(status_code=404, detail="Organization not found")
    now = datetime.now(UTC)
    existing = session.scalars(
        select(ScimToken).where(
            ScimToken.organization_id == organization.id,
            ScimToken.revoked_at.is_(None),
        )
    ).all()
    for token in existing:
        token.revoked_at = now
    raw_token = secrets.token_urlsafe(48)
    token = ScimToken(
        organization_id=organization.id,
        token_digest=hashlib.sha256(raw_token.encode()).hexdigest(),
        description=payload.description.strip(),
        expires_at=now + timedelta(days=90),
    )
    session.add(token)
    record_audit(
        session,
        organization_id=organization.id,
        actor_user_id=principal.user_id,
        action="identity.scim_token_rotated",
        resource_type="scim_token",
        resource_id=token.id,
        details={"expires_at": token.expires_at.isoformat() if token.expires_at else None},
    )
    session.commit()
    settings = cast(Settings, request.app.state.settings)
    return ScimTokenCreated(
        token=raw_token,
        expires_at=token.expires_at.isoformat() if token.expires_at else "",
        scim_base_url=f"{settings.public_api_base_url.rstrip('/')}/scim/v2/{organization.slug}",
    )


@router.get("/organizations/current/scim-token")
def list_scim_tokens(
    principal: Annotated[Principal, Depends(require_permission("identity:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> dict[str, object]:
    tokens = session.scalars(
        select(ScimToken)
        .where(ScimToken.organization_id == principal.organization_id)
        .order_by(ScimToken.created_at.desc())
        .limit(20)
    ).all()
    return {
        "items": [
            {
                "id": str(token.id),
                "description": token.description,
                "created_at": token.created_at,
                "expires_at": token.expires_at,
                "last_used_at": token.last_used_at,
                "revoked_at": token.revoked_at,
            }
            for token in tokens
        ]
    }


@router.put("/organizations/current/scim/groups/{external_id}")
def map_scim_group(
    external_id: Annotated[str, Path(min_length=1, max_length=200)],
    payload: ScimGroupMappingWrite,
    principal: Annotated[Principal, Depends(require_permission("identity:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> dict[str, str]:
    role = session.scalar(select(Role).where(Role.code == payload.role_code))
    if role is None:
        raise HTTPException(status_code=422, detail="The requested role is unavailable.")
    group = session.scalar(
        select(ScimGroup).where(
            ScimGroup.organization_id == principal.organization_id,
            ScimGroup.external_id == external_id,
        )
    )
    if group is None:
        group = ScimGroup(
            organization_id=principal.organization_id,
            external_id=external_id,
            display_name=payload.display_name.strip(),
            role_id=role.id,
        )
        session.add(group)
    else:
        group.display_name = payload.display_name.strip()
        group.role_id = role.id
        group.is_active = True
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="identity.scim_group_role_mapped",
        resource_type="scim_group",
        resource_id=group.id,
        details={"external_id": external_id, "role_code": payload.role_code},
    )
    session.commit()
    return {"id": str(group.id), "external_id": group.external_id, "role_code": payload.role_code}


@router.get("/organizations/current/scim/groups")
def list_scim_group_mappings(
    principal: Annotated[Principal, Depends(require_permission("identity:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> dict[str, list[dict[str, object]]]:
    rows = session.execute(
        select(ScimGroup, Role.code)
        .join(Role, Role.id == ScimGroup.role_id)
        .where(ScimGroup.organization_id == principal.organization_id)
        .order_by(ScimGroup.display_name)
    ).all()
    return {
        "items": [
            {
                "external_id": group.external_id,
                "display_name": group.display_name,
                "role_code": role_code,
                "is_active": group.is_active,
            }
            for group, role_code in rows
        ]
    }


@router.get("/scim/v2/{organization_slug}/ServiceProviderConfig")
def service_provider_config(
    context: Annotated[ScimContext, Depends(get_scim_context)],
) -> JSONResponse:
    return _scim_response(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 100},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "Bearer Token",
                    "description": "Organization-specific, rotating SCIM bearer token.",
                }
            ],
        }
    )


@router.get("/scim/v2/{organization_slug}/Users")
def list_scim_users(
    organization_slug: str,
    context: Annotated[ScimContext, Depends(get_scim_context)],
    start_index: Annotated[int, Query(ge=1)] = 1,
    count: Annotated[int, Query(ge=1, le=100)] = 100,
    filter_expression: Annotated[str | None, Query(alias="filter", max_length=500)] = None,
) -> JSONResponse:
    statement = (
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == context.organization.id)
    )
    matched = None
    if filter_expression:
        matched = re.fullmatch(r'\s*userName\s+eq\s+"([^"\\]{1,320})"\s*', filter_expression, re.I)
        if matched is None:
            raise _scim_error(400, "Only userName eq \"value\" filters are supported.", "invalidFilter")
        statement = statement.where(func.lower(User.email) == matched.group(1).casefold())
    count_statement = select(func.count(Membership.id)).where(
        Membership.organization_id == context.organization.id
    )
    if matched is not None:
        count_statement = count_statement.join(User, User.id == Membership.user_id).where(
            func.lower(User.email) == matched.group(1).casefold()
        )
    total = context.session.scalar(count_statement) or 0
    rows = context.session.execute(
        statement.order_by(Membership.created_at, Membership.id)
        .offset(start_index - 1)
        .limit(count)
    ).all()
    resources = [
        _user_resource(context, membership, user)
        for membership, user in rows
    ]
    return _scim_response(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "startIndex": start_index,
            "itemsPerPage": len(resources),
            "Resources": resources,
        }
    )


@router.post("/scim/v2/{organization_slug}/Users", status_code=201)
async def create_scim_user(
    organization_slug: str,
    request: Request,
    context: Annotated[ScimContext, Depends(get_scim_context)],
) -> JSONResponse:
    payload = await _read_scim_json(request)
    email = _email(payload.get("userName"))
    external_id = _external_id(payload.get("externalId"))
    existing_user = context.session.scalar(select(User).where(func.lower(User.email) == email))
    if existing_user is not None and not existing_user.is_active:
        raise _scim_error(409, "The identity is disabled in CloudSentinel.", "uniqueness")
    if existing_user is not None:
        member = context.session.scalar(
            select(Membership).where(
                Membership.organization_id == context.organization.id,
                Membership.user_id == existing_user.id,
            )
        )
        if member is not None:
            raise _scim_error(409, "This user already exists in the organization.", "uniqueness")
    if external_id is not None and context.session.scalar(
        select(Membership.id).where(
            Membership.organization_id == context.organization.id,
            Membership.scim_external_id == external_id,
        )
    ) is not None:
        raise _scim_error(409, "The externalId already exists in this organization.", "uniqueness")
    user = existing_user or User(
        email=email,
        display_name=_display_name(payload, email),
        password_hash=hash_password(secrets.token_urlsafe(48)),
    )
    if existing_user is None:
        context.session.add(user)
        context.session.flush()
    viewer = context.session.scalar(select(Role).where(Role.code == "VIEWER"))
    if viewer is None:
        raise _scim_error(503, "User provisioning is temporarily unavailable.")
    member = Membership(
        organization_id=context.organization.id,
        user_id=user.id,
        role_id=viewer.id,
        scim_external_id=external_id,
        provisioning_source="scim",
    )
    context.session.add(member)
    record_audit(
        context.session,
        organization_id=context.organization.id,
        actor_user_id=None,
        action="identity.scim_user_provisioned",
        resource_type="membership",
        resource_id=member.id,
        details={"email_hash": hashlib.sha256(email.encode()).hexdigest()},
    )
    context.session.commit()
    return _scim_response(_user_resource(context, member, user), status_code=201)


@router.get("/scim/v2/{organization_slug}/Users/{user_id}")
def read_scim_user(
    organization_slug: str,
    user_id: UUID,
    context: Annotated[ScimContext, Depends(get_scim_context)],
) -> JSONResponse:
    membership, user = _get_scim_user(context, user_id)
    return _scim_response(_user_resource(context, membership, user))


@router.put("/scim/v2/{organization_slug}/Users/{user_id}")
async def replace_scim_user(
    organization_slug: str,
    user_id: UUID,
    request: Request,
    context: Annotated[ScimContext, Depends(get_scim_context)],
) -> JSONResponse:
    payload = await _read_scim_json(request)
    membership, user = _get_scim_user(context, user_id)
    _update_scim_user(context, membership, user, payload)
    context.session.commit()
    return _scim_response(_user_resource(context, membership, user))


@router.patch("/scim/v2/{organization_slug}/Users/{user_id}")
async def patch_scim_user(
    organization_slug: str,
    user_id: UUID,
    request: Request,
    context: Annotated[ScimContext, Depends(get_scim_context)],
) -> JSONResponse:
    payload = await _read_scim_json(request)
    membership, user = _get_scim_user(context, user_id)
    operations = payload.get("Operations")
    if not isinstance(operations, list) or len(operations) > 30:
        raise _scim_error(400, "A bounded Operations list is required.", "invalidSyntax")
    current: dict[str, Any] = {
        "userName": user.email,
        "displayName": user.display_name,
        "active": membership.is_active,
        "externalId": membership.scim_external_id,
    }
    for operation in operations:
        if not isinstance(operation, dict):
            raise _scim_error(400, "Invalid SCIM operation.", "invalidSyntax")
        value = operation.get("value")
        path = operation.get("path")
        if path is None and isinstance(value, dict):
            current.update(value)
        elif isinstance(path, str) and path.lower() in {"active", "username", "displayname", "externalid"}:
            key = {"username": "userName", "displayname": "displayName", "externalid": "externalId"}.get(path.lower(), "active")
            current[key] = value
        else:
            raise _scim_error(400, "Unsupported SCIM user patch path.", "noTarget")
    _update_scim_user(context, membership, user, current)
    context.session.commit()
    return _scim_response(_user_resource(context, membership, user))


@router.delete("/scim/v2/{organization_slug}/Users/{user_id}", status_code=204)
def delete_scim_user(
    organization_slug: str,
    user_id: UUID,
    context: Annotated[ScimContext, Depends(get_scim_context)],
) -> Response:
    membership, _user = _get_scim_user(context, user_id)
    _deactivate_membership(context, membership)
    record_audit(
        context.session,
        organization_id=context.organization.id,
        actor_user_id=None,
        action="identity.scim_user_deprovisioned",
        resource_type="membership",
        resource_id=membership.id,
    )
    context.session.commit()
    return Response(status_code=204)


@router.get("/scim/v2/{organization_slug}/Groups")
def list_scim_groups(
    organization_slug: str,
    context: Annotated[ScimContext, Depends(get_scim_context)],
    start_index: Annotated[int, Query(ge=1)] = 1,
    count: Annotated[int, Query(ge=1, le=100)] = 100,
) -> JSONResponse:
    total = context.session.scalar(
        select(func.count(ScimGroup.id)).where(
            ScimGroup.organization_id == context.organization.id,
            ScimGroup.is_active.is_(True),
        )
    ) or 0
    groups = context.session.scalars(
        select(ScimGroup)
        .where(
            ScimGroup.organization_id == context.organization.id,
            ScimGroup.is_active.is_(True),
        )
        .order_by(ScimGroup.display_name, ScimGroup.id)
        .offset(start_index - 1)
        .limit(count)
    ).all()
    resources = [_group_resource(context, group) for group in groups]
    return _scim_response(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "startIndex": start_index,
            "itemsPerPage": len(resources),
            "Resources": resources,
        }
    )


@router.post("/scim/v2/{organization_slug}/Groups", status_code=201)
async def create_scim_group(
    organization_slug: str,
    request: Request,
    context: Annotated[ScimContext, Depends(get_scim_context)],
) -> JSONResponse:
    payload = await _read_scim_json(request)
    external_id = _external_id(payload.get("externalId"))
    if external_id is None:
        raise _scim_error(400, "SCIM group externalId is required.", "invalidValue")
    group = context.session.scalar(
        select(ScimGroup).where(
            ScimGroup.organization_id == context.organization.id,
            ScimGroup.external_id == external_id,
        )
    )
    if group is None:
        raise _scim_error(403, "An administrator must map this group before provisioning.", "mutability")
    group.display_name = _group_name(payload, external_id)
    group.is_active = True
    members = payload.get("members", [])
    if not isinstance(members, list) or len(members) > 500:
        raise _scim_error(400, "A bounded members list is required.", "invalidValue")
    for member_item in members:
        await _add_group_member(context, group, member_item)
    record_audit(
        context.session,
        organization_id=context.organization.id,
        actor_user_id=None,
        action="identity.scim_group_provisioned",
        resource_type="scim_group",
        resource_id=group.id,
        details={"external_id": external_id},
    )
    context.session.commit()
    return _scim_response(_group_resource(context, group), status_code=201)


@router.get("/scim/v2/{organization_slug}/Groups/{group_id}")
def read_scim_group(
    organization_slug: str,
    group_id: UUID,
    context: Annotated[ScimContext, Depends(get_scim_context)],
) -> JSONResponse:
    group = _get_group(context, group_id)
    return _scim_response(_group_resource(context, group))


@router.patch("/scim/v2/{organization_slug}/Groups/{group_id}")
async def patch_scim_group(
    organization_slug: str,
    group_id: UUID,
    request: Request,
    context: Annotated[ScimContext, Depends(get_scim_context)],
) -> JSONResponse:
    payload = await _read_scim_json(request)
    group = _get_group(context, group_id)
    operations = payload.get("Operations")
    if not isinstance(operations, list) or len(operations) > 30:
        raise _scim_error(400, "A bounded Operations list is required.", "invalidSyntax")
    for operation in operations:
        if not isinstance(operation, dict):
            raise _scim_error(400, "Invalid SCIM operation.", "invalidSyntax")
        action = str(operation.get("op", "")).lower()
        path = operation.get("path")
        if path is None or str(path).lower().startswith("members"):
            values = operation.get("value")
            path_match = re.fullmatch(r'members\[value eq "([^"\\]{1,36})"\]', str(path), re.I) if path else None
            if action == "remove" and path_match is not None:
                values = [{"value": path_match.group(1)}]
            if isinstance(values, dict):
                values = [values]
            if not isinstance(values, list) or len(values) > 500:
                raise _scim_error(400, "SCIM group members must be a bounded list.", "invalidValue")
            if action == "replace":
                existing_links = context.session.scalars(
                    select(ScimGroupMembership).where(
                        ScimGroupMembership.organization_id == context.organization.id,
                        ScimGroupMembership.group_id == group.id,
                    )
                ).all()
                affected = {link.membership_id for link in existing_links}
                for link in existing_links:
                    context.session.delete(link)
                context.session.flush()
                for membership_id in affected:
                    membership = context.session.get(Membership, membership_id)
                    if membership is not None:
                        _recompute_group_role(context, membership)
            for item in values:
                if action in {"add", "replace"}:
                    await _add_group_member(context, group, item)
                elif action == "remove":
                    await _remove_group_member(context, group, item)
                else:
                    raise _scim_error(400, "Unsupported SCIM group operation.", "invalidSyntax")
        else:
            raise _scim_error(400, "Unsupported SCIM group patch path.", "noTarget")
    context.session.commit()
    return _scim_response(_group_resource(context, group))


@router.delete("/scim/v2/{organization_slug}/Groups/{group_id}", status_code=204)
def delete_scim_group(
    organization_slug: str,
    group_id: UUID,
    context: Annotated[ScimContext, Depends(get_scim_context)],
) -> Response:
    group = _get_group(context, group_id)
    links = context.session.scalars(
        select(ScimGroupMembership).where(
            ScimGroupMembership.organization_id == context.organization.id,
            ScimGroupMembership.group_id == group.id,
        )
    ).all()
    membership_ids = {item.membership_id for item in links}
    for link in links:
        context.session.delete(link)
    group.is_active = False
    context.session.flush()
    for membership_id in membership_ids:
        membership = context.session.get(Membership, membership_id)
        if membership is not None:
            _recompute_group_role(context, membership)
    context.session.commit()
    return Response(status_code=204)


async def _read_scim_json(request: Request) -> dict[str, Any]:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_SCIM_BODY_BYTES:
                raise _scim_error(413, "The SCIM request is too large.", "tooLarge")
        except ValueError:
            raise _scim_error(400, "Invalid Content-Length header.", "invalidSyntax") from None
    body = await request.body()
    if len(body) > MAX_SCIM_BODY_BYTES:
        raise _scim_error(413, "The SCIM request is too large.", "tooLarge")
    try:
        payload = await request.json()
    except Exception:
        raise _scim_error(400, "A valid JSON SCIM document is required.", "invalidSyntax") from None
    if not isinstance(payload, dict):
        raise _scim_error(400, "A SCIM resource object is required.", "invalidSyntax")
    return cast(dict[str, Any], payload)


def _email(value: object) -> str:
    if not isinstance(value, str) or len(value) > 320:
        raise _scim_error(400, "A valid userName email address is required.", "invalidValue")
    try:
        return str(EMAIL_ADAPTER.validate_python(value)).strip().casefold()
    except ValidationError:
        raise _scim_error(400, "A valid userName email address is required.", "invalidValue") from None


def _external_id(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise _scim_error(400, "externalId must be a non-empty string of at most 200 characters.", "invalidValue")
    return value.strip()


def _display_name(payload: dict[str, Any], fallback: str) -> str:
    name = payload.get("name")
    display = payload.get("displayName")
    if isinstance(display, str) and display.strip():
        return display.strip()[:200]
    if isinstance(name, dict):
        formatted = name.get("formatted")
        if isinstance(formatted, str) and formatted.strip():
            return formatted.strip()[:200]
        given = str(name.get("givenName", "")).strip()
        family = str(name.get("familyName", "")).strip()
        combined = " ".join(part for part in (given, family) if part)
        if combined:
            return combined[:200]
    return fallback[:200]


def _update_scim_user(
    context: ScimContext, membership: Membership, user: User, payload: dict[str, Any]
) -> None:
    new_email = _email(payload.get("userName", user.email))
    if new_email != user.email.casefold():
        other_membership_count = context.session.scalar(
            select(func.count(Membership.id)).where(
                Membership.user_id == user.id,
                Membership.organization_id != context.organization.id,
                Membership.is_active.is_(True),
            )
        ) or 0
        if other_membership_count:
            raise _scim_error(409, "A shared identity's email cannot be changed by one organization.", "mutability")
        if context.session.scalar(select(User.id).where(func.lower(User.email) == new_email, User.id != user.id)):
            raise _scim_error(409, "This userName is already in use.", "uniqueness")
        user.email = new_email
    name = _display_name(payload, user.display_name)
    if name != user.display_name:
        other_membership_count = context.session.scalar(
            select(func.count(Membership.id)).where(
                Membership.user_id == user.id,
                Membership.organization_id != context.organization.id,
                Membership.is_active.is_(True),
            )
        ) or 0
        if other_membership_count:
            raise _scim_error(409, "A shared identity's name cannot be changed by one organization.", "mutability")
        user.display_name = name
    external_id = _external_id(payload.get("externalId"))
    if external_id != membership.scim_external_id:
        if external_id is not None and context.session.scalar(
            select(Membership.id).where(
                Membership.organization_id == context.organization.id,
                Membership.scim_external_id == external_id,
                Membership.id != membership.id,
            )
        ):
            raise _scim_error(409, "The externalId already exists in this organization.", "uniqueness")
        membership.scim_external_id = external_id
    active = payload.get("active", membership.is_active)
    if not isinstance(active, bool):
        raise _scim_error(400, "active must be a boolean.", "invalidValue")
    if active and not user.is_active:
        raise _scim_error(409, "The identity is disabled in CloudSentinel.", "mutability")
    if membership.is_active and not active:
        _deactivate_membership(context, membership)
    elif active:
        membership.is_active = True
    record_audit(
        context.session,
        organization_id=context.organization.id,
        actor_user_id=None,
        action="identity.scim_user_updated",
        resource_type="membership",
        resource_id=membership.id,
        details={"active": membership.is_active, "email_hash": hashlib.sha256(user.email.encode()).hexdigest()},
    )


def _deactivate_membership(context: ScimContext, membership: Membership) -> None:
    now = datetime.now(UTC)
    membership.is_active = False
    sessions = context.session.scalars(
        select(RefreshSession).where(
            RefreshSession.organization_id == context.organization.id,
            RefreshSession.membership_id == membership.id,
            RefreshSession.revoked_at.is_(None),
        )
    ).all()
    for auth_session in sessions:
        auth_session.revoked_at = now


def _get_scim_user(context: ScimContext, user_id: UUID) -> tuple[Membership, User]:
    row = context.session.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.organization_id == context.organization.id,
            Membership.id == user_id,
        )
    ).first()
    if row is None:
        raise _scim_error(404, "User not found.", "noTarget")
    return row[0], row[1]


def _user_resource(context: ScimContext, membership: Membership, user: User) -> dict[str, Any]:
    group_links = context.session.scalars(
        select(ScimGroupMembership)
        .where(
            ScimGroupMembership.organization_id == context.organization.id,
            ScimGroupMembership.membership_id == membership.id,
        )
        .limit(50)
    ).all()
    groups = []
    for link in group_links:
        group = context.session.get(ScimGroup, link.group_id)
        if group is not None and group.is_active:
            groups.append(
                {"value": str(group.id), "display": group.display_name, "$ref": f"Groups/{group.id}"}
            )
    return {
        "schemas": [USER_SCHEMA],
        "id": str(membership.id),
        "externalId": membership.scim_external_id,
        "userName": user.email,
        "name": {"formatted": user.display_name},
        "displayName": user.display_name,
        "emails": [{"value": user.email, "type": "work", "primary": True}],
        "active": bool(membership.is_active and user.is_active),
        "groups": groups,
        "meta": {"resourceType": "User", "created": membership.created_at.isoformat(), "lastModified": membership.updated_at.isoformat()},
    }


def _group_name(payload: dict[str, Any], fallback: str) -> str:
    display_name = payload.get("displayName")
    if not isinstance(display_name, str) or not display_name.strip():
        return fallback[:200]
    return display_name.strip()[:200]


def _get_group(context: ScimContext, group_id: UUID) -> ScimGroup:
    group = context.session.scalar(
        select(ScimGroup).where(
            ScimGroup.organization_id == context.organization.id,
            ScimGroup.id == group_id,
            ScimGroup.is_active.is_(True),
        )
    )
    if group is None:
        raise _scim_error(404, "Group not found.", "noTarget")
    return group


def _group_resource(context: ScimContext, group: ScimGroup) -> dict[str, Any]:
    rows = context.session.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .join(
            ScimGroupMembership,
            (ScimGroupMembership.membership_id == Membership.id)
            & (ScimGroupMembership.organization_id == context.organization.id),
        )
        .where(
            Membership.organization_id == context.organization.id,
            ScimGroupMembership.group_id == group.id,
            Membership.is_active.is_(True),
            User.is_active.is_(True),
        )
        .order_by(Membership.id)
        .limit(500)
    ).all()
    return {
        "schemas": [GROUP_SCHEMA],
        "id": str(group.id),
        "externalId": group.external_id,
        "displayName": group.display_name,
        "members": [
            {"value": str(membership.id), "display": user.display_name, "$ref": f"Users/{membership.id}"}
            for membership, user in rows
        ],
        "meta": {"resourceType": "Group", "created": group.created_at.isoformat(), "lastModified": group.updated_at.isoformat()},
    }


async def _add_group_member(context: ScimContext, group: ScimGroup, value: object) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("value"), str):
        raise _scim_error(400, "Each group member must include a user resource id.", "invalidValue")
    try:
        member_id = UUID(value["value"])
    except ValueError:
        raise _scim_error(400, "Invalid group member id.", "invalidValue") from None
    membership = context.session.scalar(
        select(Membership).where(
            Membership.organization_id == context.organization.id,
            Membership.id == member_id,
        )
    )
    if membership is None or not membership.is_active:
        raise _scim_error(404, "Group member not found.", "noTarget")
    link = context.session.get(ScimGroupMembership, (group.id, membership.id))
    if link is None:
        link = ScimGroupMembership(
            organization_id=context.organization.id,
            group_id=group.id,
            membership_id=membership.id,
        )
        context.session.add(link)
    if membership.pre_scim_role_id is None:
        membership.pre_scim_role_id = membership.role_id
    context.session.flush()
    _recompute_group_role(context, membership)


async def _remove_group_member(context: ScimContext, group: ScimGroup, value: object) -> None:
    if isinstance(value, str):
        raw_id = value
    elif isinstance(value, dict) and isinstance(value.get("value"), str):
        raw_id = value["value"]
    else:
        raise _scim_error(400, "A group member id is required.", "invalidValue")
    try:
        member_id = UUID(raw_id)
    except ValueError:
        raise _scim_error(400, "Invalid group member id.", "invalidValue") from None
    link = context.session.get(ScimGroupMembership, (group.id, member_id))
    if link is None or link.organization_id != context.organization.id:
        return
    context.session.delete(link)
    context.session.flush()
    membership = context.session.scalar(
        select(Membership).where(
            Membership.organization_id == context.organization.id,
            Membership.id == member_id,
        )
    )
    if membership is not None:
        _recompute_group_role(context, membership)


def _recompute_group_role(context: ScimContext, membership: Membership) -> None:
    rows = context.session.execute(
        select(Role.code, Role.id)
        .join(ScimGroup, ScimGroup.role_id == Role.id)
        .join(ScimGroupMembership, ScimGroupMembership.group_id == ScimGroup.id)
        .where(
            ScimGroupMembership.organization_id == context.organization.id,
            ScimGroupMembership.membership_id == membership.id,
            ScimGroup.organization_id == context.organization.id,
            ScimGroup.is_active.is_(True),
        )
    ).all()
    mapped = [(ROLE_ORDER.get(code, -1), role_id) for code, role_id in rows]
    if mapped:
        membership.role_id = max(mapped, key=lambda item: item[0])[1]
    elif membership.pre_scim_role_id is not None:
        membership.role_id = membership.pre_scim_role_id
        membership.pre_scim_role_id = None
    elif membership.provisioning_source in {"scim", "saml"}:
        default_role = context.session.scalar(select(Role.id).where(Role.code == "VIEWER"))
        if default_role is not None:
            membership.role_id = default_role


def _scim_response(payload: dict[str, Any], status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, media_type="application/scim+json")


def _scim_error(
    status_code: int, message: str, scim_type: str | None = None
) -> ScimProtocolError:
    return ScimProtocolError(status_code, message, scim_type)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
