"""SAML 2.0 SP endpoints and tenant administration for enterprise identity."""

import hashlib
import json
import logging
import secrets
from datetime import UTC, datetime
from typing import Annotated, Any, cast
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.auth.router import _set_session_cookies
from app.auth.schemas import TokenResponse
from app.auth.security import hash_password
from app.auth.service import AuthenticationFailure, issue_federated_session
from app.core.config import Settings
from app.core.database import get_system_session
from app.core.domain_errors import InvalidOperationError, NotFoundError
from app.core.models import (
    Membership,
    Organization,
    Role,
    SamlIdentityProvider,
    User,
    UserMfa,
)
from app.core.redis import RedisClient, get_redis_client
from app.identity.schemas import SamlSettingsRead, SamlSettingsWrite, SsoExchangeRequest
from app.operations.service import record_audit

logger = logging.getLogger("cloudsentinel.identity.saml")
router = APIRouter(tags=["enterprise identity"])
SAML_STATE_COOKIE = "cloudsentinel_saml_state"
SAML_STATE_TTL_SECONDS = 300
SSO_CODE_TTL_SECONDS = 90
SAML_RESPONSE_LIMIT = 180_000
SAML_ENTITY_PREFIX = "urn:cloudsentinel:organization:"
SAML_BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


@router.get("/organizations/current/sso/saml", response_model=SamlSettingsRead)
def read_saml_settings(
    principal: Annotated[Principal, Depends(require_permission("identity:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    request: Request,
) -> SamlSettingsRead:
    configuration = session.scalar(
        select(SamlIdentityProvider).where(
            SamlIdentityProvider.organization_id == principal.organization_id
        )
    )
    organization = session.get(Organization, principal.organization_id)
    if organization is None:
        raise NotFoundError("Organization")
    return _configuration_read(configuration, organization.slug, request.app.state.settings)


@router.put("/organizations/current/sso/saml", response_model=SamlSettingsRead)
async def write_saml_settings(
    payload: SamlSettingsWrite,
    request: Request,
    principal: Annotated[Principal, Depends(require_permission("identity:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> SamlSettingsRead:
    """Save a pasted IdP metadata document after local parsing and trust checks."""
    settings = cast(Settings, request.app.state.settings)
    try:
        idp_data = await run_in_threadpool(_parse_metadata, payload.metadata_xml)
        _validate_idp_https(idp_data, settings)
    except (ValueError, RuntimeError):
        raise InvalidOperationError("The SAML identity provider metadata is invalid.") from None
    if payload.enforce_sso and not payload.is_active:
        raise InvalidOperationError("Enable the SAML connection before enforcing single sign-on.")

    organization = session.get(Organization, principal.organization_id)
    if organization is None or not organization.is_active:
        raise NotFoundError("Organization")
    configuration = session.scalar(
        select(SamlIdentityProvider).where(
            SamlIdentityProvider.organization_id == principal.organization_id
        )
    )
    created = configuration is None
    if configuration is None:
        configuration = SamlIdentityProvider(organization_id=principal.organization_id)
        session.add(configuration)
    before = {
        "active": configuration.is_active,
        "enforce_sso": configuration.enforce_sso,
        "jit_provisioning": configuration.jit_provisioning,
        "require_mfa": configuration.require_mfa,
        "default_role_code": configuration.default_role_code,
    }
    configuration.metadata_xml = payload.metadata_xml
    configuration.is_active = payload.is_active
    configuration.enforce_sso = payload.enforce_sso
    configuration.jit_provisioning = payload.jit_provisioning
    configuration.require_mfa = payload.require_mfa
    configuration.default_role_code = payload.default_role_code
    configuration.email_attribute = payload.email_attribute
    configuration.name_attribute = payload.name_attribute
    configuration.mfa_contexts = payload.mfa_contexts
    record_audit(
        session,
        organization_id=organization.id,
        actor_user_id=principal.user_id,
        action="identity.saml_configuration_updated",
        resource_type="saml_identity_provider",
        resource_id=configuration.id,
        details={
            "before": before,
            "after": {
                "active": payload.is_active,
                "enforce_sso": payload.enforce_sso,
                "jit_provisioning": payload.jit_provisioning,
                "require_mfa": payload.require_mfa,
                "default_role_code": payload.default_role_code,
                "idp_entity_id": idp_data["idp"]["entityId"],
                "metadata_sha256": hashlib.sha256(payload.metadata_xml.encode()).hexdigest(),
                "created": created,
            },
        },
    )
    session.commit()
    return _configuration_read(configuration, organization.slug, settings)


@router.delete("/organizations/current/sso/saml", status_code=204)
def disable_saml_settings(
    principal: Annotated[Principal, Depends(require_permission("identity:manage"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    configuration = session.scalar(
        select(SamlIdentityProvider).where(
            SamlIdentityProvider.organization_id == principal.organization_id
        )
    )
    if configuration is None:
        return Response(status_code=204)
    configuration.is_active = False
    configuration.enforce_sso = False
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="identity.saml_configuration_disabled",
        resource_type="saml_identity_provider",
        resource_id=configuration.id,
    )
    session.commit()
    return Response(status_code=204)


@router.get("/sso/saml/{organization_slug}/metadata")
def saml_metadata(
    organization_slug: str,
    request: Request,
    session: Annotated[Session, Depends(get_system_session)],
) -> Response:
    organization, configuration = _public_configuration(session, organization_slug)
    settings = cast(Settings, request.app.state.settings)
    saml_settings = _saml_settings(organization.slug, configuration, settings)
    service_provider = OneLogin_Saml2_Settings(saml_settings)
    metadata = service_provider.get_sp_metadata()
    errors = service_provider.validate_metadata(metadata)
    if errors:
        logger.error("Generated SAML SP metadata failed validation", extra={"error_count": len(errors)})
        raise HTTPException(status_code=503, detail="SAML is temporarily unavailable.")
    return Response(metadata, media_type="application/samlmetadata+xml")


@router.get("/sso/saml/{organization_slug}/login")
async def saml_login(
    organization_slug: str,
    request: Request,
    redis: Annotated[RedisClient, Depends(get_redis_client)],
    session: Annotated[Session, Depends(get_system_session)],
) -> RedirectResponse:
    organization, configuration = _public_configuration(session, organization_slug)
    settings = cast(Settings, request.app.state.settings)
    toolkit_request = _toolkit_request(
        settings, f"/sso/saml/{organization.slug}/login", {}
    )
    try:
        auth = OneLogin_Saml2_Auth(
            toolkit_request,
            _saml_settings(organization.slug, configuration, settings),
        )
        redirect_url = auth.login()
        request_id = auth.get_last_request_id()
    except Exception as error:
        logger.warning("SAML authentication request could not be created", extra={"error_type": type(error).__name__})
        raise HTTPException(status_code=503, detail="SAML is temporarily unavailable.") from None
    if not isinstance(request_id, str) or not request_id or not isinstance(redirect_url, str):
        raise HTTPException(status_code=503, detail="SAML is temporarily unavailable.")
    state = secrets.token_urlsafe(32)
    state_key = _redis_key("saml-state", state)
    redis_client = cast(Any, redis)
    stored = await redis_client.set(state_key, request_id, ex=SAML_STATE_TTL_SECONDS, nx=True)
    if not stored:
        raise HTTPException(status_code=503, detail="SAML is temporarily unavailable.")
    response = RedirectResponse(redirect_url, status_code=303)
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(
        SAML_STATE_COOKIE,
        state,
        max_age=SAML_STATE_TTL_SECONDS,
        httponly=True,
        secure=settings.app_env in {"staging", "production"},
        samesite="none" if settings.app_env in {"staging", "production"} else "lax",
        path=f"/sso/saml/{organization.slug}/acs",
    )
    return response


@router.post("/sso/saml/{organization_slug}/acs")
async def saml_acs(
    organization_slug: str,
    request: Request,
    redis: Annotated[RedisClient, Depends(get_redis_client)],
    session: Annotated[Session, Depends(get_system_session)],
) -> RedirectResponse:
    organization, configuration = _public_configuration(session, organization_slug)
    settings = cast(Settings, request.app.state.settings)
    state = request.cookies.get(SAML_STATE_COOKIE)
    redis_client = cast(Any, redis)
    content_length = request.headers.get("content-length")
    try:
        declared_length = int(content_length) if content_length is not None else 0
    except ValueError:
        raise _saml_rejected() from None
    if declared_length <= 0 or declared_length > SAML_RESPONSE_LIMIT + 32_000:
        raise _saml_rejected()
    if not state or len(state) > 128:
        raise _saml_rejected()
    request_id = await redis_client.getdel(_redis_key("saml-state", state))
    if not isinstance(request_id, str) or not request_id:
        raise _saml_rejected()

    try:
        form = await request.form(max_files=0, max_fields=20, max_part_size=SAML_RESPONSE_LIMIT)
        saml_response = form.get("SAMLResponse")
        if not isinstance(saml_response, str) or len(saml_response) > SAML_RESPONSE_LIMIT:
            raise ValueError("SAML response exceeds the configured size limit")
        post_data = {str(key): str(value) for key, value in form.items()}
        toolkit_request = _toolkit_request(
            settings, f"/sso/saml/{organization.slug}/acs", post_data
        )
        attributes, assertion_id, authentication_contexts = await run_in_threadpool(
            _process_saml_response,
            toolkit_request,
            _saml_settings(organization.slug, configuration, settings),
            request_id,
        )
        if not assertion_id:
            raise ValueError("Missing SAML assertion identifier")
        replay_key = f"cloudsentinel:saml-assertion:{hashlib.sha256(assertion_id.encode()).hexdigest()}"
        if not await redis_client.set(replay_key, "1", ex=7200, nx=True):
            raise ValueError("SAML assertion replay")
    except Exception as error:
        logger.info("SAML assertion was rejected", extra={"error_type": type(error).__name__})
        raise _saml_rejected() from None

    email_value = _first_attribute(attributes, configuration.email_attribute)
    if email_value is None or len(email_value) > 320 or "@" not in email_value:
        raise _saml_rejected()
    email = email_value.strip().casefold()
    name = _first_attribute(attributes, configuration.name_attribute) or email
    name = name.strip()[:200] or email
    user = session.scalar(select(User).where(User.email == email).with_for_update())
    if user is not None and not user.is_active:
        raise _saml_rejected()
    membership = (
        session.scalar(
            select(Membership)
            .where(
                Membership.organization_id == organization.id,
                Membership.user_id == user.id,
            )
            .with_for_update()
        )
        if user is not None
        else None
    )
    if membership is None:
        if not configuration.jit_provisioning:
            raise _saml_rejected()
        role = session.scalar(
            select(Role).where(Role.code == configuration.default_role_code)
        )
        if role is None:
            raise _saml_rejected()
        if user is None:
            user = User(
                email=email,
                display_name=name,
                password_hash=hash_password(secrets.token_urlsafe(48)),
            )
            session.add(user)
            session.flush()
        membership = Membership(
            organization_id=organization.id,
            user_id=user.id,
            role_id=role.id,
            provisioning_source="saml",
        )
        session.add(membership)
        session.flush()
        record_audit(
            session,
            organization_id=organization.id,
            actor_user_id=None,
            action="identity.saml_user_provisioned",
            resource_type="membership",
            resource_id=membership.id,
            details={"email_hash": hashlib.sha256(email.encode()).hexdigest(), "role": role.code},
        )
    elif not membership.is_active or membership.is_locked:
        raise _saml_rejected()

    mfa = session.scalar(select(UserMfa).where(UserMfa.user_id == user.id))
    if (configuration.require_mfa or (mfa is not None and mfa.is_enabled)) and not set(
        configuration.mfa_contexts
    ).intersection(authentication_contexts):
        logger.warning("SAML sign-in lacked a configured MFA authentication context")
        raise _saml_rejected()

    record_audit(
        session,
        organization_id=organization.id,
        actor_user_id=user.id,
        action="identity.saml_login_succeeded",
        resource_type="user",
        resource_id=user.id,
        details={"authentication_contexts": authentication_contexts},
    )
    session.commit()
    code = secrets.token_urlsafe(32)
    exchange_payload = json.dumps(
        {
            "organization_id": str(organization.id),
            "user_id": str(user.id),
            "membership_id": str(membership.id),
            "authentication_contexts": authentication_contexts,
        },
        separators=(",", ":"),
    )
    stored = await redis_client.set(
        _redis_key("saml-code", code), exchange_payload, ex=SSO_CODE_TTL_SECONDS, nx=True
    )
    if not stored:
        raise HTTPException(status_code=503, detail="SAML is temporarily unavailable.")
    callback = f"{settings.frontend_base_url.rstrip('/')}/sso/callback?code={code}"
    redirect = RedirectResponse(callback, status_code=303)
    redirect.headers["Cache-Control"] = "no-store"
    redirect.delete_cookie(
        SAML_STATE_COOKIE,
        path=f"/sso/saml/{organization.slug}/acs",
        secure=settings.app_env in {"staging", "production"},
        httponly=True,
        samesite="none" if settings.app_env in {"staging", "production"} else "lax",
    )
    return redirect


@router.post("/auth/sso/exchange", response_model=TokenResponse)
async def exchange_sso_code(
    payload: SsoExchangeRequest,
    request: Request,
    response: Response,
    redis: Annotated[RedisClient, Depends(get_redis_client)],
    session: Annotated[Session, Depends(get_system_session)],
) -> TokenResponse:
    """Consume a short-lived, one-use SAML code and create a normal app session."""
    redis_client = cast(Any, redis)
    exchange = await redis_client.getdel(_redis_key("saml-code", payload.code))
    if not isinstance(exchange, str):
        raise _saml_rejected()
    try:
        identity = json.loads(exchange)
        organization_id = UUID(identity["organization_id"])
        user_id = UUID(identity["user_id"])
        membership_id = UUID(identity["membership_id"])
        contexts = identity["authentication_contexts"]
        if not isinstance(contexts, list) or any(not isinstance(item, str) for item in contexts):
            raise ValueError("Invalid authentication context")
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise _saml_rejected() from None
    configuration = session.scalar(
        select(SamlIdentityProvider).where(
            SamlIdentityProvider.organization_id == organization_id,
            SamlIdentityProvider.is_active.is_(True),
        )
    )
    user_mfa = session.scalar(select(UserMfa).where(UserMfa.user_id == user_id))
    if (
        configuration is None
        or (
            (configuration.require_mfa or (user_mfa is not None and user_mfa.is_enabled))
            and not set(configuration.mfa_contexts).intersection(contexts)
        )
    ):
        raise _saml_rejected()
    settings = cast(Settings, request.app.state.settings)
    try:
        result, refresh_token, csrf_token = await run_in_threadpool(
            issue_federated_session,
            session,
            settings,
            user_id=user_id,
            membership_id=membership_id,
            organization_id=organization_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except AuthenticationFailure:
        raise _saml_rejected() from None
    _set_session_cookies(
        response,
        settings,
        refresh_token,
        csrf_token,
        False,
        result.refresh_expires_in,
    )
    response.headers["Cache-Control"] = "no-store"
    return result


def _configuration_read(
    configuration: SamlIdentityProvider | None, organization_slug: str, settings: Settings
) -> SamlSettingsRead:
    base = settings.public_api_base_url.rstrip("/")
    configured = configuration is not None
    return SamlSettingsRead(
        configured=configured,
        active=bool(configuration and configuration.is_active),
        enforce_sso=bool(configuration and configuration.enforce_sso),
        jit_provisioning=bool(configuration and configuration.jit_provisioning),
        require_mfa=bool(configuration and configuration.require_mfa),
        default_role_code=configuration.default_role_code if configuration else "VIEWER",
        email_attribute=configuration.email_attribute if configuration else "email",
        name_attribute=configuration.name_attribute if configuration else "name",
        mfa_contexts=configuration.mfa_contexts if configuration else [],
        metadata_url=f"{base}/sso/saml/{organization_slug}/metadata",
        login_url=f"{base}/sso/saml/{organization_slug}/login",
    )


def _public_configuration(
    session: Session, organization_slug: str
) -> tuple[Organization, SamlIdentityProvider]:
    row = session.execute(
        select(Organization, SamlIdentityProvider)
        .join(
            SamlIdentityProvider,
            SamlIdentityProvider.organization_id == Organization.id,
        )
        .where(
            Organization.slug == organization_slug,
            Organization.is_active.is_(True),
            SamlIdentityProvider.is_active.is_(True),
        )
    ).first()
    if row is None:
        raise NotFoundError("SAML connection")
    return row[0], row[1]


def _parse_metadata(metadata_xml: str) -> dict[str, Any]:
    parsed = OneLogin_Saml2_IdPMetadataParser.parse(metadata_xml)
    idp = parsed.get("idp") if isinstance(parsed, dict) else None
    if not isinstance(idp, dict) or not isinstance(idp.get("entityId"), str):
        raise ValueError("IdP entity identifier is missing")
    service = idp.get("singleSignOnService")
    if not isinstance(service, dict) or not isinstance(service.get("url"), str):
        raise ValueError("IdP SSO service is missing")
    if not isinstance(idp.get("x509cert"), str) or not idp["x509cert"].strip():
        raise ValueError("IdP signing certificate is missing")
    return parsed


def _validate_idp_https(idp_data: dict[str, Any], settings: Settings) -> None:
    if settings.app_env not in {"staging", "production"}:
        return
    url = str(idp_data["idp"]["singleSignOnService"]["url"])
    if urlsplit(url).scheme != "https":
        raise ValueError("Production identity providers must use HTTPS")


def _saml_settings(
    organization_slug: str, configuration: SamlIdentityProvider, settings: Settings
) -> dict[str, Any]:
    parsed = _parse_metadata(configuration.metadata_xml)
    _validate_idp_https(parsed, settings)
    base = settings.public_api_base_url.rstrip("/")
    entity_id = f"{SAML_ENTITY_PREFIX}{organization_slug}"
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": entity_id,
            "assertionConsumerService": {
                "url": f"{base}/sso/saml/{organization_slug}/acs",
                "binding": SAML_BINDING_POST,
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "x509cert": "",
            "privateKey": "",
        },
        "idp": parsed["idp"],
        "security": {
            "authnRequestsSigned": False,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "signMetadata": False,
            "wantMessagesSigned": True,
            "wantAssertionsSigned": True,
            "wantAssertionsEncrypted": False,
            "wantNameIdEncrypted": False,
            "wantNameId": True,
            "requestedAuthnContext": False,
            "rejectUnsolicitedResponsesWithInResponseTo": True,
            "allowRepeatAttributeName": False,
            "rejectDeprecatedAlgorithm": True,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def _toolkit_request(
    settings: Settings, path: str, post_data: dict[str, str]
) -> dict[str, object]:
    public_url = urlsplit(settings.public_api_base_url)
    query = ""
    return {
        "http_host": public_url.netloc,
        "script_name": path,
        "request_uri": path,
        "query_string": query,
        "https": "on" if public_url.scheme == "https" else "off",
        "get_data": {},
        "post_data": post_data,
    }


def _process_saml_response(
    toolkit_request: dict[str, object], settings_data: dict[str, Any], request_id: str
) -> tuple[dict[str, list[str]], str | None, list[str]]:
    auth = OneLogin_Saml2_Auth(toolkit_request, settings_data)
    auth.process_response(request_id=request_id)
    if auth.get_errors() or not auth.is_authenticated():
        raise ValueError("SAML response validation failed")
    raw_attributes = auth.get_attributes()
    attributes = {
        str(name): [str(value) for value in values]
        for name, values in raw_attributes.items()
        if isinstance(values, (list, tuple))
    }
    contexts = [str(value) for value in auth.get_last_authn_contexts() or []]
    return attributes, auth.get_last_assertion_id(), contexts


def _first_attribute(attributes: dict[str, list[str]], name: str) -> str | None:
    values = attributes.get(name)
    return values[0] if values and isinstance(values[0], str) else None


def _redis_key(kind: str, value: str) -> str:
    return f"cloudsentinel:{kind}:{hashlib.sha256(value.encode()).hexdigest()}"


def _saml_rejected() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unable to complete SAML sign-in.",
    )
