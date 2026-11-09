"""Login, refresh, logout, and current-principal endpoints."""

import hmac
from typing import Annotated, cast
from uuid import UUID

import pyotp
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.auth.dependencies import Principal, get_current_principal, get_tenant_session
from app.auth.mfa import (
    create_recovery_codes,
    encrypt_totp_secret,
    generate_totp_secret,
    verify_and_consume_mfa_code,
    verify_totp_code,
)
from app.auth.recovery import (
    RATE_LIMIT_SCRIPT,
    create_recovery_request,
    enforce_login_rate_limit,
    enforce_recovery_rate_limit,
    login_rate_limit_keys,
    recovery_rate_limit_keys,
    send_recovery_email,
)
from app.auth.schemas import (
    AcceptInvitationRequest,
    ForcePasswordChangeRequest,
    InvitationAccepted,
    LoginRequest,
    MfaChallenge,
    MfaCodeRequest,
    MfaDisableRequest,
    MfaSetupRequest,
    MfaSetupResponse,
    MfaStatus,
    PasswordChangeAccepted,
    PasswordRecoveryAccepted,
    PasswordRecoveryRequest,
    PasswordResetAccepted,
    PasswordResetRequest,
    PasswordResetTokenRequest,
    SessionRead,
    TokenResponse,
)
from app.auth.security import verify_password
from app.auth.service import (
    AuthenticationFailure,
    MultiFactorChallengeRequired,
    authenticate,
    force_change_password,
    password_minimum_for_reset_token,
    password_minimum_for_user,
    reset_password,
    revoke_refresh_session,
    rotate_session,
    validate_password_reset_token,
)
from app.core.config import Settings
from app.core.database import get_system_session
from app.core.domain_errors import InvalidOperationError
from app.core.models import RefreshSession, User, UserMfa, utc_now
from app.core.redis import RedisClient, get_redis_client
from app.operations.service import record_audit
from app.users.service import accept_invitation, invitation_password_minimum

router = APIRouter(prefix="/auth", tags=["authentication"])
REFRESH_COOKIE = "cloudsentinel_refresh"
CSRF_COOKIE = "cloudsentinel_csrf"
RECOVERY_MESSAGE = "If an account exists for this email, a password reset link has been sent."


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={202: {"model": MfaChallenge}},
)
async def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    session: Annotated[Session, Depends(get_system_session)],
    redis: Annotated[RedisClient, Depends(get_redis_client)],
) -> TokenResponse | JSONResponse:
    """Authenticate an explicit or uniquely resolved active organization membership."""
    settings = cast(Settings, request.app.state.settings)
    client_ip = request.client.host if request.client is not None else "unknown"
    email_key, ip_key = login_rate_limit_keys(settings, str(payload.email), client_ip)
    try:
        counters = await redis.eval(
            RATE_LIMIT_SCRIPT,
            2,
            ip_key,
            email_key,
            settings.login_rate_limit_per_email,
            settings.login_rate_limit_window_seconds,
        )
        limited = enforce_login_rate_limit(
            counters,
            email_limit=settings.login_rate_limit_per_email,
            ip_limit=settings.login_rate_limit_per_ip,
        )
    except (RedisError, TypeError, ValueError, RuntimeError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable.",
        ) from None
    if limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(settings.login_rate_limit_window_seconds)},
        )
    try:
        result, refresh_token, csrf_token = await run_in_threadpool(
            authenticate,
            session,
            settings,
            email=str(payload.email).lower(),
            organization_slug=payload.organization_slug,
            password=payload.password,
            mfa_code=payload.mfa_code,
            remember_session=payload.remember_session,
            ip_address=client_ip if client_ip != "unknown" else None,
            user_agent=request.headers.get("user-agent"),
        )
    except AuthenticationFailure:
        raise _invalid_login() from None
    except MultiFactorChallengeRequired:
        response.headers["Cache-Control"] = "no-store"
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={"mfa_required": True},
            headers={"Cache-Control": "no-store"},
        )
    _set_session_cookies(
        response,
        settings,
        refresh_token,
        csrf_token,
        result.remember_session,
        result.refresh_expires_in,
    )
    return result


@router.get("/mfa", response_model=MfaStatus)
def get_mfa_status(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_system_session)],
) -> MfaStatus:
    """Return only whether the current identity has an enabled or pending MFA setup."""
    enrollment = session.scalar(
        select(UserMfa).where(UserMfa.user_id == principal.user_id)
    )
    return MfaStatus(
        enabled=bool(enrollment and enrollment.is_enabled),
        pending_enrollment=bool(enrollment and not enrollment.is_enabled),
    )


@router.post("/mfa/setup", response_model=MfaSetupResponse)
def setup_mfa(
    payload: MfaSetupRequest,
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_system_session)],
) -> MfaSetupResponse:
    """Start a password-confirmed TOTP enrollment and return recovery codes once."""
    response.headers["Cache-Control"] = "no-store"
    settings = cast(Settings, request.app.state.settings)
    user = session.get(User, principal.user_id)
    if user is None or not verify_password(payload.current_password, user.password_hash):
        raise _invalid_login()
    enrollment = session.scalar(
        select(UserMfa).where(UserMfa.user_id == principal.user_id).with_for_update()
    )
    if enrollment is not None and enrollment.is_enabled:
        raise HTTPException(
            status_code=409,
            detail="Multi-factor authentication is already enabled.",
        )
    secret = generate_totp_secret()
    try:
        encrypted_secret = encrypt_totp_secret(settings, secret)
    except RuntimeError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Multi-factor authentication is not configured for this environment.",
        ) from None
    recovery_codes, recovery_digests = create_recovery_codes()
    if enrollment is None:
        enrollment = UserMfa(
            user_id=principal.user_id,
            secret_ciphertext=encrypted_secret,
            recovery_code_digests=recovery_digests,
        )
        session.add(enrollment)
    else:
        enrollment.secret_ciphertext = encrypted_secret
        enrollment.recovery_code_digests = recovery_digests
        enrollment.last_totp_counter = None
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.mfa.setup_started",
        resource_type="user_mfa",
        resource_id=str(principal.user_id),
        details={"recovery_codes_generated": len(recovery_codes)},
    )
    session.commit()
    return MfaSetupResponse(
        secret=secret,
        otpauth_url=pyotp.TOTP(secret).provisioning_uri(
            name=user.email, issuer_name=settings.app_name
        ),
        recovery_codes=recovery_codes,
    )


@router.post("/mfa/verify", response_model=MfaStatus)
def verify_mfa_enrollment(
    payload: MfaCodeRequest,
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_system_session)],
) -> MfaStatus:
    """Confirm the first TOTP code before enabling MFA for the identity."""
    response.headers["Cache-Control"] = "no-store"
    enrollment = session.scalar(
        select(UserMfa).where(UserMfa.user_id == principal.user_id).with_for_update()
    )
    if enrollment is None or enrollment.is_enabled:
        raise HTTPException(status_code=409, detail="No pending multi-factor setup was found.")
    if not verify_totp_code(cast(Settings, request.app.state.settings), enrollment, payload.code):
        raise HTTPException(status_code=400, detail="The authenticator code is invalid or expired.")
    enrollment.is_enabled = True
    enrollment.verified_at = utc_now()
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.mfa.enabled",
        resource_type="user_mfa",
        resource_id=str(principal.user_id),
        details={},
    )
    session.commit()
    return MfaStatus(enabled=True, pending_enrollment=False)


@router.post("/mfa/disable", response_model=MfaStatus)
def disable_mfa(
    payload: MfaDisableRequest,
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_system_session)],
) -> MfaStatus:
    """Disable MFA only after a fresh password and second-factor verification."""
    response.headers["Cache-Control"] = "no-store"
    user = session.get(User, principal.user_id)
    if user is None or not verify_password(payload.current_password, user.password_hash):
        raise _invalid_login()
    enrollment = session.scalar(
        select(UserMfa).where(UserMfa.user_id == principal.user_id).with_for_update()
    )
    if enrollment is None or not enrollment.is_enabled:
        raise HTTPException(status_code=409, detail="Multi-factor authentication is not enabled.")
    settings = cast(Settings, request.app.state.settings)
    if not verify_and_consume_mfa_code(session, settings, enrollment, payload.code):
        raise HTTPException(
            status_code=400,
            detail="The authenticator or recovery code is invalid.",
        )
    session.delete(enrollment)
    now = utc_now()
    session.execute(
        update(RefreshSession)
        .where(
            RefreshSession.user_id == principal.user_id,
            RefreshSession.id != principal.session_id,
            RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.mfa.disabled",
        resource_type="user_mfa",
        resource_id=str(principal.user_id),
        details={"other_sessions_revoked": True},
    )
    session.commit()
    return MfaStatus(enabled=False, pending_enrollment=False)


@router.post(
    "/forgot-password",
    response_model=PasswordRecoveryAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def forgot_password(
    payload: PasswordRecoveryRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_system_session)],
) -> PasswordRecoveryAccepted:
    """Rate limit and queue generic password recovery for an active identity."""
    settings = cast(Settings, request.app.state.settings)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    if not settings.smtp_host or not settings.smtp_from_email:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

    email = str(payload.email).strip().lower()
    client_ip = request.client.host if request.client is not None else "unknown"
    email_key, ip_key = recovery_rate_limit_keys(settings, email, client_ip)
    try:
        counters = await get_redis_client(request).eval(
            RATE_LIMIT_SCRIPT,
            2,
            email_key,
            ip_key,
            settings.password_reset_rate_limit_requests,
            settings.password_reset_rate_limit_window_seconds,
        )
    except RedisError:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE) from None
    try:
        limited = enforce_recovery_rate_limit(
            counters, limit=settings.password_reset_rate_limit_requests
        )
    except (TypeError, ValueError, RuntimeError):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE) from None
    if limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(settings.password_reset_rate_limit_window_seconds)},
        )

    delivery = await run_in_threadpool(create_recovery_request, session, settings, email)
    if delivery is not None:
        background_tasks.add_task(send_recovery_email, settings, delivery)
    return PasswordRecoveryAccepted(message=RECOVERY_MESSAGE)


@router.post("/password-reset/validate", status_code=status.HTTP_200_OK)
def validate_reset_token(
    payload: PasswordResetTokenRequest,
    response: Response,
    session: Annotated[Session, Depends(get_system_session)],
) -> dict[str, int | bool]:
    """Validate a reset link without revealing any account identity."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    if not validate_password_reset_token(session, payload.token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset link is invalid or expired",
        )
    minimum_length = password_minimum_for_reset_token(session, payload.token)
    return {"valid": True, "minimum_length": minimum_length}


@router.post("/password-reset", response_model=PasswordResetAccepted)
def complete_password_reset(
    payload: PasswordResetRequest,
    response: Response,
    request: Request,
    session: Annotated[Session, Depends(get_system_session)],
) -> PasswordResetAccepted:
    """Consume the one-time recovery token and revoke every active session."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    try:
        reset_password(session, payload.token, payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except AuthenticationFailure:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset link is invalid or expired",
        ) from None
    _clear_session_cookies(response, cast(Settings, request.app.state.settings))
    return PasswordResetAccepted()


@router.post("/change-password", response_model=PasswordChangeAccepted)
def complete_forced_password_change(
    payload: ForcePasswordChangeRequest,
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_system_session)],
) -> PasswordChangeAccepted:
    """Require a password change for a currently authenticated marked identity."""
    try:
        force_change_password(
            session,
            user_id=principal.user_id,
            session_id=principal.session_id,
            current_password=payload.current_password,
            new_password=payload.new_password,
        )
    except AuthenticationFailure:
        raise _invalid_login() from None
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from None
    return PasswordChangeAccepted()


@router.post("/accept-invitation", response_model=InvitationAccepted)
def accept_user_invitation(
    payload: AcceptInvitationRequest,
    session: Annotated[Session, Depends(get_system_session)],
) -> InvitationAccepted:
    """Accept a one-time organization invitation and establish a password."""
    accept_invitation(session, token=payload.token, password=payload.password)
    return InvitationAccepted()


@router.post("/invitation/validate")
def validate_invitation(
    payload: PasswordResetTokenRequest,
    response: Response,
    session: Annotated[Session, Depends(get_system_session)],
) -> dict[str, int | bool]:
    """Validate an invitation link and return only its password minimum."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    try:
        minimum_length = invitation_password_minimum(session, payload.token)
    except InvalidOperationError:
        raise HTTPException(
            status_code=400, detail="Invitation link is invalid or expired"
        ) from None
    return {"valid": True, "minimum_length": minimum_length}


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_system_session)],
    csrf_header: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> TokenResponse | Response:
    """Rotate the HttpOnly refresh cookie after double-submit CSRF validation."""
    settings = cast(Settings, request.app.state.settings)
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    csrf_cookie = request.cookies.get(CSRF_COOKIE)
    if (
        not refresh_token
        or not csrf_cookie
        or csrf_header is None
        or not hmac.compare_digest(csrf_cookie, csrf_header)
    ):
        return _invalid_refresh_response(settings)
    try:
        result, replacement, csrf_token = rotate_session(
            session, settings, refresh_token=refresh_token
        )
    except AuthenticationFailure:
        return _invalid_refresh_response(settings)
    _set_session_cookies(
        response,
        settings,
        replacement,
        csrf_token,
        result.remember_session,
        result.refresh_expires_in,
    )
    return result


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_system_session)],
    csrf_header: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    """Revoke the refresh session and clear its browser cookies."""
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    csrf_cookie = request.cookies.get(CSRF_COOKIE)
    if (
        refresh_token
        and csrf_cookie
        and csrf_header
        and hmac.compare_digest(csrf_cookie, csrf_header)
    ):
        revoke_refresh_session(session, refresh_token)
    _clear_session_cookies(response, cast(Settings, request.app.state.settings))
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me")
def current_user(
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> dict[str, object]:
    """Return the active token principal's current authorization context."""
    return {
        "user_id": str(principal.user_id),
        "membership_id": str(principal.membership_id),
        "organization_id": str(principal.organization_id),
        "role": principal.role_code,
        "permissions": sorted(principal.permissions),
        "force_password_change": principal.force_password_change,
    }


@router.get("/password-policy")
def current_password_policy(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_system_session)],
) -> dict[str, int]:
    """Expose only the authenticated identity's effective password minimum."""
    return {"minimum_length": password_minimum_for_user(session, principal.user_id)}


@router.get("/sessions", response_model=list[SessionRead])
def list_sessions(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[SessionRead]:
    """List unexpired active sessions for the authenticated user only."""
    rows = session.scalars(
        select(RefreshSession)
        .where(
            RefreshSession.organization_id == principal.organization_id,
            RefreshSession.user_id == principal.user_id,
            RefreshSession.revoked_at.is_(None),
            RefreshSession.expires_at > utc_now(),
        )
        .order_by(RefreshSession.created_at.desc())
    ).all()
    return [
        SessionRead(
            id=str(row.id),
            created_at=row.created_at,
            last_used_at=row.last_used_at,
            expires_at=row.expires_at,
            current=row.id == principal.session_id,
        )
        for row in rows
    ]


@router.post("/sessions/revoke-others", status_code=status.HTTP_204_NO_CONTENT)
def revoke_other_sessions(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    """Revoke all other active sessions without invalidating this request."""
    session.execute(
        update(RefreshSession)
        .where(
            RefreshSession.organization_id == principal.organization_id,
            RefreshSession.user_id == principal.user_id,
            RefreshSession.id != principal.session_id,
            RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=utc_now())
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.sessions_revoked",
        resource_type="user",
        resource_id=principal.user_id,
        details={"scope": "other_sessions"},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(
    session_id: UUID,
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    """Revoke a selected session belonging to the authenticated user."""
    row = session.scalar(
        select(RefreshSession).where(
            RefreshSession.id == session_id,
            RefreshSession.organization_id == principal.organization_id,
            RefreshSession.user_id == principal.user_id,
            RefreshSession.revoked_at.is_(None),
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Session not found")
    row.revoked_at = utc_now()
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.session_revoked",
        resource_type="auth_session",
        resource_id=row.id,
        details={"current": row.id == principal.session_id},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _set_session_cookies(
    response: Response,
    settings: Settings,
    refresh_token: str,
    csrf_token: str,
    remember_session: bool,
    refresh_expires_in: int,
) -> None:
    secure = settings.app_env in {"staging", "production"}
    max_age = refresh_expires_in if remember_session else None
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/auth",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


def _clear_session_cookies(response: Response, settings: Settings) -> None:
    secure = settings.app_env in {"staging", "production"}
    response.delete_cookie(
        REFRESH_COOKIE, path="/auth", secure=secure, httponly=True, samesite="strict"
    )
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, httponly=False, samesite="strict")


def _invalid_refresh_response(settings: Settings) -> JSONResponse:
    """Reject stale refresh credentials and remove their browser cookies."""
    response = JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": "Bearer"},
        content={"error": {"code": "http_error", "message": "Unauthorized"}},
    )
    _clear_session_cookies(response, settings)
    return response


def _invalid_login() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
