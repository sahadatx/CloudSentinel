"""Validated request and response contracts for foundation authentication."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    """Credentials with optional organization scope for multi-organization identities."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    organization_slug: str | None = Field(
        default=None, min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9-]*$"
    )
    password: str = Field(min_length=1, max_length=1024)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=20)
    remember_session: bool = False


class MfaChallenge(BaseModel):
    """Signal that valid primary credentials need a second factor before a session is issued."""

    mfa_required: bool = True


class MfaStatus(BaseModel):
    enabled: bool
    pending_enrollment: bool


class MfaSetupRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_url: str
    recovery_codes: list[str]


class MfaCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=20)


class MfaDisableRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=20)


class PasswordRecoveryRequest(BaseModel):
    """Request a password reset without revealing whether the identity exists."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr


class PasswordRecoveryAccepted(BaseModel):
    """Generic response shared by known and unknown email addresses."""

    message: str = "If an account exists for this email, a password reset link has been sent."


class PasswordResetTokenRequest(BaseModel):
    """Validate or consume an emailed one-time recovery token."""

    token: str = Field(min_length=32, max_length=128)


class PasswordResetRequest(PasswordResetTokenRequest):
    """Set a new password after possession of a valid recovery token."""

    new_password: str = Field(min_length=1, max_length=128)


class PasswordResetAccepted(BaseModel):
    status: str = "password_updated"


class PasswordChangeAccepted(BaseModel):
    force_password_change: bool = False


class ForcePasswordChangeRequest(BaseModel):
    """Change a password in an authenticated forced-change session."""

    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class AuthenticatedUser(BaseModel):
    """Safe identity fields returned to the caller."""

    id: str
    email: str
    display_name: str
    organization_id: str
    membership_id: str
    role: str
    permissions: list[str]
    force_password_change: bool = False


class TokenResponse(BaseModel):
    """Short-lived bearer token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    remember_session: bool = False
    refresh_expires_in: int
    user: AuthenticatedUser


class AcceptInvitationRequest(BaseModel):
    """One-time invitation acceptance establishes a local password."""

    token: str = Field(min_length=32, max_length=128)
    password: str = Field(min_length=1, max_length=128)


class InvitationAccepted(BaseModel):
    """Non-sensitive invitation acceptance result."""

    status: str = "accepted"


class SessionRead(BaseModel):
    """Safe metadata for a refresh session owned by the current user."""

    id: str
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime
    current: bool
