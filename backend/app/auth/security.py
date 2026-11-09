"""Password hashing, access token issuance, and refresh-token primitives."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError
from pwdlib.hashers.argon2 import Argon2Hasher

from app.core.config import Settings

ALGORITHM = "HS256"
ISSUER = "cloudsentinel"
AUDIENCE = "cloudsentinel-api"
_password_hash = PasswordHash((Argon2Hasher(),))
_DUMMY_PASSWORD_HASH = _password_hash.hash("constant-timing-only-not-a-login")


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password, performing a dummy Argon2 verification for malformed hashes."""
    try:
        return _password_hash.verify(password, password_hash)
    except (ValueError, TypeError, UnknownHashError):
        _password_hash.verify(password, _DUMMY_PASSWORD_HASH)
        return False


def create_access_token(
    settings: Settings,
    *,
    user_id: UUID,
    membership_id: UUID,
    organization_id: UUID,
    role_code: str,
    permissions: list[str],
    session_id: UUID,
    now: datetime | None = None,
) -> str:
    """Create a short-lived signed token with explicit issuer and audience."""
    key = _signing_key(settings)
    issued_at = now or datetime.now(UTC)
    expires_at = issued_at + timedelta(minutes=settings.access_token_ttl_minutes)
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": str(user_id),
        "mid": str(membership_id),
        "org": str(organization_id),
        "sid": str(session_id),
        "role": role_code,
        "permissions": permissions,
        "jti": secrets.token_urlsafe(18),
        "iat": issued_at,
        "exp": expires_at,
    }
    return jwt.encode(claims, key, algorithm=ALGORITHM)


def decode_access_token(settings: Settings, token: str) -> dict[str, Any]:
    """Validate a token using only the fixed algorithm and required claims."""
    return jwt.decode(
        token,
        _signing_key(settings),
        algorithms=[ALGORITHM],
        issuer=ISSUER,
        audience=AUDIENCE,
        options={"require": ["sub", "mid", "org", "sid", "role", "iat", "exp", "jti"]},
    )


def create_refresh_token() -> str:
    """Generate a high-entropy opaque refresh token."""
    return secrets.token_urlsafe(48)


def digest_refresh_token(token: str) -> str:
    """Return the SHA-256 digest stored for a refresh token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _signing_key(settings: Settings) -> str:
    secret = settings.jwt_signing_key
    if secret is None:
        raise RuntimeError("CLOUDSENTINEL_JWT_SIGNING_KEY is not configured")
    value = secret.get_secret_value()
    if len(value) < 32:
        raise RuntimeError("CLOUDSENTINEL_JWT_SIGNING_KEY must be at least 32 characters")
    return value
