"""Encrypted TOTP credentials and single-use recovery-code helpers."""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from typing import cast

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.models import UserMfa


def generate_totp_secret() -> str:
    """Return a base32 secret suitable for a standards-compliant authenticator app."""
    return cast(str, pyotp.random_base32())


def encrypt_totp_secret(settings: Settings, secret: str) -> str:
    """Encrypt an authenticator secret with the dedicated deployment Fernet key."""
    return _fernet(settings).encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_totp_secret(settings: Settings, encrypted: str) -> str:
    """Decrypt an authenticator secret without exposing ciphertext or key material."""
    try:
        return _fernet(settings).decrypt(encrypted.encode("ascii")).decode("ascii")
    except (InvalidToken, UnicodeDecodeError, ValueError):
        raise RuntimeError(
            "The configured MFA encryption key cannot decrypt this credential"
        ) from None


def create_recovery_codes(*, count: int = 10) -> tuple[list[str], list[str]]:
    """Create one-time, high-entropy recovery codes and persist only their digests."""
    codes = [secrets.token_hex(8).upper() for _ in range(count)]
    return codes, [_recovery_digest(code) for code in codes]


def verify_and_consume_mfa_code(
    session: Session,
    settings: Settings,
    enrollment: UserMfa,
    code: str,
) -> bool:
    """Verify a current TOTP once or atomically consume one recovery code."""
    submitted = code.strip().upper()
    if len(submitted) == 6 and submitted.isdigit():
        return verify_totp_code(settings, enrollment, submitted)

    normalized = submitted.replace("-", "")
    if len(normalized) != 16:
        return False
    candidate = _recovery_digest(normalized)
    for index, digest in enumerate(enrollment.recovery_code_digests):
        if hmac.compare_digest(candidate, digest):
            enrollment.recovery_code_digests = [
                *enrollment.recovery_code_digests[:index],
                *enrollment.recovery_code_digests[index + 1 :],
            ]
            return True
    return False


def verify_totp_code(settings: Settings, enrollment: UserMfa, code: str) -> bool:
    """Verify and consume a fresh current-window authenticator code."""
    submitted = code.strip()
    if len(submitted) != 6 or not submitted.isdigit():
        return False
    try:
        secret = decrypt_totp_secret(settings, enrollment.secret_ciphertext)
    except RuntimeError:
        return False
    totp = pyotp.TOTP(secret)
    now = datetime.now(UTC)
    counter = totp.timecode(now)
    last_counter = enrollment.last_totp_counter
    if last_counter is not None and counter <= last_counter:
        return False
    if not totp.verify(submitted, for_time=now, valid_window=0):
        return False
    enrollment.last_totp_counter = counter
    return True


def _recovery_digest(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").strip().upper().encode("ascii")).hexdigest()


def _fernet(settings: Settings) -> Fernet:
    key = settings.mfa_encryption_key
    if key is None:
        raise RuntimeError("MFA encryption is not configured")
    try:
        return Fernet(key.get_secret_value().encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise RuntimeError("MFA encryption is not configured with a valid Fernet key") from None
