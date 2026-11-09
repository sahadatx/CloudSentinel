"""Password recovery token persistence, abuse controls, and SMTP delivery."""

import hashlib
import hmac
import logging
import smtplib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from secrets import token_urlsafe
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.models import PasswordResetToken, User

logger = logging.getLogger("cloudsentinel.auth.recovery")

RATE_LIMIT_SCRIPT = """
local ip_count = redis.call('INCR', KEYS[1])
if ip_count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
local email_count = redis.call('INCR', KEYS[2])
if email_count == 1 then redis.call('EXPIRE', KEYS[2], ARGV[2]) end
return {ip_count, email_count}
"""


@dataclass(frozen=True)
class RecoveryDelivery:
    """Transient email data; the plaintext token is never persisted or logged."""

    recipient: str
    token: str


def enforce_recovery_rate_limit(counts: object, *, limit: int) -> bool:
    """Return whether either Redis counter exceeds the configured bound."""
    if not isinstance(counts, (list, tuple)) or len(counts) != 2:
        raise RuntimeError("Invalid rate-limit response")
    return any(int(count) > limit for count in counts)


def enforce_login_rate_limit(
    counts: object, *, email_limit: int, ip_limit: int
) -> bool:
    """Check the source and identity counters returned by the shared Redis script."""
    if not isinstance(counts, (list, tuple)) or len(counts) != 2:
        raise RuntimeError("Invalid rate-limit response")
    ip_count, email_count = (int(count) for count in counts)
    return ip_count > ip_limit or email_count > email_limit


def create_recovery_request(
    session: Session, settings: Settings, email: str
) -> RecoveryDelivery | None:
    """Revoke prior links and create a new one-time token for an active identity."""
    user = session.scalar(
        select(User).where(User.email == email, User.is_active.is_(True)).with_for_update()
    )
    if user is None:
        return None

    now = datetime.now(UTC)
    session.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.revoked_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(revoked_at=now)
        .execution_options(synchronize_session=False)
    )
    token = token_urlsafe(32)
    session.add(
        PasswordResetToken(
            id=uuid4(),
            user_id=user.id,
            token_digest=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            expires_at=now + timedelta(minutes=settings.password_reset_token_ttl_minutes),
        )
    )
    session.commit()
    return RecoveryDelivery(recipient=user.email, token=token)


def send_recovery_email(settings: Settings, delivery: RecoveryDelivery) -> None:
    """Send a reset link using configured SMTP without logging its address or token."""
    if not settings.smtp_host or not settings.smtp_from_email:
        logger.warning("Password recovery email is unavailable because SMTP is not configured")
        return

    link = f"{settings.frontend_base_url.rstrip('/')}/reset-password#token={delivery.token}"
    message = EmailMessage()
    message["Subject"] = "Reset your CloudSentinel password"
    message["From"] = settings.smtp_from_email
    message["To"] = delivery.recipient
    message.set_content(
        "A password reset was requested for your CloudSentinel account.\n\n"
        f"Use this one-time link within {settings.password_reset_token_ttl_minutes} minutes:\n"
        f"{link}\n\nIf you did not request this change, you can ignore this email."
    )

    try:
        with smtplib.SMTP(
            settings.smtp_host,
            settings.smtp_port,
            timeout=settings.smtp_timeout_seconds,
        ) as smtp:
            if settings.smtp_starttls:
                smtp.starttls()
            if settings.smtp_username and settings.smtp_password:
                smtp.login(settings.smtp_username, settings.smtp_password.get_secret_value())
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        # Do not attach the exception text: SMTP errors may contain addresses or message data.
        logger.error(
            "Password recovery email delivery failed",
            extra={"error_type": type(exc).__name__},
        )


def recovery_rate_limit_keys(settings: Settings, email: str, client_ip: str) -> tuple[str, str]:
    """Return non-reversible, keyed Redis identifiers for address and source limits."""
    secret = (
        settings.jwt_signing_key.get_secret_value()
        if settings.jwt_signing_key is not None
        else "cloudsentinel-recovery-rate-limit-development-key"
    ).encode("utf-8")
    email_digest = hmac.new(secret, email.encode("utf-8"), hashlib.sha256).hexdigest()
    ip_digest = hmac.new(secret, client_ip.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"auth:password-reset:email:{email_digest}", f"auth:password-reset:ip:{ip_digest}"


def login_rate_limit_keys(settings: Settings, email: str, client_ip: str) -> tuple[str, str]:
    """Return non-reversible Redis keys for login attempt limits."""
    secret = (
        settings.jwt_signing_key.get_secret_value()
        if settings.jwt_signing_key is not None
        else "cloudsentinel-login-rate-limit-development-key"
    ).encode("utf-8")
    email_digest = hmac.new(secret, email.lower().encode("utf-8"), hashlib.sha256).hexdigest()
    ip_digest = hmac.new(secret, client_ip.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"auth:login:email:{email_digest}", f"auth:login:ip:{ip_digest}"
