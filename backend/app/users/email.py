"""Email delivery for organization invitations."""

import logging
import smtplib
from email.message import EmailMessage

from app.core.config import Settings

logger = logging.getLogger("cloudsentinel.users.invitation_email")


def send_invitation_email(
    settings: Settings,
    *,
    recipient: str,
    display_name: str,
    organization_name: str,
    organization_slug: str,
    role_code: str,
    token: str,
    expires_hours: int = 72,
) -> bool:
    """Send a one-time invitation without logging its token or recipient."""
    if not settings.smtp_host or not settings.smtp_from_email:
        return False

    invitation_url = f"{settings.frontend_base_url.rstrip('/')}/accept-invitation#token={token}"
    message = EmailMessage()
    message["Subject"] = f"Invitation to join {organization_name} on CloudSentinel"
    message["From"] = settings.smtp_from_email
    message["To"] = recipient
    message.set_content(
        f"Hello {display_name},\n\n"
        f"You have been invited to join {organization_name} on CloudSentinel "
        f"with the {role_code} role.\n\n"
        f"Organization workspace: {organization_slug}\n"
        f"Accept your invitation within {expires_hours} hours:\n{invitation_url}\n\n"
        "This invitation link can be used once. If you were not expecting this, "
        "you can ignore this email."
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
        logger.error(
            "Organization invitation email delivery failed",
            extra={"error_type": type(exc).__name__},
        )
        return False
    return True
