"""Shared tenant-scoped persistence helpers for Phase 08 workflows."""

import re
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.domain_errors import ConflictError
from app.core.models import (
    AuditEvent,
    Membership,
    Notification,
    Organization,
    Permission,
    RemediationRequest,
    Role,
    RolePermission,
    User,
)


def record_audit(
    session: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: UUID | str | None,
    details: dict[str, object] | None = None,
    status: str = "SUCCESS",
    before: dict[str, object] | None = None,
    after: dict[str, object] | None = None,
    target_type: str | None = None,
    target_id: UUID | str | None = None,
) -> AuditEvent:
    """Append a tenant audit fact, redacting credential-like fields defensively."""

    def sanitize(value: object, depth: int = 0) -> object:
        if depth > 6:
            return "[TRUNCATED]"
        if isinstance(value, dict):
            cleaned: dict[str, object] = {}
            for key, item in list(value.items())[:100]:
                label = str(key)[:100]
                if re.search(
                    r"password|secret|token|private.?key|credential|authorization|api.?key",
                    label,
                    re.I,
                ):
                    cleaned[label] = "[REDACTED]"
                else:
                    cleaned[label] = sanitize(item, depth + 1)
            return cleaned
        if isinstance(value, (list, tuple)):
            return [sanitize(item, depth + 1) for item in value[:100]]
        if isinstance(value, str):
            return value[:4000]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return str(value)[:500]

    actor_name = "System"
    actor_role = None
    if actor_user_id is not None:
        actor = session.scalar(select(User).where(User.id == actor_user_id))
        actor_name = actor.display_name if actor is not None else "User"
        actor_role = session.scalar(
            select(Role.code)
            .join(Membership, Membership.role_id == Role.id)
            .where(
                Membership.user_id == actor_user_id,
                Membership.organization_id == organization_id,
                Membership.is_active.is_(True),
            )
        )
    action_code = re.sub(r"[^A-Z0-9_]+", "_", action.upper()).strip("_")[:80] or "UNKNOWN_ACTION"
    context = session.info
    audit_details = sanitize(details or {})
    if not isinstance(audit_details, dict):
        audit_details = {"value": audit_details}
    if before is None and "from_status" in audit_details:
        before = {"status": audit_details["from_status"]}
    if after is None and "to_status" in audit_details:
        after = {"status": audit_details["to_status"]}
    if after is None and "is_active" in audit_details:
        after = {"is_active": audit_details["is_active"]}
    organization = session.get(Organization, organization_id)
    retention_days = organization.audit_retention_days if organization is not None else 365
    created_at = datetime.now(UTC)
    row = AuditEvent(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        actor_type="USER" if actor_user_id is not None else "SYSTEM",
        actor_name=actor_name,
        actor_role=actor_role,
        action=action_code,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        target_type=target_type or resource_type,
        target_id=str(target_id if target_id is not None else resource_id)
        if (target_id is not None or resource_id is not None)
        else None,
        status=status.upper() if status.upper() in {"SUCCESS", "FAILURE"} else "SUCCESS",
        ip_address=context.get("audit_ip_address"),
        user_agent=context.get("audit_user_agent"),
        request_id=context.get("audit_request_id"),
        before=sanitize(before) if before is not None else None,
        after=sanitize(after) if after is not None else None,
        details=audit_details,
        created_at=created_at,
        retention_until=created_at + timedelta(days=retention_days),
    )
    if row.status == "FAILURE":
        session.info["audit_failure_recorded"] = True
    session.add(row)
    return row


def notify_user(
    session: Session,
    *,
    organization_id: UUID,
    recipient_user_id: UUID,
    category: str,
    title: str,
    message: str,
    resource_type: str | None = None,
    resource_id: UUID | str | None = None,
) -> Notification | None:
    """Queue an in-app notification for an active organization member."""
    member = session.scalar(
        select(Membership.id)
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.organization_id == organization_id,
            Membership.user_id == recipient_user_id,
            Membership.is_active.is_(True),
            User.is_active.is_(True),
        )
    )
    if member is None:
        return None
    row = Notification(
        organization_id=organization_id,
        recipient_user_id=recipient_user_id,
        category=category,
        title=title,
        message=message,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
    )
    session.add(row)
    return row


def decide_remediation(
    session: Session,
    request: RemediationRequest,
    *,
    actor_user_id: UUID,
    decision: str,
    note: str,
) -> RemediationRequest:
    """Apply one approval decision with separation of duties and audit trail."""
    if request.status != "PENDING_APPROVAL":
        raise ConflictError("Only pending remediation requests can receive a decision.")
    if request.requested_by_user_id == actor_user_id:
        raise ConflictError("The requester cannot approve or reject their own remediation request.")
    request.status = decision
    request.verification_status = "PENDING" if decision == "APPROVED" else "NOT_STARTED"
    request.decided_by_user_id = actor_user_id
    request.decision_note = note.strip()
    request.decided_at = datetime.now(UTC)
    record_audit(
        session,
        organization_id=request.organization_id,
        actor_user_id=actor_user_id,
        action=f"remediation.{decision.lower()}",
        resource_type="remediation_request",
        resource_id=request.id,
        details={"finding_id": str(request.finding_id)},
    )
    notify_user(
        session,
        organization_id=request.organization_id,
        recipient_user_id=request.requested_by_user_id,
        category="remediation",
        title=f"Remediation {decision.lower()}",
        message=f"Your remediation request was {decision.lower()}.",
        resource_type="remediation_request",
        resource_id=request.id,
    )
    session.commit()
    session.refresh(request)
    return request


def notify_remediation_approvers(
    session: Session,
    *,
    organization_id: UUID,
    excluded_user_id: UUID,
    request_id: UUID,
) -> None:
    """Notify active tenant members holding the backend approval permission."""
    user_ids = session.scalars(
        select(Membership.user_id)
        .join(User, User.id == Membership.user_id)
        .join(RolePermission, RolePermission.role_id == Membership.role_id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(
            Membership.organization_id == organization_id,
            Membership.is_active.is_(True),
            User.is_active.is_(True),
            User.id != excluded_user_id,
            Permission.code == "remediation:execute",
        )
        .distinct()
    ).all()
    for user_id in user_ids:
        notify_user(
            session,
            organization_id=organization_id,
            recipient_user_id=user_id,
            category="remediation",
            title="Remediation approval needed",
            message="A remediation recommendation is awaiting review.",
            resource_type="remediation_request",
            resource_id=request_id,
        )
