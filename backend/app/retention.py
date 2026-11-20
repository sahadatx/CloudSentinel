"""Audited data lifecycle maintenance for expired audit rows and offboarded tenants."""

import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.models import AuditEvent, CustomerScanJob, Organization, Report

logger = logging.getLogger("cloudsentinel.retention")
RETENTION_BATCH_SIZE = 500


def purge_expired_audit_events(factory: sessionmaker[Session]) -> int:
    """Delete only events past their organization retention deadline in bounded batches."""
    now = datetime.now(UTC)
    with factory(info={"allow_unscoped": True}) as session:
        ids = list(
            session.scalars(
                select(AuditEvent.id)
                .where(AuditEvent.retention_until.is_not(None), AuditEvent.retention_until <= now)
                .order_by(AuditEvent.retention_until)
                .limit(RETENTION_BATCH_SIZE)
            ).all()
        )
        if not ids:
            return 0
        _enable_database_retention_purge(session)
        session.info["allow_audit_retention_purge"] = True
        result = session.execute(delete(AuditEvent).where(AuditEvent.id.in_(ids)))
        deleted = result.rowcount or 0
        session.commit()
    if deleted:
        logger.info("Expired audit records purged", extra={"deleted_count": deleted})
    return deleted


def purge_offboarded_organizations(factory: sessionmaker[Session]) -> int:
    """Erase tenant-owned rows only after the grace period and every audit deadline."""
    now = datetime.now(UTC)
    with factory(info={"allow_unscoped": True}) as session:
        organization_ids = list(
            session.scalars(
                select(Organization.id)
                .where(
                    Organization.is_active.is_(False),
                    Organization.offboarding_at.is_not(None),
                    Organization.purge_after.is_not(None),
                    Organization.purge_after <= now,
                    ~select(AuditEvent.id)
                    .where(
                        AuditEvent.organization_id == Organization.id,
                        AuditEvent.retention_until.is_not(None),
                        AuditEvent.retention_until > now,
                    )
                    .exists(),
                    ~select(Report.id)
                    .where(
                        Report.organization_id == Organization.id,
                        Report.retention_until.is_not(None),
                        Report.retention_until > now,
                    )
                    .exists(),
                    ~select(CustomerScanJob.id)
                    .where(
                        CustomerScanJob.organization_id == Organization.id,
                        CustomerScanJob.expires_at > now,
                    )
                    .exists(),
                )
                .order_by(Organization.purge_after)
                .limit(25)
                .with_for_update(skip_locked=True)
            ).all()
        )
        if not organization_ids:
            return 0
        _enable_database_retention_purge(session)
        session.info["allow_audit_retention_purge"] = True
        for organization_id in organization_ids:
            organization = session.get(Organization, organization_id)
            if organization is not None:
                session.delete(organization)
        session.commit()
    logger.info("Offboarded organizations purged", extra={"organization_count": len(organization_ids)})
    return len(organization_ids)


def _enable_database_retention_purge(session: Session) -> None:
    """Set a transaction-local PostgreSQL guard checked by the audit immutability trigger."""
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(text("SET LOCAL cloudsentinel.retention_purge = 'on'"))


def retention_deadline(session: Session, organization_id: UUID) -> datetime:
    """Return the latest retained audit, report, or customer-scan deadline."""
    deadline = session.scalar(
        select(func.max(AuditEvent.retention_until)).where(AuditEvent.organization_id == organization_id)
    )
    report_deadline = session.scalar(
        select(func.max(Report.retention_until)).where(Report.organization_id == organization_id)
    )
    scan_deadline = session.scalar(
        select(func.max(CustomerScanJob.expires_at)).where(
            CustomerScanJob.organization_id == organization_id
        )
    )
    values = [value for value in (deadline, report_deadline, scan_deadline) if value is not None]
    if not values:
        return datetime.now(UTC)
    normalized = [value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC) for value in values]
    return max(normalized)
