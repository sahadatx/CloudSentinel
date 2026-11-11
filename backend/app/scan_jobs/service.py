"""Scan request lifecycle, scoped account/region validation, and Celery dispatch."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from app.core.domain_errors import (
    ConflictError,
    InvalidOperationError,
    NotFoundError,
)
from app.core.models import CloudAccount, CloudRegion, ScanJob
from app.operations.service import record_audit
from app.scan_jobs.planning import planned_units
from app.scan_jobs.tasks import process_scan_job
from app.task_outbox import dispatch_outbox_event_now, enqueue_task
from cloudsentinel_scanner.collectors.aws_inventory import AWS_RESOURCE_TYPES


def create_scan_job(
    session: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    membership_id: UUID,
    cloud_account_id: UUID,
    requested_regions: list[str] | None,
    requested_resource_types: list[str] | None,
    allow_mock: bool = False,
) -> ScanJob:
    """Persist an authorized, bounded request and asynchronously dispatch its worker."""
    account = session.scalar(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == organization_id,
        )
    )
    if account is None:
        raise NotFoundError("Cloud account")
    if account.connection_status != "connected":
        raise ConflictError("Validate the cloud account connection before requesting a scan.")
    if account.validation_mode == "mock" and not allow_mock:
        raise ConflictError(
            "Mock-validated connections are only available for scans in local mock mode."
        )
    if account.validation_mode not in {"real", "mock"}:
        raise ConflictError("Validate the cloud account connection before requesting a scan.")
    if not account.role_arn:
        raise ConflictError("Configure and validate an IAM role before requesting a scan.")

    enabled_regions = list(
        session.scalars(
            select(CloudRegion.region_code)
            .where(
                CloudRegion.organization_id == organization_id,
                CloudRegion.cloud_account_id == account.id,
                CloudRegion.is_enabled.is_(True),
            )
            .order_by(CloudRegion.region_code)
        ).all()
    )
    regions = enabled_regions if requested_regions is None else requested_regions
    if not regions or not set(regions).issubset(enabled_regions):
        raise InvalidOperationError("Select only regions enabled for this cloud account.")

    resource_types = requested_resource_types or list(AWS_RESOURCE_TYPES)
    if not resource_types or not set(resource_types).issubset(AWS_RESOURCE_TYPES):
        raise InvalidOperationError("One or more resource types are not supported.")
    job = ScanJob(
        organization_id=organization_id,
        cloud_account_id=account.id,
        requested_by_user_id=user_id,
        requested_by_membership_id=membership_id,
        status="queued",
        requested_regions=regions,
        requested_resource_types=resource_types,
        progress_total=sum(1 for _ in planned_units(resource_types, regions)),
    )
    session.add(job)
    session.flush()
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=user_id,
        action="scan.requested",
        resource_type="scan_job",
        resource_id=job.id,
        details={"cloud_account_id": str(account.id)},
    )
    outbox_event = enqueue_task(
        session,
        organization_id=organization_id,
        task_type="cloudsentinel.scan_jobs.process",
        aggregate_id=str(job.id),
        payload={"scan_job_id": str(job.id)},
    )
    session.commit()
    dispatch_outbox_event_now(
        session,
        outbox_id=outbox_event.id,
        publisher=process_scan_job.apply_async,
        task_id=str(job.id),
    )
    return job


def get_scan_job(session: Session, organization_id: UUID, job_id: UUID) -> ScanJob:
    """Read a scan only through an explicit tenant predicate."""
    job = session.scalar(
        select(ScanJob).where(
            ScanJob.id == job_id,
            ScanJob.organization_id == organization_id,
        )
    )
    if job is None:
        raise NotFoundError("Scan job")
    return job


def list_scan_jobs(
    session: Session,
    *,
    organization_id: UUID,
    offset: int,
    limit: int,
    status: str | None = None,
    cloud_account_id: UUID | None = None,
    search: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
) -> tuple[list[ScanJob], int]:
    """List bounded scan history for the active organization."""
    criteria = [ScanJob.organization_id == organization_id]
    if status is not None:
        criteria.append(ScanJob.status == status)
    if cloud_account_id is not None:
        criteria.append(ScanJob.cloud_account_id == cloud_account_id)
    if created_after is not None:
        criteria.append(ScanJob.created_at >= created_after)
    if created_before is not None:
        criteria.append(ScanJob.created_at <= created_before)
    statement = select(ScanJob).where(*criteria)
    search_filter = None
    if search is not None:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        search_filter = or_(
            cast(ScanJob.id, String).ilike(pattern),
            CloudAccount.name.ilike(pattern),
            CloudAccount.account_id.ilike(pattern),
        )
        tenant_account_join = (CloudAccount.id == ScanJob.cloud_account_id) & (
            CloudAccount.organization_id == organization_id
        )
        statement = statement.join(CloudAccount, tenant_account_join).where(search_filter)
    count_statement = select(func.count(ScanJob.id)).where(*criteria)
    if search_filter is not None:
        count_statement = count_statement.join(CloudAccount, tenant_account_join).where(
            search_filter
        )
    total = session.scalar(count_statement) or 0
    rows = list(
        session.scalars(
            statement.order_by(ScanJob.created_at.desc(), ScanJob.id).offset(offset).limit(limit)
        ).all()
    )
    return rows, total


def request_scan_cancellation(session: Session, *, organization_id: UUID, job_id: UUID) -> ScanJob:
    """Request cooperative cancellation; the worker stops between collection units."""
    job = session.scalar(
        select(ScanJob)
        .where(ScanJob.organization_id == organization_id, ScanJob.id == job_id)
        .with_for_update()
    )
    if job is None:
        raise NotFoundError("Scan job")
    if job.status not in {"queued", "running"}:
        raise ConflictError("Only queued or running scans can be cancelled.")
    job.status = "cancelling"
    job.cancel_requested_at = datetime.now(UTC)
    session.commit()
    return job


