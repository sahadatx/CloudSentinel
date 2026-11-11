"""Tenant-scoped scan job creation, progress, and cooperative cancellation API."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.core.models import ScanJob
from app.operations.service import record_audit
from app.scan_jobs.schemas import ScanCreate, ScanJobPage, ScanJobRead
from app.scan_jobs.service import (
    create_scan_job,
    get_scan_job,
    list_scan_jobs,
    request_scan_cancellation,
)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanJobRead, status_code=202)
def create_scan(
    payload: ScanCreate,
    request: Request,
    principal: Annotated[Principal, Depends(require_permission("scans:create"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> ScanJobRead:
    """Accept a bounded scan request and hand it to the Celery worker."""
    job = create_scan_job(
        session,
        organization_id=principal.organization_id,
        user_id=principal.user_id,
        membership_id=principal.membership_id,
        cloud_account_id=payload.cloud_account_id,
        requested_regions=payload.regions,
        requested_resource_types=(
            list(payload.resource_types) if payload.resource_types is not None else None
        ),
        allow_mock=(
            request.app.state.settings.aws_validation_mode == "mock"
            and request.app.state.settings.app_env in {"development", "test"}
        ),
    )
    return _scan_job_read(job)


@router.get("", response_model=ScanJobPage)
def list_scans(
    principal: Annotated[Principal, Depends(require_permission("scans:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    status: Annotated[
        str | None,
        Query(pattern="^(queued|running|cancelling|completed|partial|failed|cancelled)$"),
    ] = None,
    cloud_account_id: UUID | None = None,
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
) -> ScanJobPage:
    """List current organization scan history with bounded pagination."""
    items, total = list_scan_jobs(
        session,
        organization_id=principal.organization_id,
        offset=offset,
        limit=limit,
        status=status,
        cloud_account_id=cloud_account_id,
        search=search,
        created_after=created_after,
        created_before=created_before,
    )
    counts = session.execute(
        select(ScanJob.status, func.count(ScanJob.id))
        .where(ScanJob.organization_id == principal.organization_id)
        .group_by(ScanJob.status)
    ).all()
    return ScanJobPage(
        items=[_scan_job_read(item) for item in items],
        total=total,
        offset=offset,
        limit=limit,
        status_counts={status: count for status, count in counts},
    )


@router.get("/{job_id}", response_model=ScanJobRead)
def get_scan(
    job_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("scans:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> ScanJobRead:
    """Read current job status and progress inside the active organization."""
    return _scan_job_read(get_scan_job(session, principal.organization_id, job_id))


@router.post("/{job_id}/cancel", response_model=ScanJobRead)
def cancel_scan(
    job_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("scans:cancel"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> ScanJobRead:
    """Request cooperative cancellation between AWS collection units."""
    job = request_scan_cancellation(
        session, organization_id=principal.organization_id, job_id=job_id
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="scan.cancel_requested",
        resource_type="scan_job",
        resource_id=job.id,
    )
    session.commit()
    return _scan_job_read(job)


@router.post("/{job_id}/rerun", response_model=ScanJobRead, status_code=202)
def rerun_scan(
    job_id: UUID,
    request: Request,
    principal: Annotated[Principal, Depends(require_permission("scans:create"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> ScanJobRead:
    """Create a new scan using a prior job's account, regions, and resource types."""
    source = get_scan_job(session, principal.organization_id, job_id)
    job = create_scan_job(
        session,
        organization_id=principal.organization_id,
        user_id=principal.user_id,
        membership_id=principal.membership_id,
        cloud_account_id=source.cloud_account_id,
        requested_regions=source.requested_regions,
        requested_resource_types=source.requested_resource_types,
        allow_mock=(
            request.app.state.settings.aws_validation_mode == "mock"
            and request.app.state.settings.app_env in {"development", "test"}
        ),
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="scan.rerun_requested",
        resource_type="scan_job",
        resource_id=job.id,
        details={"source_scan_id": str(source.id)},
    )
    session.commit()
    return _scan_job_read(job)


def _scan_job_read(job: ScanJob) -> ScanJobRead:
    """Build a safe response and derive current percentage from bounded counters."""
    progress = (
        0
        if job.progress_total == 0
        else min(100, int(job.progress_completed * 100 / job.progress_total))
    )
    return ScanJobRead(
        id=job.id,
        cloud_account_id=job.cloud_account_id,
        status=job.status,
        requested_regions=job.requested_regions,
        requested_resource_types=job.requested_resource_types,
        progress_total=job.progress_total,
        progress_completed=job.progress_completed,
        resources_discovered=job.resources_discovered,
        errors_count=job.errors_count,
        error_codes=job.error_codes,
        progress_percent=progress,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
    )
