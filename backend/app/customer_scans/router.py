"""Tenant-owned upload and results APIs for isolated IaC and image assessments."""

from datetime import UTC, datetime, timedelta
import logging
from pathlib import PurePosixPath
from typing import Annotated, Literal
from uuid import UUID, uuid4

import boto3
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.core.config import Settings
from app.core.domain_errors import NotFoundError, ServiceUnavailableError
from app.core.models import CustomerScanFinding, CustomerScanJob, TaskOutbox
from app.customer_scans.schemas import (
    CustomerScanFindingPage,
    CustomerScanFindingRead,
    CustomerScanPage,
    CustomerScanRead,
    CustomerScanStatusRead,
)
from app.operations.service import record_audit
from app.task_outbox import enqueue_task

router = APIRouter(prefix="/customer-scans", tags=["customer assessments"])
logger = logging.getLogger("cloudsentinel.customer_scan_api")
MAX_FILENAME = 255
IAC_SUFFIXES = (".tfvars.json", ".tf.json", ".tar.gz", ".tfvars", ".zip", ".tar", ".tgz", ".tf", ".json", ".yaml", ".yml", ".hcl", ".template")


@router.get("/status", response_model=CustomerScanStatusRead)
def get_customer_scan_status(
    request: Request,
    principal: Annotated[Principal, Depends(require_permission("scans:read"))],
) -> CustomerScanStatusRead:
    """Expose deployment feature availability without returning infrastructure details."""
    settings: Settings = request.app.state.settings
    return CustomerScanStatusRead(
        enabled=settings.customer_scan_enabled,
        max_upload_bytes=settings.customer_scan_max_upload_bytes,
        timeout_seconds=settings.customer_scan_timeout_seconds,
    )


@router.post("", status_code=202, response_model=CustomerScanRead)
async def create_customer_scan(
    request: Request,
    scan_type: Annotated[Literal["iac", "container"], Form()],
    file: Annotated[UploadFile, File()],
    principal: Annotated[Principal, Depends(require_permission("scans:create"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> CustomerScanJob:
    settings: Settings = request.app.state.settings
    if not settings.customer_scan_enabled:
        raise ServiceUnavailableError("Customer assessment is not enabled for this deployment.")
    if not settings.customer_scan_bucket:
        raise ServiceUnavailableError("Customer assessment storage is not configured.")
    now = datetime.now(UTC)
    active_count = session.scalar(
        select(func.count(CustomerScanJob.id)).where(
            CustomerScanJob.organization_id == principal.organization_id,
            CustomerScanJob.status.in_(("queued", "running", "cancelling")),
            CustomerScanJob.expires_at > now,
        )
    ) or 0
    recent_count = session.scalar(
        select(func.count(CustomerScanJob.id)).where(
            CustomerScanJob.organization_id == principal.organization_id,
            CustomerScanJob.created_at >= now - timedelta(hours=1),
        )
    ) or 0
    if active_count >= 5 or recent_count >= 20:
        raise HTTPException(
            status_code=429,
            detail="The organization has reached its customer scan quota. Try again after a scan completes or the hourly window resets.",
            headers={"Retry-After": "300"},
        )
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.customer_scan_max_upload_bytes + 64_000:
                raise HTTPException(status_code=413, detail="The uploaded artifact exceeds the size limit.")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid upload size.") from None
    filename = _safe_filename(file.filename or "artifact")
    lower_filename = filename.lower()
    is_supported = lower_filename.endswith(IAC_SUFFIXES) if scan_type == "iac" else lower_filename.endswith(".tar")
    if not is_supported:
        raise HTTPException(
            status_code=415,
            detail="Upload a supported IaC archive or source file; container scans require an OCI image tar archive.",
        )
    if scan_type == "container" and not lower_filename.endswith(".tar"):
        raise HTTPException(status_code=415, detail="Container scans accept OCI image tar archives only.")

    artifact_id = uuid4()
    prefix = settings.customer_scan_prefix.strip("/")
    artifact_key = f"{prefix}/{principal.organization_id}/{artifact_id}/input"
    try:
        await file.seek(0, 2)
        file_size = file.file.tell()
        if not file_size:
            raise HTTPException(status_code=400, detail="The uploaded artifact is empty.")
        if file_size > settings.customer_scan_max_upload_bytes:
            raise HTTPException(status_code=413, detail="The uploaded artifact exceeds the size limit.")
        await file.seek(0)
        s3 = _s3_client(settings)
        await run_in_threadpool(
            s3.upload_fileobj,
            file.file,
            settings.customer_scan_bucket,
            artifact_key,
            ExtraArgs={"ContentType": "application/octet-stream"},
        )
    except Exception as error:
        if isinstance(error, HTTPException):
            raise
        logger.warning("Customer scan artifact could not be stored", extra={"error_type": type(error).__name__})
        raise ServiceUnavailableError("Artifact storage is temporarily unavailable.") from None
    finally:
        await file.close()

    job = CustomerScanJob(
        id=artifact_id,
        organization_id=principal.organization_id,
        created_by_user_id=principal.user_id,
        scan_type=scan_type,
        source_filename=filename,
        artifact_key=artifact_key,
        status="queued",
        expires_at=now + timedelta(days=1),
    )
    session.add(job)
    enqueue_task(
        session,
        organization_id=principal.organization_id,
        task_type="cloudsentinel.customer_scans.run",
        aggregate_id=str(job.id),
        payload={"customer_scan_id": str(job.id)},
    )
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="customer_scan.created",
        resource_type="customer_scan_job",
        resource_id=job.id,
        details={"scan_type": scan_type, "file_size_bytes": file_size, "filename": filename},
    )
    session.commit()
    return job


@router.get("", response_model=CustomerScanPage)
def list_customer_scans(
    principal: Annotated[Principal, Depends(require_permission("scans:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    scan_type: Literal["iac", "container"] | None = None,
    status: Annotated[str | None, Query(pattern="^(queued|running|cancelling|completed|failed|cancelled)$")] = None,
) -> CustomerScanPage:
    now = datetime.now(UTC)
    statement = select(CustomerScanJob).where(
        CustomerScanJob.organization_id == principal.organization_id,
        CustomerScanJob.expires_at > now,
    )
    count_statement = select(func.count(CustomerScanJob.id)).where(
        CustomerScanJob.organization_id == principal.organization_id,
        CustomerScanJob.expires_at > now,
    )
    if scan_type:
        statement = statement.where(CustomerScanJob.scan_type == scan_type)
        count_statement = count_statement.where(CustomerScanJob.scan_type == scan_type)
    if status:
        statement = statement.where(CustomerScanJob.status == status)
        count_statement = count_statement.where(CustomerScanJob.status == status)
    total = session.scalar(count_statement) or 0
    items = session.scalars(
        statement.order_by(CustomerScanJob.created_at.desc(), CustomerScanJob.id)
        .offset(offset)
        .limit(limit)
    ).all()
    return CustomerScanPage(items=items, total=total, offset=offset, limit=limit)


@router.get("/{scan_id}", response_model=CustomerScanRead)
def read_customer_scan(
    scan_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("scans:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> CustomerScanJob:
    job = _get_job(session, principal.organization_id, scan_id)
    if job.expires_at <= datetime.now(UTC):
        raise NotFoundError("Customer scan")
    return job


@router.get("/{scan_id}/findings", response_model=CustomerScanFindingPage)
def list_customer_scan_findings(
    scan_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("scans:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    severity: Annotated[str | None, Query(pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN)$")] = None,
) -> CustomerScanFindingPage:
    job = _get_job(session, principal.organization_id, scan_id)
    if job.expires_at <= datetime.now(UTC):
        raise NotFoundError("Customer scan")
    statement = select(CustomerScanFinding).where(
        CustomerScanFinding.organization_id == principal.organization_id,
        CustomerScanFinding.scan_job_id == scan_id,
    )
    count_statement = select(func.count(CustomerScanFinding.id)).where(
        CustomerScanFinding.organization_id == principal.organization_id,
        CustomerScanFinding.scan_job_id == scan_id,
    )
    if severity:
        statement = statement.where(CustomerScanFinding.severity == severity)
        count_statement = count_statement.where(CustomerScanFinding.severity == severity)
    total = session.scalar(count_statement) or 0
    items = session.scalars(
        statement.order_by(CustomerScanFinding.severity, CustomerScanFinding.title)
        .offset(offset)
        .limit(limit)
    ).all()
    return CustomerScanFindingPage(items=items, total=total, offset=offset, limit=limit)


@router.post("/{scan_id}/cancel", response_model=CustomerScanRead)
def cancel_customer_scan(
    scan_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("scans:cancel"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> CustomerScanJob:
    job = _get_job(session, principal.organization_id, scan_id)
    if job.status == "queued":
        job.status = "cancelled"
        job.finished_at = datetime.now(UTC)
        outbox = session.scalar(
            select(TaskOutbox).where(
                TaskOutbox.organization_id == principal.organization_id,
                TaskOutbox.aggregate_id == str(job.id),
                TaskOutbox.task_type == "cloudsentinel.customer_scans.run",
                TaskOutbox.status == "pending",
            )
        )
        if outbox is not None:
            outbox.status = "dead"
            outbox.dead_lettered_at = datetime.now(UTC)
            outbox.last_error_code = "cancelled_by_user"
    elif job.status == "running":
        job.status = "cancelling"
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="customer_scan.cancel_requested",
        resource_type="customer_scan_job",
        resource_id=job.id,
    )
    session.commit()
    return job


def _get_job(session: Session, organization_id: UUID, scan_id: UUID) -> CustomerScanJob:
    job = session.scalar(
        select(CustomerScanJob).where(
            CustomerScanJob.id == scan_id,
            CustomerScanJob.organization_id == organization_id,
        )
    )
    if job is None:
        raise NotFoundError("Customer scan")
    return job


def _safe_filename(value: str) -> str:
    name = PurePosixPath(value.replace("\\", "/")).name
    cleaned = "".join(character for character in name if character.isalnum() or character in "._-")
    cleaned = cleaned[:MAX_FILENAME]
    return cleaned if cleaned not in {"", ".", ".."} else "artifact"


def _s3_client(settings: Settings):
    options: dict[str, object] = {
        "region_name": settings.report_storage_region,
        "endpoint_url": settings.report_storage_endpoint_url or None,
    }
    if settings.report_storage_access_key and settings.report_storage_secret_key:
        options["aws_access_key_id"] = settings.report_storage_access_key.get_secret_value()
        options["aws_secret_access_key"] = settings.report_storage_secret_key.get_secret_value()
    return boto3.client("s3", **options)
