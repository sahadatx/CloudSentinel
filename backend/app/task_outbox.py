"""Durable Celery dispatch for database-backed asynchronous work."""

import logging
import signal
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from app.alerts.service import emit_scan_alert
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.database import create_database_engine, create_session_factory
from app.core.domain_errors import ServiceUnavailableError
from app.core.models import CustomerScanJob, Organization, Report, ScanJob, TaskOutbox
from app.operations.service import record_audit

logger = logging.getLogger("cloudsentinel.task_outbox")
MAX_DISPATCH_ATTEMPTS = 8
CLAIM_LEASE_SECONDS = 90
BATCH_SIZE = 50
POLL_INTERVAL_SECONDS = 2


def enqueue_task(
    session: Session,
    *,
    organization_id: UUID,
    task_type: str,
    aggregate_id: str,
    payload: dict[str, object],
    available_at: datetime | None = None,
) -> TaskOutbox:
    """Record task intent in the same transaction as its domain change."""
    if task_type not in {
        "cloudsentinel.scan_jobs.process",
        "cloudsentinel.reports.generate",
        "cloudsentinel.customer_scans.run",
    }:
        raise ValueError("Unsupported asynchronous task type")
    if len(aggregate_id) > 100:
        raise ValueError("Asynchronous task aggregate identifier is too long")
    existing = session.scalar(
        select(TaskOutbox)
        .where(
            TaskOutbox.organization_id == organization_id,
            TaskOutbox.task_type == task_type,
            TaskOutbox.aggregate_id == aggregate_id,
        )
        .with_for_update()
    )
    if existing is not None:
        if existing.status in {"dispatched", "dead"}:
            existing.status = "pending"
            existing.available_at = available_at or datetime.now(UTC)
            existing.claimed_until = None
            existing.claim_token = None
            existing.dispatched_at = None
            existing.dead_lettered_at = None
            existing.last_error_code = None
        elif existing.status == "pending" and available_at is not None:
            existing.available_at = min(existing.available_at, available_at)
        return existing
    event = TaskOutbox(
        organization_id=organization_id,
        task_type=task_type,
        aggregate_id=aggregate_id,
        payload=payload,
        available_at=available_at or datetime.now(UTC),
    )
    session.add(event)
    return event


def dispatch_pending_tasks(
    factory: sessionmaker[Session], *, batch_size: int = BATCH_SIZE
) -> int:
    """Publish a bounded batch, retrying delivery and dead-lettering exhausted work."""
    now = datetime.now(UTC)
    with factory(info={"allow_unscoped": True}) as session:
        events = list(
            session.scalars(
                select(TaskOutbox)
                .where(
                    or_(
                        and_(TaskOutbox.status == "pending", TaskOutbox.available_at <= now),
                        and_(
                            TaskOutbox.status == "dispatching",
                            TaskOutbox.claimed_until <= now,
                        ),
                    )
                )
                .order_by(TaskOutbox.available_at, TaskOutbox.created_at)
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            ).all()
        )
        claims: list[tuple[UUID, UUID, str, dict[str, object], int]] = []
        for event in events:
            token = uuid4()
            event.status = "dispatching"
            event.attempt_count += 1
            event.claim_token = token
            event.claimed_until = now + timedelta(seconds=CLAIM_LEASE_SECONDS)
            claims.append(
                (event.id, token, event.task_type, dict(event.payload), event.attempt_count)
            )
        session.commit()

    for outbox_id, token, task_type, payload, attempt_count in claims:
        try:
            args = _task_args(task_type, payload)
            celery_app.send_task(task_type, args=args, task_id=str(outbox_id))
        except Exception as error:
            logger.warning(
                "Task dispatch failed",
                extra={"task_type": task_type, "error_type": type(error).__name__},
            )
            _record_dispatch_failure(
                factory,
                outbox_id=outbox_id,
                claim_token=token,
                attempt_count=attempt_count,
                error_code=(
                    "invalid_outbox_payload"
                    if isinstance(error, ValueError)
                    else "broker_unavailable"
                ),
            )
            continue
        _mark_dispatched(factory, outbox_id=outbox_id, claim_token=token)
    return len(claims)


def reconcile_stale_work(factory: sessionmaker[Session], *, stale_after_minutes: int) -> int:
    """Retry work with an expired worker heartbeat or fail it after the attempt limit."""
    settings = get_settings()
    now_for_cutoff = datetime.now(UTC)
    cutoff = now_for_cutoff - timedelta(minutes=stale_after_minutes)
    queued_cutoff = now_for_cutoff - timedelta(minutes=5)
    customer_scan_cutoff = now_for_cutoff - timedelta(
        seconds=settings.customer_scan_timeout_seconds + 300
    )
    with factory(info={"allow_unscoped": True}) as session:
        stale_scans = list(
            session.execute(
                select(ScanJob.id, ScanJob.organization_id, ScanJob.attempt_count)
                .where(ScanJob.status == "running", ScanJob.updated_at < cutoff)
                .order_by(ScanJob.updated_at)
                .limit(BATCH_SIZE)
            ).all()
        )
        stale_reports = list(
            session.execute(
                select(Report.id, Report.organization_id, Report.generation_attempt_count)
                .where(Report.status == "GENERATING", Report.updated_at < cutoff)
                .order_by(Report.updated_at)
                .limit(BATCH_SIZE)
            ).all()
        )
        stale_customer_scans = list(
            session.execute(
                select(CustomerScanJob.id, CustomerScanJob.organization_id, CustomerScanJob.attempt_count)
                .where(
                    CustomerScanJob.status.in_(("running", "cancelling")),
                    CustomerScanJob.updated_at < customer_scan_cutoff,
                )
                .order_by(CustomerScanJob.updated_at)
                .limit(BATCH_SIZE)
            ).all()
        )
        queued_scans = list(
            session.execute(
                select(ScanJob.id, ScanJob.organization_id)
                .join(Organization, Organization.id == ScanJob.organization_id)
                .where(
                    ScanJob.status == "queued",
                    ScanJob.updated_at < queued_cutoff,
                    Organization.is_active.is_(True),
                )
                .order_by(ScanJob.updated_at)
                .limit(BATCH_SIZE)
            ).all()
        )
        queued_reports = list(
            session.execute(
                select(Report.id, Report.organization_id, Report.report_version)
                .join(Organization, Organization.id == Report.organization_id)
                .where(
                    Report.status == "QUEUED",
                    Report.updated_at < queued_cutoff,
                    Organization.is_active.is_(True),
                )
                .order_by(Report.updated_at)
                .limit(BATCH_SIZE)
            ).all()
        )
        queued_customer_scans = list(
            session.execute(
                select(CustomerScanJob.id, CustomerScanJob.organization_id)
                .join(Organization, Organization.id == CustomerScanJob.organization_id)
                .where(
                    CustomerScanJob.status == "queued",
                    CustomerScanJob.updated_at < queued_cutoff,
                    Organization.is_active.is_(True),
                )
                .order_by(CustomerScanJob.updated_at)
                .limit(BATCH_SIZE)
            ).all()
        )

    reconciled = 0
    for job_id, organization_id, attempt_count in stale_scans:
        with factory(info={"allow_unscoped": True}) as session:
            job = session.scalar(
                select(ScanJob)
                .where(
                    ScanJob.id == job_id,
                    ScanJob.status == "running",
                    ScanJob.updated_at < cutoff,
                )
                .with_for_update(skip_locked=True)
            )
            if job is None:
                continue
            session.info.pop("allow_unscoped", None)
            session.info["tenant_id"] = organization_id
            now = datetime.now(UTC)
            if job.attempt_count < settings.task_execution_max_attempts:
                retry_delay = min(300, 2**max(1, job.attempt_count))
                job.status = "queued"
                job.started_at = None
                job.finished_at = None
                job.updated_at = now
                enqueue_task(
                    session,
                    organization_id=organization_id,
                    task_type="cloudsentinel.scan_jobs.process",
                    aggregate_id=f"{job.id}:stale-attempt:{job.attempt_count}",
                    payload={"scan_job_id": str(job.id)},
                    available_at=now + timedelta(seconds=retry_delay),
                )
                record_audit(
                    session,
                    organization_id=organization_id,
                    actor_user_id=None,
                    action="scan.worker_stale_retry_scheduled",
                    resource_type="scan_job",
                    resource_id=job.id,
                    details={
                        "error_code": "worker_stale_timeout",
                        "attempt": job.attempt_count,
                        "retry_delay_seconds": retry_delay,
                    },
                )
            else:
                job.status = "failed"
                job.errors_count += 1
                job.error_codes = [*job.error_codes, {"code": "worker_stale_timeout"}][:100]
                job.finished_at = now
                emit_scan_alert(session, job)
                record_audit(
                    session,
                    organization_id=organization_id,
                    actor_user_id=None,
                    action="scan.worker_stale",
                    resource_type="scan_job",
                    resource_id=job.id,
                    status="FAILURE",
                    details={"error_code": "worker_stale_timeout", "attempts": attempt_count},
                )
            session.commit()
            reconciled += 1

    for report_id, organization_id, attempt_count in stale_reports:
        with factory(info={"allow_unscoped": True}) as session:
            report = session.scalar(
                select(Report)
                .where(
                    Report.id == report_id,
                    Report.status == "GENERATING",
                    Report.updated_at < cutoff,
                )
                .with_for_update(skip_locked=True)
            )
            if report is None:
                continue
            session.info.pop("allow_unscoped", None)
            session.info["tenant_id"] = organization_id
            now = datetime.now(UTC)
            if report.generation_attempt_count < settings.task_execution_max_attempts:
                retry_delay = min(300, 2**max(1, report.generation_attempt_count))
                report.status = "QUEUED"
                report.error_code = "worker_stale_retry"
                report.error_message = "Report generation stopped unexpectedly and was rescheduled."
                report.updated_at = now
                enqueue_task(
                    session,
                    organization_id=organization_id,
                    task_type="cloudsentinel.reports.generate",
                    aggregate_id=(
                        f"{report.id}:v{report.report_version}:stale:{report.generation_attempt_count}"
                    ),
                    payload={
                        "report_id": str(report.id),
                        "report_version": report.report_version,
                    },
                    available_at=now + timedelta(seconds=retry_delay),
                )
                record_audit(
                    session,
                    organization_id=organization_id,
                    actor_user_id=None,
                    action="report.worker_stale_retry_scheduled",
                    resource_type="report",
                    resource_id=report.id,
                    details={
                        "error_code": "worker_stale_timeout",
                        "attempt": report.generation_attempt_count,
                        "retry_delay_seconds": retry_delay,
                    },
                )
            else:
                report.status = "FAILED"
                report.error_code = "worker_stale_timeout"
                report.error_message = (
                    "Report generation stopped unexpectedly. Please regenerate it."
                )
                report.updated_at = now
                record_audit(
                    session,
                    organization_id=organization_id,
                    actor_user_id=None,
                    action="report.worker_stale",
                    resource_type="report",
                    resource_id=report.id,
                    status="FAILURE",
                    details={
                        "error_code": "worker_stale_timeout",
                        "attempts": attempt_count,
                    },
                )
            session.commit()
            reconciled += 1

    for scan_id, organization_id, attempt_count in stale_customer_scans:
        with factory(info={"allow_unscoped": True}) as session:
            job = session.scalar(
                select(CustomerScanJob)
                .where(
                    CustomerScanJob.id == scan_id,
                    CustomerScanJob.status.in_(("running", "cancelling")),
                    CustomerScanJob.updated_at < customer_scan_cutoff,
                )
                .with_for_update(skip_locked=True)
            )
            if job is None:
                continue
            session.info.pop("allow_unscoped", None)
            session.info["tenant_id"] = organization_id
            now = datetime.now(UTC)
            if job.status == "cancelling":
                if job.ecs_task_arn:
                    import boto3

                    from app.customer_scans.tasks import stop_customer_scan_task

                    ecs = boto3.client("ecs", region_name=settings.report_storage_region)
                    if not stop_customer_scan_task(
                        ecs,
                        cluster=settings.customer_scan_ecs_cluster_arn,
                        task_arn=job.ecs_task_arn,
                        reason="CloudSentinel is reconciling a cancelled scan",
                    ):
                        continue
                job.status = "cancelled"
                job.finished_at = now
            elif job.attempt_count < settings.task_execution_max_attempts:
                job.status = "queued"
                job.started_at = None
                job.ecs_task_arn = None
                enqueue_task(
                    session,
                    organization_id=organization_id,
                    task_type="cloudsentinel.customer_scans.run",
                    aggregate_id=f"{job.id}:stale-attempt:{job.attempt_count}",
                    payload={"customer_scan_id": str(job.id)},
                    available_at=now + timedelta(seconds=min(300, 2**max(1, attempt_count))),
                )
                record_audit(
                    session,
                    organization_id=organization_id,
                    actor_user_id=None,
                    action="customer_scan.worker_stale_retry_scheduled",
                    resource_type="customer_scan_job",
                    resource_id=job.id,
                    details={"error_code": "worker_stale_timeout", "attempt": attempt_count},
                )
            else:
                job.status = "failed"
                job.error_code = "worker_stale_timeout"
                job.finished_at = now
                record_audit(
                    session,
                    organization_id=organization_id,
                    actor_user_id=None,
                    action="customer_scan.worker_stale",
                    resource_type="customer_scan_job",
                    resource_id=job.id,
                    status="FAILURE",
                    details={"error_code": "worker_stale_timeout", "attempts": attempt_count},
                )
            job.updated_at = now
            session.commit()
            reconciled += 1

    for job_id, organization_id in queued_scans:
        with factory(info={"allow_unscoped": True}) as session:
            job = session.scalar(
                select(ScanJob)
                .where(
                    ScanJob.id == job_id,
                    ScanJob.organization_id == organization_id,
                    ScanJob.status == "queued",
                    ScanJob.updated_at < queued_cutoff,
                )
                .with_for_update(skip_locked=True)
            )
            if job is None or _has_live_task_event(
                session, organization_id, "cloudsentinel.scan_jobs.process", str(job.id)
            ):
                continue
            session.info.pop("allow_unscoped", None)
            session.info["tenant_id"] = organization_id
            now = datetime.now(UTC)
            job.updated_at = now
            enqueue_task(
                session,
                organization_id=organization_id,
                task_type="cloudsentinel.scan_jobs.process",
                aggregate_id=f"{job.id}:queued-recovery",
                payload={"scan_job_id": str(job.id)},
                available_at=now,
            )
            record_audit(
                session,
                organization_id=organization_id,
                actor_user_id=None,
                action="scan.queued_delivery_recovered",
                resource_type="scan_job",
                resource_id=job.id,
            )
            session.commit()
            reconciled += 1

    for report_id, organization_id, version in queued_reports:
        with factory(info={"allow_unscoped": True}) as session:
            report = session.scalar(
                select(Report)
                .where(
                    Report.id == report_id,
                    Report.organization_id == organization_id,
                    Report.status == "QUEUED",
                    Report.report_version == version,
                    Report.updated_at < queued_cutoff,
                )
                .with_for_update(skip_locked=True)
            )
            if report is None or _has_live_task_event(
                session,
                organization_id,
                "cloudsentinel.reports.generate",
                f"{report.id}:v{version}",
            ):
                continue
            session.info.pop("allow_unscoped", None)
            session.info["tenant_id"] = organization_id
            now = datetime.now(UTC)
            report.updated_at = now
            enqueue_task(
                session,
                organization_id=organization_id,
                task_type="cloudsentinel.reports.generate",
                aggregate_id=f"{report.id}:v{version}:queued-recovery",
                payload={"report_id": str(report.id), "report_version": version},
                available_at=now,
            )
            record_audit(
                session,
                organization_id=organization_id,
                actor_user_id=None,
                action="report.queued_delivery_recovered",
                resource_type="report",
                resource_id=report.id,
            )
            session.commit()
            reconciled += 1

    for scan_id, organization_id in queued_customer_scans:
        with factory(info={"allow_unscoped": True}) as session:
            job = session.scalar(
                select(CustomerScanJob)
                .where(
                    CustomerScanJob.id == scan_id,
                    CustomerScanJob.organization_id == organization_id,
                    CustomerScanJob.status == "queued",
                    CustomerScanJob.updated_at < queued_cutoff,
                )
                .with_for_update(skip_locked=True)
            )
            if job is None or _has_live_task_event(
                session,
                organization_id,
                "cloudsentinel.customer_scans.run",
                str(job.id),
            ):
                continue
            session.info.pop("allow_unscoped", None)
            session.info["tenant_id"] = organization_id
            now = datetime.now(UTC)
            job.updated_at = now
            enqueue_task(
                session,
                organization_id=organization_id,
                task_type="cloudsentinel.customer_scans.run",
                aggregate_id=f"{job.id}:queued-recovery",
                payload={"customer_scan_id": str(job.id)},
                available_at=now,
            )
            record_audit(
                session,
                organization_id=organization_id,
                actor_user_id=None,
                action="customer_scan.queued_delivery_recovered",
                resource_type="customer_scan_job",
                resource_id=job.id,
            )
            session.commit()
            reconciled += 1
    return reconciled


def _has_live_task_event(
    session: Session, organization_id: UUID, task_type: str, aggregate_prefix: str
) -> bool:
    """Avoid duplicate recovery publishes while any event for this job is in flight."""
    return session.scalar(
        select(TaskOutbox.id)
        .where(
            TaskOutbox.organization_id == organization_id,
            TaskOutbox.task_type == task_type,
            TaskOutbox.status.in_(("pending", "dispatching")),
            or_(
                TaskOutbox.aggregate_id == aggregate_prefix,
                TaskOutbox.aggregate_id.like(f"{aggregate_prefix}:%"),
            ),
        )
        .limit(1)
    ) is not None


def expire_retained_reports(factory: sessionmaker[Session], *, limit: int = BATCH_SIZE) -> int:
    """Purge retained report snapshots and artifacts while preserving audit history."""
    from boto3 import client as boto3_client

    from app.core.models import Report

    settings = get_settings()
    now = datetime.now(UTC)
    with factory(info={"allow_unscoped": True}) as session:
        candidates = list(
            session.execute(
                select(Report.id, Report.organization_id, Report.storage_key)
                .where(
                    Report.status == "COMPLETED",
                    Report.retention_until.is_not(None),
                    Report.retention_until <= now,
                )
                .order_by(Report.retention_until)
                .limit(limit)
            ).all()
        )

    expired = 0
    storage = None
    report_bucket = settings.report_storage_bucket
    if report_bucket:
        client_options: dict[str, str | None] = {
            "region_name": settings.report_storage_region or None,
            "endpoint_url": settings.report_storage_endpoint_url or None,
        }
        if settings.report_storage_access_key and settings.report_storage_secret_key:
            client_options["aws_access_key_id"] = (
                settings.report_storage_access_key.get_secret_value()
            )
            client_options["aws_secret_access_key"] = (
                settings.report_storage_secret_key.get_secret_value()
            )
        storage = boto3_client("s3", **client_options)

    for report_id, organization_id, storage_key in candidates:
        if storage_key:
            if storage is None or report_bucket is None:
                logger.error("Cannot expire stored report without configured object storage")
                continue
            try:
                _delete_report_artifact(storage, bucket=report_bucket, key=storage_key)
            except Exception as error:
                logger.error(
                    "Report artifact deletion failed",
                    extra={"error_type": type(error).__name__},
                )
                continue

        with factory(info={"allow_unscoped": True}) as session:
            report = session.scalar(
                select(Report)
                .where(
                    Report.id == report_id,
                    Report.organization_id == organization_id,
                    Report.status == "COMPLETED",
                    Report.retention_until.is_not(None),
                    Report.retention_until <= now,
                )
                .with_for_update(skip_locked=True)
            )
            if report is None:
                continue
            session.info.pop("allow_unscoped", None)
            session.info["tenant_id"] = organization_id
            retention_until = report.retention_until
            report.status = "EXPIRED"
            report.snapshot = None
            report.checksum = None
            report.snapshot_checksum = None
            report.storage_key = None
            report.storage_version_id = None
            report.file_size = None
            report.error_code = "retention_expired"
            report.error_message = "This report has passed its configured retention period."
            report.updated_at = now
            record_audit(
                session,
                organization_id=organization_id,
                actor_user_id=None,
                action="report.retention_expired",
                resource_type="report",
                resource_id=report.id,
                details={
                    "retention_until": retention_until.isoformat()
                    if retention_until is not None
                    else None
                },
            )
            session.commit()
            expired += 1
    return expired


def _delete_report_artifact(storage: Any, *, bucket: str, key: str) -> None:
    """Delete the exact report key, including previous versions in a versioned bucket."""
    paginator = storage.get_paginator("list_object_versions")
    versions: list[dict[str, str]] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=key):
        for field in ("Versions", "DeleteMarkers"):
            for item in page.get(field, []):
                if item.get("Key") == key and isinstance(item.get("VersionId"), str):
                    versions.append({"Key": key, "VersionId": item["VersionId"]})
    if not versions:
        storage.delete_object(Bucket=bucket, Key=key)
        return
    for start in range(0, len(versions), 1000):
        response = storage.delete_objects(
            Bucket=bucket,
            Delete={"Objects": versions[start : start + 1000], "Quiet": True},
        )
        if response.get("Errors"):
            raise RuntimeError("One or more retained report versions could not be deleted")


def dispatch_outbox_event_now(
    session: Session,
    *,
    outbox_id: UUID,
    publisher: Any,
    task_id: str | None = None,
) -> None:
    """Attempt immediate delivery after commit while retaining relay recovery."""
    event = session.scalar(
        select(TaskOutbox).where(TaskOutbox.id == outbox_id).with_for_update()
    )
    if event is None or event.status != "pending" or event.available_at > datetime.now(UTC):
        return
    token = uuid4()
    event.status = "dispatching"
    event.attempt_count += 1
    event.claim_token = token
    event.claimed_until = datetime.now(UTC) + timedelta(seconds=CLAIM_LEASE_SECONDS)
    task_type = event.task_type
    payload = dict(event.payload)
    attempt_count = event.attempt_count
    session.commit()

    try:
        publisher(args=_task_args(task_type, payload), task_id=task_id or str(outbox_id))
    except Exception as error:
        logger.warning(
            "Immediate task dispatch failed",
            extra={"task_type": task_type, "error_type": type(error).__name__},
        )
        current = session.scalar(
            select(TaskOutbox)
            .where(
                TaskOutbox.id == outbox_id,
                TaskOutbox.status == "dispatching",
                TaskOutbox.claim_token == token,
            )
            .with_for_update()
        )
        if current is not None:
            _apply_dispatch_failure(
                session,
                current,
                attempt_count=attempt_count,
                error_code=(
                    "invalid_outbox_payload"
                    if isinstance(error, ValueError)
                    else "broker_unavailable"
                ),
            )
        return

    current = session.scalar(
        select(TaskOutbox)
        .where(
            TaskOutbox.id == outbox_id,
            TaskOutbox.status == "dispatching",
            TaskOutbox.claim_token == token,
        )
        .with_for_update()
    )
    if current is not None:
        current.status = "dispatched"
        current.dispatched_at = datetime.now(UTC)
        current.claimed_until = None
        current.claim_token = None
        current.last_error_code = None
        session.commit()


def _task_args(task_type: str, payload: dict[str, object]) -> list[str | int]:
    if task_type == "cloudsentinel.scan_jobs.process":
        scan_job_id = payload.get("scan_job_id")
        if not isinstance(scan_job_id, str):
            raise ValueError("Scan task payload is invalid")
        UUID(scan_job_id)
        return [scan_job_id]
    if task_type == "cloudsentinel.reports.generate":
        report_id = payload.get("report_id")
        report_version = payload.get("report_version")
        if not isinstance(report_id, str) or not isinstance(report_version, int):
            raise ValueError("Report task payload is invalid")
        UUID(report_id)
        return [report_id, report_version]
    if task_type == "cloudsentinel.customer_scans.run":
        customer_scan_id = payload.get("customer_scan_id")
        if not isinstance(customer_scan_id, str):
            raise ValueError("Customer scan task payload is invalid")
        UUID(customer_scan_id)
        return [customer_scan_id]
    raise ValueError("Unsupported task type")


def _mark_dispatched(
    factory: sessionmaker[Session], *, outbox_id: UUID, claim_token: UUID
) -> None:
    with factory(info={"allow_unscoped": True}) as session:
        event = session.scalar(
            select(TaskOutbox).where(
                TaskOutbox.id == outbox_id,
                TaskOutbox.status == "dispatching",
                TaskOutbox.claim_token == claim_token,
            )
        )
        if event is None:
            return
        event.status = "dispatched"
        event.dispatched_at = datetime.now(UTC)
        event.claimed_until = None
        event.claim_token = None
        event.last_error_code = None
        session.commit()


def _record_dispatch_failure(
    factory: sessionmaker[Session],
    *,
    outbox_id: UUID,
    claim_token: UUID,
    attempt_count: int,
    error_code: str,
) -> None:
    with factory(info={"allow_unscoped": True}) as session:
        event = session.scalar(
            select(TaskOutbox)
            .where(
                TaskOutbox.id == outbox_id,
                TaskOutbox.status == "dispatching",
                TaskOutbox.claim_token == claim_token,
            )
            .with_for_update()
        )
        if event is None:
            return
        session.info.pop("allow_unscoped", None)
        session.info["tenant_id"] = event.organization_id
        _apply_dispatch_failure(session, event, attempt_count=attempt_count, error_code=error_code)


def _apply_dispatch_failure(
    session: Session,
    event: TaskOutbox,
    *,
    attempt_count: int,
    error_code: str,
) -> None:
    event.last_error_code = error_code
    event.claim_token = None
    event.claimed_until = None
    if attempt_count < MAX_DISPATCH_ATTEMPTS:
        delay_seconds = min(300, 2**min(attempt_count, 8))
        event.status = "pending"
        event.available_at = datetime.now(UTC) + timedelta(seconds=delay_seconds)
        session.commit()
        return

    event.status = "dead"
    event.dead_lettered_at = datetime.now(UTC)
    _fail_domain_work(session, event, error_code=error_code)
    session.commit()


def _fail_domain_work(session: Session, event: TaskOutbox, *, error_code: str) -> None:
    organization = session.get(Organization, event.organization_id)
    if organization is None:
        return
    if event.task_type == "cloudsentinel.scan_jobs.process":
        raw_id = event.payload.get("scan_job_id")
        if not isinstance(raw_id, str):
            return
        try:
            scan_job_id = UUID(raw_id)
        except ValueError:
            return
        job = session.scalar(
            select(ScanJob).where(
                ScanJob.id == scan_job_id,
                ScanJob.organization_id == event.organization_id,
            )
        )
        if job is None or job.status != "queued":
            return
        job.status = "failed"
        job.errors_count = 1
        job.error_codes = [{"code": "scan_queue_delivery_failed"}]
        job.finished_at = datetime.now(UTC)
        emit_scan_alert(session, job)
        record_audit(
            session,
            organization_id=event.organization_id,
            actor_user_id=None,
            action="scan.dispatch_failed",
            resource_type="scan_job",
            resource_id=job.id,
            status="FAILURE",
            details={"error_code": error_code},
        )
        return

    if event.task_type == "cloudsentinel.reports.generate":
        raw_id = event.payload.get("report_id")
        version = event.payload.get("report_version")
        if not isinstance(raw_id, str) or not isinstance(version, int):
            return
        try:
            report_id = UUID(raw_id)
        except ValueError:
            return
        report = session.scalar(
            select(Report).where(
                Report.id == report_id,
                Report.organization_id == event.organization_id,
                Report.report_version == version,
            )
        )
        if report is None or report.status != "QUEUED":
            return
        report.status = "FAILED"
        report.error_code = "queue_delivery_failed"
        report.error_message = "Report generation could not be queued. Please retry later."
        report.updated_at = datetime.now(UTC)
        record_audit(
            session,
            organization_id=event.organization_id,
            actor_user_id=None,
            action="report.dispatch_failed",
            resource_type="report",
            resource_id=report.id,
            status="FAILURE",
            details={"error_code": error_code, "report_version": version},
        )
        return

    if event.task_type == "cloudsentinel.customer_scans.run":
        raw_id = event.payload.get("customer_scan_id")
        if not isinstance(raw_id, str):
            return
        try:
            scan_id = UUID(raw_id)
        except ValueError:
            return
        job = session.scalar(
            select(CustomerScanJob).where(
                CustomerScanJob.id == scan_id,
                CustomerScanJob.organization_id == event.organization_id,
            )
        )
        if job is None or job.status != "queued":
            return
        job.status = "failed"
        job.error_code = "queue_delivery_failed"
        job.finished_at = datetime.now(UTC)
        record_audit(
            session,
            organization_id=event.organization_id,
            actor_user_id=None,
            action="customer_scan.dispatch_failed",
            resource_type="customer_scan_job",
            resource_id=job.id,
            status="FAILURE",
            details={"error_code": error_code},
        )


def run_relay_forever() -> None:
    """Run the small database-backed dispatcher as a separately scalable process."""
    settings = get_settings()
    engine = create_database_engine(settings)
    if engine is None:
        raise ServiceUnavailableError("The task relay requires a configured database.")
    factory = create_session_factory(engine)
    stopped = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    next_reconciliation = 0.0
    next_retention_sweep = 0.0
    next_metrics_publish = 0.0
    try:
        while not stopped:
            current_time = time.monotonic()
            if current_time >= next_reconciliation:
                try:
                    reconciled = reconcile_stale_work(
                        factory, stale_after_minutes=settings.task_stale_after_minutes
                    )
                    if reconciled:
                        logger.warning(
                            "Reconciled stale asynchronous work",
                            extra={"count": reconciled},
                        )
                except Exception as error:
                    logger.error(
                        "Stale work reconciliation failed",
                        extra={"error_type": type(error).__name__},
                    )
                next_reconciliation = current_time + 60
            if current_time >= next_retention_sweep:
                try:
                    expired = expire_retained_reports(factory)
                    if expired:
                        logger.info("Expired retained reports", extra={"count": expired})
                    from app.retention import (
                        purge_expired_audit_events,
                        purge_offboarded_organizations,
                    )

                    purged_audit = purge_expired_audit_events(factory)
                    purged_tenants = purge_offboarded_organizations(factory)
                    from app.customer_scans.retention import purge_expired_customer_scans

                    purged_scans = purge_expired_customer_scans(factory)
                    if purged_audit or purged_tenants or purged_scans:
                        logger.info(
                            "Retention maintenance completed",
                            extra={
                                "expired_audit_events": purged_audit,
                                "offboarded_organizations": purged_tenants,
                                "expired_customer_scans": purged_scans,
                            },
                        )
                except Exception as error:
                    logger.error(
                        "Data retention sweep failed",
                        extra={"error_type": type(error).__name__},
                    )
                next_retention_sweep = current_time + 3600
            if current_time >= next_metrics_publish:
                try:
                    publish_operational_metrics(factory)
                except Exception as error:
                    logger.error(
                        "Operational metric publication failed",
                        extra={"error_type": type(error).__name__},
                    )
                next_metrics_publish = current_time + 60
            try:
                dispatched = dispatch_pending_tasks(factory)
            except Exception as error:
                logger.error("Task relay cycle failed", extra={"error_type": type(error).__name__})
                dispatched = 0
            if dispatched == 0:
                time.sleep(POLL_INTERVAL_SECONDS)
    finally:
        engine.dispose()


def publish_operational_metrics(factory: sessionmaker[Session]) -> None:
    """Publish queue depth, age, and stuck-work signals to CloudWatch."""
    from boto3 import client as boto3_client

    settings = get_settings()
    now = datetime.now(UTC)
    stale_before = now - timedelta(minutes=settings.task_stale_after_minutes)
    customer_scan_stale_before = now - timedelta(
        seconds=settings.customer_scan_timeout_seconds + 300
    )
    with factory(info={"allow_unscoped": True}) as session:
        counts: dict[str, int] = {
            str(row[0]): int(row[1])
            for row in session.execute(
                select(TaskOutbox.status, func.count()).group_by(TaskOutbox.status)
            )
        }
        oldest_pending = session.scalar(
            select(func.min(TaskOutbox.created_at)).where(TaskOutbox.status == "pending")
        )
        stuck_scans = session.scalar(
            select(func.count())
            .select_from(ScanJob)
            .where(ScanJob.status == "running", ScanJob.updated_at < stale_before)
        ) or 0
        stuck_reports = session.scalar(
            select(func.count())
            .select_from(Report)
            .where(Report.status == "GENERATING", Report.updated_at < stale_before)
        ) or 0
        customer_scan_counts: dict[str, int] = {
            str(row[0]): int(row[1])
            for row in session.execute(
                select(CustomerScanJob.status, func.count()).group_by(CustomerScanJob.status)
            )
        }
        stuck_customer_scans = session.scalar(
            select(func.count())
            .select_from(CustomerScanJob)
            .where(
                CustomerScanJob.status.in_(("running", "cancelling")),
                CustomerScanJob.updated_at < customer_scan_stale_before,
            )
        ) or 0

    oldest_pending_age = 0.0
    if oldest_pending is not None:
        if oldest_pending.tzinfo is None:
            oldest_pending = oldest_pending.replace(tzinfo=UTC)
        oldest_pending_age = max(0.0, (now - oldest_pending).total_seconds())

    metric_data = [
        {
            "MetricName": "OutboxPendingEvents",
            "Value": float(counts.get("pending", 0)),
            "Unit": "Count",
        },
        {
            "MetricName": "OutboxDispatchingEvents",
            "Value": float(counts.get("dispatching", 0)),
            "Unit": "Count",
        },
        {
            "MetricName": "OutboxDeadEvents",
            "Value": float(counts.get("dead", 0)),
            "Unit": "Count",
        },
        {
            "MetricName": "OutboxOldestPendingAgeSeconds",
            "Value": oldest_pending_age,
            "Unit": "Seconds",
        },
        {"MetricName": "StuckScanJobs", "Value": float(stuck_scans), "Unit": "Count"},
        {"MetricName": "StuckReportJobs", "Value": float(stuck_reports), "Unit": "Count"},
        {"MetricName": "CustomerScanQueuedJobs", "Value": float(customer_scan_counts.get("queued", 0)), "Unit": "Count"},
        {"MetricName": "StuckCustomerScanJobs", "Value": float(stuck_customer_scans), "Unit": "Count"},
    ]
    cloudwatch = boto3_client("cloudwatch")
    cloudwatch.put_metric_data(
        Namespace="CloudSentinel",
        MetricData=[
            {
                **metric,
                "Timestamp": now,
                "Dimensions": [{"Name": "Environment", "Value": settings.app_env}],
            }
            for metric in metric_data
        ],
    )


if __name__ == "__main__":
    run_relay_forever()
