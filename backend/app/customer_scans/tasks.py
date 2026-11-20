"""Dispatch bounded scans to network-restricted one-shot ECS Fargate tasks."""

import json
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.core.config import Settings, get_settings
from app.core.database import create_database_engine, create_session_factory
from app.core.models import (
    CustomerScanFinding,
    CustomerScanJob,
    Membership,
    Organization,
    Permission,
    RolePermission,
    User,
)
from app.operations.service import record_audit
from app.task_outbox import enqueue_task

logger = logging.getLogger("cloudsentinel.customer_scan_worker")
MAX_FINDINGS = 2_000
MAX_RESULT_BYTES = 2 * 1024 * 1024
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}
ALLOWED_DETAILS = {
    "message", "primary_url", "installed_version", "fixed_version", "file_path",
    "file_line_range", "guideline", "code", "match",
}


@celery_app.task(name="cloudsentinel.customer_scans.run", acks_late=True)  # type: ignore[untyped-decorator]
def run_customer_scan_task(scan_id: str) -> str:
    try:
        parsed_id = UUID(scan_id)
    except ValueError:
        logger.warning("Rejected customer scan message with invalid identifier")
        return "invalid"
    settings = get_settings()
    engine = create_database_engine(settings)
    if engine is None:
        return "unavailable"
    factory = create_session_factory(engine)
    try:
        with factory(info={"allow_unscoped": True}) as session:
            return _run_customer_scan(session, parsed_id, factory, settings)
    except Exception as error:
        logger.error("Customer scan task failed", extra={"error_type": type(error).__name__})
        _schedule_retry(factory, parsed_id, settings, "worker_error")
        return "retrying"
    finally:
        engine.dispose()


def _run_customer_scan(session: Session, scan_id: UUID, factory: Any, settings: Settings) -> str:
    job = session.scalar(select(CustomerScanJob).where(CustomerScanJob.id == scan_id).with_for_update())
    if job is None or job.status in {"completed", "failed", "cancelled"}:
        return "ignored"
    if job.status == "cancelling":
        job.status = "cancelled"
        job.finished_at = datetime.now(UTC)
        session.commit()
        return "cancelled"
    if job.status != "queued":
        return "ignored"
    organization = session.get(Organization, job.organization_id)
    session.info.pop("allow_unscoped", None)
    session.info["tenant_id"] = job.organization_id
    authorized = session.scalar(
        select(Membership.id)
        .join(User, User.id == Membership.user_id)
        .join(RolePermission, RolePermission.role_id == Membership.role_id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(
            Membership.organization_id == job.organization_id,
            Membership.user_id == job.created_by_user_id,
            Membership.is_active.is_(True),
            Membership.is_locked.is_(False),
            User.is_active.is_(True),
            Permission.code == "scans:create",
        )
    ) if job.created_by_user_id else None
    if organization is None or not organization.is_active or authorized is None:
        return _finish(session, job, "failed", "initiator_no_longer_authorized")
    if job.expires_at <= datetime.now(UTC):
        return _finish(session, job, "failed", "artifact_expired")
    if not settings.customer_scan_enabled:
        return _finish(session, job, "failed", "sandbox_not_configured")

    job.status = "running"
    job.attempt_count += 1
    job.started_at = datetime.now(UTC)
    job.error_code = None
    session.commit()

    region = settings.report_storage_region
    ecs = boto3.client("ecs", region_name=region)
    s3 = _s3_client(settings)
    try:
        task_definition = ecs.describe_task_definition(
            taskDefinition=settings.customer_scan_task_definition_arn
        )["taskDefinition"]
        if task_definition.get("taskRoleArn"):
            return _finish(session, job, "failed", "scanner_task_role_forbidden")
        if task_definition.get("networkMode") != "awsvpc" or "FARGATE" not in task_definition.get("requiresCompatibilities", []):
            return _finish(session, job, "failed", "scanner_task_definition_invalid")
        input_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": settings.customer_scan_bucket, "Key": job.artifact_key},
            ExpiresIn=settings.customer_scan_timeout_seconds + 600,
        )
        result_key = f"{settings.customer_scan_prefix.strip('/')}/{job.organization_id}/{job.id}/result.json"
        result_url = s3.generate_presigned_url(
            "put_object",
            Params={"Bucket": settings.customer_scan_bucket, "Key": result_key, "ContentType": "application/json"},
            ExpiresIn=settings.customer_scan_timeout_seconds + 600,
        )
        response = ecs.run_task(
            cluster=settings.customer_scan_ecs_cluster_arn,
            taskDefinition=settings.customer_scan_task_definition_arn,
            launchType="FARGATE",
            platformVersion="1.4.0",
            count=1,
            startedBy=str(job.id),
            enableExecuteCommand=False,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [part.strip() for part in settings.customer_scan_task_subnets.split(",") if part.strip()],
                    "securityGroups": [settings.customer_scan_task_security_group],
                    "assignPublicIp": "DISABLED",
                }
            },
            overrides={
                "containerOverrides": [{
                    "name": "scanner",
                    "environment": [
                        {"name": "SCAN_TYPE", "value": job.scan_type},
                        {"name": "SOURCE_FILENAME", "value": job.source_filename},
                        {"name": "INPUT_URL", "value": input_url},
                        {"name": "RESULT_URL", "value": result_url},
                    ],
                }]
            },
            tags=[
                {"key": "Application", "value": "CloudSentinel"},
                {"key": "ScanId", "value": str(job.id)},
            ],
        )
        tasks = response.get("tasks", [])
        if response.get("failures") or len(tasks) != 1:
            logger.warning("ECS rejected customer scan launch", extra={"failure_count": len(response.get("failures", []))})
            return _schedule_retry(factory, job.id, settings, "sandbox_capacity_unavailable")
        task_arn = tasks[0].get("taskArn")
        if not isinstance(task_arn, str):
            return _schedule_retry(factory, job.id, settings, "sandbox_task_unavailable")
        job.ecs_task_arn = task_arn
        session.commit()
        return _wait_for_task(session, factory, ecs, s3, job, task_arn, result_key, settings)
    except (BotoCoreError, ClientError) as error:
        logger.warning("Customer scan sandbox request failed", extra={"error_type": type(error).__name__})
        return _schedule_retry(factory, job.id, settings, "sandbox_service_unavailable")


def _wait_for_task(
    session: Session,
    factory: Any,
    ecs: Any,
    s3: Any,
    job: CustomerScanJob,
    task_arn: str,
    result_key: str,
    settings: Settings,
) -> str:
    deadline = time.monotonic() + settings.customer_scan_timeout_seconds + 120
    while time.monotonic() < deadline:
        session.refresh(job)
        if job.status == "cancelling":
            if not stop_customer_scan_task(
                ecs,
                cluster=settings.customer_scan_ecs_cluster_arn,
                task_arn=task_arn,
                reason="User requested cancellation",
            ):
                return "cancelling"
            return _finish(session, job, "cancelled", None)
        try:
            tasks = ecs.describe_tasks(cluster=settings.customer_scan_ecs_cluster_arn, tasks=[task_arn]).get("tasks", [])
        except (BotoCoreError, ClientError) as error:
            logger.warning("ECS task status query failed", extra={"error_type": type(error).__name__})
            time.sleep(10)
            continue
        if not tasks:
            time.sleep(10)
            continue
        task = tasks[0]
        if task.get("lastStatus") != "STOPPED":
            time.sleep(10)
            continue
        container = next((item for item in task.get("containers", []) if item.get("name") == "scanner"), {})
        if container.get("exitCode") != 0:
            return _schedule_retry(factory, job.id, settings, "scanner_execution_failed")
        return _collect_result(session, s3, job, result_key)
    try:
        ecs.stop_task(cluster=settings.customer_scan_ecs_cluster_arn, task=task_arn, reason="CloudSentinel scan timeout")
    except Exception:
        logger.warning("Timed out scanner task could not be stopped")
    return _schedule_retry(factory, job.id, settings, "scanner_timeout")


def _collect_result(session: Session, s3: Any, job: CustomerScanJob, result_key: str) -> str:
    try:
        response = s3.get_object(Bucket=get_settings().customer_scan_bucket, Key=result_key)
        body = response["Body"].read(MAX_RESULT_BYTES + 1)
        if len(body) > MAX_RESULT_BYTES:
            raise ValueError("result_too_large")
        payload = json.loads(body)
    except Exception as error:
        logger.warning("Customer scan result could not be read", extra={"error_type": type(error).__name__})
        return _finish(session, job, "failed", "scanner_result_unavailable")
    if not isinstance(payload, dict) or payload.get("status") != "completed":
        return _finish(session, job, "failed", "scanner_execution_failed")
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list) or len(raw_findings) > MAX_FINDINGS:
        return _finish(session, job, "failed", "scanner_result_invalid")
    inserted: list[CustomerScanFinding] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            return _finish(session, job, "failed", "scanner_result_invalid")
        rule_id = _clean_text(raw.get("rule_id"), 160)
        title = _clean_text(raw.get("title"), 500)
        category = _clean_text(raw.get("category"), 40)
        severity = _clean_text(raw.get("severity"), 20).upper()
        if not rule_id or not title or category not in {"misconfiguration", "vulnerability", "secret"} or severity not in SEVERITIES:
            return _finish(session, job, "failed", "scanner_result_invalid")
        raw_details = raw.get("details")
        details = _sanitize_details(raw_details, category)
        inserted.append(CustomerScanFinding(
            organization_id=job.organization_id,
            scan_job_id=job.id,
            rule_id=rule_id,
            title=title,
            severity=severity,
            category=category,
            resource=_clean_text(raw.get("resource"), 700) or None,
            details=details,
        ))
    session.add_all(inserted)
    job.finding_count = len(inserted)
    job.scanner_version = _clean_text(payload.get("scanner_version"), 80) or "unknown"
    job.result = {"duration_seconds": _bounded_int(payload.get("duration_seconds"), 720)}
    job.status = "completed"
    job.error_code = None
    job.finished_at = datetime.now(UTC)
    record_audit(
        session,
        organization_id=job.organization_id,
        actor_user_id=None,
        action="customer_scan.completed",
        resource_type="customer_scan_job",
        resource_id=job.id,
        details={"finding_count": len(inserted), "scan_type": job.scan_type},
    )
    session.commit()
    return "completed"


def _schedule_retry(factory: Any, scan_id: UUID, settings: Settings, error_code: str) -> str:
    with factory(info={"allow_unscoped": True}) as session:
        existing = session.get(CustomerScanJob, scan_id)
        if existing is None or existing.status not in {"running", "queued"}:
            return "ignored"
        task_arn = existing.ecs_task_arn
        organization_id = existing.organization_id
        attempts = existing.attempt_count
        should_retry = attempts < settings.task_execution_max_attempts and existing.expires_at > datetime.now(UTC)

    stopped = True
    if should_retry and task_arn:
        ecs = boto3.client("ecs", region_name=settings.report_storage_region)
        stopped = stop_customer_scan_task(
            ecs,
            cluster=settings.customer_scan_ecs_cluster_arn,
            task_arn=task_arn,
            reason="CloudSentinel is safely retrying this scan",
        )

    with factory(info={"allow_unscoped": True}) as session:
        job = session.scalar(select(CustomerScanJob).where(CustomerScanJob.id == scan_id).with_for_update())
        if job is None or job.status not in {"running", "queued"}:
            return "ignored"
        now = datetime.now(UTC)
        if job.attempt_count < settings.task_execution_max_attempts and job.expires_at > now:
            if job.ecs_task_arn and (job.ecs_task_arn != task_arn or not stopped):
                job.status = "failed"
                job.error_code = "scanner_stop_unconfirmed"
                job.finished_at = now
                record_audit(
                    session,
                    organization_id=job.organization_id,
                    actor_user_id=None,
                    action="customer_scan.failed",
                    resource_type="customer_scan_job",
                    resource_id=job.id,
                    status="FAILURE",
                    details={"error_code": job.error_code, "attempts": job.attempt_count},
                )
                session.commit()
                return "failed"
            delay = min(300, 2 ** max(1, job.attempt_count))
            job.status = "queued"
            job.started_at = None
            job.ecs_task_arn = None
            job.error_code = error_code
            enqueue_task(
                session,
                organization_id=job.organization_id,
                task_type="cloudsentinel.customer_scans.run",
                aggregate_id=f"{job.id}:attempt:{job.attempt_count}",
                payload={"customer_scan_id": str(job.id)},
                available_at=now + timedelta(seconds=delay),
            )
            session.commit()
            return "retrying"
        job.status = "failed"
        job.error_code = error_code
        job.finished_at = now
        record_audit(
            session,
            organization_id=job.organization_id,
            actor_user_id=None,
            action="customer_scan.failed",
            resource_type="customer_scan_job",
            resource_id=job.id,
            status="FAILURE",
            details={"error_code": error_code, "attempts": job.attempt_count},
        )
        session.commit()
    return "failed"


def stop_customer_scan_task(
    ecs: Any, *, cluster: str | None, task_arn: str, reason: str
) -> bool:
    """Stop one owned Fargate task and confirm it reached STOPPED before a retry."""
    if not cluster:
        return False
    try:
        described = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        if described and described[0].get("lastStatus") == "STOPPED":
            return True
        ecs.stop_task(cluster=cluster, task=task_arn, reason=reason[:255])
        ecs.get_waiter("tasks_stopped").wait(
            cluster=cluster,
            tasks=[task_arn],
            WaiterConfig={"Delay": 5, "MaxAttempts": 24},
        )
        return True
    except Exception as error:
        logger.warning(
            "Customer scan Fargate task could not be confirmed stopped",
            extra={"error_type": type(error).__name__},
        )
        return False


def _finish(session: Session, job: CustomerScanJob, status: str, error_code: str | None) -> str:
    job.status = status
    job.error_code = error_code
    job.finished_at = datetime.now(UTC)
    if status == "failed":
        record_audit(
            session,
            organization_id=job.organization_id,
            actor_user_id=None,
            action="customer_scan.failed",
            resource_type="customer_scan_job",
            resource_id=job.id,
            status="FAILURE",
            details={"error_code": error_code},
        )
    session.commit()
    return status


def _clean_text(value: object, max_length: int) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("\x00", " ").strip()[:max_length]


def _bounded_int(value: object, max_value: int) -> int:
    return value if isinstance(value, int) and 0 <= value <= max_value else 0


def _sanitize_details(raw: object, category: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        return {}
    safe: dict[str, object] = {}
    for key, value in raw.items():
        if key not in ALLOWED_DETAILS:
            continue
        if category == "secret" and key != "code":
            continue
        if key == "match":
            safe[key] = "[REDACTED]"
        elif key == "file_line_range" and isinstance(value, list):
            safe[key] = [int(part) for part in value[:2] if isinstance(part, int) and 0 <= part <= 10_000_000]
        elif isinstance(value, str):
            safe[key] = _clean_text(value, 1000)
    return safe


def _s3_client(settings: Settings):
    options: dict[str, object] = {
        "region_name": settings.report_storage_region,
        "endpoint_url": settings.report_storage_endpoint_url or None,
    }
    if settings.report_storage_access_key and settings.report_storage_secret_key:
        options["aws_access_key_id"] = settings.report_storage_access_key.get_secret_value()
        options["aws_secret_access_key"] = settings.report_storage_secret_key.get_secret_value()
    return boto3.client("s3", **options)
