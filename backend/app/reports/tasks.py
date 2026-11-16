"""Celery worker for immutable report snapshots."""

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

import boto3
from botocore.exceptions import (
    ClientError,
    ConnectionClosedError,
    EndpointConnectionError,
    ReadTimeoutError,
)
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.database import create_database_engine, create_session_factory
from app.core.models import (
    Membership,
    Organization,
    Permission,
    Report,
    RolePermission,
    User,
)
from app.operations.router import _build_report_snapshot, _report_csv, _report_pdf
from app.operations.service import notify_user, record_audit
from app.task_outbox import enqueue_task

logger = logging.getLogger("cloudsentinel.report_worker")


@celery_app.task(name="cloudsentinel.reports.generate", acks_late=True)  # type: ignore[untyped-decorator]
def generate_report_task(report_id: str, report_version: int | None = None) -> str:
    """Revalidate the report creator and create a tenant-owned point-in-time snapshot."""
    try:
        parsed_id = UUID(report_id)
    except ValueError:
        logger.warning("Rejected report message with invalid identifier")
        return "invalid"

    settings = get_settings()
    engine = create_database_engine(settings)
    if engine is None:
        logger.error("Report worker has no database configuration")
        return "unavailable"
    factory = create_session_factory(engine)
    try:
        with factory(info={"allow_unscoped": True}) as session:
            return _generate_report(session, parsed_id, report_version)
    except Exception as error:
        logger.error("Report worker failed", extra={"error_type": type(error).__name__})
        return (
            "retrying"
            if _schedule_report_retry(
                factory,
                parsed_id,
                report_version,
                error,
                max_attempts=settings.task_execution_max_attempts,
            )
            else "failed"
        )
    finally:
        engine.dispose()


def _creator_authorized(session: Session, report: Report) -> bool:
    return (
        session.scalar(
            select(Membership.id)
            .join(User, User.id == Membership.user_id)
            .join(RolePermission, RolePermission.role_id == Membership.role_id)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(
                Membership.organization_id == report.organization_id,
                Membership.user_id == report.created_by_user_id,
                Membership.is_active.is_(True),
                Membership.is_locked.is_(False),
                User.is_active.is_(True),
                Permission.code == "reports:create",
            )
        )
        is not None
    )


def _generate_report(
    session: Session, report_id: UUID, expected_version: int | None = None
) -> str:
    report = session.scalar(select(Report).where(Report.id == report_id).with_for_update())
    if (
        report is None
        or report.status != "QUEUED"
        or (expected_version is not None and report.report_version != expected_version)
    ):
        return "ignored"
    organization_id = report.organization_id
    session.info.pop("allow_unscoped", None)
    session.info["tenant_id"] = organization_id
    organization = session.get(Organization, organization_id)
    if (
        organization is None
        or not organization.is_active
        or not _creator_authorized(session, report)
    ):
        report.status = "FAILED"
        report.error_code = "creator_not_authorized"
        report.error_message = "The report creator is no longer authorized to generate reports."
        report.updated_at = datetime.now(UTC)
        session.commit()
        return "unauthorized"

    report.status = "GENERATING"
    report.generation_attempt_count += 1
    generation_attempt = report.generation_attempt_count
    report.error_code = None
    report.error_message = None
    report.updated_at = datetime.now(UTC)
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=report.created_by_user_id,
        action="report.generation_started",
        resource_type="report",
        resource_id=report.id,
        details={"report_type": report.report_type, "report_version": report.report_version},
    )
    session.commit()

    snapshot_at = datetime.now(UTC)
    snapshot = _build_report_snapshot(
        session,
        organization_id,
        report.report_type,
        filters=report.filters,
        report_name=report.name,
        data_snapshot_at=snapshot_at,
    )
    canonical = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    snapshot_checksum = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    file_body, content_type = _render_report(report, snapshot)
    file_checksum = hashlib.sha256(file_body).hexdigest()
    settings = get_settings()
    storage_key: str | None = None
    storage_version_id: str | None = None
    if settings.report_storage_bucket:
        prefix = settings.report_storage_prefix.strip("/")
        storage_key = (
            f"{prefix}/{organization_id}/reports/{report_id}/v{report.report_version}."
            f"{report.file_format.lower()}"
        )
        storage_client_options: dict[str, str | None] = {
            "region_name": settings.report_storage_region or None,
            "endpoint_url": settings.report_storage_endpoint_url or None,
        }
        if settings.report_storage_access_key and settings.report_storage_secret_key:
            storage_client_options["aws_access_key_id"] = (
                settings.report_storage_access_key.get_secret_value()
            )
            storage_client_options["aws_secret_access_key"] = (
                settings.report_storage_secret_key.get_secret_value()
            )
        s3 = boto3.client("s3", **storage_client_options)
        upload_result = s3.put_object(
            Bucket=settings.report_storage_bucket,
            Key=storage_key,
            Body=file_body,
            ContentType=content_type,
        )
        version_id = upload_result.get("VersionId")
        if isinstance(version_id, str):
            storage_version_id = version_id
    row = session.scalar(select(Report).where(Report.id == report_id).with_for_update())
    if (
        row is None
        or row.status != "GENERATING"
        or row.generation_attempt_count != generation_attempt
    ):
        if row is not None and row.status == "CANCELLED" and storage_key and settings.report_storage_bucket:
            try:
                delete_params: dict[str, str] = {
                    "Bucket": settings.report_storage_bucket,
                    "Key": storage_key,
                }
                if storage_version_id:
                    delete_params["VersionId"] = storage_version_id
                s3.delete_object(**delete_params)
            except Exception as error:
                logger.warning(
                    "Cancelled report artifact cleanup failed",
                    extra={"error_type": type(error).__name__},
                )
        return "ignored"
    row.snapshot = snapshot
    row.checksum = file_checksum
    row.snapshot_checksum = snapshot_checksum
    row.storage_key = storage_key
    row.storage_version_id = storage_version_id
    row.file_size = len(file_body)
    row.data_snapshot_at = snapshot_at
    row.generated_at = datetime.now(UTC)
    row.retention_until = row.generated_at + timedelta(days=settings.report_retention_days)
    row.status = "COMPLETED"
    row.updated_at = row.generated_at
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=row.created_by_user_id,
        action="report.generated",
        resource_type="report",
        resource_id=row.id,
        details={
            "report_type": row.report_type,
            "report_version": row.report_version,
            "checksum": row.checksum,
            "snapshot_checksum": row.snapshot_checksum,
        },
    )
    notify_user(
        session,
        organization_id=organization_id,
        recipient_user_id=row.created_by_user_id,
        category="report",
        title="Report is ready",
        message=f"{row.name} has been generated.",
        resource_type="report",
        resource_id=row.id,
    )
    session.commit()
    return "completed"


def _render_report(report: Report, snapshot: dict[str, object]) -> tuple[bytes, str]:
    if report.file_format == "CSV":
        return _report_csv(snapshot).encode("utf-8"), "text/csv; charset=utf-8"
    if report.file_format == "PDF":
        return _report_pdf(snapshot, report.name), "application/pdf"
    return (
        json.dumps(snapshot, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8"),
        "application/json",
    )


def _schedule_report_retry(
    factory: sessionmaker[Session],
    report_id: UUID,
    expected_version: int | None,
    error: Exception,
    *,
    max_attempts: int,
) -> bool:
    """Retry transient report failures through the outbox, otherwise fail safely."""
    try:
        with factory(info={"allow_unscoped": True}) as session:
            row = session.get(Report, report_id)
            if (
                row is None
                or row.status not in {"QUEUED", "GENERATING"}
                or (expected_version is not None and row.report_version != expected_version)
            ):
                return False
            organization_id = row.organization_id
            session.info.pop("allow_unscoped", None)
            session.info["tenant_id"] = organization_id
            retryable = _is_transient_report_error(error)
            if retryable and row.generation_attempt_count < max_attempts:
                row.status = "QUEUED"
                retry_delay = min(300, 2**row.generation_attempt_count)
                enqueue_task(
                    session,
                    organization_id=organization_id,
                    task_type="cloudsentinel.reports.generate",
                    aggregate_id=(
                        f"{row.id}:v{row.report_version}:attempt:{row.generation_attempt_count}"
                    ),
                    payload={
                        "report_id": str(row.id),
                        "report_version": row.report_version,
                    },
                    available_at=datetime.now(UTC) + timedelta(seconds=retry_delay),
                )
                record_audit(
                    session,
                    organization_id=organization_id,
                    actor_user_id=None,
                    action="report.retry_scheduled",
                    resource_type="report",
                    resource_id=row.id,
                    details={
                        "attempt": row.generation_attempt_count,
                        "retry_delay_seconds": retry_delay,
                    },
                )
                session.commit()
                return True

            row.status = "FAILED"
            row.error_code = "generation_retry_exhausted" if retryable else "generation_failed"
            row.error_message = (
                "Report generation failed. Contact an administrator if this persists."
            )
            row.updated_at = datetime.now(UTC)
            record_audit(
                session,
                organization_id=organization_id,
                actor_user_id=None,
                action="report.generation_failed",
                resource_type="report",
                resource_id=row.id,
                status="FAILURE",
                details={"error_code": row.error_code, "attempts": row.generation_attempt_count},
            )
            session.commit()
            return False
    except Exception as error:
        logger.error("Could not persist report failure", extra={"error_type": type(error).__name__})
        return False


def _is_transient_report_error(error: Exception) -> bool:
    if isinstance(
        error,
        (
            OperationalError,
            InterfaceError,
            EndpointConnectionError,
            ReadTimeoutError,
            ConnectionClosedError,
            TimeoutError,
            ConnectionError,
        ),
    ):
        return True
    if isinstance(error, DBAPIError) and error.connection_invalidated:
        return True
    if isinstance(error, ClientError):
        error_details = error.response.get("Error", {})
        metadata = error.response.get("ResponseMetadata", {})
        code = error_details.get("Code")
        status_code = metadata.get("HTTPStatusCode")
        return bool(
            status_code is not None and status_code >= 500
            or code in {"Throttling", "ThrottlingException", "RequestLimitExceeded", "SlowDown"}
        )
    return False
