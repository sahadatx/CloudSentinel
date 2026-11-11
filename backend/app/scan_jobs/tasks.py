"""Tenant-revalidated Celery execution for AWS inventory collection jobs."""

import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectionClosedError,
    EndpointConnectionError,
    ReadTimeoutError,
)
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.orm import Session

from app.alerts.service import emit_scan_alert
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.database import create_database_engine, create_session_factory
from app.core.domain_errors import ConflictError
from app.core.models import (
    Asset,
    AssetRelationship,
    CloudAccount,
    CloudRegion,
    Membership,
    Organization,
    Permission,
    PolicyDefinition,
    RolePermission,
    ScanJob,
    User,
)
from app.findings.service import record_policy_evaluations
from app.operations.service import notify_user, record_audit
from app.policies.service import ensure_builtin_policies, record_asset_assessments
from app.task_outbox import enqueue_task
from cloudsentinel_scanner.collectors.aws_inventory import AWSInventoryCollector
from cloudsentinel_scanner.normalizers.aws import NormalizedAsset, ResourceReference
from cloudsentinel_scanner.providers.aws.session import AWSIdentityMismatch, assume_readonly_session

logger = logging.getLogger("cloudsentinel.scan_worker")
TERMINAL_STATES = {"completed", "partial", "failed", "cancelled"}
ERROR_CODE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


@celery_app.task(name="cloudsentinel.scan_jobs.process", acks_late=True)  # type: ignore[untyped-decorator]
def process_scan_job(job_id: str) -> str:
    """Process one persisted job; task messages never carry tenant or credential data."""
    try:
        parsed_job_id = UUID(job_id)
    except ValueError:
        logger.warning("Rejected scan message with invalid job identifier")
        return "invalid"

    settings = get_settings()
    engine = create_database_engine(settings)
    if engine is None:
        logger.error("Scan worker has no database configuration")
        return "unavailable"
    factory = create_session_factory(engine)
    try:
        with factory(info={"allow_unscoped": True}) as session:
            return _execute_job(session, parsed_job_id, settings=settings)
    except Exception as error:
        logger.error("Scan worker failed", extra={"error_type": type(error).__name__})
        return (
            "retrying"
            if _schedule_scan_retry(
                factory,
                parsed_job_id,
                error,
                max_attempts=settings.task_execution_max_attempts,
            )
            else "failed"
        )
    finally:
        engine.dispose()


def _execute_job(session: Session, job_id: UUID, *, settings: Any | None = None) -> str:
    job = session.scalar(select(ScanJob).where(ScanJob.id == job_id).with_for_update())
    if job is None or job.status in TERMINAL_STATES:
        return "ignored"
    if job.status == "cancelling":
        job.status = "cancelled"
        job.finished_at = datetime.now(UTC)
        session.commit()
        return "cancelled"
    if job.status != "queued":
        return "ignored"

    organization_id = job.organization_id
    session.info.pop("allow_unscoped", None)
    session.info["tenant_id"] = organization_id
    organization = session.get(Organization, organization_id)
    account = session.scalar(
        select(CloudAccount).where(
            CloudAccount.id == job.cloud_account_id,
            CloudAccount.organization_id == organization_id,
        )
    )
    if (
        organization is None
        or not organization.is_active
        or not _initiator_authorized(session, job)
    ):
        return _finish_job(session, job, "failed", error_code="initiator_no_longer_authorized")
    active_settings = settings or get_settings()
    if (
        account is None
        or account.connection_status != "connected"
        or account.validation_mode not in {"real", "mock"}
        or (
            account.validation_mode == "mock"
            and (
                active_settings.aws_validation_mode != "mock"
                or active_settings.app_env not in {"development", "test"}
            )
        )
    ):
        return _finish_job(session, job, "failed", error_code="cloud_account_unavailable")
    role_arn = account.role_arn
    if role_arn is None:
        return _finish_job(session, job, "failed", error_code="cloud_account_unavailable")

    configured_regions = set(
        session.scalars(
            select(CloudRegion.region_code).where(
                CloudRegion.organization_id == organization_id,
                CloudRegion.cloud_account_id == account.id,
                CloudRegion.is_enabled.is_(True),
            )
        ).all()
    )
    regions = list(job.requested_regions)
    if not regions or not set(regions).issubset(configured_regions):
        return _finish_job(session, job, "failed", error_code="scan_scope_invalid")

    job.status = "running"
    job.attempt_count += 1
    attempt_number = job.attempt_count
    job.started_at = datetime.now(UTC)
    job.progress_completed = 0
    job.resources_discovered = 0
    job.errors_count = 0
    job.error_codes = []
    session.commit()
    ensure_builtin_policies(session, organization_id)
    enabled_policies = list(
        session.scalars(
            select(PolicyDefinition)
            .where(
                PolicyDefinition.organization_id == organization_id,
                PolicyDefinition.status == "enabled",
            )
            .order_by(PolicyDefinition.rule_id)
        ).all()
    )

    if account.validation_mode == "mock":
        # Local mock connections use deterministic sample inventory so the scan
        # and Assets workflow can be exercised without AWS credentials. The
        # marker remains in asset attributes to distinguish it from AWS data.
        from app.scan_jobs.mock_inventory import mock_inventory
        from app.scan_jobs.planning import planned_units

        pending_relationships: list[tuple[UUID, ResourceReference]] = []
        for resource_type, region in planned_units(
            list(job.requested_resource_types), list(job.requested_regions)
        ):
            session.refresh(job)
            if job.attempt_count != attempt_number:
                return "superseded"
            mock_resources = mock_inventory(
                resource_type,
                region,
                account_id=account.account_id,
                partition=role_arn.split(":", maxsplit=2)[1],
                environment=account.environment,
            )
            session.refresh(job)
            if job.attempt_count != attempt_number:
                return "superseded"
            pending_relationships.extend(
                _persist_resources(session, job, account, mock_resources, enabled_policies)
            )
            job.resources_discovered += len(mock_resources)
            job.progress_completed += 1
            session.commit()
        _resolve_relationships(session, job, account, pending_relationships)
        session.refresh(job)
        if job.attempt_count != attempt_number:
            return "superseded"
        job.status = "completed"
        job.finished_at = datetime.now(UTC)
        _record_job_completion(session, job, execution_mode="mock")
        session.commit()
        return "completed"

    pending_relationships = []
    partition = role_arn.split(":", maxsplit=2)[1]
    regional_sessions: dict[str, Any] = {}
    resource_types = list(job.requested_resource_types)
    from app.scan_jobs.planning import planned_units

    for resource_type, collection_region in planned_units(resource_types, regions):
        session.refresh(job)
        if job.attempt_count != attempt_number:
            return "superseded"
        if job.status == "cancelling" or job.cancel_requested_at is not None:
            return _finish_with_relationships(
                session,
                job,
                account,
                pending_relationships,
                "cancelled",
            )
        if not _initiator_authorized(session, job):
            return _finish_with_relationships(
                session,
                job,
                account,
                pending_relationships,
                "failed",
                error_code="initiator_no_longer_authorized",
            )
        result_error: str | None = None
        try:
            session.refresh(account)
            if account.connection_status != "connected" or account.validation_mode != "real":
                raise RuntimeError("configured account state changed")
            aws_session = regional_sessions.get(collection_region)
            if aws_session is None:
                aws_session = _assume_region_session(account, job, collection_region)
                regional_sessions[collection_region] = aws_session
            collector = AWSInventoryCollector(
                aws_session,
                account_id=account.account_id,
                partition=partition,
                allowed_regions=frozenset(regions),
            )
            result = collector.collect(resource_type, collection_region)
            if result.error_code in {
                "ExpiredToken",
                "ExpiredTokenException",
                "RequestExpired",
            }:
                aws_session = _assume_region_session(account, job, collection_region)
                regional_sessions[collection_region] = aws_session
                collector = AWSInventoryCollector(
                    aws_session,
                    account_id=account.account_id,
                    partition=partition,
                    allowed_regions=frozenset(regions),
                )
                result = collector.collect(resource_type, collection_region)
        except AWSIdentityMismatch:
            result_error = "account_identity_mismatch"
            collected_resources: tuple[NormalizedAsset, ...] = ()
        except (BotoCoreError, ClientError) as error:
            result_error = _safe_error_code(error)
            collected_resources = ()
        except RuntimeError:
            result_error = "cloud_account_unavailable"
            collected_resources = ()
        else:
            result_error = result.error_code
            collected_resources = result.resources

        session.refresh(job)
        if job.attempt_count != attempt_number:
            return "superseded"
        if result_error is not None:
            _record_error(job, resource_type, collection_region, result_error)
        else:
            pending_relationships.extend(
                _persist_resources(
                    session,
                    job,
                    account,
                    collected_resources,
                    enabled_policies,
                )
            )
            job.resources_discovered += len(collected_resources)
        job.progress_completed = min(job.progress_total, job.progress_completed + 1)
        session.commit()

    session.refresh(job)
    if job.attempt_count != attempt_number:
        return "superseded"
    if job.status == "cancelling" or job.cancel_requested_at is not None:
        terminal_state = "cancelled"
    elif job.errors_count and job.resources_discovered:
        terminal_state = "partial"
    elif job.errors_count:
        terminal_state = "failed"
    else:
        terminal_state = "completed"
    _resolve_relationships(session, job, account, pending_relationships)
    if terminal_state == "completed" and job.errors_count == 0:
        _mark_unseen_assets(session, job, account)
    job.status = terminal_state
    job.finished_at = datetime.now(UTC)
    emit_scan_alert(session, job)
    _record_job_completion(session, job)
    session.commit()
    return terminal_state


def _assume_region_session(account: CloudAccount, job: ScanJob, region: str) -> Any:
    role_arn = account.role_arn
    if role_arn is None:
        raise RuntimeError("cloud account role is unavailable")
    return assume_readonly_session(
        role_arn=role_arn,
        external_id=account.external_id,
        expected_account_id=account.account_id,
        region_name=region,
        session_name=f"CloudSentinel-{job.id.hex[:16]}-{region}",
    )


def _initiator_authorized(session: Session, job: ScanJob) -> bool:
    return (
        session.scalar(
            select(Membership.id)
            .join(User, User.id == Membership.user_id)
            .join(RolePermission, RolePermission.role_id == Membership.role_id)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(
                Membership.id == job.requested_by_membership_id,
                Membership.organization_id == job.organization_id,
                Membership.user_id == job.requested_by_user_id,
                Membership.is_active.is_(True),
                User.is_active.is_(True),
                Permission.code == "scans:create",
            )
        )
        is not None
    )


def _persist_resources(
    session: Session,
    job: ScanJob,
    account: CloudAccount,
    resources: tuple[NormalizedAsset, ...],
    policies: list[PolicyDefinition],
) -> list[tuple[UUID, ResourceReference]]:
    pending: list[tuple[UUID, ResourceReference]] = []
    now = datetime.now(UTC)
    for resource in resources:
        asset = session.scalar(
            select(Asset).where(
                Asset.organization_id == job.organization_id,
                Asset.cloud_account_id == account.id,
                Asset.resource_type == resource.resource_type,
                Asset.region_code == resource.region_code,
                Asset.resource_id == resource.resource_id,
            )
        )
        if asset is None:
            asset = Asset(
                organization_id=job.organization_id,
                cloud_account_id=account.id,
                provider="AWS",
                resource_type=resource.resource_type,
                resource_id=resource.resource_id,
                region_code=resource.region_code,
                first_seen_at=now,
            )
            session.add(asset)
        asset.resource_arn = resource.resource_arn
        asset.name = resource.name
        asset.tags = resource.tags
        asset.owner_metadata = resource.owner_metadata
        asset.attributes = resource.attributes
        asset.status = "active"
        asset.missed_scan_count = 0
        asset.last_seen_at = now
        asset.last_scan_job_id = job.id
        session.flush()
        record_asset_assessments(session, job=job, asset=asset, policies=policies)
        record_policy_evaluations(
            session,
            job=job,
            account=account,
            asset=asset,
            asset_data={
                "resource_type": asset.resource_type,
                "resource_id": asset.resource_id,
                "resource_arn": asset.resource_arn,
                "region_code": asset.region_code,
                "tags": asset.tags,
                "attributes": asset.attributes,
            },
            policies=policies,
        )
        pending.extend((asset.id, reference) for reference in resource.relationships)
    return pending


def _mark_unseen_assets(session: Session, job: ScanJob, account: CloudAccount) -> None:
    """Mark assets stale after one clean miss and removed after a second clean miss."""
    if not job.requested_regions or not job.requested_resource_types:
        return
    unseen = session.scalars(
        select(Asset).where(
            Asset.organization_id == job.organization_id,
            Asset.cloud_account_id == account.id,
            Asset.region_code.in_(job.requested_regions),
            Asset.resource_type.in_(job.requested_resource_types),
            Asset.status != "removed",
            Asset.last_scan_job_id != job.id,
        )
    ).all()
    # SQL NULL does not match `!=`; include older assets that predate scan linking.
    unlinked = session.scalars(
        select(Asset).where(
            Asset.organization_id == job.organization_id,
            Asset.cloud_account_id == account.id,
            Asset.region_code.in_(job.requested_regions),
            Asset.resource_type.in_(job.requested_resource_types),
            Asset.status != "removed",
            Asset.last_scan_job_id.is_(None),
        )
    ).all()
    now = datetime.now(UTC)
    for asset in [*unseen, *unlinked]:
        asset.missed_scan_count += 1
        asset.status = "removed" if asset.missed_scan_count >= 2 else "stale"
        asset.updated_at = now


def _resolve_relationships(
    session: Session,
    job: ScanJob,
    account: CloudAccount,
    pending: list[tuple[UUID, ResourceReference]],
) -> None:
    for source_id, reference in pending:
        target = session.scalar(
            select(Asset).where(
                Asset.organization_id == job.organization_id,
                Asset.cloud_account_id == account.id,
                Asset.resource_type == reference.resource_type,
                Asset.region_code == reference.region_code,
                Asset.resource_id == reference.resource_id,
            )
        )
        if target is None:
            continue
        exists = session.scalar(
            select(AssetRelationship.id).where(
                AssetRelationship.organization_id == job.organization_id,
                AssetRelationship.source_asset_id == source_id,
                AssetRelationship.target_asset_id == target.id,
                AssetRelationship.relationship_type == reference.relationship_type,
            )
        )
        if exists is None:
            session.add(
                AssetRelationship(
                    organization_id=job.organization_id,
                    source_asset_id=source_id,
                    target_asset_id=target.id,
                    relationship_type=reference.relationship_type,
                )
            )
    session.flush()


def _finish_with_relationships(
    session: Session,
    job: ScanJob,
    account: CloudAccount,
    pending: list[tuple[UUID, ResourceReference]],
    status: str,
    *,
    error_code: str | None = None,
) -> str:
    _resolve_relationships(session, job, account, pending)
    return _finish_job(session, job, status, error_code=error_code)


def _finish_job(
    session: Session, job: ScanJob, status: str, *, error_code: str | None = None
) -> str:
    if error_code is not None:
        _record_error(job, "scan", "global", error_code)
    job.status = status
    job.finished_at = datetime.now(UTC)
    emit_scan_alert(session, job)
    _record_job_completion(session, job)
    session.commit()
    return status


def _record_job_completion(session: Session, job: ScanJob, *, execution_mode: str = "real") -> None:
    """Write a secret-free scan completion event and notify its active requester."""
    record_audit(
        session,
        organization_id=job.organization_id,
        actor_user_id=None,
        action="scan.completed",
        resource_type="scan_job",
        resource_id=job.id,
        details={
            "status": job.status,
            "resources_discovered": job.resources_discovered,
            "errors_count": job.errors_count,
            "execution_mode": execution_mode,
        },
    )
    try:
        notify_user(
            session,
            organization_id=job.organization_id,
            recipient_user_id=job.requested_by_user_id,
            category="scan",
            title="Cloud scan finished",
            message=f"The scan finished with status {job.status}.",
            resource_type="scan_job",
            resource_id=job.id,
        )
    except ConflictError:
        # A deactivated requester cannot receive organization notifications.
        pass


def _record_error(job: ScanJob, resource_type: str, region: str, code: str) -> None:
    job.errors_count += 1
    if len(job.error_codes) < 100:
        job.error_codes.append(
            {"resource_type": resource_type, "region": region, "code": code[:80]}
        )


def _safe_error_code(error: Exception) -> str:
    code: str | None = None
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code")
    if code is None or ERROR_CODE_PATTERN.fullmatch(code) is None:
        code = type(error).__name__
    return code[:80]


def _schedule_scan_retry(
    factory: Any,
    job_id: UUID,
    error: Exception,
    *,
    max_attempts: int,
) -> bool:
    """Retry transient worker failures through the durable outbox, otherwise fail safely."""
    try:
        with factory(info={"allow_unscoped": True}) as session:
            job = session.get(ScanJob, job_id)
            if job is None or job.status not in {"running", "queued"}:
                return False
            organization_id = job.organization_id
            session.info.pop("allow_unscoped", None)
            session.info["tenant_id"] = organization_id
            retryable = _is_transient_scan_error(error)
            if retryable and job.attempt_count < max_attempts:
                job.status = "queued"
                job.started_at = None
                job.finished_at = None
                retry_delay = min(300, 2**job.attempt_count)
                enqueue_task(
                    session,
                    organization_id=organization_id,
                    task_type="cloudsentinel.scan_jobs.process",
                    aggregate_id=f"{job.id}:attempt:{job.attempt_count}",
                    payload={"scan_job_id": str(job.id)},
                    available_at=datetime.now(UTC) + timedelta(seconds=retry_delay),
                )
                record_audit(
                    session,
                    organization_id=organization_id,
                    actor_user_id=None,
                    action="scan.retry_scheduled",
                    resource_type="scan_job",
                    resource_id=job.id,
                    details={
                        "attempt": job.attempt_count,
                        "retry_delay_seconds": retry_delay,
                    },
                )
                session.commit()
                return True

            job.status = "failed"
            job.errors_count += 1
            if len(job.error_codes) < 100:
                job.error_codes.append(
                    {
                        "resource_type": "scan",
                        "region": "global",
                        "code": "worker_retry_exhausted"
                        if retryable
                        else "worker_error",
                    }
                )
            job.finished_at = datetime.now(UTC)
            emit_scan_alert(session, job)
            record_audit(
                session,
                organization_id=organization_id,
                actor_user_id=None,
                action="scan.worker_failed",
                resource_type="scan_job",
                resource_id=job.id,
                status="FAILURE",
                details={"retryable": retryable, "attempts": job.attempt_count},
            )
            session.commit()
            return False
    except Exception as error:
        logger.error("Could not persist worker failure", extra={"error_type": type(error).__name__})
        return False


def _is_transient_scan_error(error: Exception) -> bool:
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
