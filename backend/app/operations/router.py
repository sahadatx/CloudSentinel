"""Tenant-scoped remediation, report, notification, and audit APIs."""

import csv
import hashlib
import html
import io
import json
from collections.abc import Mapping
from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.compliance.service import control_status
from app.core.config import get_settings
from app.core.domain_errors import ConflictError, NotFoundError
from app.core.models import (
    Alert,
    Asset,
    AuditEvent,
    CloudAccount,
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    Finding,
    FindingComplianceControl,
    FindingEvidence,
    Membership,
    Notification,
    RemediationRequest,
    Report,
    RiskScore,
    Role,
    ScanJob,
    TaskOutbox,
    User,
)
from app.operations.schemas import (
    AuditEventPage,
    AuditEventRead,
    AuditSummary,
    NotificationPage,
    NotificationRead,
    RemediationCancel,
    RemediationCreate,
    RemediationDecision,
    RemediationDetail,
    RemediationEvidenceRead,
    RemediationFindingRead,
    RemediationPage,
    RemediationRead,
    RemediationSummary,
    RemediationVerify,
    ReportCreate,
    ReportDetail,
    ReportPage,
    ReportRead,
    ReportSummary,
)
from app.operations.service import (
    decide_remediation,
    notify_remediation_approvers,
    notify_user,
    record_audit,
)
from app.risk.service import aggregate_scores, risk_level
from app.task_outbox import dispatch_outbox_event_now, enqueue_task

router = APIRouter(tags=["operations"])
MAX_REPORT_ROWS = 500


def _report_filter_list(filters: dict[str, object], key: str) -> list[str]:
    value = filters.get(key)
    return [str(item) for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _report_count(row: dict[str, object], key: str) -> int:
    value = row.get(key)
    return value if isinstance(value, int) else 0


@router.get("/remediation", response_model=RemediationPage)
def list_remediation(
    principal: Annotated[Principal, Depends(require_permission("remediation:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    status: Annotated[str | None, Query(max_length=30)] = None,
) -> RemediationPage:
    criteria = [RemediationRequest.organization_id == principal.organization_id]
    if status:
        criteria.append(RemediationRequest.status == status.upper())
    total = session.scalar(select(func.count(RemediationRequest.id)).where(*criteria)) or 0
    rows = session.scalars(
        select(RemediationRequest)
        .where(*criteria)
        .order_by(RemediationRequest.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return RemediationPage(
        items=[RemediationRead.model_validate(row) for row in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("/findings/{finding_id}/remediation", response_model=RemediationRead, status_code=201)
def request_remediation(
    finding_id: UUID,
    payload: RemediationCreate,
    principal: Annotated[Principal, Depends(require_permission("remediation:execute"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> RemediationRequest:
    finding = _get_finding(session, principal.organization_id, finding_id, lock=True)
    if finding.status in {"RESOLVED", "VERIFIED", "CLOSED", "SUPPRESSED"}:
        raise ConflictError("Remediation cannot be requested for an inactive finding.")
    existing = session.scalar(
        select(RemediationRequest.id).where(
            RemediationRequest.organization_id == principal.organization_id,
            RemediationRequest.finding_id == finding_id,
            RemediationRequest.status.in_(("PENDING_APPROVAL", "APPROVED", "VERIFYING")),
        )
    )
    if existing is not None:
        raise ConflictError("A pending remediation request already exists for this finding.")
    request = RemediationRequest(
        organization_id=principal.organization_id,
        finding_id=finding.id,
        requested_by_user_id=principal.user_id,
        status="PENDING_APPROVAL",
        request_note=payload.request_note.strip(),
    )
    asset = session.get(Asset, finding.asset_id)
    account = session.get(CloudAccount, finding.cloud_account_id)
    evidence = session.scalar(
        select(FindingEvidence)
        .where(
            FindingEvidence.organization_id == principal.organization_id,
            FindingEvidence.finding_id == finding.id,
        )
        .order_by(FindingEvidence.collected_at.desc())
    )
    request.evidence_id = evidence.id if evidence else None
    request.action_definition = {
        "execution_mode": "MANUAL",
        "recommendation": finding.remediation,
        "resource_type": asset.resource_type if asset else "unknown",
        "resource_id": asset.resource_id if asset else str(finding.asset_id),
        "account_id": account.account_id if account else "unknown",
        "automated_execution_available": False,
        "available_methods": ["manual"],
    }
    session.add(request)
    session.flush()
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="remediation.requested",
        resource_type="remediation_request",
        resource_id=request.id,
        details={"finding_id": str(finding.id)},
    )
    notify_user(
        session,
        organization_id=principal.organization_id,
        recipient_user_id=principal.user_id,
        category="remediation",
        title="Remediation approval requested",
        message="Your remediation recommendation is awaiting a separate approver.",
        resource_type="remediation_request",
        resource_id=request.id,
    )
    notify_remediation_approvers(
        session,
        organization_id=principal.organization_id,
        excluded_user_id=principal.user_id,
        request_id=request.id,
    )
    session.commit()
    session.refresh(request)
    return request


@router.get("/remediation/summary", response_model=RemediationSummary)
def remediation_summary(
    principal: Annotated[Principal, Depends(require_permission("remediation:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> RemediationSummary:
    rows = session.execute(
        select(
            RemediationRequest.status,
            RemediationRequest.verification_status,
            func.count(RemediationRequest.id),
        )
        .where(RemediationRequest.organization_id == principal.organization_id)
        .group_by(RemediationRequest.status, RemediationRequest.verification_status)
    ).all()
    counts: dict[str, int] = {}
    verification_pending = 0
    for status, verification_status, count in rows:
        counts[status] = counts.get(status, 0) + count
        if status == "APPROVED" and verification_status == "PENDING":
            verification_pending += count
    return RemediationSummary(
        pending_approval=counts.get("PENDING_APPROVAL", 0),
        approved=counts.get("APPROVED", 0),
        verification_pending=verification_pending,
        completed=counts.get("COMPLETED", 0),
        failed=counts.get("FAILED", 0),
        rejected=counts.get("REJECTED", 0),
        cancelled=counts.get("CANCELLED", 0),
    )


@router.get("/remediation/{request_id}", response_model=RemediationDetail)
def get_remediation(
    request_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("remediation:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> RemediationDetail:
    request = session.scalar(
        select(RemediationRequest).where(
            RemediationRequest.organization_id == principal.organization_id,
            RemediationRequest.id == request_id,
        )
    )
    if request is None:
        raise NotFoundError("Remediation request")
    finding = _get_finding(session, principal.organization_id, request.finding_id)
    asset = session.get(Asset, finding.asset_id)
    account = session.get(CloudAccount, finding.cloud_account_id)
    score = session.scalar(
        select(RiskScore.score).where(
            RiskScore.organization_id == principal.organization_id,
            RiskScore.finding_id == finding.id,
        )
    )
    evidence = session.get(FindingEvidence, request.evidence_id) if request.evidence_id else None
    return RemediationDetail(
        request=RemediationRead.model_validate(request),
        finding=RemediationFindingRead(
            id=finding.id,
            title=finding.title,
            severity=finding.severity,
            status=finding.status,
            asset_id=finding.asset_id,
            asset_name=asset.name if asset else str(finding.asset_id),
            resource_id=asset.resource_id if asset else str(finding.asset_id),
            account_id=finding.cloud_account_id,
            account_name=account.name if account else str(finding.cloud_account_id),
            aws_account_id=account.account_id if account else "unknown",
            region_code=finding.region_code,
            risk_score=score,
        ),
        evidence=(
            RemediationEvidenceRead(
                id=evidence.id,
                source=evidence.source,
                expected_state=evidence.expected_state,
                detected_condition=evidence.detected_condition,
                collected_at=evidence.collected_at,
            )
            if evidence
            else None
        ),
    )


@router.post("/remediation/{request_id}/decision", response_model=RemediationRead)
def decide_remediation_request(
    request_id: UUID,
    payload: RemediationDecision,
    principal: Annotated[Principal, Depends(require_permission("remediation:execute"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> RemediationRequest:
    row = session.scalar(
        select(RemediationRequest)
        .where(
            RemediationRequest.organization_id == principal.organization_id,
            RemediationRequest.id == request_id,
        )
        .with_for_update()
    )
    if row is None:
        raise NotFoundError("Remediation request")
    return decide_remediation(
        session,
        row,
        actor_user_id=principal.user_id,
        decision=payload.decision,
        note=payload.decision_note,
    )


@router.post("/remediation/{request_id}/cancel", response_model=RemediationRead)
def cancel_remediation_request(
    request_id: UUID,
    payload: RemediationCancel,
    principal: Annotated[Principal, Depends(require_permission("remediation:execute"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> RemediationRequest:
    row = session.scalar(
        select(RemediationRequest)
        .where(
            RemediationRequest.organization_id == principal.organization_id,
            RemediationRequest.id == request_id,
        )
        .with_for_update()
    )
    if row is None:
        raise NotFoundError("Remediation request")
    if row.status not in {"PENDING_APPROVAL", "APPROVED"}:
        raise ConflictError("Only pending or approved manual remediations can be cancelled.")
    row.status = "CANCELLED"
    row.decided_by_user_id = principal.user_id
    row.decision_note = payload.decision_note.strip()
    row.decided_at = datetime.now(UTC)
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="remediation.cancelled",
        resource_type="remediation_request",
        resource_id=row.id,
        details={"finding_id": str(row.finding_id)},
    )
    session.commit()
    session.refresh(row)
    return row


@router.post("/remediation/{request_id}/verify", response_model=RemediationRead)
def verify_remediation_request(
    request_id: UUID,
    payload: RemediationVerify,
    principal: Annotated[Principal, Depends(require_permission("remediation:execute"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> RemediationRequest:
    row = session.scalar(
        select(RemediationRequest)
        .where(
            RemediationRequest.organization_id == principal.organization_id,
            RemediationRequest.id == request_id,
        )
        .with_for_update()
    )
    if row is None:
        raise NotFoundError("Remediation request")
    if row.status != "APPROVED":
        raise ConflictError("Only approved manual remediations can be verified.")
    finding = _get_finding(session, principal.organization_id, row.finding_id)
    scan = session.scalar(
        select(ScanJob).where(
            ScanJob.organization_id == principal.organization_id,
            ScanJob.id == payload.scan_job_id,
            ScanJob.cloud_account_id == finding.cloud_account_id,
        )
    )
    if scan is None:
        raise NotFoundError("Verification scan")
    if scan.status != "completed" or scan.errors_count:
        raise ConflictError(
            "Verification requires a clean completed scan for the affected account."
        )
    scan_created = scan.created_at
    request_created = row.requested_at
    if scan_created.tzinfo is None:
        scan_created = scan_created.replace(tzinfo=UTC)
    if request_created.tzinfo is None:
        request_created = request_created.replace(tzinfo=UTC)
    if scan_created < request_created:
        raise ConflictError("Verification scan must be newer than the remediation request.")
    if payload.result == "PASSED" and finding.status not in {"RESOLVED", "VERIFIED", "CLOSED"}:
        raise ConflictError("Mark the finding resolved after the scan confirms the fix.")
    row.verification_status = payload.result
    row.status = "COMPLETED" if payload.result == "PASSED" else "FAILED"
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action=(
            "remediation.verified"
            if payload.result == "PASSED"
            else "remediation.verification_failed"
        ),
        resource_type="remediation_request",
        resource_id=row.id,
        details={"scan_job_id": str(scan.id), "result": payload.result, "note": payload.note},
    )
    session.commit()
    session.refresh(row)
    return row


@router.post("/reports", response_model=ReportRead, status_code=201)
def create_report(
    payload: ReportCreate,
    principal: Annotated[Principal, Depends(require_permission("reports:create"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Report:
    report_id = uuid4()
    row = Report(
        id=report_id,
        organization_id=principal.organization_id,
        report_series_id=report_id,
        name=payload.name,
        report_type=payload.report_type,
        status="QUEUED",
        file_format=payload.file_format,
        report_version=1,
        generator_version="1.0",
        created_by_user_id=principal.user_id,
        filters=payload.filters.model_dump(mode="json", exclude_none=True),
    )
    session.add(row)
    session.flush()
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="report.created",
        resource_type="report",
        resource_id=row.id,
        details={"report_type": payload.report_type, "file_format": payload.file_format},
    )
    outbox_event = _enqueue_report_generation(session, row)
    session.commit()
    session.refresh(row)
    _dispatch_report_generation(session, row, outbox_event.id)
    return row


def _enqueue_report_generation(session: Session, row: Report) -> TaskOutbox:
    """Persist report work atomically with its queued report version."""
    return enqueue_task(
        session,
        organization_id=row.organization_id,
        task_type="cloudsentinel.reports.generate",
        aggregate_id=f"{row.id}:{row.report_version}",
        payload={"report_id": str(row.id), "report_version": row.report_version},
    )


def _dispatch_report_generation(session: Session, row: Report, outbox_id: UUID) -> None:
    """Try immediate delivery; the durable relay retries if the broker is unavailable."""
    from app.reports.tasks import generate_report_task

    dispatch_outbox_event_now(
        session,
        outbox_id=outbox_id,
        publisher=generate_report_task.apply_async,
    )


@router.get("/reports/summary", response_model=ReportSummary)
def report_summary(
    principal: Annotated[Principal, Depends(require_permission("reports:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> ReportSummary:
    rows = session.execute(
        select(Report.status, func.count(Report.id))
        .where(Report.organization_id == principal.organization_id)
        .group_by(Report.status)
    ).all()
    counts: dict[str, int] = {status: count for status, count in rows}
    return ReportSummary(
        total=sum(counts.values()),
        queued=counts.get("QUEUED", 0),
        generating=counts.get("GENERATING", 0),
        completed=counts.get("COMPLETED", 0),
        failed=counts.get("FAILED", 0),
        expired=counts.get("EXPIRED", 0),
    )


@router.get("/reports", response_model=ReportPage)
def list_reports(
    principal: Annotated[Principal, Depends(require_permission("reports:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    search: Annotated[str | None, Query(max_length=160)] = None,
    status: Annotated[str | None, Query(max_length=20)] = None,
    report_type: Annotated[str | None, Query(max_length=40)] = None,
    file_format: Annotated[str | None, Query(max_length=10)] = None,
    environment: Annotated[str | None, Query(max_length=80)] = None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> ReportPage:
    criteria = [Report.organization_id == principal.organization_id]
    if search and search.strip():
        criteria.append(Report.name.ilike(f"%{search.strip()}%"))
    if status:
        criteria.append(Report.status == status.upper())
    if report_type:
        criteria.append(Report.report_type == report_type)
    if file_format:
        criteria.append(Report.file_format == file_format.upper())
    if environment:
        criteria.append(Report.filters["environment"].as_string() == environment)
    if date_from:
        criteria.append(Report.created_at >= datetime.combine(date_from, time.min, tzinfo=UTC))
    if date_to:
        criteria.append(
            Report.created_at < datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=UTC)
        )
    total = session.scalar(select(func.count(Report.id)).where(*criteria)) or 0
    rows = session.execute(
        select(Report, User.display_name, Role.code)
        .where(*criteria)
        .outerjoin(
            Membership,
            and_(
                Membership.user_id == Report.created_by_user_id,
                Membership.organization_id == principal.organization_id,
            ),
        )
        .outerjoin(User, User.id == Report.created_by_user_id)
        .outerjoin(Role, Role.id == Membership.role_id)
        .order_by(Report.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return ReportPage(
        items=[
            ReportRead.model_validate(report).model_copy(
                update={"created_by_name": display_name, "created_by_role": role_code}
            )
            for report, display_name, role_code in rows
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/reports/{report_id}", response_model=ReportDetail)
def get_report(
    report_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("reports:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> ReportDetail:
    result = session.execute(
        select(Report, User.display_name, Role.code)
        .where(
            Report.organization_id == principal.organization_id,
            Report.id == report_id,
        )
        .outerjoin(
            Membership,
            and_(
                Membership.user_id == Report.created_by_user_id,
                Membership.organization_id == principal.organization_id,
            ),
        )
        .outerjoin(User, User.id == Report.created_by_user_id)
        .outerjoin(Role, Role.id == Membership.role_id)
    ).one_or_none()
    if result is None:
        raise NotFoundError("Report")
    row, display_name, role_code = result
    return ReportDetail.model_validate(row).model_copy(
        update={"created_by_name": display_name, "created_by_role": role_code}
    )


@router.post("/reports/{report_id}/regenerate", response_model=ReportRead, status_code=202)
def regenerate_report(
    report_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("reports:create"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Report:
    source = session.scalar(
        select(Report).where(
            Report.organization_id == principal.organization_id,
            Report.id == report_id,
        )
    )
    if source is None:
        raise NotFoundError("Report")
    if source.status in {"QUEUED", "GENERATING"}:
        raise ConflictError("A report version is already being generated.")
    root_id = source.report_series_id
    session.scalar(
        select(Report.id)
        .where(
            Report.organization_id == principal.organization_id,
            Report.id == root_id,
        )
        .with_for_update()
    )
    version = session.scalar(
        select(func.max(Report.report_version)).where(
            Report.organization_id == principal.organization_id,
            Report.report_series_id == root_id,
        )
    )
    report_id = uuid4()
    row = Report(
        id=report_id,
        organization_id=principal.organization_id,
        report_series_id=root_id,
        name=source.name,
        report_type=source.report_type,
        status="QUEUED",
        file_format=source.file_format,
        report_version=(version or 0) + 1,
        generator_version="1.0",
        created_by_user_id=principal.user_id,
        filters=dict(source.filters),
        parent_report_id=root_id,
    )
    session.add(row)
    session.flush()
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="report.regeneration_requested",
        resource_type="report",
        resource_id=row.id,
        details={"source_report_id": str(source.id), "report_version": row.report_version},
    )
    outbox_event = _enqueue_report_generation(session, row)
    session.commit()
    session.refresh(row)
    _dispatch_report_generation(session, row, outbox_event.id)
    return row


@router.post("/reports/{report_id}/cancel", response_model=ReportRead)
def cancel_report(
    report_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("reports:create"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Report:
    row = session.scalar(
        select(Report)
        .where(
            Report.organization_id == principal.organization_id,
            Report.id == report_id,
        )
        .with_for_update()
    )
    if row is None:
        raise NotFoundError("Report")
    if row.status != "QUEUED":
        raise ConflictError("Only queued reports can be cancelled.")
    row.status = "CANCELLED"
    row.updated_at = datetime.now(UTC)
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="report.cancelled",
        resource_type="report",
        resource_id=row.id,
        details={"report_version": row.report_version},
    )
    session.commit()
    session.refresh(row)
    return row


@router.get("/reports/{report_id}/export")
def export_report(
    report_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("reports:export"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    format: Annotated[str, Query(pattern="^(json|csv|pdf)$")] = "json",
) -> StreamingResponse:
    row = session.scalar(
        select(Report).where(
            Report.organization_id == principal.organization_id,
            Report.id == report_id,
        )
    )
    if row is None:
        raise NotFoundError("Report")
    if row.status != "COMPLETED" or row.snapshot is None:
        raise ConflictError("Only completed report snapshots can be exported.")
    canonical = json.dumps(row.snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if (
        row.snapshot_checksum
        and row.snapshot_checksum != hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    ):
        raise ConflictError("Report snapshot integrity verification failed.")
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="report.downloaded",
        resource_type="report",
        resource_id=row.id,
        details={"format": format},
    )
    session.commit()
    filename = f"cloudsentinel-{row.report_type}-{row.id}.{format}"
    if format == "json":
        content: str | bytes = json.dumps(
            row.snapshot, ensure_ascii=False, sort_keys=True, indent=2
        ).encode("utf-8")
        media_type = "application/json"
    elif format == "csv":
        content = _report_csv(row.snapshot).encode("utf-8")
        media_type = "text/csv; charset=utf-8"
    else:
        content = _report_pdf(row.snapshot, row.name)
        media_type = "application/pdf"
    settings = get_settings()
    if row.storage_key and format.upper() == row.file_format and settings.report_storage_bucket:
        import boto3

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
        client = boto3.client("s3", **storage_client_options)
        get_options: dict[str, str] = {
            "Bucket": settings.report_storage_bucket,
            "Key": row.storage_key,
        }
        if row.storage_version_id:
            get_options["VersionId"] = row.storage_version_id
        stored = client.get_object(**get_options)["Body"].read()
        if row.checksum and hashlib.sha256(stored).hexdigest() != row.checksum:
            raise ConflictError("Stored report integrity verification failed.")
        content = stored
    elif row.checksum and format.upper() == row.file_format:
        rendered_checksum = hashlib.sha256(
            content.encode("utf-8") if isinstance(content, str) else content
        ).hexdigest()
        if rendered_checksum != row.checksum:
            raise ConflictError("Generated report integrity verification failed.")
    return StreamingResponse(
        iter([content]),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-Checksum": row.checksum or "",
        },
    )


@router.get("/notifications", response_model=NotificationPage)
def list_notifications(
    principal: Annotated[Principal, Depends(require_permission("organizations:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> NotificationPage:
    criteria = [
        Notification.organization_id == principal.organization_id,
        Notification.recipient_user_id == principal.user_id,
    ]
    total = session.scalar(select(func.count(Notification.id)).where(*criteria)) or 0
    unread = (
        session.scalar(
            select(func.count(Notification.id)).where(*criteria, Notification.read_at.is_(None))
        )
        or 0
    )
    rows = session.scalars(
        select(Notification)
        .where(*criteria)
        .order_by(Notification.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return NotificationPage(
        items=[NotificationRead.model_validate(row) for row in rows],
        total=total,
        unread=unread,
        offset=offset,
        limit=limit,
    )


@router.post("/notifications/{notification_id}/read", response_model=NotificationRead)
def mark_notification_read(
    notification_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("organizations:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Notification:
    row = session.scalar(
        select(Notification)
        .where(
            Notification.organization_id == principal.organization_id,
            Notification.recipient_user_id == principal.user_id,
            Notification.id == notification_id,
        )
        .with_for_update()
    )
    if row is None:
        raise NotFoundError("Notification")
    row.read_at = row.read_at or datetime.now(UTC)
    session.commit()
    session.refresh(row)
    return row


@router.get("/audit-events", response_model=AuditEventPage)
def list_audit_events(
    principal: Annotated[Principal, Depends(require_permission("audit:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    action: Annotated[str | None, Query(max_length=80)] = None,
    resource_type: Annotated[str | None, Query(max_length=80)] = None,
    resource_id: Annotated[str | None, Query(max_length=100)] = None,
    actor_id: UUID | None = None,
    actor_role: Annotated[str | None, Query(max_length=40)] = None,
    status: Annotated[str | None, Query(pattern="^(SUCCESS|FAILURE)$")] = None,
    ip_address: Annotated[str | None, Query(max_length=64)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> AuditEventPage:
    criteria = [AuditEvent.organization_id == principal.organization_id]
    if action is not None:
        criteria.append(AuditEvent.action == action)
    if resource_type is not None:
        criteria.append(AuditEvent.resource_type == resource_type)
    if resource_id is not None:
        criteria.append(AuditEvent.resource_id == resource_id)
    if actor_id is not None:
        criteria.append(AuditEvent.actor_user_id == actor_id)
    if actor_role is not None:
        criteria.append(AuditEvent.actor_role == actor_role)
    if status is not None:
        criteria.append(AuditEvent.status == status)
    if ip_address is not None:
        criteria.append(AuditEvent.ip_address == ip_address)
    if date_from is not None:
        criteria.append(AuditEvent.created_at >= date_from)
    if date_to is not None:
        criteria.append(AuditEvent.created_at <= date_to)
    if search:
        term = f"%{search.strip()}%"
        criteria.append(
            or_(
                AuditEvent.action.ilike(term),
                AuditEvent.resource_type.ilike(term),
                AuditEvent.resource_id.ilike(term),
                AuditEvent.actor_name.ilike(term),
                AuditEvent.request_id.ilike(term),
            )
        )
    total = session.scalar(select(func.count(AuditEvent.id)).where(*criteria)) or 0
    rows = session.scalars(
        select(AuditEvent)
        .where(*criteria)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return AuditEventPage(
        items=[AuditEventRead.model_validate(row) for row in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/audit-events/summary", response_model=AuditSummary)
def audit_summary(
    principal: Annotated[Principal, Depends(require_permission("audit:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AuditSummary:
    base = AuditEvent.organization_id == principal.organization_id
    day_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    total_today = (
        session.scalar(
            select(func.count(AuditEvent.id)).where(base, AuditEvent.created_at >= day_start)
        )
        or 0
    )
    failed = (
        session.scalar(
            select(func.count(AuditEvent.id)).where(
                base, AuditEvent.status == "FAILURE", AuditEvent.created_at >= day_start
            )
        )
        or 0
    )
    security = (
        session.scalar(
            select(func.count(AuditEvent.id)).where(
                base,
                AuditEvent.created_at >= day_start,
                AuditEvent.resource_type.in_(
                    ("finding", "asset", "risk", "compliance", "alert", "scan_job")
                ),
            )
        )
        or 0
    )
    administrative = (
        session.scalar(
            select(func.count(AuditEvent.id)).where(
                base,
                AuditEvent.created_at >= day_start,
                AuditEvent.resource_type.in_(
                    ("user", "team", "organization", "cloud_account", "policy", "role")
                ),
            )
        )
        or 0
    )
    return AuditSummary(
        events_today=total_today,
        security_events=security,
        failed_actions=failed,
        administrative_actions=administrative,
    )


@router.get("/audit-events/{audit_id}", response_model=AuditEventRead)
def get_audit_event(
    audit_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("audit:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> AuditEvent:
    row = session.scalar(
        select(AuditEvent).where(
            AuditEvent.organization_id == principal.organization_id, AuditEvent.id == audit_id
        )
    )
    if row is None:
        raise NotFoundError("Audit event")
    return row


@router.get("/audit-export")
def export_audit_events(
    principal: Annotated[Principal, Depends(require_permission("audit:export"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    file_format: Annotated[str, Query(alias="format", pattern="^(CSV|JSON)$")] = "CSV",
    limit: Annotated[int, Query(ge=1, le=10000)] = 5000,
    action: Annotated[str | None, Query(max_length=80)] = None,
    resource_type: Annotated[str | None, Query(max_length=80)] = None,
    actor_id: UUID | None = None,
    actor_role: Annotated[str | None, Query(max_length=40)] = None,
    status: Annotated[str | None, Query(pattern="^(SUCCESS|FAILURE)$")] = None,
    ip_address: Annotated[str | None, Query(max_length=64)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> StreamingResponse:
    criteria = [AuditEvent.organization_id == principal.organization_id]
    if action:
        criteria.append(AuditEvent.action == action)
    if resource_type:
        criteria.append(AuditEvent.resource_type == resource_type)
    if actor_id:
        criteria.append(AuditEvent.actor_user_id == actor_id)
    if actor_role:
        criteria.append(AuditEvent.actor_role == actor_role)
    if status:
        criteria.append(AuditEvent.status == status)
    if ip_address:
        criteria.append(AuditEvent.ip_address == ip_address)
    if date_from:
        criteria.append(AuditEvent.created_at >= date_from)
    if date_to:
        criteria.append(AuditEvent.created_at <= date_to)
    if search:
        term = f"%{search.strip()}%"
        criteria.append(
            or_(
                AuditEvent.action.ilike(term),
                AuditEvent.resource_type.ilike(term),
                AuditEvent.resource_id.ilike(term),
                AuditEvent.actor_name.ilike(term),
                AuditEvent.request_id.ilike(term),
            )
        )
    rows = session.scalars(
        select(AuditEvent).where(*criteria).order_by(AuditEvent.created_at.desc()).limit(limit)
    ).all()
    record_audit(
        session,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="AUDIT_EXPORTED",
        resource_type="audit",
        resource_id=None,
        details={"format": file_format, "row_count": len(rows)},
    )
    session.commit()
    payload = [AuditEventRead.model_validate(row).model_dump(mode="json") for row in rows]
    if file_format == "JSON":
        return StreamingResponse(
            iter([json.dumps(payload, ensure_ascii=False)]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": "attachment; filename=audit-events.json"},
        )
    output = io.StringIO()
    fields = [
        "id",
        "created_at",
        "actor_name",
        "actor_type",
        "actor_role",
        "action",
        "resource_type",
        "resource_id",
        "status",
        "ip_address",
        "request_id",
        "before",
        "after",
        "details",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in payload:
        writer.writerow(
            {
                key: _spreadsheet_safe(
                    json.dumps(row[key], ensure_ascii=False)
                    if isinstance(row.get(key), (dict, list))
                    else row.get(key)
                )
                for key in fields
            }
        )
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit-events.csv"},
    )


def _get_finding(
    session: Session, organization_id: UUID, finding_id: UUID, *, lock: bool = False
) -> Finding:
    statement = select(Finding).where(
        Finding.organization_id == organization_id,
        Finding.id == finding_id,
    )
    if lock:
        statement = statement.with_for_update()
    row = session.scalar(statement)
    if row is None:
        raise NotFoundError("Finding")
    return row


def _build_report_snapshot(
    session: Session,
    organization_id: UUID,
    report_type: str,
    *,
    filters: dict[str, object] | None = None,
    report_name: str | None = None,
    data_snapshot_at: datetime | None = None,
) -> dict[str, object]:
    """Build a reproducible, tenant-bound report payload from canonical records."""
    effective_filters = filters or {}
    raw_type = report_type
    if report_type in {"executive_security", "security_assessment"}:
        report_type = "security_posture"
    snapshot = _build_report_snapshot_data(
        session,
        organization_id,
        report_type,
        filters=effective_filters,
    )
    if raw_type == "security_assessment":
        snapshot["sections"] = {
            "assets": _build_report_snapshot_data(
                session, organization_id, "assets", filters=effective_filters
            ),
            "findings": _build_report_snapshot_data(
                session, organization_id, "findings", filters=effective_filters
            ),
            "risk": _build_report_snapshot_data(
                session, organization_id, "risk", filters=effective_filters
            ),
            "compliance": _build_report_snapshot_data(
                session, organization_id, "compliance", filters=effective_filters
            ),
            "scans": _build_report_snapshot_data(
                session, organization_id, "scans", filters=effective_filters
            ),
            "remediation": _build_report_snapshot_data(
                session, organization_id, "remediation", filters=effective_filters
            ),
            "alerts": _build_report_snapshot_data(
                session, organization_id, "alerts", filters=effective_filters
            ),
            "audit_activity": _build_report_snapshot_data(
                session, organization_id, "audit_activity", filters=effective_filters
            ),
        }
    snapshot["metadata"] = {
        "report_name": report_name or report_type.replace("_", " ").title(),
        "report_type": raw_type,
        "organization_id": str(organization_id),
        "filters": effective_filters,
        "generator_version": "1.0",
        "data_snapshot_at": (data_snapshot_at or datetime.now(UTC)).isoformat(),
    }
    return snapshot


def _build_report_snapshot_data(
    session: Session,
    organization_id: UUID,
    report_type: str,
    *,
    filters: dict[str, object],
) -> dict[str, object]:
    generated_at = datetime.now(UTC).isoformat()
    account_id = filters.get("cloud_account_id")
    environment = filters.get("environment")
    region = filters.get("region")
    account_ids = select(CloudAccount.id).where(CloudAccount.organization_id == organization_id)
    if account_id:
        account_ids = account_ids.where(CloudAccount.id == UUID(str(account_id)))
    if environment:
        account_ids = account_ids.where(CloudAccount.environment == environment)

    if report_type == "assets":
        asset_statement = (
            select(Asset, CloudAccount)
            .join(CloudAccount, CloudAccount.id == Asset.cloud_account_id)
            .where(
                Asset.organization_id == organization_id,
                CloudAccount.organization_id == organization_id,
            )
        )
        asset_statement = asset_statement.where(Asset.cloud_account_id.in_(account_ids))
        if region:
            asset_statement = asset_statement.where(Asset.region_code == region)
        if filters.get("asset_type"):
            asset_statement = asset_statement.where(
                Asset.resource_type == str(filters["asset_type"])
            )
        if filters.get("date_from"):
            asset_statement = asset_statement.where(
                Asset.last_seen_at
                >= datetime.fromisoformat(str(filters["date_from"])).replace(tzinfo=UTC)
            )
        if filters.get("date_to"):
            asset_statement = asset_statement.where(
                Asset.last_seen_at
                < datetime.fromisoformat(str(filters["date_to"])).replace(tzinfo=UTC)
                + timedelta(days=1)
            )
        asset_rows = session.execute(
            asset_statement.order_by(Asset.name, Asset.resource_id).limit(MAX_REPORT_ROWS)
        ).all()
        return {
            "generated_at": generated_at,
            "items": [
                {
                    "id": str(asset.id),
                    "name": asset.name or asset.resource_id,
                    "resource_type": asset.resource_type,
                    "provider": asset.provider,
                    "cloud_account_id": str(account.id),
                    "account": account.name,
                    "account_number": account.account_id,
                    "region": asset.region_code,
                    "environment": account.environment,
                    "owner": asset.owner_metadata,
                    "status": asset.status,
                    "last_seen_at": asset.last_seen_at.isoformat(),
                }
                for asset, account in asset_rows
            ],
            "truncated": len(asset_rows) == MAX_REPORT_ROWS,
        }

    if report_type == "scans":
        scan_statement = (
            select(ScanJob, CloudAccount)
            .join(CloudAccount, CloudAccount.id == ScanJob.cloud_account_id)
            .where(
                ScanJob.organization_id == organization_id,
                CloudAccount.organization_id == organization_id,
            )
            .where(ScanJob.cloud_account_id.in_(account_ids))
        )
        if filters.get("date_from"):
            scan_statement = scan_statement.where(
                ScanJob.created_at
                >= datetime.fromisoformat(str(filters["date_from"])).replace(tzinfo=UTC)
            )
        if filters.get("date_to"):
            scan_statement = scan_statement.where(
                ScanJob.created_at
                < datetime.fromisoformat(str(filters["date_to"])).replace(tzinfo=UTC)
                + timedelta(days=1)
            )
        scan_rows = session.execute(
            scan_statement.order_by(ScanJob.created_at.desc()).limit(MAX_REPORT_ROWS * 5)
        ).all()
        if region:
            scan_rows = [row for row in scan_rows if region in row[0].requested_regions]
        scan_rows = scan_rows[:MAX_REPORT_ROWS]
        return {
            "generated_at": generated_at,
            "items": [
                {
                    "id": str(job.id),
                    "account": account.name,
                    "account_id": account.account_id,
                    "regions": job.requested_regions,
                    "started_at": job.started_at.isoformat() if job.started_at else None,
                    "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                    "status": job.status,
                    "resources_discovered": job.resources_discovered,
                    "errors": job.errors_count,
                    "warnings": job.error_codes,
                }
                for job, account in scan_rows
            ],
            "truncated": len(scan_rows) == MAX_REPORT_ROWS,
        }

    if report_type == "remediation":
        remediation_statement = (
            select(RemediationRequest, Finding)
            .join(Finding, Finding.id == RemediationRequest.finding_id)
            .where(RemediationRequest.organization_id == organization_id)
            .where(Finding.cloud_account_id.in_(account_ids))
        )
        if region:
            remediation_statement = remediation_statement.where(Finding.region_code == region)
        if filters.get("date_from"):
            remediation_statement = remediation_statement.where(
                RemediationRequest.requested_at
                >= datetime.fromisoformat(str(filters["date_from"])).replace(tzinfo=UTC)
            )
        if filters.get("date_to"):
            remediation_statement = remediation_statement.where(
                RemediationRequest.requested_at
                < datetime.fromisoformat(str(filters["date_to"])).replace(tzinfo=UTC)
                + timedelta(days=1)
            )
        remediation_rows = session.execute(
            remediation_statement.order_by(RemediationRequest.created_at.desc()).limit(
                MAX_REPORT_ROWS
            )
        ).all()
        return {
            "generated_at": generated_at,
            "items": [
                {
                    "id": str(request.id),
                    "finding_id": str(finding.id),
                    "finding_title": finding.title,
                    "action": request.action_definition,
                    "status": request.status,
                    "requested_by": str(request.requested_by_user_id),
                    "approved_by": str(request.decided_by_user_id)
                    if request.decided_by_user_id
                    else None,
                    "requested_at": request.requested_at.isoformat(),
                    "verification": request.verification_status,
                }
                for request, finding in remediation_rows
            ],
            "truncated": len(remediation_rows) == MAX_REPORT_ROWS,
        }

    if report_type in {"alerts", "audit_activity"}:
        if report_type == "alerts":
            statement = select(Alert).where(Alert.organization_id == organization_id)
            if filters.get("date_from"):
                statement = statement.where(
                    Alert.created_at
                    >= datetime.fromisoformat(str(filters["date_from"])).replace(tzinfo=UTC)
                )
            if filters.get("date_to"):
                statement = statement.where(
                    Alert.created_at
                    < datetime.fromisoformat(str(filters["date_to"])).replace(tzinfo=UTC)
                    + timedelta(days=1)
                )
            severities = _report_filter_list(filters, "severities")
            statuses = _report_filter_list(filters, "finding_statuses")
            if severities:
                statement = statement.where(Alert.severity.in_(severities))
            if statuses:
                statement = statement.where(Alert.status.in_(statuses))
            alert_rows = session.scalars(
                statement.order_by(Alert.created_at.desc()).limit(MAX_REPORT_ROWS)
            ).all()
            return {
                "generated_at": generated_at,
                "items": [
                    {
                        "id": str(alert.id),
                        "alert_type": alert.alert_type,
                        "source_type": alert.source_type,
                        "source_id": alert.source_id,
                        "title": alert.title,
                        "description": alert.description,
                        "severity": alert.severity,
                        "status": alert.status,
                        "occurrences": alert.occurrence_count,
                        "first_seen_at": alert.first_seen_at.isoformat(),
                        "last_seen_at": alert.last_seen_at.isoformat(),
                    }
                    for alert in alert_rows
                ],
                "truncated": len(alert_rows) == MAX_REPORT_ROWS,
            }

        audit_statement = select(AuditEvent).where(AuditEvent.organization_id == organization_id)
        if filters.get("date_from"):
            audit_statement = audit_statement.where(
                AuditEvent.created_at
                >= datetime.fromisoformat(str(filters["date_from"])).replace(tzinfo=UTC)
            )
        if filters.get("date_to"):
            audit_statement = audit_statement.where(
                AuditEvent.created_at
                < datetime.fromisoformat(str(filters["date_to"])).replace(tzinfo=UTC)
                + timedelta(days=1)
            )
        audit_rows = session.scalars(
            audit_statement.order_by(AuditEvent.created_at.desc()).limit(MAX_REPORT_ROWS)
        ).all()
        return {
            "generated_at": generated_at,
            "items": [
                {
                    "id": str(event.id),
                    "action": event.action,
                    "resource_type": event.resource_type,
                    "resource_id": event.resource_id,
                    "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
                    "created_at": event.created_at.isoformat(),
                }
                for event in audit_rows
            ],
            "truncated": len(audit_rows) == MAX_REPORT_ROWS,
        }

    if report_type == "accounts":
        account_statement = select(CloudAccount).where(
            CloudAccount.organization_id == organization_id,
            CloudAccount.id.in_(account_ids),
        )
        if region:
            account_statement = account_statement.where(CloudAccount.primary_region == region)
        if filters.get("date_from"):
            account_statement = account_statement.where(
                CloudAccount.created_at
                >= datetime.fromisoformat(str(filters["date_from"])).replace(tzinfo=UTC)
            )
        if filters.get("date_to"):
            account_statement = account_statement.where(
                CloudAccount.created_at
                < datetime.fromisoformat(str(filters["date_to"])).replace(tzinfo=UTC)
                + timedelta(days=1)
            )
        account_rows = session.scalars(
            account_statement.order_by(CloudAccount.name).limit(MAX_REPORT_ROWS)
        ).all()
        return {
            "generated_at": generated_at,
            "items": [
                {
                    "id": str(row.id),
                    "name": row.name,
                    "account_id": row.account_id,
                    "environment": row.environment,
                    "provider": "AWS",
                    "status": row.connection_status,
                }
                for row in account_rows
            ],
            "truncated": len(account_rows) == MAX_REPORT_ROWS,
        }
    if report_type == "findings":
        finding_statement = (
            select(Finding, Asset, CloudAccount, RiskScore)
            .join(
                Asset, (Asset.id == Finding.asset_id) & (Asset.organization_id == organization_id)
            )
            .join(
                CloudAccount,
                (CloudAccount.id == Finding.cloud_account_id)
                & (CloudAccount.organization_id == organization_id),
            )
            .outerjoin(
                RiskScore,
                (RiskScore.finding_id == Finding.id)
                & (RiskScore.organization_id == organization_id),
            )
            .where(Finding.organization_id == organization_id)
            .where(Finding.cloud_account_id.in_(account_ids))
        )
        if region:
            finding_statement = finding_statement.where(Finding.region_code == region)
        severity_values = _report_filter_list(filters, "severities")
        if severity_values:
            finding_statement = finding_statement.where(Finding.severity.in_(severity_values))
        status_values = _report_filter_list(filters, "finding_statuses")
        if status_values:
            finding_statement = finding_statement.where(Finding.status.in_(status_values))
        if filters.get("date_from"):
            finding_statement = finding_statement.where(
                Finding.first_seen_at
                >= datetime.fromisoformat(str(filters["date_from"])).replace(tzinfo=UTC)
            )
        if filters.get("date_to"):
            finding_statement = finding_statement.where(
                Finding.first_seen_at
                < datetime.fromisoformat(str(filters["date_to"])).replace(tzinfo=UTC)
                + timedelta(days=1)
            )
        if filters.get("asset_type"):
            finding_statement = finding_statement.where(
                Asset.resource_type == str(filters["asset_type"])
            )
        finding_rows = session.execute(
            finding_statement.order_by(Finding.last_seen_at.desc()).limit(MAX_REPORT_ROWS)
        ).all()
        evidence_by_finding: dict[UUID, FindingEvidence] = {}
        if finding_rows:
            evidences = session.scalars(
                select(FindingEvidence)
                .where(
                    FindingEvidence.organization_id == organization_id,
                    FindingEvidence.finding_id.in_(
                        [finding.id for finding, *_rest in finding_rows]
                    ),
                )
                .order_by(FindingEvidence.collected_at.desc())
            ).all()
            for evidence in evidences:
                evidence_by_finding.setdefault(evidence.finding_id, evidence)
        return {
            "generated_at": generated_at,
            "items": [
                {
                    "id": str(row.id),
                    "rule_id": row.rule_id,
                    "policy_version": row.rule_version,
                    "title": row.title,
                    "description": row.description,
                    "severity": row.severity,
                    "status": row.status,
                    "asset_id": str(asset.id),
                    "asset": asset.name or asset.resource_id,
                    "asset_type": asset.resource_type,
                    "account_id": str(account.id),
                    "account": account.name,
                    "region": row.region_code,
                    "risk_score": risk.score if risk else None,
                    "risk_level": risk.level if risk else None,
                    "risk_factors": risk.factors if risk else None,
                    "evidence_id": str(evidence_by_finding[row.id].id)
                    if row.id in evidence_by_finding
                    else None,
                    "observed": evidence_by_finding[row.id].detected_condition
                    if row.id in evidence_by_finding
                    else None,
                    "expected": evidence_by_finding[row.id].expected_state
                    if row.id in evidence_by_finding
                    else None,
                    "remediation": row.remediation,
                    "first_seen_at": row.first_seen_at.isoformat(),
                    "last_seen_at": row.last_seen_at.isoformat(),
                }
                for row, asset, account, risk in finding_rows
            ],
            "truncated": len(finding_rows) == MAX_REPORT_ROWS,
        }
    if report_type == "compliance":
        frameworks = session.scalars(
            select(ComplianceFramework)
            .where(ComplianceFramework.is_active.is_(True))
            .order_by(ComplianceFramework.code)
        ).all()
        if isinstance(filters.get("compliance_framework"), str):
            frameworks = [
                framework
                for framework in frameworks
                if framework.code == filters["compliance_framework"]
            ]
        scoped_asset_ids = select(Asset.id).where(
            Asset.organization_id == organization_id,
            Asset.cloud_account_id.in_(account_ids),
        )
        if region:
            scoped_asset_ids = scoped_asset_ids.where(Asset.region_code == region)
        if filters.get("asset_type"):
            scoped_asset_ids = scoped_asset_ids.where(
                Asset.resource_type == str(filters["asset_type"])
            )
        items: list[dict[str, object]] = []
        for framework in frameworks:
            controls = session.scalars(
                select(ComplianceControl).where(ComplianceControl.framework_id == framework.id)
            ).all()
            control_summaries: list[dict[str, object]] = []
            for control in controls:
                assessment_statement = select(
                    ComplianceAssessment.asset_id,
                    ComplianceAssessment.status,
                    ComplianceAssessment.evidence_id,
                ).where(
                    ComplianceAssessment.organization_id == organization_id,
                    ComplianceAssessment.control_id == control.id,
                    ComplianceAssessment.asset_id.in_(scoped_asset_ids),
                )
                if filters.get("date_from"):
                    assessment_statement = assessment_statement.where(
                        ComplianceAssessment.checked_at
                        >= datetime.fromisoformat(str(filters["date_from"])).replace(tzinfo=UTC)
                    )
                if filters.get("date_to"):
                    assessment_statement = assessment_statement.where(
                        ComplianceAssessment.checked_at
                        < datetime.fromisoformat(str(filters["date_to"])).replace(tzinfo=UTC)
                        + timedelta(days=1)
                    )
                assessments = session.execute(
                    assessment_statement.order_by(ComplianceAssessment.checked_at.desc())
                ).all()
                latest: dict[UUID, tuple[str, UUID | None]] = {}
                for asset_id, status_value, evidence_id in assessments:
                    latest.setdefault(asset_id, (status_value, evidence_id))
                related_findings = list(
                    session.scalars(
                        select(FindingComplianceControl.finding_id).where(
                            FindingComplianceControl.organization_id == organization_id,
                            FindingComplianceControl.control_id == control.id,
                            FindingComplianceControl.finding_id.in_(
                                select(Finding.id).where(
                                    Finding.organization_id == organization_id,
                                    Finding.cloud_account_id.in_(account_ids),
                                )
                            ),
                        )
                    ).all()
                )
                statuses = [status_value for status_value, _evidence in latest.values()]
                assessed_count = sum(
                    status_value in {"PASS", "FAIL", "PARTIAL"} for status_value in statuses
                )
                passed_count = sum(status_value == "PASS" for status_value in statuses)
                control_summaries.append(
                    {
                        "control": control.control_code,
                        "title": control.title,
                        "description": control.description,
                        "category": control.category,
                        "status": (
                            "NOT_ASSESSED"
                            if not assessed_count
                            else "FAIL"
                            if any(value == "FAIL" for value in statuses)
                            else "PARTIAL"
                            if any(value == "PARTIAL" for value in statuses)
                            else "PASS"
                        ),
                        "assessed_assets": assessed_count,
                        "passed_assets": passed_count,
                        "failed_assets": sum(value == "FAIL" for value in statuses),
                        "partial_assets": sum(value == "PARTIAL" for value in statuses),
                        "not_assessed_assets": sum(value == "NOT_ASSESSED" for value in statuses),
                        "compliance_percent": (
                            round(passed_count * 100 / assessed_count) if assessed_count else None
                        ),
                        "affected_asset_ids": [
                            str(asset_id)
                            for asset_id, (status_value, _evidence) in latest.items()
                            if status_value == "FAIL"
                        ],
                        "evidence_ids": [
                            str(evidence_id)
                            for _status_value, evidence_id in latest.values()
                            if evidence_id is not None
                        ],
                        "finding_ids": [str(finding_id) for finding_id in related_findings],
                    }
                )
            framework_passed = sum(
                _report_count(control, "passed_assets") for control in control_summaries
            )
            framework_assessed = sum(
                _report_count(control, "assessed_assets") for control in control_summaries
            )
            items.append(
                {
                    "framework": framework.code,
                    "name": framework.name,
                    "version": framework.version,
                    "compliance_percent": (
                        round(framework_passed * 100 / framework_assessed)
                        if framework_assessed
                        else None
                    ),
                    "passing_controls": sum(
                        control["status"] == "PASS" for control in control_summaries
                    ),
                    "failing_controls": sum(
                        control["status"] == "FAIL" for control in control_summaries
                    ),
                    "partial_controls": sum(
                        control["status"] == "PARTIAL" for control in control_summaries
                    ),
                    "not_assessed_controls": sum(
                        control["status"] == "NOT_ASSESSED" for control in control_summaries
                    ),
                    "controls": control_summaries,
                }
            )
        return {"generated_at": generated_at, "items": items}
    if report_type == "risk":
        scoped_findings = select(Finding.id).where(
            Finding.organization_id == organization_id,
            Finding.cloud_account_id.in_(account_ids),
        )
        if region:
            scoped_findings = scoped_findings.where(Finding.region_code == region)
        if filters.get("asset_type"):
            scoped_findings = scoped_findings.where(
                Finding.asset_id.in_(
                    select(Asset.id).where(
                        Asset.organization_id == organization_id,
                        Asset.resource_type == str(filters["asset_type"]),
                    )
                )
            )
        if filters.get("date_from"):
            scoped_findings = scoped_findings.where(
                Finding.first_seen_at
                >= datetime.fromisoformat(str(filters["date_from"])).replace(tzinfo=UTC)
            )
        if filters.get("date_to"):
            scoped_findings = scoped_findings.where(
                Finding.first_seen_at
                < datetime.fromisoformat(str(filters["date_to"])).replace(tzinfo=UTC)
                + timedelta(days=1)
            )
        severity_values = _report_filter_list(filters, "severities")
        if severity_values:
            scoped_findings = scoped_findings.where(Finding.severity.in_(severity_values))
        status_values = _report_filter_list(filters, "finding_statuses")
        if status_values:
            scoped_findings = scoped_findings.where(Finding.status.in_(status_values))
        scores = list(
            session.scalars(
                select(RiskScore.score).where(
                    RiskScore.organization_id == organization_id,
                    RiskScore.finding_id.in_(scoped_findings),
                )
            ).all()
        )
        score = aggregate_scores(scores) if scores else None
        level = risk_level(score) if score is not None else None
        factors: dict[str, object] = {"assessed_findings": len(scores)}
        distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for value in scores:
            distribution[risk_level(value)] += 1
        top_findings = session.execute(
            select(Finding.id, Finding.title, Finding.severity, RiskScore.score, RiskScore.level)
            .join(RiskScore, RiskScore.finding_id == Finding.id)
            .where(
                Finding.organization_id == organization_id,
                Finding.id.in_(scoped_findings),
                RiskScore.organization_id == organization_id,
            )
            .order_by(RiskScore.score.desc())
            .limit(10)
        ).all()
        asset_risk_rows = session.execute(
            select(Asset, CloudAccount, RiskScore.score)
            .join(Finding, Finding.asset_id == Asset.id)
            .join(RiskScore, RiskScore.finding_id == Finding.id)
            .join(CloudAccount, CloudAccount.id == Asset.cloud_account_id)
            .where(
                Asset.organization_id == organization_id,
                Finding.organization_id == organization_id,
                Finding.id.in_(scoped_findings),
                RiskScore.organization_id == organization_id,
                CloudAccount.organization_id == organization_id,
            )
        ).all()
        asset_scores: dict[UUID, list[int]] = {}
        asset_details: dict[UUID, tuple[Asset, CloudAccount]] = {}
        for asset, account, finding_score in asset_risk_rows:
            asset_scores.setdefault(asset.id, []).append(finding_score)
            asset_details[asset.id] = (asset, account)
        top_assets = sorted(
            ((asset_id, aggregate_scores(values)) for asset_id, values in asset_scores.items()),
            key=lambda item: (-item[1], str(item[0])),
        )[:10]
        return {
            "generated_at": generated_at,
            "organization_score": score,
            "level": level,
            "factors": factors,
            "distribution": distribution,
            "top_findings": [
                {
                    "finding_id": str(finding_id),
                    "title": title,
                    "severity": severity_value,
                    "risk_score": score_value,
                    "risk_level": level_value,
                }
                for finding_id, title, severity_value, score_value, level_value in top_findings
            ],
            "top_assets": [
                {
                    "asset_id": str(asset_id),
                    "name": asset_details[asset_id][0].name
                    or asset_details[asset_id][0].resource_id,
                    "resource_type": asset_details[asset_id][0].resource_type,
                    "account": asset_details[asset_id][1].name,
                    "region": asset_details[asset_id][0].region_code,
                    "risk_score": asset_score,
                    "risk_level": risk_level(asset_score),
                }
                for asset_id, asset_score in top_assets
            ],
        }
    if report_type == "security_posture":
        scoped_findings = select(Finding.id).where(
            Finding.organization_id == organization_id,
            Finding.cloud_account_id.in_(account_ids),
        )
        if region:
            scoped_findings = scoped_findings.where(Finding.region_code == region)
        if filters.get("asset_type"):
            scoped_findings = scoped_findings.where(
                Finding.asset_id.in_(
                    select(Asset.id).where(
                        Asset.organization_id == organization_id,
                        Asset.resource_type == str(filters["asset_type"]),
                    )
                )
            )
        if filters.get("date_from"):
            scoped_findings = scoped_findings.where(
                Finding.first_seen_at
                >= datetime.fromisoformat(str(filters["date_from"])).replace(tzinfo=UTC)
            )
        if filters.get("date_to"):
            scoped_findings = scoped_findings.where(
                Finding.first_seen_at
                < datetime.fromisoformat(str(filters["date_to"])).replace(tzinfo=UTC)
                + timedelta(days=1)
            )
        severity_values = _report_filter_list(filters, "severities")
        if severity_values:
            scoped_findings = scoped_findings.where(Finding.severity.in_(severity_values))
        status_values = _report_filter_list(filters, "finding_statuses")
        if status_values:
            scoped_findings = scoped_findings.where(Finding.status.in_(status_values))
        open_findings = scoped_findings.where(
            Finding.status.in_(("OPEN", "TRIAGED", "ASSIGNED", "IN_PROGRESS"))
        )
        asset_count_statement = select(func.count(Asset.id)).where(
            Asset.organization_id == organization_id,
            Asset.cloud_account_id.in_(account_ids),
        )
        if region:
            asset_count_statement = asset_count_statement.where(Asset.region_code == region)
        assets = session.scalar(asset_count_statement) or 0
        accounts = (
            session.scalar(
                select(func.count(CloudAccount.id)).where(
                    CloudAccount.organization_id == organization_id,
                    CloudAccount.id.in_(account_ids),
                )
            )
            or 0
        )
        findings = (
            session.scalar(select(func.count(Finding.id)).where(Finding.id.in_(scoped_findings)))
            or 0
        )
        scores = list(
            session.scalars(
                select(RiskScore.score).where(
                    RiskScore.organization_id == organization_id,
                    RiskScore.finding_id.in_(scoped_findings),
                )
            ).all()
        )
        score = aggregate_scores(scores) if scores else None
        level = risk_level(score) if score is not None else None
        severity_counts = {
            severity: session.scalar(
                select(func.count(Finding.id)).where(
                    Finding.id.in_(open_findings), Finding.severity == severity
                )
            )
            or 0
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        }
        high_risk_assets = (
            session.scalar(
                select(func.count(func.distinct(Finding.asset_id)))
                .join(RiskScore, RiskScore.finding_id == Finding.id)
                .where(
                    Finding.organization_id == organization_id,
                    Finding.id.in_(open_findings),
                    RiskScore.organization_id == organization_id,
                    RiskScore.score >= 60,
                )
            )
            or 0
        )
        posture_asset_ids = list(
            session.scalars(
                select(Asset.id).where(
                    Asset.organization_id == organization_id,
                    Asset.cloud_account_id.in_(account_ids),
                    *([Asset.region_code == region] if region else []),
                )
            ).all()
        )
        control_scores: list[int] = []
        compliance_counts: dict[str, int] = dict.fromkeys(
            ("PASS", "FAIL", "PARTIAL", "NOT_ASSESSED"), 0
        )
        frameworks = session.scalars(
            select(ComplianceFramework).where(ComplianceFramework.is_active.is_(True))
        ).all()
        for framework in frameworks:
            controls = session.scalars(
                select(ComplianceControl).where(ComplianceControl.framework_id == framework.id)
            ).all()
            for control in controls:
                status_value, assessed, passed, _failed, _partial, _na, _not_assessed = (
                    control_status(session, organization_id, control, asset_ids=posture_asset_ids)
                )
                compliance_counts[status_value] = compliance_counts.get(status_value, 0) + 1
                if assessed:
                    control_scores.append(round(passed * 100 / assessed))
        compliance_score = (
            round(sum(control_scores) / len(control_scores)) if control_scores else None
        )
        security_score = (
            round(0.4 * (100 - score) + 0.6 * compliance_score)
            if score is not None and compliance_score is not None
            else None
        )
        top_risks = session.execute(
            select(Finding.id, Finding.title, Finding.severity, RiskScore.score, RiskScore.level)
            .join(RiskScore, RiskScore.finding_id == Finding.id)
            .where(
                Finding.organization_id == organization_id,
                Finding.id.in_(scoped_findings),
                RiskScore.organization_id == organization_id,
            )
            .order_by(RiskScore.score.desc())
            .limit(5)
        ).all()
        return {
            "generated_at": generated_at,
            "accounts": accounts,
            "assets": assets,
            "findings": findings,
            "open_findings": sum(severity_counts.values()),
            "critical_findings": severity_counts["CRITICAL"],
            "findings_by_severity": severity_counts,
            "high_risk_assets": high_risk_assets,
            "compliance_score": compliance_score,
            "compliance_controls": compliance_counts,
            "security_score": security_score,
            "security_score_model_version": "1.0",
            "top_risks": [
                {
                    "finding_id": str(finding_id),
                    "title": title,
                    "severity": finding_severity,
                    "risk_score": risk_value,
                    "risk_level": risk_value_level,
                }
                for finding_id, title, finding_severity, risk_value, risk_value_level in top_risks
            ],
            "risk_score": score,
            "risk_level": level,
        }
    raise ValueError("Unsupported report type")


def _report_csv(snapshot: Mapping[str, object]) -> str:
    sections = snapshot.get("sections")
    items = snapshot.get("items")
    if isinstance(sections, dict):
        findings_section = sections.get("findings")
        if isinstance(findings_section, dict):
            section_items = findings_section.get("items")
            if isinstance(section_items, list):
                items = section_items
    rows = items if isinstance(items, list) else [snapshot]
    flattened: list[dict[str, object]] = []
    for item in rows:
        flattened.append(item if isinstance(item, dict) else {"value": item})
    if not flattened:
        return "generated_at\n" + str(snapshot.get("generated_at", "")) + "\n"
    columns = sorted({key for row in flattened for key in row})
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in flattened:
        safe = {key: _spreadsheet_safe(row.get(key)) for key in columns}
        writer.writerow(safe)
    return buffer.getvalue()


def _report_html(snapshot: Mapping[str, object], report_type: str) -> str:
    """Render a small self-contained HTML table with escaped tenant data."""
    items = snapshot.get("items")
    values = items if isinstance(items, list) else [snapshot]
    rows = [item if isinstance(item, dict) else {"value": item} for item in values]
    columns = sorted({key for item in rows for key in item})
    heading = html.escape(report_type.replace("_", " ").title())
    head = "".join(
        f"<th>{html.escape(column.replace('_', ' ').title())}</th>" for column in columns
    )
    body_rows = []
    for row in rows:
        cells = "".join(
            f"<td>{html.escape(_html_value(row.get(column)))}</td>" for column in columns
        )
        body_rows.append(f"<tr>{cells}</tr>")
    generated = html.escape(str(snapshot.get("generated_at", "")))
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>CloudSentinel · {heading}</title><h1>{heading}</h1>"
        f"<p>Generated {generated}</p><table><thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table></html>"
    )


def _report_pdf(snapshot: Mapping[str, object], report_name: str) -> bytes:
    """Render a safe, dependency-free text PDF from the immutable JSON snapshot."""
    serialized = json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True)
    wrapped: list[str] = ["CLOUDSENTINEL SECURITY REPORT", report_name, ""]
    for raw_line in serialized.splitlines():
        line = raw_line
        while len(line) > 100:
            wrapped.append(line[:100])
            line = line[100:]
        wrapped.append(line)
    chunks = [wrapped[index : index + 48] for index in range(0, len(wrapped), 48)] or [[]]

    def pdf_text(value: str) -> bytes:
        encoded = value.encode("cp1252", errors="replace").decode("cp1252")
        escaped = encoded.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        return escaped.encode("cp1252")

    objects: list[bytes] = []
    page_ids = [4 + index * 2 for index in range(len(chunks))]
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids).encode("ascii")
    objects.append(b"<< /Type /Pages /Kids [" + kids + f"] /Count {len(chunks)} >>".encode("ascii"))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for index, lines in enumerate(chunks):
        page_id = page_ids[index]
        stream_id = page_id + 1
        commands = [b"BT /F1 9 Tf 48 750 Td 12 TL"]
        for line in lines:
            commands.append(b"(" + pdf_text(line) + b") Tj T*")
        commands.append(b"ET")
        stream = b"\n".join(commands)
        objects.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            + b"/Resources << /Font << /F1 3 0 R >> >> "
            + f"/Contents {stream_id} 0 R >>".encode("ascii")
        )
        objects.append(
            b"<< /Length "
            + str(len(stream)).encode("ascii")
            + b" >>\nstream\n"
            + stream
            + b"\nendstream"
        )

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def _html_value(value: object) -> str:
    if isinstance(value, dict | list):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value) if value is not None else ""


def _spreadsheet_safe(value: object) -> object:
    if isinstance(value, dict | list):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value
