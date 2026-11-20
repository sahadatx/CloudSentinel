"""Purge expired customer uploads, result rows, and tenant finding data."""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import boto3
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.models import CustomerScanJob

logger = logging.getLogger("cloudsentinel.customer_scan_retention")


def purge_expired_customer_scans(factory: sessionmaker[Session], *, limit: int = 100) -> int:
    settings = get_settings()
    now = datetime.now(UTC)
    with factory(info={"allow_unscoped": True}) as session:
        candidates = list(
            session.scalars(
                select(CustomerScanJob)
                .where(CustomerScanJob.expires_at <= now)
                .order_by(CustomerScanJob.expires_at)
                .limit(max(1, min(limit, 500)))
            ).all()
        )
        selected = [(job.id, job.artifact_key, job.organization_id) for job in candidates]

    storage = _s3_client(settings) if settings.customer_scan_bucket else None
    purged = 0
    for job_id, input_key, organization_id in selected:
        if storage is None:
            logger.error("Cannot expire customer scan without object storage", extra={"scan_id": str(job_id)})
            continue
        result_key = f"{settings.customer_scan_prefix.strip('/')}/{organization_id}/{job_id}/result.json"
        try:
            storage.delete_object(Bucket=settings.customer_scan_bucket, Key=input_key)
            storage.delete_object(Bucket=settings.customer_scan_bucket, Key=result_key)
        except Exception as error:
            logger.warning("Customer scan artifact expiry failed", extra={"error_type": type(error).__name__})
            continue
        with factory(info={"allow_unscoped": True}) as session:
            job = session.scalar(
                select(CustomerScanJob)
                .where(CustomerScanJob.id == job_id, CustomerScanJob.expires_at <= now)
                .with_for_update()
            )
            if job is not None:
                session.delete(job)
                session.commit()
                purged += 1
    return purged


def _s3_client(settings: Any):
    options: dict[str, object] = {
        "region_name": settings.report_storage_region,
        "endpoint_url": settings.report_storage_endpoint_url or None,
    }
    if settings.report_storage_access_key and settings.report_storage_secret_key:
        options["aws_access_key_id"] = settings.report_storage_access_key.get_secret_value()
        options["aws_secret_access_key"] = settings.report_storage_secret_key.get_secret_value()
    return boto3.client("s3", **options)
