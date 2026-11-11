"""AWS account metadata lifecycle and narrowly scoped STS validation."""

import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.cloud_accounts.aws_provider import (
    AwsProviderValidationError,
    Boto3AwsValidationProvider,
    MockAwsValidationProvider,
    validate_role_arn,
)
from app.core.domain_errors import ConflictError, InvalidOperationError, NotFoundError
from app.core.models import CloudAccount, CloudRegion, Organization, ScanJob
from app.operations.service import record_audit

REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)?-[a-z]+-\d$")
StsClientFactory = Callable[..., Any]


def normalize_regions(regions: list[str]) -> list[str]:
    """Validate and de-duplicate the explicitly configured AWS regions."""
    normalized = [region.strip().lower() for region in regions]
    if not normalized or any(REGION_PATTERN.fullmatch(region) is None for region in normalized):
        raise InvalidOperationError("One or more AWS region codes are invalid.")
    if len(set(normalized)) != len(normalized):
        raise InvalidOperationError("AWS region codes must be unique.")
    return normalized


def create_cloud_account(
    session: Session,
    *,
    organization_id: UUID,
    created_by_user_id: UUID,
    name: str,
    environment: str | None = None,
    account_id: str,
    primary_region: str | None = None,
    role_arn: str | None,
    regions: list[str],
) -> tuple[CloudAccount, str]:
    """Persist account metadata and a generated ExternalId; return it for setup once."""
    if role_arn is not None:
        validate_role_arn(role_arn, account_id)
    normalized_regions = normalize_regions(regions)
    normalized_primary_region = (primary_region or normalized_regions[0]).strip().lower()
    if normalized_primary_region not in normalized_regions:
        raise InvalidOperationError("The primary region must be one of the enabled regions.")
    organization = session.scalar(
        select(Organization)
        .where(Organization.id == organization_id, Organization.is_active.is_(True))
        .with_for_update()
    )
    if organization is None:
        raise NotFoundError("Organization")
    if (
        session.scalar(
            select(CloudAccount.id).where(
                CloudAccount.organization_id == organization_id,
                CloudAccount.account_id == account_id,
            )
        )
        is not None
    ):
        raise ConflictError("This AWS account is already registered in the organization.")
    account = CloudAccount(
        organization_id=organization_id,
        created_by_user_id=created_by_user_id,
        name=name,
        environment=environment,
        account_id=account_id,
        primary_region=normalized_primary_region,
        role_arn=role_arn,
        external_id=secrets.token_urlsafe(32),
    )
    session.add(account)
    session.flush()
    session.add_all(
        [
            CloudRegion(
                organization_id=organization_id,
                cloud_account_id=account.id,
                region_code=region,
            )
            for region in normalized_regions
        ]
    )
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=created_by_user_id,
        action="cloud_account.created",
        resource_type="cloud_account",
        resource_id=account.id,
        details={"provider": "AWS", "account_id": account_id},
    )
    session.commit()
    return account, account.external_id


def get_cloud_account(session: Session, organization_id: UUID, account_id: UUID) -> CloudAccount:
    """Return one account only when it belongs to the requested organization."""
    account = session.scalar(
        select(CloudAccount).where(
            CloudAccount.id == account_id,
            CloudAccount.organization_id == organization_id,
        )
    )
    if account is None:
        raise NotFoundError("Cloud account")
    return account


def list_cloud_accounts(session: Session, organization_id: UUID) -> list[CloudAccount]:
    """List account metadata belonging to the active organization."""
    return list(
        session.scalars(
            select(CloudAccount)
            .where(CloudAccount.organization_id == organization_id)
            .order_by(CloudAccount.name)
        ).all()
    )


def update_cloud_account(
    session: Session,
    *,
    organization_id: UUID,
    account_id: UUID,
    actor_user_id: UUID,
    changes: dict[str, Any],
) -> CloudAccount:
    """Update account metadata and replace region configuration atomically."""
    account = get_cloud_account(session, organization_id, account_id)
    previous_regions = sorted(
        session.scalars(
            select(CloudRegion.region_code).where(
                CloudRegion.organization_id == organization_id,
                CloudRegion.cloud_account_id == account.id,
            )
        ).all()
    )
    before_values: dict[str, object] = {
        "name": account.name,
        "environment": account.environment,
        "role_arn": account.role_arn,
        "primary_region": account.primary_region,
        "regions": previous_regions,
        "connection_status": account.connection_status,
        "validation_mode": account.validation_mode,
    }
    if "role_arn" in changes:
        if not changes["role_arn"]:
            raise InvalidOperationError("IAM role ARN cannot be blank.")
        validate_role_arn(changes["role_arn"], account.account_id)
        account.role_arn = changes["role_arn"]
        account.connection_status = "pending"
        account.validation_mode = None
        account.last_validated_at = None
        account.last_error_code = None
    if "name" in changes:
        account.name = changes["name"]
    if "environment" in changes:
        account.environment = changes["environment"]
    if "regions" in changes:
        normalized_regions = normalize_regions(changes["regions"])
        current_primary = changes.get("primary_region", account.primary_region)
        normalized_primary = (current_primary or normalized_regions[0]).strip().lower()
        if normalized_primary not in normalized_regions:
            raise InvalidOperationError("The primary region must be one of the enabled regions.")
        account.primary_region = normalized_primary
        for region in session.scalars(
            select(CloudRegion).where(CloudRegion.cloud_account_id == account.id)
        ).all():
            session.delete(region)
        session.flush()
        session.add_all(
            [
                CloudRegion(
                    organization_id=organization_id,
                    cloud_account_id=account.id,
                    region_code=region,
                )
                for region in normalized_regions
            ]
        )
    elif "primary_region" in changes:
        normalized_primary = changes["primary_region"].strip().lower()
        enabled_regions = set(
            session.scalars(
                select(CloudRegion.region_code).where(
                    CloudRegion.organization_id == organization_id,
                    CloudRegion.cloud_account_id == account.id,
                    CloudRegion.is_enabled.is_(True),
                )
            ).all()
        )
        if normalized_primary not in enabled_regions:
            raise InvalidOperationError("The primary region must be one of the enabled regions.")
        account.primary_region = normalized_primary
    tracked_fields = set(changes) | {"connection_status", "validation_mode"}
    if "regions" in changes:
        tracked_fields.add("primary_region")
    after_values: dict[str, object] = {
        field: (
            sorted(
                session.scalars(
                    select(CloudRegion.region_code).where(
                        CloudRegion.organization_id == organization_id,
                        CloudRegion.cloud_account_id == account.id,
                    )
                ).all()
            )
            if field == "regions"
            else getattr(account, field)
        )
        for field in tracked_fields
    }
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action=("cloud_account.role_updated" if "role_arn" in changes else "cloud_account.updated"),
        resource_type="cloud_account",
        resource_id=account.id,
        details={
            "before": {field: before_values[field] for field in tracked_fields},
            "after": after_values,
        },
    )
    session.commit()
    return account


def delete_cloud_account(
    session: Session, *, organization_id: UUID, account_id: UUID, actor_user_id: UUID
) -> None:
    """Disconnect an AWS account by deleting its tenant-owned configuration."""
    account = get_cloud_account(session, organization_id, account_id)
    if (
        session.scalar(
            select(ScanJob.id)
            .where(
                ScanJob.organization_id == organization_id,
                ScanJob.cloud_account_id == account.id,
            )
            .limit(1)
        )
        is not None
    ):
        raise ConflictError(
            "Disable this account to retain it; accounts with scan history cannot be removed."
        )
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="cloud_account.disconnected",
        resource_type="cloud_account",
        resource_id=account.id,
        details={"account_id": account.account_id},
    )
    session.delete(account)
    session.commit()


def disable_cloud_account(
    session: Session, *, organization_id: UUID, account_id: UUID, actor_user_id: UUID
) -> CloudAccount:
    """Disable new scans while retaining tenant-owned account history and metadata."""
    account = get_cloud_account(session, organization_id, account_id)
    if account.connection_status != "disabled":
        previous_status = account.connection_status
        account.connection_status = "disabled"
        record_audit(
            session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="cloud_account.disabled",
            resource_type="cloud_account",
            resource_id=account.id,
            details={
                "account_id": account.account_id,
                "before": {"connection_status": previous_status},
                "after": {"connection_status": account.connection_status},
            },
        )
        session.commit()
    return account


def rotate_external_id(
    session: Session,
    *,
    organization_id: UUID,
    account_id: UUID,
    actor_user_id: UUID,
) -> tuple[CloudAccount, str]:
    """Rotate the AWS trust ExternalId and return the new value once."""
    account = get_cloud_account(session, organization_id, account_id)
    value = secrets.token_urlsafe(32)
    account.external_id = value
    account.connection_status = "pending"
    account.validation_mode = None
    account.last_validated_at = None
    account.last_error_code = None
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="cloud_account.external_id_rotated",
        resource_type="cloud_account",
        resource_id=account.id,
    )
    session.commit()
    return account, value


def validate_cloud_account(
    session: Session,
    *,
    organization_id: UUID,
    account_id: UUID,
    actor_user_id: UUID | None = None,
    sts_client_factory: StsClientFactory | None = None,
    validation_mode: str = "real",
    mock_scenario: str = "success",
) -> CloudAccount:
    """Validate role trust through real AWS STS or an explicitly enabled local mock."""
    account = get_cloud_account(session, organization_id, account_id)
    if not account.role_arn:
        raise InvalidOperationError("Configure an IAM role before validating this AWS account.")
    validate_role_arn(account.role_arn, account.account_id)
    if validation_mode not in {"real", "mock"}:
        raise InvalidOperationError("Unsupported AWS validation mode.")
    enabled_region_query = select(CloudRegion.region_code).where(
        CloudRegion.organization_id == organization_id,
        CloudRegion.cloud_account_id == account.id,
        CloudRegion.is_enabled.is_(True),
    )
    region = None
    if account.primary_region:
        region = session.scalar(
            enabled_region_query.where(CloudRegion.region_code == account.primary_region)
        )
    if region is None:
        region = session.scalar(enabled_region_query.order_by(CloudRegion.region_code).limit(1))
    if region is None:
        raise InvalidOperationError("Configure at least one enabled AWS region before validation.")
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="cloud_account.validation_requested",
        resource_type="cloud_account",
        resource_id=account.id,
        details={"provider": "AWS", "validation_mode": validation_mode},
    )
    try:
        provider = (
            MockAwsValidationProvider(mock_scenario)
            if validation_mode == "mock"
            else Boto3AwsValidationProvider(sts_client_factory)
        )
        outcome = provider.validate_connection(
            role_arn=account.role_arn,
            account_id=account.account_id,
            external_id=account.external_id,
            region=region,
            session_name=f"CloudSentinel-{str(account.id)[:8]}",
        )
    except InvalidOperationError as error:
        account.connection_status = "error"
        account.validation_mode = validation_mode
        account.last_error_code = (
            "account_identity_mismatch" if "identity" in str(error).lower() else "invalid_role_arn"
        )
        account.last_validated_at = datetime.now(UTC)
        record_audit(
            session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="cloud_account.validation_failed",
            resource_type="cloud_account",
            resource_id=account.id,
            status="FAILURE",
            details={"error_code": account.last_error_code, "validation_mode": validation_mode},
        )
        session.commit()
        raise
    except AwsProviderValidationError as error:
        account.connection_status = "error"
        account.validation_mode = validation_mode
        account.last_error_code = error.code
        account.last_validated_at = datetime.now(UTC)
        record_audit(
            session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="cloud_account.validation_failed",
            resource_type="cloud_account",
            resource_id=account.id,
            status="FAILURE",
            details={"error_code": account.last_error_code, "validation_mode": validation_mode},
        )
        session.commit()
        if error.code == "account_identity_mismatch":
            raise InvalidOperationError(
                "AWS role identity does not match the configured account."
            ) from None
        raise InvalidOperationError("AWS role validation failed.") from None

    account.connection_status = "connected"
    account.validation_mode = outcome.validation_mode
    account.last_error_code = None
    account.last_validated_at = datetime.now(UTC)
    record_audit(
        session,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="cloud_account.validated",
        resource_type="cloud_account",
        resource_id=account.id,
        details={
            "provider": "AWS",
            "validation_mode": outcome.validation_mode,
            "baseline_permissions_status": outcome.baseline_permissions_status,
        },
    )
    session.commit()
    return account
