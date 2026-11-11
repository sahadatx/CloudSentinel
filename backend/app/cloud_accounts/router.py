"""Tenant-scoped AWS account configuration and STS connection validation."""

from datetime import datetime
from hashlib import sha256
from typing import Annotated, cast
from uuid import UUID

import boto3
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from redis.exceptions import RedisError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import Principal, get_tenant_session, require_permission
from app.cloud_accounts.schemas import (
    CloudAccountCreate,
    CloudAccountCreated,
    CloudAccountExternalId,
    CloudAccountRead,
    CloudAccountUpdate,
    CloudAccountValidation,
    CloudAccountValidationMode,
    CloudRegionInventoryRead,
    CloudRegionRead,
)
from app.cloud_accounts.service import (
    create_cloud_account,
    delete_cloud_account,
    disable_cloud_account,
    get_cloud_account,
    list_cloud_accounts,
    rotate_external_id,
    update_cloud_account,
    validate_cloud_account,
)
from app.core.models import Asset, CloudRegion, ScanJob
from app.core.redis import RedisClient, get_redis_client

router = APIRouter(prefix="/cloud-accounts", tags=["cloud accounts"])

AWS_VALIDATION_RATE_LIMIT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return count
"""


@router.get("", response_model=list[CloudAccountRead])
def list_accounts(
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[CloudAccountRead]:
    """List safe account metadata for the authenticated organization."""
    scan_rows = session.execute(
        select(ScanJob.cloud_account_id, func.max(ScanJob.created_at))
        .where(ScanJob.organization_id == principal.organization_id)
        .group_by(ScanJob.cloud_account_id)
    ).all()
    latest_scans: dict[UUID, datetime] = {
        cloud_account_id: last_scan_at
        for cloud_account_id, last_scan_at in scan_rows
        if last_scan_at is not None
    }
    return [
        CloudAccountRead.model_validate(row).model_copy(
            update={"last_scan_at": latest_scans.get(row.id)}
        )
        for row in list_cloud_accounts(session, principal.organization_id)
    ]


@router.post("", response_model=CloudAccountCreated, status_code=status.HTTP_201_CREATED)
def register_account(
    payload: CloudAccountCreate,
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:create"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> CloudAccountCreated:
    """Register AWS role metadata and return its generated ExternalId once."""
    account, external_id = create_cloud_account(
        session,
        organization_id=principal.organization_id,
        created_by_user_id=principal.user_id,
        name=payload.name,
        environment=payload.environment,
        account_id=payload.account_id,
        primary_region=payload.primary_region,
        role_arn=payload.role_arn,
        regions=payload.regions,
    )
    return CloudAccountCreated.model_validate(
        {**CloudAccountRead.model_validate(account).model_dump(), "external_id": external_id}
    )


@router.get("/metadata/aws-regions", response_model=list[str])
def list_aws_regions(
    _: Annotated[Principal, Depends(require_permission("cloud_accounts:create"))],
) -> list[str]:
    """Return AWS EC2 regions supported by the installed AWS SDK endpoint catalog."""
    return sorted(boto3.session.Session().get_available_regions("ec2", allow_non_regional=False))


@router.get("/metadata/validation-mode", response_model=CloudAccountValidationMode)
def get_validation_mode(
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:read"))],
    request: Request,
) -> CloudAccountValidationMode:
    """Expose the explicit local validation mode so the UI can label mock results."""
    del principal
    return CloudAccountValidationMode(mode=request.app.state.settings.aws_validation_mode)


@router.get("/{account_id}", response_model=CloudAccountRead)
def get_account(
    account_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> CloudAccountRead:
    """Get an account without disclosing the ExternalId."""
    account = get_cloud_account(session, principal.organization_id, account_id)
    last_scan_at = session.scalar(
        select(func.max(ScanJob.created_at)).where(
            ScanJob.organization_id == principal.organization_id,
            ScanJob.cloud_account_id == account.id,
        )
    )
    return CloudAccountRead.model_validate(account).model_copy(
        update={"last_scan_at": last_scan_at}
    )


@router.get("/{account_id}/regions", response_model=list[CloudRegionInventoryRead])
def list_account_regions(
    account_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:read"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> list[CloudRegionInventoryRead]:
    """List configured regions and inventory counts without implying discovery."""
    get_cloud_account(session, principal.organization_id, account_id)
    rows = session.execute(
        select(CloudRegion, func.count(Asset.id))
        .outerjoin(
            Asset,
            (Asset.organization_id == CloudRegion.organization_id)
            & (Asset.cloud_account_id == CloudRegion.cloud_account_id)
            & (Asset.region_code == CloudRegion.region_code),
        )
        .where(
            CloudRegion.organization_id == principal.organization_id,
            CloudRegion.cloud_account_id == account_id,
        )
        .group_by(CloudRegion.id)
        .order_by(CloudRegion.region_code)
    ).all()
    return [
        CloudRegionInventoryRead(
            **CloudRegionRead.model_validate(region).model_dump(),
            asset_count=asset_count,
        )
        for region, asset_count in rows
    ]


@router.patch("/{account_id}", response_model=CloudAccountRead)
def update_account(
    account_id: UUID,
    payload: CloudAccountUpdate,
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> CloudAccountRead:
    """Update account metadata or configured regions within the active tenant."""
    account = update_cloud_account(
        session,
        organization_id=principal.organization_id,
        account_id=account_id,
        actor_user_id=principal.user_id,
        changes=payload.model_dump(exclude_unset=True),
    )
    return CloudAccountRead.model_validate(account)


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def disconnect_account(
    account_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:delete"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> Response:
    """Remove account integration metadata and its configured regions."""
    delete_cloud_account(
        session,
        organization_id=principal.organization_id,
        account_id=account_id,
        actor_user_id=principal.user_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{account_id}/disable", response_model=CloudAccountRead)
def disable_account(
    account_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> CloudAccountRead:
    """Disable future scans while retaining account and historical records."""
    account = disable_cloud_account(
        session,
        organization_id=principal.organization_id,
        account_id=account_id,
        actor_user_id=principal.user_id,
    )
    return CloudAccountRead.model_validate(account)


@router.post("/{account_id}/validate", response_model=CloudAccountValidation)
async def validate_account(
    account_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
    request: Request,
    redis: Annotated[RedisClient, Depends(get_redis_client)],
) -> CloudAccountValidation:
    """Validate the role trust and account identity using AWS STS only."""
    settings = request.app.state.settings
    client_ip = request.client.host if request.client else "unknown"
    rate_key = sha256(
        f"{principal.organization_id}:{principal.user_id}:{client_ip}".encode()
    ).hexdigest()
    try:
        count_value = await redis.eval(
            AWS_VALIDATION_RATE_LIMIT_SCRIPT,
            1,
            f"cloud-account:validate:{rate_key}",
            settings.aws_validation_rate_limit_window_seconds,
        )
        count = int(cast(int | str | bytes, count_value))
    except (RedisError, TypeError, ValueError):
        raise HTTPException(
            status_code=503, detail="AWS validation is temporarily unavailable."
        ) from None
    if count > settings.aws_validation_rate_limit_requests:
        raise HTTPException(
            status_code=429,
            detail="AWS validation rate limit exceeded. Try again later.",
            headers={"Retry-After": str(settings.aws_validation_rate_limit_window_seconds)},
        )
    account = validate_cloud_account(
        session,
        organization_id=principal.organization_id,
        account_id=account_id,
        actor_user_id=principal.user_id,
        validation_mode=settings.aws_validation_mode,
        mock_scenario=settings.aws_mock_scenario,
    )
    if account.last_validated_at is None:
        raise RuntimeError("Account validation did not produce a timestamp")
    return CloudAccountValidation(
        account_id=account.account_id,
        connection_status=account.connection_status,
        validated_at=account.last_validated_at,
        validation_mode=account.validation_mode or settings.aws_validation_mode,
        baseline_permissions_status=(
            "simulated_passed"
            if settings.aws_validation_mode == "mock" and account.connection_status == "connected"
            else "not_checked"
        ),
    )


@router.post("/{account_id}/external-id", response_model=CloudAccountExternalId)
def rotate_account_external_id(
    account_id: UUID,
    principal: Annotated[Principal, Depends(require_permission("cloud_accounts:update"))],
    session: Annotated[Session, Depends(get_tenant_session)],
) -> CloudAccountExternalId:
    """Issue a new one-time AWS trust ExternalId for connection setup."""
    _, external_id = rotate_external_id(
        session,
        organization_id=principal.organization_id,
        account_id=account_id,
        actor_user_id=principal.user_id,
    )
    return CloudAccountExternalId(external_id=external_id)
