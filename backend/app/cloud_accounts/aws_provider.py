"""Real and local-mock AWS role validation adapters."""

import re
from dataclasses import dataclass
from typing import Any, Literal, Protocol

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from app.core.domain_errors import InvalidOperationError

ROLE_ARN_PATTERN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):iam::(?P<account_id>\d{12}):role/[A-Za-z0-9+=,.@_/-]{1,480}$"
)
AWS_CLIENT_CONFIG = BotoConfig(
    connect_timeout=3,
    read_timeout=5,
    retries={"max_attempts": 2, "mode": "standard"},
)


def validate_role_arn(role_arn: str, expected_account_id: str) -> None:
    """Require a role ARN in the registered account, excluding custom endpoints."""
    match = ROLE_ARN_PATTERN.fullmatch(role_arn)
    if match is None or match.group("account_id") != expected_account_id:
        raise InvalidOperationError(
            "The role ARN must identify a role in the configured AWS account."
        )


class AwsProviderValidationError(Exception):
    """Safe, bounded validation failure code; never contains provider messages."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AwsValidationOutcome:
    """Sanitized validation outcome suitable for API and persistence."""

    validation_mode: Literal["real", "mock"]
    actual_account_id: str
    baseline_permissions_status: Literal["not_checked", "simulated_passed", "simulated_failed"]


class AwsValidationProvider(Protocol):
    """Provider contract for validating role trust and caller identity."""

    def validate_connection(
        self,
        *,
        role_arn: str,
        account_id: str,
        external_id: str,
        region: str,
        session_name: str,
    ) -> AwsValidationOutcome: ...


def safe_aws_error_code(error: Exception) -> str:
    """Return only a bounded AWS error identifier, never a provider message."""
    code: str | None = None
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code")
    if code is None or re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", code) is None:
        code = type(error).__name__
    return code[:80]


class Boto3AwsValidationProvider:
    """Use the runtime AWS workload identity to call STS AssumeRole."""

    def __init__(self, sts_client_factory: Any = None) -> None:
        self._sts_client_factory = sts_client_factory or boto3.client

    def validate_connection(
        self,
        *,
        role_arn: str,
        account_id: str,
        external_id: str,
        region: str,
        session_name: str,
    ) -> AwsValidationOutcome:
        validate_role_arn(role_arn, account_id)
        try:
            sts = self._sts_client_factory("sts", region_name=region, config=AWS_CLIENT_CONFIG)
            assumed = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                ExternalId=external_id,
                DurationSeconds=900,
            )
            credentials = assumed["Credentials"]
            identity_client = self._sts_client_factory(
                "sts",
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=region,
                config=AWS_CLIENT_CONFIG,
            )
            identity = identity_client.get_caller_identity()
        except (BotoCoreError, ClientError, KeyError, TypeError) as error:
            raise AwsProviderValidationError(safe_aws_error_code(error)) from None
        actual_account_id = identity.get("Account")
        if actual_account_id != account_id:
            raise AwsProviderValidationError("account_identity_mismatch")
        return AwsValidationOutcome(
            validation_mode="real",
            actual_account_id=actual_account_id,
            baseline_permissions_status="not_checked",
        )


@dataclass(frozen=True)
class _MockAssumedRole:
    """Non-credential marker used only inside the deterministic mock adapter."""

    account_id: str
    external_id: str


class MockAwsValidationProvider:
    """Simulate STS with deterministic checks and no AWS credentials or network."""

    def __init__(self, scenario: str = "success") -> None:
        self._scenario = scenario

    def assume_role(
        self,
        *,
        role_arn: str,
        account_id: str,
        external_id: str,
    ) -> _MockAssumedRole:
        validate_role_arn(role_arn, account_id)
        if self._scenario == "assume_role_denied":
            raise AwsProviderValidationError("mock_assume_role_denied")
        trusted_external_id = external_id
        if self._scenario == "external_id_mismatch":
            trusted_external_id = f"{external_id}-mismatch"
        if not external_id or external_id != trusted_external_id:
            raise AwsProviderValidationError("mock_external_id_mismatch")
        return _MockAssumedRole(account_id=account_id, external_id=external_id)

    def get_caller_identity(self, assumed_role: _MockAssumedRole) -> dict[str, str]:
        actual_account_id = assumed_role.account_id
        if self._scenario == "identity_mismatch":
            actual_account_id = (
                "000000000000" if actual_account_id != "000000000000" else "111111111111"
            )
        return {"Account": actual_account_id}

    def validate_baseline_permissions(self, _assumed_role: _MockAssumedRole) -> bool:
        if self._scenario == "permission_denied":
            return False
        return True

    def validate_connection(
        self,
        *,
        role_arn: str,
        account_id: str,
        external_id: str,
        region: str,
        session_name: str,
    ) -> AwsValidationOutcome:
        del region, session_name
        assumed = self.assume_role(
            role_arn=role_arn,
            account_id=account_id,
            external_id=external_id,
        )
        identity = self.get_caller_identity(assumed)
        actual_account_id = identity.get("Account", "")
        if actual_account_id != account_id:
            raise AwsProviderValidationError("account_identity_mismatch")
        permissions_ok = self.validate_baseline_permissions(assumed)
        if not permissions_ok:
            raise AwsProviderValidationError("mock_baseline_permissions_denied")
        return AwsValidationOutcome(
            validation_mode="mock",
            actual_account_id=actual_account_id,
            baseline_permissions_status="simulated_passed",
        )
