"""Create narrowly scoped AWS SDK sessions from a registered read-only role."""

import boto3
from boto3 import Session
from botocore.config import Config

AWS_CONFIG = Config(
    connect_timeout=3,
    read_timeout=20,
    retries={"max_attempts": 3, "mode": "standard"},
    user_agent_extra="CloudSentinel-Inventory/1.0",
)


def assume_readonly_session(
    *,
    role_arn: str,
    external_id: str,
    expected_account_id: str,
    region_name: str,
    session_name: str,
) -> Session:
    """Assume a registered customer role, validate identity, and hold credentials in memory."""
    sts = boto3.client("sts", region_name=region_name, config=AWS_CONFIG)
    response = sts.assume_role(
        RoleArn=role_arn,
        ExternalId=external_id,
        RoleSessionName=session_name,
        DurationSeconds=900,
    )
    credentials = response["Credentials"]
    identity_sts = boto3.client(
        "sts",
        region_name=region_name,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        config=AWS_CONFIG,
    )
    identity = identity_sts.get_caller_identity()
    if identity.get("Account") != expected_account_id:
        raise AWSIdentityMismatch
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region_name,
    )


class AWSIdentityMismatch(RuntimeError):
    """The assumed role returned an identity outside the registered AWS account."""
