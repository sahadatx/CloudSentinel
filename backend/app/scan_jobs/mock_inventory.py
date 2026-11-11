"""Deterministic local inventory fixtures for exercising scan-to-assets flows."""

from __future__ import annotations

import hashlib

from cloudsentinel_scanner.normalizers.aws import (
    NormalizedAsset,
    ResourceReference,
    normalize_aws_resource,
)

_RESOURCE_DETAILS: dict[str, tuple[str, dict[str, object]]] = {
    "vpc": (
        "production-network",
        {"state": "available", "cidr_block": "10.20.0.0/16"},
    ),
    "subnet": (
        "private-subnet-a",
        {"availability_zone": "us-east-1a", "cidr_block": "10.20.1.0/24"},
    ),
    "security_group": (
        "web-tier",
        {
            "Description": "Sample security group with SSH exposed for policy testing",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        },
    ),
    "network_interface": (
        "app-network-interface",
        {"status": "in-use", "private_ip": "10.20.1.25"},
    ),
    "ec2_instance": (
        "production-web-01",
        {"instance_type": "t3.medium", "state": "running", "public_ip": None},
    ),
    "ebs_volume": (
        "production-data-volume",
        {"volume_type": "gp3", "size_gib": 100, "encrypted": True},
    ),
    "rds_instance": (
        "production-postgres",
        {
            "engine": "postgres",
            "storage_encrypted": False,
            "publicly_accessible": True,
        },
    ),
    "lambda_function": (
        "event-processor",
        {"runtime": "python3.12", "timeout_seconds": 30},
    ),
    "s3_bucket": (
        "production-data",
        {
            "bucket_policy_public": True,
            "public_acl": False,
            "public_access_block": {
                "block_public_acls": False,
                "ignore_public_acls": False,
                "block_public_policy": False,
                "restrict_public_buckets": False,
            },
            "encryption_enabled": False,
            "versioning_enabled": True,
            "logging_enabled": True,
        },
    ),
    "iam_user": ("automation-reader", {"mfa_enabled": True, "console_access": False}),
    "iam_role": ("application-runtime-role", {"trust_policy_present": True}),
    "iam_policy": ("application-read-policy", {"attachment_count": 1, "managed": True}),
    "cloudtrail": (
        "organization-trail",
        {"multi_region": True, "log_file_validation": True, "is_logging": False},
    ),
    "cloudwatch_alarm": ("high-cpu-alarm", {"state": "OK", "metric": "CPUUtilization"}),
    "kms_key": (
        "application-data-key",
        {"key_state": "Enabled", "key_spec": "SYMMETRIC_DEFAULT"},
    ),
    "ecr_repository": (
        "application",
        {"image_scan_on_push": True, "tag_immutability": "IMMUTABLE"},
    ),
    "ecs_cluster": ("production-cluster", {"status": "ACTIVE", "running_tasks": 2}),
    "ecs_service": ("web-service", {"status": "ACTIVE", "desired_count": 2}),
    "eks_cluster": ("production-eks", {"status": "ACTIVE", "version": "1.30"}),
}

_GLOBAL_TYPES = {"s3_bucket", "iam_user", "iam_role", "iam_policy"}
_RESOURCE_RELATIONSHIPS: dict[str, tuple[tuple[str, str], ...]] = {
    "subnet": (("vpc", "contained_by"),),
    "security_group": (("vpc", "attached_to"),),
    "network_interface": (
        ("vpc", "attached_to"),
        ("subnet", "attached_to"),
        ("security_group", "protected_by"),
    ),
    "ec2_instance": (
        ("vpc", "runs_in"),
        ("subnet", "runs_in"),
        ("security_group", "protected_by"),
        ("network_interface", "uses"),
        ("ebs_volume", "attached_volume"),
    ),
    "ebs_volume": (("ec2_instance", "attached_to"),),
    "rds_instance": (("security_group", "protected_by"), ("vpc", "runs_in")),
    "lambda_function": (
        ("vpc", "runs_in"),
        ("subnet", "runs_in"),
        ("security_group", "protected_by"),
    ),
    "ecs_service": (("ecs_cluster", "runs_on"),),
    "eks_cluster": (
        ("vpc", "runs_in"),
        ("subnet", "runs_in"),
        ("security_group", "protected_by"),
    ),
}


def mock_inventory(
    resource_type: str,
    region: str,
    *,
    account_id: str,
    partition: str = "aws",
    environment: str | None = None,
) -> tuple[NormalizedAsset, ...]:
    """Return one stable, visibly simulated resource for a requested scan unit."""
    details = _RESOURCE_DETAILS.get(resource_type)
    if details is None:
        return ()

    name, attributes = details
    identity_region = "global" if resource_type in _GLOBAL_TYPES else region
    identity = f"{account_id}:{resource_type}:{identity_region}"
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:12]
    resource_id = _resource_id(resource_type, name, suffix)
    arn_region = "" if resource_type in _GLOBAL_TYPES else region
    arn = _resource_arn(resource_type, name, resource_id, partition, arn_region, account_id)
    relationships = tuple(
        _resource_reference(account_id, target_type, region, relationship_type)
        for target_type, relationship_type in _RESOURCE_RELATIONSHIPS.get(resource_type, ())
    )
    tags = {"Application": "CloudSentinel Sample Inventory"}
    if environment:
        tags["Environment"] = environment
    return (
        normalize_aws_resource(
            resource_type,
            resource_id,
            name,
            region,
            tags,
            attributes={**attributes, "cloudsentinel_data_origin": "local_mock"},
            arn=arn,
            relationships=relationships,
        ),
    )


def _resource_reference(
    account_id: str,
    resource_type: str,
    region: str,
    relationship_type: str,
) -> ResourceReference:
    """Build a reference to the deterministic mock identity for this account and region."""
    name = _RESOURCE_DETAILS[resource_type][0]
    identity_region = "global" if resource_type in _GLOBAL_TYPES else region
    identity = f"{account_id}:{resource_type}:{identity_region}"
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:12]
    return ResourceReference(
        resource_type=resource_type,
        resource_id=_resource_id(resource_type, name, suffix),
        region_code=region,
        relationship_type=relationship_type,
    )


def _resource_id(resource_type: str, name: str, suffix: str) -> str:
    if resource_type == "s3_bucket":
        return f"cs-demo-{suffix}"
    if resource_type == "ec2_instance":
        return f"i-{suffix}"
    if resource_type == "ebs_volume":
        return f"vol-{suffix}"
    if resource_type == "vpc":
        return f"vpc-{suffix}"
    if resource_type == "subnet":
        return f"subnet-{suffix}"
    if resource_type == "security_group":
        return f"sg-{suffix}"
    if resource_type == "network_interface":
        return f"eni-{suffix}"
    if resource_type == "rds_instance":
        return name
    if resource_type == "lambda_function":
        return name
    return name


def _resource_arn(
    resource_type: str,
    name: str,
    resource_id: str,
    partition: str,
    region: str,
    account_id: str,
) -> str:
    if resource_type == "s3_bucket":
        return f"arn:{partition}:s3:::{resource_id}"
    if resource_type.startswith("iam_"):
        iam_kind = resource_type.removeprefix("iam_")
        return f"arn:{partition}:iam::{account_id}:{iam_kind}/{name}"
    service_by_type = {
        "vpc": "ec2",
        "subnet": "ec2",
        "security_group": "ec2",
        "network_interface": "ec2",
        "ec2_instance": "ec2",
        "ebs_volume": "ec2",
        "rds_instance": "rds",
        "lambda_function": "lambda",
        "cloudtrail": "cloudtrail",
        "cloudwatch_alarm": "cloudwatch",
        "kms_key": "kms",
        "ecr_repository": "ecr",
        "ecs_cluster": "ecs",
        "ecs_service": "ecs",
        "eks_cluster": "eks",
    }
    service = service_by_type[resource_type]
    return f"arn:{partition}:{service}:{region}:{account_id}:{resource_id}"
