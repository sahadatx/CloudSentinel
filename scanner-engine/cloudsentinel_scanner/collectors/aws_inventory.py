"""Read-only AWS SDK inventory collectors with explicit safe field projection."""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from boto3 import Session
from botocore.exceptions import BotoCoreError, ClientError

from cloudsentinel_scanner.normalizers.aws import (
    NormalizedAsset,
    ResourceReference,
    normalize_aws_resource,
)
from cloudsentinel_scanner.providers.aws.session import AWS_CONFIG

AWS_RESOURCE_TYPES = (
    "vpc",
    "subnet",
    "security_group",
    "network_interface",
    "ec2_instance",
    "ebs_volume",
    "rds_instance",
    "lambda_function",
    "s3_bucket",
    "iam_user",
    "iam_role",
    "iam_policy",
    "cloudtrail",
    "cloudwatch_alarm",
    "kms_key",
    "ecr_repository",
    "ecs_cluster",
    "ecs_service",
    "eks_cluster",
)
GLOBAL_RESOURCE_TYPES = frozenset({"s3_bucket", "iam_user", "iam_role", "iam_policy"})


@dataclass(frozen=True)
class CollectionResult:
    """Resources and sanitized errors returned for one service collection unit."""

    resources: tuple[NormalizedAsset, ...]
    error_code: str | None = None


class AWSInventoryCollector:
    """Collect inventory only; no policy evaluation, rule execution, or findings."""

    def __init__(
        self,
        session: Session,
        *,
        account_id: str,
        partition: str,
        allowed_regions: frozenset[str] | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.partition = partition
        self.allowed_regions = allowed_regions

    def collect(self, resource_type: str, region_code: str) -> CollectionResult:
        """Run the explicitly mapped AWS read call for a supported resource type."""
        if resource_type not in AWS_RESOURCE_TYPES:
            raise ValueError("Unsupported AWS resource type")
        try:
            resources = getattr(self, f"_collect_{resource_type}")(region_code)
            return CollectionResult(tuple(resources))
        except (BotoCoreError, ClientError, KeyError, TypeError, ValueError) as error:
            return CollectionResult((), _safe_error_code(error))

    def _client(self, service_name: str, region_code: str) -> Any:
        return self.session.client(service_name, region_name=region_code, config=AWS_CONFIG)

    def _pages(self, client: Any, operation: str, result_key: str, **kwargs: Any) -> Iterable[Any]:
        paginator = client.get_paginator(operation)
        for page in paginator.paginate(**kwargs):
            yield from page.get(result_key, [])

    def _collect_vpc(self, region: str) -> list[NormalizedAsset]:
        client = self._client("ec2", region)
        return [
            normalize_aws_resource(
                "vpc",
                row["VpcId"],
                row.get("VpcId"),
                region,
                row.get("Tags", []),
                attributes={
                    key: row[key]
                    for key in ("CidrBlock", "State", "IsDefault", "DhcpOptionsId")
                    if key in row
                },
                arn=_ec2_arn(self.partition, region, self.account_id, "vpc", row["VpcId"]),
            )
            for row in self._pages(client, "describe_vpcs", "Vpcs")
        ]

    def _collect_subnet(self, region: str) -> list[NormalizedAsset]:
        client = self._client("ec2", region)
        return [
            normalize_aws_resource(
                "subnet",
                row["SubnetId"],
                row.get("SubnetId"),
                region,
                row.get("Tags", []),
                attributes={
                    key: row[key]
                    for key in (
                        "VpcId",
                        "CidrBlock",
                        "AvailabilityZone",
                        "State",
                        "MapPublicIpOnLaunch",
                    )
                    if key in row
                },
                arn=_ec2_arn(self.partition, region, self.account_id, "subnet", row["SubnetId"]),
                relationships=(ResourceReference("vpc", row["VpcId"], region, "contained_by"),)
                if row.get("VpcId")
                else (),
            )
            for row in self._pages(client, "describe_subnets", "Subnets")
        ]

    def _collect_security_group(self, region: str) -> list[NormalizedAsset]:
        client = self._client("ec2", region)
        resources: list[NormalizedAsset] = []
        for row in self._pages(client, "describe_security_groups", "SecurityGroups"):
            relationships = (
                (ResourceReference("vpc", row["VpcId"], region, "attached_to"),)
                if row.get("VpcId")
                else ()
            )
            resources.append(
                normalize_aws_resource(
                    "security_group",
                    row["GroupId"],
                    row.get("GroupName"),
                    region,
                    row.get("Tags", []),
                    attributes={
                        key: row[key]
                        for key in ("Description", "VpcId", "IpPermissions", "IpPermissionsEgress")
                        if key in row
                    },
                    arn=_ec2_arn(
                        self.partition, region, self.account_id, "security-group", row["GroupId"]
                    ),
                    relationships=relationships,
                )
            )
        return resources

    def _collect_network_interface(self, region: str) -> list[NormalizedAsset]:
        client = self._client("ec2", region)
        resources: list[NormalizedAsset] = []
        for row in self._pages(client, "describe_network_interfaces", "NetworkInterfaces"):
            refs: list[ResourceReference] = []
            if row.get("VpcId"):
                refs.append(ResourceReference("vpc", row["VpcId"], region, "attached_to"))
            if row.get("SubnetId"):
                refs.append(ResourceReference("subnet", row["SubnetId"], region, "attached_to"))
            refs.extend(
                ResourceReference("security_group", group["GroupId"], region, "protected_by")
                for group in row.get("Groups", [])
                if group.get("GroupId")
            )
            resources.append(
                normalize_aws_resource(
                    "network_interface",
                    row["NetworkInterfaceId"],
                    row.get("Description"),
                    region,
                    row.get("TagSet", []),
                    attributes={
                        key: row[key]
                        for key in (
                            "Status",
                            "InterfaceType",
                            "VpcId",
                            "SubnetId",
                            "PrivateIpAddress",
                            "PublicIp",
                            "RequesterManaged",
                        )
                        if key in row
                    },
                    arn=_ec2_arn(
                        self.partition,
                        region,
                        self.account_id,
                        "network-interface",
                        row["NetworkInterfaceId"],
                    ),
                    relationships=tuple(refs),
                )
            )
        return resources

    def _collect_ec2_instance(self, region: str) -> list[NormalizedAsset]:
        client = self._client("ec2", region)
        resources: list[NormalizedAsset] = []
        for reservation in self._pages(client, "describe_instances", "Reservations"):
            for row in reservation.get("Instances", []):
                refs: list[ResourceReference] = []
                if row.get("VpcId"):
                    refs.append(ResourceReference("vpc", row["VpcId"], region, "runs_in"))
                if row.get("SubnetId"):
                    refs.append(ResourceReference("subnet", row["SubnetId"], region, "runs_in"))
                refs.extend(
                    ResourceReference("security_group", group["GroupId"], region, "protected_by")
                    for group in row.get("SecurityGroups", [])
                    if group.get("GroupId")
                )
                refs.extend(
                    ResourceReference(
                        "network_interface", interface["NetworkInterfaceId"], region, "uses"
                    )
                    for interface in row.get("NetworkInterfaces", [])
                    if interface.get("NetworkInterfaceId")
                )
                refs.extend(
                    ResourceReference(
                        "ebs_volume", mapping["Ebs"]["VolumeId"], region, "attached_volume"
                    )
                    for mapping in row.get("BlockDeviceMappings", [])
                    if mapping.get("Ebs", {}).get("VolumeId")
                )
                attrs = {
                    "instance_type": row.get("InstanceType"),
                    "state": row.get("State", {}).get("Name"),
                    "image_id": row.get("ImageId"),
                    "launch_time": _iso(row.get("LaunchTime")),
                    "private_ip": row.get("PrivateIpAddress"),
                    "public_ip": row.get("PublicIpAddress"),
                    "vpc_id": row.get("VpcId"),
                    "subnet_id": row.get("SubnetId"),
                }
                resources.append(
                    normalize_aws_resource(
                        "ec2_instance",
                        row["InstanceId"],
                        row["InstanceId"],
                        region,
                        row.get("Tags", []),
                        attributes={
                            key: value for key, value in attrs.items() if value is not None
                        },
                        arn=_ec2_arn(
                            self.partition, region, self.account_id, "instance", row["InstanceId"]
                        ),
                        relationships=tuple(refs),
                    )
                )
        return resources

    def _collect_ebs_volume(self, region: str) -> list[NormalizedAsset]:
        client = self._client("ec2", region)
        resources: list[NormalizedAsset] = []
        for row in self._pages(client, "describe_volumes", "Volumes"):
            refs = tuple(
                ResourceReference("ec2_instance", attachment["InstanceId"], region, "attached_to")
                for attachment in row.get("Attachments", [])
                if attachment.get("InstanceId")
            )
            resources.append(
                normalize_aws_resource(
                    "ebs_volume",
                    row["VolumeId"],
                    row["VolumeId"],
                    region,
                    row.get("Tags", []),
                    attributes={
                        key: row[key]
                        for key in (
                            "State",
                            "Size",
                            "VolumeType",
                            "Encrypted",
                            "KmsKeyId",
                            "SnapshotId",
                        )
                        if key in row
                    },
                    arn=_ec2_arn(
                        self.partition, region, self.account_id, "volume", row["VolumeId"]
                    ),
                    relationships=refs,
                )
            )
        return resources

    def _collect_rds_instance(self, region: str) -> list[NormalizedAsset]:
        client = self._client("rds", region)
        resources: list[NormalizedAsset] = []
        for row in self._pages(client, "describe_db_instances", "DBInstances"):
            refs = tuple(
                ResourceReference(
                    "security_group", group["VpcSecurityGroupId"], region, "protected_by"
                )
                for group in row.get("VpcSecurityGroups", [])
                if group.get("VpcSecurityGroupId")
            )
            attrs = {
                "engine": row.get("Engine"),
                "engine_version": row.get("EngineVersion"),
                "status": row.get("DBInstanceStatus"),
                "instance_class": row.get("DBInstanceClass"),
                "storage_encrypted": row.get("StorageEncrypted"),
                "kms_key_id": row.get("KmsKeyId"),
                "publicly_accessible": row.get("PubliclyAccessible"),
                "multi_az": row.get("MultiAZ"),
                "endpoint_address": row.get("Endpoint", {}).get("Address"),
                "endpoint_port": row.get("Endpoint", {}).get("Port"),
                "vpc_id": row.get("DBSubnetGroup", {}).get("VpcId"),
            }
            if attrs.get("vpc_id"):
                refs += (ResourceReference("vpc", str(attrs["vpc_id"]), region, "runs_in"),)
            resources.append(
                normalize_aws_resource(
                    "rds_instance",
                    row["DBInstanceIdentifier"],
                    row.get("DBInstanceIdentifier"),
                    region,
                    row.get("TagList", []),
                    attributes={key: value for key, value in attrs.items() if value is not None},
                    arn=row.get("DBInstanceArn"),
                    relationships=refs,
                )
            )
        return resources

    def _collect_lambda_function(self, region: str) -> list[NormalizedAsset]:
        client = self._client("lambda", region)
        resources: list[NormalizedAsset] = []
        for row in self._pages(client, "list_functions", "Functions"):
            vpc = row.get("VpcConfig", {})
            refs: list[ResourceReference] = []
            if vpc.get("VpcId"):
                refs.append(ResourceReference("vpc", vpc["VpcId"], region, "runs_in"))
            refs.extend(
                ResourceReference("subnet", subnet, region, "runs_in")
                for subnet in vpc.get("SubnetIds", [])
            )
            refs.extend(
                ResourceReference("security_group", group, region, "protected_by")
                for group in vpc.get("SecurityGroupIds", [])
            )
            attrs = {
                "runtime": row.get("Runtime"),
                "handler": row.get("Handler"),
                "role_arn": row.get("Role"),
                "timeout": row.get("Timeout"),
                "memory_size": row.get("MemorySize"),
                "package_type": row.get("PackageType"),
                "code_sha256": row.get("CodeSha256"),
                "last_modified": row.get("LastModified"),
                "architectures": row.get("Architectures", []),
            }
            resources.append(
                normalize_aws_resource(
                    "lambda_function",
                    row["FunctionName"],
                    row.get("FunctionName"),
                    region,
                    row.get("Tags", {}),
                    attributes={key: value for key, value in attrs.items() if value is not None},
                    arn=row.get("FunctionArn"),
                    relationships=tuple(refs),
                )
            )
        return resources

    def _collect_s3_bucket(self, region: str) -> list[NormalizedAsset]:
        client = self._client("s3", region)
        control_client = self._client("s3control", region)
        try:
            account_block = control_client.get_public_access_block(AccountId=self.account_id)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as error:
            if (
                error.response.get("Error", {}).get("Code")
                != "NoSuchPublicAccessBlockConfiguration"
            ):
                raise
            account_block = {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        resources: list[NormalizedAsset] = []
        for row in self._pages(client, "list_buckets", "Buckets"):
            bucket = row["Name"]
            location = (
                client.get_bucket_location(Bucket=bucket).get("LocationConstraint") or "us-east-1"
            )
            if location == "EU":
                location = "eu-west-1"
            if self.allowed_regions is not None and location not in self.allowed_regions:
                continue
            try:
                bucket_block = client.get_public_access_block(Bucket=bucket)[
                    "PublicAccessBlockConfiguration"
                ]
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") != (
                    "NoSuchPublicAccessBlockConfiguration"
                ):
                    raise
                bucket_block = {}
            try:
                policy_public = bool(
                    client.get_bucket_policy_status(Bucket=bucket)
                    .get("PolicyStatus", {})
                    .get("IsPublic", False)
                )
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
                    policy_public = False
                else:
                    raise
            acl = client.get_bucket_acl(Bucket=bucket)
            public_acl = any(
                str(grant.get("Grantee", {}).get("URI", "")).endswith(
                    ("/AllUsers", "/AuthenticatedUsers")
                )
                for grant in acl.get("Grants", [])
            )
            try:
                encryption = client.get_bucket_encryption(Bucket=bucket).get(
                    "ServerSideEncryptionConfiguration", {}
                )
                encryption_enabled = bool(encryption.get("Rules"))
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") != (
                    "ServerSideEncryptionConfigurationNotFoundError"
                ):
                    raise
                encryption_enabled = False
            versioning_enabled = (
                client.get_bucket_versioning(Bucket=bucket).get("Status") == "Enabled"
            )
            logging_enabled = bool(client.get_bucket_logging(Bucket=bucket).get("LoggingEnabled"))
            public_block = {
                "block_public_acls": bool(
                    bucket_block.get("BlockPublicAcls", False) or account_block["BlockPublicAcls"]
                ),
                "ignore_public_acls": bool(
                    bucket_block.get("IgnorePublicAcls", False) or account_block["IgnorePublicAcls"]
                ),
                "block_public_policy": bool(
                    bucket_block.get("BlockPublicPolicy", False)
                    or account_block["BlockPublicPolicy"]
                ),
                "restrict_public_buckets": bool(
                    bucket_block.get("RestrictPublicBuckets", False)
                    or account_block["RestrictPublicBuckets"]
                ),
            }
            tags: list[dict[str, str]] = []
            try:
                tags = client.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") not in {
                    "NoSuchTagSet",
                    "NotImplemented",
                }:
                    raise
            resources.append(
                normalize_aws_resource(
                    "s3_bucket",
                    bucket,
                    bucket,
                    location,
                    tags,
                    attributes={
                        "creation_date": _iso(row.get("CreationDate")),
                        "bucket_policy_public": policy_public,
                        "public_acl": public_acl,
                        "public_access_block": public_block,
                        "encryption_enabled": encryption_enabled,
                        "versioning_enabled": versioning_enabled,
                        "logging_enabled": logging_enabled,
                    },
                    arn=f"arn:{self.partition}:s3:::{bucket}",
                )
            )
        return resources

    def _collect_iam_user(self, region: str) -> list[NormalizedAsset]:
        client = self._client("iam", region)
        return [
            normalize_aws_resource(
                "iam_user",
                row["UserId"],
                row.get("UserName"),
                "global",
                attributes={
                    key: value
                    for key, value in {
                        "path": row.get("Path"),
                        "created_at": _iso(row.get("CreateDate")),
                    }.items()
                    if value is not None
                },
                arn=row.get("Arn"),
            )
            for row in self._pages(client, "list_users", "Users")
        ]

    def _collect_iam_role(self, region: str) -> list[NormalizedAsset]:
        client = self._client("iam", region)
        return [
            normalize_aws_resource(
                "iam_role",
                row["RoleId"],
                row.get("RoleName"),
                "global",
                row.get("Tags", []),
                attributes={
                    key: value
                    for key, value in {
                        "path": row.get("Path"),
                        "description": row.get("Description"),
                        "max_session_duration": row.get("MaxSessionDuration"),
                        "created_at": _iso(row.get("CreateDate")),
                    }.items()
                    if value is not None
                },
                arn=row.get("Arn"),
            )
            for row in self._pages(client, "list_roles", "Roles")
        ]

    def _collect_iam_policy(self, region: str) -> list[NormalizedAsset]:
        client = self._client("iam", region)
        return [
            normalize_aws_resource(
                "iam_policy",
                row["PolicyId"],
                row.get("PolicyName"),
                "global",
                attributes={
                    key: row[key]
                    for key in (
                        "Path",
                        "Description",
                        "DefaultVersionId",
                        "AttachmentCount",
                        "IsAttachable",
                    )
                    if key in row
                },
                arn=row.get("Arn"),
            )
            for row in self._pages(client, "list_policies", "Policies", Scope="Local")
        ]

    def _collect_cloudtrail(self, region: str) -> list[NormalizedAsset]:
        client = self._client("cloudtrail", region)
        response = client.describe_trails(includeShadowTrails=False)
        resources: list[NormalizedAsset] = []
        for row in response.get("trailList", []):
            trail_arn = row.get("TrailARN") or row["Name"]
            status = client.get_trail_status(Name=trail_arn)
            attributes = {
                key: row[key]
                for key in (
                    "IsMultiRegionTrail",
                    "IsOrganizationTrail",
                    "LogFileValidationEnabled",
                )
                if key in row
            }
            attributes["is_logging"] = bool(status.get("IsLogging", False))
            resources.append(
                normalize_aws_resource(
                    "cloudtrail",
                    trail_arn,
                    row.get("Name"),
                    row.get("HomeRegion") or region,
                    attributes=attributes,
                    arn=row.get("TrailARN"),
                )
            )
        return resources

    def _collect_cloudwatch_alarm(self, region: str) -> list[NormalizedAsset]:
        client = self._client("cloudwatch", region)
        resources: list[NormalizedAsset] = []
        for row in self._pages(client, "describe_alarms", "MetricAlarms"):
            arn = row.get("AlarmArn")
            resources.append(
                normalize_aws_resource(
                    "cloudwatch_alarm",
                    arn or row["AlarmName"],
                    row.get("AlarmName"),
                    region,
                    attributes={
                        key: row[key]
                        for key in (
                            "Namespace",
                            "MetricName",
                            "StateValue",
                            "ActionsEnabled",
                            "TreatMissingData",
                        )
                        if key in row
                    },
                    arn=arn,
                )
            )
        return resources

    def _collect_kms_key(self, region: str) -> list[NormalizedAsset]:
        client = self._client("kms", region)
        resources: list[NormalizedAsset] = []
        for row in self._pages(client, "list_keys", "Keys"):
            key_id = row["KeyId"]
            detail = client.describe_key(KeyId=key_id).get("KeyMetadata", {})
            attributes: dict[str, Any] = {
                key: detail[key]
                for key in (
                    "KeyState",
                    "KeyManager",
                    "KeySpec",
                    "KeyUsage",
                    "Enabled",
                    "MultiRegion",
                )
                if key in detail
            }
            if (
                detail.get("KeyManager") == "CUSTOMER"
                and detail.get("KeySpec") == "SYMMETRIC_DEFAULT"
            ):
                attributes["key_rotation_enabled"] = bool(
                    client.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
                )
            resources.append(
                normalize_aws_resource(
                    "kms_key",
                    key_id,
                    detail.get("Description") or key_id,
                    region,
                    attributes=attributes,
                    arn=detail.get("Arn") or row.get("KeyArn"),
                )
            )
        return resources

    def _collect_ecr_repository(self, region: str) -> list[NormalizedAsset]:
        client = self._client("ecr", region)
        return [
            normalize_aws_resource(
                "ecr_repository",
                row["repositoryName"],
                row.get("repositoryName"),
                region,
                attributes={
                    "repository_uri": row.get("repositoryUri"),
                    "image_tag_mutability": row.get("imageTagMutability"),
                    "image_scanning_on_push": row.get("imageScanningConfiguration", {}).get(
                        "scanOnPush"
                    ),
                    "encryption_type": row.get("encryptionConfiguration", {}).get("encryptionType"),
                },
                arn=row.get("repositoryArn"),
            )
            for row in self._pages(client, "describe_repositories", "repositories")
        ]

    def _collect_ecs_cluster(self, region: str) -> list[NormalizedAsset]:
        client = self._client("ecs", region)
        resources: list[NormalizedAsset] = []
        for arn in self._pages(client, "list_clusters", "clusterArns"):
            rows = client.describe_clusters(clusters=[arn], include=["TAGS"]).get("clusters", [])
            for row in rows:
                resources.append(
                    normalize_aws_resource(
                        "ecs_cluster",
                        row["clusterArn"],
                        row.get("clusterName"),
                        region,
                        row.get("tags", []),
                        attributes={
                            key: row[key]
                            for key in (
                                "status",
                                "runningTasksCount",
                                "pendingTasksCount",
                                "activeServicesCount",
                            )
                            if key in row
                        },
                        arn=row.get("clusterArn"),
                    )
                )
        return resources

    def _collect_ecs_service(self, region: str) -> list[NormalizedAsset]:
        client = self._client("ecs", region)
        resources: list[NormalizedAsset] = []
        cluster_arns = list(self._pages(client, "list_clusters", "clusterArns"))
        for cluster_arn in cluster_arns:
            service_arns = list(
                self._pages(client, "list_services", "serviceArns", cluster=cluster_arn)
            )
            for offset in range(0, len(service_arns), 10):
                for row in client.describe_services(
                    cluster=cluster_arn,
                    services=service_arns[offset : offset + 10],
                    include=["TAGS"],
                ).get("services", []):
                    resources.append(
                        normalize_aws_resource(
                            "ecs_service",
                            row["serviceArn"],
                            row.get("serviceName"),
                            region,
                            row.get("tags", []),
                            attributes={
                                key: row[key]
                                for key in ("status", "desiredCount", "runningCount", "launchType")
                                if key in row
                            },
                            arn=row.get("serviceArn"),
                            relationships=(
                                ResourceReference("ecs_cluster", cluster_arn, region, "runs_on"),
                            ),
                        )
                    )
        return resources

    def _collect_eks_cluster(self, region: str) -> list[NormalizedAsset]:
        client = self._client("eks", region)
        resources: list[NormalizedAsset] = []
        for name in self._pages(client, "list_clusters", "clusters"):
            row = client.describe_cluster(name=name)["cluster"]
            network = row.get("resourcesVpcConfig", {})
            refs: list[ResourceReference] = []
            if network.get("vpcId"):
                refs.append(ResourceReference("vpc", network["vpcId"], region, "runs_in"))
            refs.extend(
                ResourceReference("subnet", subnet, region, "runs_in")
                for subnet in network.get("subnetIds", [])
            )
            refs.extend(
                ResourceReference("security_group", group, region, "protected_by")
                for group in network.get("securityGroupIds", [])
            )
            resources.append(
                normalize_aws_resource(
                    "eks_cluster",
                    row["name"],
                    row.get("name"),
                    region,
                    row.get("tags", {}),
                    attributes={
                        "version": row.get("version"),
                        "status": row.get("status"),
                        "endpoint_public_access": network.get("endpointPublicAccess"),
                        "endpoint_private_access": network.get("endpointPrivateAccess"),
                        "logging": row.get("logging", {}).get("clusterLogging"),
                    },
                    arn=row.get("arn"),
                    relationships=tuple(refs),
                )
            )
        return resources


def _iso(value: Any) -> str | None:
    return value.isoformat() if isinstance(value, (datetime, date)) else None


def _ec2_arn(partition: str, region: str, account_id: str, kind: str, resource_id: str) -> str:
    return f"arn:{partition}:ec2:{region}:{account_id}:{kind}/{resource_id}"


def _safe_error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code")
        if isinstance(code, str) and code.replace("_", "").replace("-", "").isalnum():
            return code[:80]
    return type(error).__name__[:80]
