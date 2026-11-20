"""Create a clearly synthetic, development-only tenant dataset for UI exploration."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.core.models import (
    Alert,
    AlertRule,
    Asset,
    AssetRelationship,
    AuditEvent,
    CloudAccount,
    CloudRegion,
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    CustomerScanFinding,
    CustomerScanJob,
    Finding,
    FindingComplianceControl,
    FindingEvent,
    FindingEvidence,
    Membership,
    Notification,
    Organization,
    RemediationRequest,
    Report,
    RiskScore,
    Role,
    ScanJob,
    Team,
    TeamMembership,
    User,
    UserInvitation,
)
from app.scan_jobs.mock_inventory import mock_inventory

DEMO_ACCOUNT_ID = "000000000000"
DEMO_MARKER = "CloudSentinel synthetic demo data; not collected from AWS."


def seed_demo_data(session: Session, *, organization_slug: str, admin_email: str) -> bool:
    """Populate UI-facing tables for an existing org; return False if already seeded.

    The caller must use a development-only session with the target tenant context.
    Refresh sessions and tokens are never fabricated. The invitation row is a
    random-digest-only, expired, revoked example that cannot be accepted.
    """
    organization = session.scalar(
        select(Organization).where(Organization.slug == organization_slug)
    )
    user = session.scalar(select(User).where(User.email == admin_email.strip().lower()))
    if organization is None or user is None:
        raise ValueError("The organization and administrator must already exist.")
    if session.info.get("tenant_id") != organization.id:
        raise ValueError("The database session is not scoped to the requested organization.")
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == organization.id,
            Membership.user_id == user.id,
            Membership.is_active.is_(True),
        )
    )
    if membership is None:
        raise ValueError("The administrator must have an active membership in the organization.")
    role = session.get(Role, membership.role_id)
    if role is None or role.code not in {"SUPER_ADMIN", "ORG_ADMIN"}:
        raise ValueError("Demo data seeding requires an organization administrator.")

    existing = session.scalar(
        select(CloudAccount).where(CloudAccount.account_id == DEMO_ACCOUNT_ID)
    )
    if existing is not None:
        if existing.name != "DEMO ONLY — Synthetic AWS Account":
            raise ValueError("The reserved synthetic demo account ID is already in use.")
        pass_added = seed_demo_compliance_pass(session, organization.id)
        invitation_added = _ensure_revoked_demo_invitation(
            session, organization.id, user.id, membership.role_id
        )
        relationship_count = seed_mock_asset_relationships(session, organization.id)
        return pass_added or invitation_added or relationship_count > 0

    existing_assets = list(
        session.scalars(select(Asset).where(Asset.organization_id == organization.id)).all()
    )
    if any(
        asset.attributes.get("cloudsentinel_data_origin") == "local_mock"
        for asset in existing_assets
    ):
        return seed_mock_asset_relationships(session, organization.id) > 0

    now = datetime.now(UTC)
    account = CloudAccount(
        organization_id=organization.id,
        name="DEMO ONLY — Synthetic AWS Account",
        environment="Development",
        account_id=DEMO_ACCOUNT_ID,
        role_arn="arn:aws:iam::000000000000:role/CloudSentinelDemoOnly",
        external_id="DEMO-ONLY-NOT-AWS-CREDENTIAL",
        connection_status="pending",
        primary_region="us-east-1",
        created_by_user_id=user.id,
    )
    session.add(account)
    session.flush()
    session.add_all(
        [
            CloudRegion(
                organization_id=organization.id,
                cloud_account_id=account.id,
                region_code=region,
                is_enabled=True,
            )
            for region in ("us-east-1", "us-west-2")
        ]
    )

    membership_id = membership.id
    scan = ScanJob(
        organization_id=organization.id,
        cloud_account_id=account.id,
        requested_by_user_id=user.id,
        requested_by_membership_id=membership_id,
        status="completed",
        requested_regions=["us-east-1", "us-west-2"],
        requested_resource_types=["ec2_instance", "security_group", "ebs_volume", "s3_bucket"],
        progress_total=4,
        progress_completed=4,
        resources_discovered=4,
        errors_count=0,
        error_codes=[],
        started_at=now - timedelta(minutes=8),
        finished_at=now - timedelta(minutes=3),
    )
    session.add(scan)
    session.flush()

    assets = [
        Asset(
            organization_id=organization.id,
            cloud_account_id=account.id,
            last_scan_job_id=scan.id,
            resource_type="ec2_instance",
            resource_id="i-demo-app-01",
            resource_arn="arn:aws:ec2:us-east-1:000000000000:instance/i-demo-app-01",
            region_code="us-east-1",
            name="DEMO — production-api-01",
            tags={"Environment": "demo", "Service": "api"},
            owner_metadata={"team": "Platform (demo)"},
            attributes={"State": "running", "InstanceType": "t3.large", "DemoData": True},
        ),
        Asset(
            organization_id=organization.id,
            cloud_account_id=account.id,
            last_scan_job_id=scan.id,
            resource_type="security_group",
            resource_id="sg-demo-public-ssh",
            resource_arn="arn:aws:ec2:us-east-1:000000000000:security-group/sg-demo-public-ssh",
            region_code="us-east-1",
            name="DEMO — public-ssh-example",
            tags={"Environment": "demo"},
            attributes={
                "IpPermissions": [
                    {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": ["0.0.0.0/0"]}
                ],
                "DemoData": True,
            },
        ),
        Asset(
            organization_id=organization.id,
            cloud_account_id=account.id,
            last_scan_job_id=scan.id,
            resource_type="ebs_volume",
            resource_id="vol-demo-unencrypted",
            resource_arn="arn:aws:ec2:us-east-1:000000000000:volume/vol-demo-unencrypted",
            region_code="us-east-1",
            name="DEMO — example-data-volume",
            tags={"Environment": "demo"},
            attributes={"Encrypted": False, "Size": 120, "DemoData": True},
        ),
        Asset(
            organization_id=organization.id,
            cloud_account_id=account.id,
            last_scan_job_id=scan.id,
            resource_type="s3_bucket",
            resource_id="cloudsentinel-demo-private-bucket",
            resource_arn="arn:aws:s3:::cloudsentinel-demo-private-bucket",
            region_code="us-east-1",
            name="DEMO — private-artifacts",
            tags={"Environment": "demo"},
            attributes={"PublicAccessBlock": True, "DemoData": True},
        ),
    ]
    session.add_all(assets)
    session.flush()
    app_asset, security_group, volume, _bucket = assets
    session.add(
        AssetRelationship(
            organization_id=organization.id,
            source_asset_id=app_asset.id,
            target_asset_id=security_group.id,
            relationship_type="attached_security_group",
        )
    )

    examples = [
        (
            security_group,
            "AWS-SG-001",
            "CRITICAL",
            "SSH exposed to the public internet",
            "Network Security",
            "Restrict inbound SSH to approved administrative networks.",
        ),
        (
            volume,
            "AWS-EBS-001",
            "HIGH",
            "EBS volume is not encrypted",
            "Encryption Security",
            "Migrate data to an encrypted EBS volume using an approved change process.",
        ),
    ]
    findings: list[Finding] = []
    for asset, rule_id, severity, title, category, remediation in examples:
        finding = Finding(
            organization_id=organization.id,
            cloud_account_id=account.id,
            asset_id=asset.id,
            scan_job_id=scan.id,
            rule_id=rule_id,
            rule_version="1.0.0",
            category=category,
            title=f"DEMO — {title}",
            description=f"{DEMO_MARKER} {title}.",
            remediation=remediation,
            severity=severity,
            region_code=asset.region_code,
            status="OPEN",
            first_seen_at=now - timedelta(days=1),
            last_seen_at=now,
        )
        findings.append(finding)
    session.add_all(findings)
    session.flush()

    team = Team(
        organization_id=organization.id,
        name="Demo Security Operations",
        description=DEMO_MARKER,
    )
    session.add(team)
    session.flush()
    session.add(TeamMembership(organization_id=organization.id, team_id=team.id, user_id=user.id))
    _ensure_revoked_demo_invitation(session, organization.id, user.id, membership.role_id)

    control = session.scalar(
        select(ComplianceControl).where(ComplianceControl.control_code == "4.1")
    )
    if control is not None:
        session.add(
            FindingComplianceControl(
                organization_id=organization.id,
                finding_id=findings[0].id,
                control_id=control.id,
            )
        )
        session.add(
            ComplianceAssessment(
                organization_id=organization.id,
                scan_job_id=scan.id,
                asset_id=security_group.id,
                control_id=control.id,
                status="FAIL",
                checked_at=now,
            )
        )
    seed_demo_compliance_pass(session, organization.id)

    for finding, asset, score, level, factors in (
        (
            findings[0],
            security_group,
            88,
            "CRITICAL",
            {
                "severity": 100,
                "exploitability": 95,
                "exposure": 100,
                "asset_criticality": 60,
                "business_impact": 80,
                "compliance_impact": 70,
            },
        ),
        (
            findings[1],
            volume,
            60,
            "HIGH",
            {
                "severity": 80,
                "exploitability": 40,
                "exposure": 35,
                "asset_criticality": 60,
                "business_impact": 65,
                "compliance_impact": 75,
            },
        ),
    ):
        session.add(
            RiskScore(
                organization_id=organization.id,
                finding_id=finding.id,
                score=score,
                level=level,
                factors=factors,
                calculated_at=now,
            )
        )
        session.add(
            FindingEvent(
                organization_id=organization.id,
                finding_id=finding.id,
                actor_user_id=user.id,
                action="DEMO_SEEDED",
                from_status=None,
                to_status="OPEN",
                reason=DEMO_MARKER,
                details={"synthetic": True},
            )
        )
        session.add(
            FindingEvidence(
                organization_id=organization.id,
                finding_id=finding.id,
                asset_id=asset.id,
                scan_job_id=scan.id,
                rule_version="1.0.0",
                scanner_version="demo-fixture",
                detected_condition={"synthetic": True, "rule_id": finding.rule_id},
                configuration=asset.attributes,
                collected_at=now,
            )
        )

    report_id = uuid4()
    session.add_all(
        [
            RemediationRequest(
                organization_id=organization.id,
                finding_id=findings[0].id,
                requested_by_user_id=user.id,
                status="PENDING_APPROVAL",
                request_note=f"{DEMO_MARKER} Review restricting public SSH.",
                requested_at=now,
            ),
            Report(
                id=report_id,
                organization_id=organization.id,
                report_series_id=report_id,
                name="Demo security posture",
                report_type="security_posture",
                status="COMPLETED",
                file_format="JSON",
                created_by_user_id=user.id,
                filters={"demo": True},
                snapshot={
                    "generated_at": now.isoformat(),
                    "notice": DEMO_MARKER,
                    "assets": len(assets),
                    "open_findings": len(findings),
                    "critical_findings": 1,
                },
                data_snapshot_at=now,
                generated_at=now,
                created_at=now,
                updated_at=now,
            ),
            Notification(
                organization_id=organization.id,
                recipient_user_id=user.id,
                category="finding",
                title="DEMO — Critical finding needs review",
                message=DEMO_MARKER,
                resource_type="finding",
                resource_id=str(findings[0].id),
            ),
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                action="demo_dataset_seeded",
                resource_type="demo_dataset",
                resource_id=str(account.id),
                details={"synthetic": True, "notice": DEMO_MARKER},
                created_at=now,
            ),
        ]
    )
    session.flush()
    return True


def seed_demo_compliance_pass(session: Session, organization_id: UUID) -> bool:
    """Record one clearly labeled demo PASS for the RDP ingress control."""
    source = session.execute(
        select(ComplianceFramework, ComplianceControl, ComplianceAssessment, Asset)
        .join(ComplianceControl, ComplianceControl.framework_id == ComplianceFramework.id)
        .join(ComplianceAssessment, ComplianceAssessment.control_id == ComplianceControl.id)
        .join(Asset, Asset.id == ComplianceAssessment.asset_id)
        .where(
            ComplianceFramework.code == "CIS_AWS_FOUNDATIONS",
            ComplianceControl.control_code == "4.1",
            ComplianceAssessment.organization_id == organization_id,
            ComplianceAssessment.status == "FAIL",
            Asset.resource_type == "security_group",
        )
        .order_by(ComplianceAssessment.checked_at.desc())
    ).first()
    if source is None:
        return False
    framework, _ssh_control, source_assessment, asset = source

    control = session.scalar(
        select(ComplianceControl).where(
            ComplianceControl.framework_id == framework.id,
            ComplianceControl.control_code == "4.2",
        )
    )
    if control is None:
        control = ComplianceControl(
            framework_id=framework.id,
            control_code="4.2",
            title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
            description=(
                f"{DEMO_MARKER} This sample evaluates the recorded security group configuration "
                "for public RDP ingress. No public rule grants port 3389."
            ),
            domain="Network Security",
            category="Network Security",
            severity="HIGH",
            control_version="1.0",
            guidance={"source": "synthetic_demo_assessment"},
        )
        session.add(control)
        session.flush()

    existing_assessment = session.scalar(
        select(ComplianceAssessment).where(
            ComplianceAssessment.organization_id == organization_id,
            ComplianceAssessment.scan_job_id == source_assessment.scan_job_id,
            ComplianceAssessment.asset_id == asset.id,
            ComplianceAssessment.control_id == control.id,
        )
    )
    if existing_assessment is not None:
        return False
    session.add(
        ComplianceAssessment(
            organization_id=organization_id,
            scan_job_id=source_assessment.scan_job_id,
            asset_id=asset.id,
            control_id=control.id,
            status="PASS",
            checked_at=source_assessment.checked_at,
            observed={
                "public_rdp_ingress": False,
                "configuration_source": asset.attributes.get(
                    "cloudsentinel_data_origin", "local_mock"
                ),
                "notice": DEMO_MARKER,
            },
            expected={"public_rdp_ingress": False, "port": 3389},
            policy_version="demo-1.0",
        )
    )
    return True


def seed_mock_asset_relationships(session: Session, organization_id: UUID) -> int:
    """Backfill deterministic edges between existing local mock inventory assets."""
    rows = session.execute(
        select(Asset, CloudAccount)
        .join(
            CloudAccount,
            (CloudAccount.id == Asset.cloud_account_id)
            & (CloudAccount.organization_id == Asset.organization_id),
        )
        .where(Asset.organization_id == organization_id)
    ).all()
    assets_by_identity = {
        (account.id, asset.resource_type, asset.region_code, asset.resource_id): asset
        for asset, account in rows
        if asset.attributes.get("cloudsentinel_data_origin") == "local_mock"
    }
    existing = {
        (row[0], row[1], row[2])
        for row in session.execute(
            select(
                AssetRelationship.source_asset_id,
                AssetRelationship.target_asset_id,
                AssetRelationship.relationship_type,
            ).where(AssetRelationship.organization_id == organization_id)
        ).all()
    }

    added = 0
    for asset, account in rows:
        if asset.attributes.get("cloudsentinel_data_origin") != "local_mock":
            continue
        mock_resources = mock_inventory(
            asset.resource_type,
            asset.region_code,
            account_id=account.account_id,
            environment=account.environment,
        )
        if not mock_resources or mock_resources[0].resource_id != asset.resource_id:
            continue
        for reference in mock_resources[0].relationships:
            target = assets_by_identity.get(
                (account.id, reference.resource_type, reference.region_code, reference.resource_id)
            )
            if target is None:
                continue
            identity = (asset.id, target.id, reference.relationship_type)
            if identity in existing:
                continue
            session.add(
                AssetRelationship(
                    organization_id=organization_id,
                    source_asset_id=asset.id,
                    target_asset_id=target.id,
                    relationship_type=reference.relationship_type,
                )
            )
            existing.add(identity)
            added += 1
    session.flush()
    return added


def seed_demo_cloud_accounts(
    session: Session,
    organization_id: UUID,
    created_by_user_id: UUID,
    *,
    count: int = 25,
) -> int:
    """Create idempotent mock-connected demo AWS accounts and their region rows."""
    regions = ("us-east-1", "us-west-2", "eu-central-1")
    environments = ("Development", "Staging", "Production")
    added = 0
    for index in range(1, count + 1):
        account_id = f"999000000{index:03d}"
        account_name = f"DEMO ONLY — AWS Account {index:02d}"
        account = session.scalar(
            select(CloudAccount).where(
                CloudAccount.organization_id == organization_id,
                CloudAccount.account_id == account_id,
            )
        )
        if account is None:
            account = CloudAccount(
                organization_id=organization_id,
                name=account_name,
                environment=environments[(index - 1) % len(environments)],
                account_id=account_id,
                role_arn=f"arn:aws:iam::{account_id}:role/CloudSentinelDemoOnly",
                external_id=f"DEMO-ONLY-NOT-AWS-CREDENTIAL-{index:03d}",
                primary_region=regions[(index - 1) % len(regions)],
                connection_status="connected",
                validation_mode="mock",
                last_validated_at=datetime.now(UTC),
                created_by_user_id=created_by_user_id,
            )
            session.add(account)
            session.flush()
            added += 1
        elif account.name != account_name:
            raise ValueError(
                f"Demo account ID {account_id} is already assigned to another account."
            )
        else:
            account.connection_status = "connected"
            account.validation_mode = "mock"
            account.last_validated_at = account.last_validated_at or datetime.now(UTC)

        configured_regions = set(
            session.scalars(
                select(CloudRegion.region_code).where(
                    CloudRegion.organization_id == organization_id,
                    CloudRegion.cloud_account_id == account.id,
                )
            ).all()
        )
        for region_code in regions:
            if region_code not in configured_regions:
                session.add(
                    CloudRegion(
                        organization_id=organization_id,
                        cloud_account_id=account.id,
                        region_code=region_code,
                        is_enabled=True,
                    )
                )
    session.flush()
    return added


def ensure_demo_table_volume(
    session: Session,
    *,
    organization_slug: str,
    admin_email: str,
    minimum_rows: int = 100,
) -> dict[str, int]:
    """Top up development-only UI collections with explicitly labeled synthetic rows.

    Authentication artifacts are never created. Demo users are disabled with inactive
    memberships; cloud accounts are mock-connected and cannot contact AWS.
    """
    if minimum_rows not in {50, 100}:
        raise ValueError("Demo table volume must be either 50 or 100 rows.")
    organization = session.scalar(
        select(Organization).where(Organization.slug == organization_slug)
    )
    user = session.scalar(select(User).where(User.email == admin_email.strip().lower()))
    if organization is None or user is None:
        raise ValueError("The organization and administrator must already exist.")
    if session.info.get("tenant_id") != organization.id:
        raise ValueError("The database session is not scoped to the requested organization.")
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == organization.id,
            Membership.user_id == user.id,
            Membership.is_active.is_(True),
        )
    )
    if membership is None:
        raise ValueError("The administrator must have an active membership in the organization.")
    admin_role = session.get(Role, membership.role_id)
    if admin_role is None or admin_role.code not in {"SUPER_ADMIN", "ORG_ADMIN"}:
        raise ValueError("Demo data expansion requires an organization administrator.")

    added: dict[str, int] = {}
    added["cloud_accounts"] = seed_demo_cloud_accounts(
        session, organization.id, user.id, count=minimum_rows
    )
    demo_accounts = list(
        session.scalars(
            select(CloudAccount)
            .where(
                CloudAccount.organization_id == organization.id,
                CloudAccount.name.like("DEMO ONLY — AWS Account %"),
            )
            .order_by(CloudAccount.account_id)
        ).all()
    )
    if len(demo_accounts) < minimum_rows:
        raise ValueError("The synthetic account inventory could not reach the requested size.")

    generated_scans: dict[UUID, ScanJob] = {}
    scan_types = ["vpc", "security_group"]
    now = datetime.now(UTC)
    created_scan_count = 0
    for index, account in enumerate(demo_accounts[:minimum_rows], start=1):
        account.connection_status = "connected"
        account.validation_mode = "mock"
        account.last_validated_at = account.last_validated_at or now
        region = account.primary_region or "us-east-1"
        configured_regions = set(
            session.scalars(
                select(CloudRegion.region_code).where(
                    CloudRegion.organization_id == organization.id,
                    CloudRegion.cloud_account_id == account.id,
                )
            ).all()
        )
        if region not in configured_regions:
            session.add(
                CloudRegion(
                    organization_id=organization.id,
                    cloud_account_id=account.id,
                    region_code=region,
                    is_enabled=True,
                )
            )

        possible_scans = session.scalars(
            select(ScanJob)
            .where(
                ScanJob.organization_id == organization.id,
                ScanJob.cloud_account_id == account.id,
                ScanJob.status == "completed",
                ScanJob.resources_discovered == len(scan_types),
            )
            .order_by(ScanJob.created_at.desc())
        ).all()
        scan = next(
            (
                candidate
                for candidate in possible_scans
                if candidate.requested_resource_types == scan_types
            ),
            None,
        )
        if scan is None:
            scan = ScanJob(
                organization_id=organization.id,
                cloud_account_id=account.id,
                requested_by_user_id=user.id,
                requested_by_membership_id=membership.id,
                status="completed",
                requested_regions=[region],
                requested_resource_types=scan_types,
                progress_total=len(scan_types),
                progress_completed=len(scan_types),
                resources_discovered=len(scan_types),
                errors_count=0,
                error_codes=[],
                started_at=now - timedelta(minutes=12 + index % 23),
                finished_at=now - timedelta(minutes=5 + index % 7),
            )
            session.add(scan)
            session.flush()
            created_scan_count += 1
        generated_scans[account.id] = scan

    added["scan_jobs"] = created_scan_count
    assets_by_account_type: dict[tuple[UUID, str], Asset] = {}
    created_assets = 0
    for index, account in enumerate(demo_accounts[:minimum_rows], start=1):
        scan = generated_scans[account.id]
        region = account.primary_region or "us-east-1"
        for resource_type in scan_types:
            normalized = mock_inventory(
                resource_type,
                region,
                account_id=account.account_id,
                environment=account.environment,
            )[0]
            asset = session.scalar(
                select(Asset).where(
                    Asset.organization_id == organization.id,
                    Asset.cloud_account_id == account.id,
                    Asset.resource_type == normalized.resource_type,
                    Asset.region_code == normalized.region_code,
                    Asset.resource_id == normalized.resource_id,
                )
            )
            if asset is None:
                asset = Asset(
                    organization_id=organization.id,
                    cloud_account_id=account.id,
                    last_scan_job_id=scan.id,
                    provider="AWS",
                    resource_type=normalized.resource_type,
                    resource_id=normalized.resource_id,
                    resource_arn=normalized.resource_arn,
                    region_code=normalized.region_code,
                    name=f"DEMO ONLY — {normalized.name}"[:512],
                    tags=normalized.tags,
                    owner_metadata=normalized.owner_metadata,
                    attributes={**normalized.attributes, "cloudsentinel_data_origin": "local_mock"},
                    status="active",
                    first_seen_at=now - timedelta(days=30 + index % 45),
                    last_seen_at=now - timedelta(minutes=index % 60),
                )
                session.add(asset)
                session.flush()
                created_assets += 1
            assets_by_account_type[(account.id, resource_type)] = asset
    added["assets"] = created_assets

    relationship_count = seed_mock_asset_relationships(session, organization.id)
    added["asset_relationships"] = relationship_count

    control = session.scalar(
        select(ComplianceControl)
        .join(ComplianceFramework, ComplianceFramework.id == ComplianceControl.framework_id)
        .where(
            ComplianceFramework.code == "CIS_AWS_FOUNDATIONS",
            ComplianceControl.control_code == "4.1",
        )
    )
    alert_rule = session.scalar(
        select(AlertRule)
        .where(
            AlertRule.organization_id == organization.id,
            AlertRule.event_type == "CRITICAL_FINDING",
            AlertRule.severity == "CRITICAL",
            AlertRule.enabled.is_(True),
        )
        .order_by(AlertRule.code)
    )
    finding_statuses = ("OPEN", "ASSIGNED", "IN_PROGRESS", "RESOLVED", "VERIFIED")
    alert_statuses = ("OPEN", "ACKNOWLEDGED", "RESOLVED", "DISMISSED")
    remediation_statuses = (
        "PENDING_APPROVAL",
        "APPROVED",
        "REJECTED",
        "COMPLETED",
        "CANCELLED",
    )
    created_finding_count = 0
    for index, account in enumerate(demo_accounts[:minimum_rows], start=1):
        asset = assets_by_account_type[(account.id, "security_group")]
        scan = generated_scans[account.id]
        finding = session.scalar(
            select(Finding).where(
                Finding.organization_id == organization.id,
                Finding.asset_id == asset.id,
                Finding.rule_id == "AWS-SG-001",
            )
        )
        if finding is None:
            status = finding_statuses[(index - 1) % len(finding_statuses)]
            seen_at = now - timedelta(days=(index % 40) + 1)
            finding = Finding(
                organization_id=organization.id,
                cloud_account_id=account.id,
                asset_id=asset.id,
                scan_job_id=scan.id,
                rule_id="AWS-SG-001",
                rule_version="demo-1.0",
                category="Network Security",
                title="DEMO ONLY — SSH exposed to the public internet",
                description=(
                    f"{DEMO_MARKER} Inbound SSH is open to 0.0.0.0/0 in a synthetic mock "
                    "security group."
                ),
                remediation=(
                    "Restrict inbound SSH to approved administrative networks and validate "
                    "the change."
                ),
                severity="CRITICAL",
                region_code=asset.region_code,
                status=status,
                assigned_to_user_id=user.id if status in {"ASSIGNED", "IN_PROGRESS"} else None,
                due_at=now + timedelta(days=(index % 14) + 1),
                first_seen_at=seen_at,
                last_seen_at=now - timedelta(minutes=index % 120),
                resolved_at=seen_at + timedelta(days=1)
                if status in {"RESOLVED", "VERIFIED"}
                else None,
                verified_at=seen_at + timedelta(days=2) if status == "VERIFIED" else None,
                verified_by_user_id=user.id if status == "VERIFIED" else None,
            )
            session.add(finding)
            session.flush()
            created_finding_count += 1
            created_event = FindingEvent(
                organization_id=organization.id,
                finding_id=finding.id,
                actor_user_id=user.id,
                action="DEMO_SEEDED",
                from_status=None,
                to_status=status,
                reason=DEMO_MARKER,
                details={"synthetic": True},
            )
            evidence = FindingEvidence(
                organization_id=organization.id,
                finding_id=finding.id,
                asset_id=asset.id,
                scan_job_id=scan.id,
                rule_version="demo-1.0",
                scanner_version="demo-fixture-1.0",
                source="Synthetic demo inventory",
                expected_state={"public_ssh_ingress": False},
                detected_condition={"public_ssh_ingress": True, "notice": DEMO_MARKER},
                configuration=asset.attributes,
                collected_at=finding.last_seen_at,
            )
            session.add_all(
                [
                    created_event,
                    evidence,
                    RiskScore(
                        organization_id=organization.id,
                        finding_id=finding.id,
                        score=85 + index % 16,
                        level="CRITICAL",
                        factors={
                            "severity": 100,
                            "exploitability": 95,
                            "exposure": 100,
                            "asset_criticality": 60 + index % 25,
                            "business_impact": 80,
                            "compliance_impact": 70,
                        },
                        calculated_at=finding.last_seen_at,
                    ),
                ]
            )
            session.flush()
            if control is not None:
                existing_link = session.scalar(
                    select(FindingComplianceControl.finding_id).where(
                        FindingComplianceControl.organization_id == organization.id,
                        FindingComplianceControl.finding_id == finding.id,
                        FindingComplianceControl.control_id == control.id,
                    )
                )
                if existing_link is None:
                    session.add(
                        FindingComplianceControl(
                            organization_id=organization.id,
                            finding_id=finding.id,
                            control_id=control.id,
                        )
                    )
                existing_assessment = session.scalar(
                    select(ComplianceAssessment.id).where(
                        ComplianceAssessment.organization_id == organization.id,
                        ComplianceAssessment.scan_job_id == scan.id,
                        ComplianceAssessment.asset_id == asset.id,
                        ComplianceAssessment.control_id == control.id,
                    )
                )
                if existing_assessment is None:
                    session.add(
                        ComplianceAssessment(
                            organization_id=organization.id,
                            scan_job_id=scan.id,
                            asset_id=asset.id,
                            control_id=control.id,
                            status="FAIL",
                            checked_at=finding.last_seen_at,
                            observed={"public_ssh_ingress": True, "notice": DEMO_MARKER},
                            expected={"public_ssh_ingress": False, "port": 22},
                            evidence_id=evidence.id,
                            policy_version="demo-1.0",
                        )
                    )
            existing_alert = session.scalar(
                select(Alert.id).where(
                    Alert.organization_id == organization.id,
                    Alert.deduplication_key == f"demo-only:{organization.id}:finding:{finding.id}",
                )
            )
            if existing_alert is None:
                alert_status = alert_statuses[(index - 1) % len(alert_statuses)]
                status_at = finding.last_seen_at
                session.add(
                    Alert(
                        organization_id=organization.id,
                        alert_rule_id=alert_rule.id if alert_rule else None,
                        deduplication_key=f"demo-only:{organization.id}:finding:{finding.id}",
                        alert_type="CRITICAL_FINDING",
                        source_type="FINDING",
                        source_id=str(finding.id),
                        title="DEMO ONLY — Public SSH ingress detected",
                        description=(
                            f"{DEMO_MARKER} Review the mock security group and restrict "
                            "inbound SSH."
                        ),
                        severity="CRITICAL",
                        status=alert_status,
                        occurrence_count=1 + index % 4,
                        first_seen_at=finding.first_seen_at,
                        last_seen_at=status_at,
                        acknowledged_by_user_id=user.id if alert_status == "ACKNOWLEDGED" else None,
                        acknowledged_at=status_at if alert_status == "ACKNOWLEDGED" else None,
                        resolved_by_user_id=user.id if alert_status == "RESOLVED" else None,
                        resolved_at=status_at if alert_status == "RESOLVED" else None,
                        dismissed_by_user_id=user.id if alert_status == "DISMISSED" else None,
                        dismissed_at=status_at if alert_status == "DISMISSED" else None,
                        created_at=status_at,
                        updated_at=status_at,
                    )
                )
            existing_remediation = session.scalar(
                select(RemediationRequest.id).where(
                    RemediationRequest.organization_id == organization.id,
                    RemediationRequest.finding_id == finding.id,
                )
            )
            if existing_remediation is None:
                remediation_status = remediation_statuses[(index - 1) % len(remediation_statuses)]
                decided = remediation_status != "PENDING_APPROVAL"
                session.add(
                    RemediationRequest(
                        organization_id=organization.id,
                        finding_id=finding.id,
                        requested_by_user_id=user.id,
                        decided_by_user_id=user.id if decided else None,
                        status=remediation_status,
                        request_note=(
                            f"{DEMO_MARKER} Review the synthetic SSH restriction "
                            f"recommendation for account {account.account_id}."
                        ),
                        decision_note=f"{DEMO_MARKER} Example workflow state." if decided else None,
                        action_definition={
                            "type": "manual_security_group_rule_update",
                            "synthetic": True,
                        },
                        evidence_id=evidence.id,
                        verification_status=(
                            "PASSED"
                            if remediation_status == "COMPLETED"
                            else "PENDING"
                            if remediation_status == "APPROVED"
                            else "NOT_STARTED"
                        ),
                        requested_at=finding.last_seen_at,
                        decided_at=finding.last_seen_at if decided else None,
                    )
                )
            if index <= minimum_rows:
                session.add(
                    Notification(
                        organization_id=organization.id,
                        recipient_user_id=user.id,
                        category="finding",
                        title="DEMO ONLY — Critical finding needs review",
                        message=f"{DEMO_MARKER} Synthetic public SSH finding for {account.name}.",
                        resource_type="finding",
                        resource_id=str(finding.id),
                        read_at=finding.last_seen_at if index % 3 else None,
                        created_at=finding.last_seen_at,
                    )
                )
    session.flush()
    added["findings"] = created_finding_count

    added["reports"] = 0
    report_types = ("security_posture", "findings", "assets", "compliance", "risk")
    for index in range(1, minimum_rows + 1):
        report_id = uuid5(NAMESPACE_URL, f"cloudsentinel-demo:{organization.id}:report:{index}")
        if session.get(Report, report_id) is not None:
            continue
        generated_at = now - timedelta(days=index % 90, hours=index % 12)
        report_type = report_types[(index - 1) % len(report_types)]
        session.add(
            Report(
                id=report_id,
                organization_id=organization.id,
                name=(f"DEMO ONLY — {report_type.replace('_', ' ').title()} sample {index:03d}"),
                report_type=report_type,
                status="COMPLETED",
                file_format=("PDF", "CSV", "JSON")[(index - 1) % 3],
                report_version=1,
                generation_attempt_count=1,
                generator_version="demo-fixture-1.0",
                created_by_user_id=user.id,
                filters={"demo": True, "notice": DEMO_MARKER},
                snapshot={
                    "generated_at": generated_at.isoformat(),
                    "notice": DEMO_MARKER,
                    "synthetic": True,
                    "assets": minimum_rows * 2,
                    "open_findings": minimum_rows,
                    "critical_findings": minimum_rows,
                },
                data_snapshot_at=generated_at,
                generated_at=generated_at,
                retention_until=now + timedelta(days=90),
                report_series_id=report_id,
                file_size=4096 + index * 37,
                created_at=generated_at,
                updated_at=generated_at,
            )
        )
        added["reports"] += 1

    added["customer_scan_jobs"] = 0
    added["customer_scan_findings"] = 0
    scan_finding_templates = (
        ("DEMO-IAC-001", "S3 bucket encryption is not configured", "HIGH", "storage"),
        ("DEMO-IAC-002", "Security group allows broad ingress", "CRITICAL", "network"),
        ("DEMO-CONTAINER-001", "Container image runs as root", "MEDIUM", "container"),
    )
    for index in range(1, minimum_rows + 1):
        scan_id = uuid5(
            NAMESPACE_URL, f"cloudsentinel-demo:{organization.id}:customer-scan:{index}"
        )
        if session.get(CustomerScanJob, scan_id) is not None:
            continue
        scan_type = "container" if index % 3 == 0 else "iac"
        suffix = "tar" if scan_type == "container" else ("tf" if index % 2 else "zip")
        source_label = "container-image" if scan_type == "container" else "infrastructure"
        finished_at = now - timedelta(days=index % 25, hours=index % 10)
        job_findings = scan_finding_templates[: (index % len(scan_finding_templates)) + 1]
        is_failed = index % 13 == 0
        job = CustomerScanJob(
            id=scan_id,
            organization_id=organization.id,
            created_by_user_id=user.id,
            scan_type=scan_type,
            source_filename=f"DEMO ONLY — {source_label}-{index:03d}.{suffix}",
            artifact_key=f"demo-only/synthetic/{organization.id}/customer-scan/{index:03d}",
            status="failed" if is_failed else "completed",
            result={
                "notice": DEMO_MARKER,
                "synthetic": True,
                "summary": {"passed": 12 + index % 30, "failed": len(job_findings)},
            },
            finding_count=0 if is_failed else len(job_findings),
            scanner_version="demo-fixture-1.0",
            error_code="DEMO_SYNTHETIC_FAILURE" if is_failed else None,
            attempt_count=1,
            started_at=finished_at - timedelta(minutes=4 + index % 28),
            finished_at=finished_at,
            expires_at=now + timedelta(days=30),
            created_at=finished_at - timedelta(minutes=6 + index % 20),
            updated_at=finished_at,
        )
        session.add(job)
        session.flush()
        if not is_failed:
            for template_index, (rule_id, title, severity, category) in enumerate(job_findings):
                session.add(
                    CustomerScanFinding(
                        organization_id=organization.id,
                        scan_job_id=job.id,
                        rule_id=rule_id,
                        title=f"DEMO ONLY — {title}",
                        severity=severity,
                        category=category,
                        resource=f"demo/module-{index:03d}/resource-{template_index + 1}",
                        details={"notice": DEMO_MARKER, "synthetic": True},
                    )
                )
                added["customer_scan_findings"] += 1
        session.flush()
        added["customer_scan_jobs"] += 1

    viewer_role = session.scalar(select(Role).where(Role.code == "VIEWER"))
    if viewer_role is None:
        raise ValueError("The locked VIEWER role must exist before adding demo users.")
    inactive_users: list[User] = []
    added["users"] = 0
    for index in range(1, min(minimum_rows, 50) + 1):
        email = f"demo.user.{index:03d}@example.invalid"
        demo_user = session.scalar(select(User).where(User.email == email))
        if demo_user is None:
            demo_user = User(
                email=email,
                display_name=f"DEMO ONLY — Simulated Member {index:03d}",
                password_hash=hash_password(secrets.token_urlsafe(48)),
                is_active=False,
                force_password_change=True,
            )
            session.add(demo_user)
            session.flush()
            added["users"] += 1
        elif demo_user.is_active:
            raise ValueError(f"Reserved demo identity {email} is unexpectedly active.")
        demo_membership = session.scalar(
            select(Membership).where(
                Membership.organization_id == organization.id,
                Membership.user_id == demo_user.id,
            )
        )
        if demo_membership is None:
            demo_membership = Membership(
                organization_id=organization.id,
                user_id=demo_user.id,
                role_id=viewer_role.id,
                is_active=False,
                is_locked=False,
            )
            session.add(demo_membership)
            session.flush()
        elif demo_membership.is_active:
            raise ValueError(f"Reserved demo membership {email} is unexpectedly active.")
        inactive_users.append(demo_user)

    added["teams"] = 0
    for index in range(1, min(minimum_rows, 50) + 1):
        team_name = f"DEMO ONLY — Platform Team {index:03d}"
        team = session.scalar(
            select(Team).where(
                Team.organization_id == organization.id,
                Team.name == team_name,
            )
        )
        if team is None:
            team = Team(
                organization_id=organization.id,
                name=team_name,
                description=f"{DEMO_MARKER} Disabled sample members for table pagination.",
                is_active=True,
            )
            session.add(team)
            session.flush()
            added["teams"] += 1
        team_user = inactive_users[index - 1]
        existing_team_member = session.scalar(
            select(TeamMembership.id).where(
                TeamMembership.organization_id == organization.id,
                TeamMembership.team_id == team.id,
                TeamMembership.user_id == team_user.id,
            )
        )
        if existing_team_member is None:
            session.add(
                TeamMembership(
                    organization_id=organization.id,
                    team_id=team.id,
                    user_id=team_user.id,
                )
            )

    added["user_invitations"] = 0
    for index in range(1, min(minimum_rows, 50) + 1):
        email = f"demo.invitation.{index:03d}@example.invalid"
        if session.scalar(select(UserInvitation.id).where(UserInvitation.email == email)):
            continue
        revoked_at = now - timedelta(days=1 + index % 20)
        session.add(
            UserInvitation(
                organization_id=organization.id,
                email=email,
                display_name=f"DEMO ONLY — Revoked invitation {index:03d}",
                role_id=viewer_role.id,
                invited_by_user_id=user.id,
                token_digest=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
                expires_at=revoked_at - timedelta(hours=1),
                revoked_at=revoked_at,
            )
        )
        added["user_invitations"] += 1

    current_notifications = (
        session.scalar(
            select(func.count(Notification.id)).where(
                Notification.organization_id == organization.id
            )
        )
        or 0
    )
    added["notifications"] = 0
    if current_notifications < minimum_rows:
        for index in range(current_notifications + 1, minimum_rows + 1):
            session.add(
                Notification(
                    organization_id=organization.id,
                    recipient_user_id=user.id,
                    category="system",
                    title=f"DEMO ONLY — Sample activity notification {index:03d}",
                    message=DEMO_MARKER,
                    resource_type="demo_dataset",
                    resource_id=str(organization.id),
                    read_at=now - timedelta(hours=index) if index % 4 else None,
                    created_at=now - timedelta(hours=index),
                )
            )
            added["notifications"] += 1

    if any(value for key, value in added.items() if key != "scan_jobs"):
        session.add(
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                actor_name="CloudSentinel demo seeder",
                actor_role=admin_role.code,
                action="demo_dataset_expanded",
                resource_type="demo_dataset",
                resource_id=str(organization.id),
                details={"synthetic": True, "notice": DEMO_MARKER, "row_target": minimum_rows},
                retention_until=now + timedelta(days=365),
                created_at=now,
            )
        )
        added["audit_events"] = 1
    else:
        added["audit_events"] = 0
    session.flush()
    return added


def _ensure_revoked_demo_invitation(
    session: Session, organization_id: UUID, user_id: UUID, role_id: UUID
) -> bool:
    """Add one non-usable synthetic invitation so its table has demo content."""
    email = "demo-revoked-invitation@example.invalid"
    existing = session.scalar(select(UserInvitation).where(UserInvitation.email == email))
    if existing is not None:
        return False
    now = datetime.now(UTC)
    unusable_digest = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    session.add(
        UserInvitation(
            organization_id=organization_id,
            email=email,
            display_name="DEMO ONLY — revoked invitation",
            role_id=role_id,
            invited_by_user_id=user_id,
            token_digest=unusable_digest,
            expires_at=now - timedelta(days=1),
            revoked_at=now,
        )
    )
    return True


def get_demo_tenant_id(session: Session, organization_slug: str) -> UUID | None:
    """Resolve an organization using a trusted, unscoped operator session."""
    return session.scalar(select(Organization.id).where(Organization.slug == organization_slug))
