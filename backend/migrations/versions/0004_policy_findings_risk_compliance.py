"""Add policy findings, evidence, risk scores, and CIS control assessments."""

from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

import sqlalchemy as sa
from alembic import op

revision = "0004_policy_findings"
down_revision = "0003_scan_asset_inventory"
branch_labels = None
depends_on = None

FRAMEWORK_ID = uuid5(NAMESPACE_URL, "cloudsentinel:framework:CIS_AWS_FOUNDATIONS")
CONTROL_ID = uuid5(NAMESPACE_URL, "cloudsentinel:control:CIS_AWS_FOUNDATIONS:4.1")


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cloud_account_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("rule_version", sa.String(length=40), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=False),
        sa.Column("remediation", sa.String(length=2000), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("region_code", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("assigned_to_user_id", sa.Uuid(), nullable=True),
        sa.Column("suppression_reason", sa.String(length=1000), nullable=True),
        sa.Column("suppressed_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("suppression_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')",
            name=op.f("ck_findings_finding_severity"),
        ),
        sa.CheckConstraint(
            "status IN ('OPEN', 'TRIAGED', 'ASSIGNED', 'IN_PROGRESS', 'RESOLVED', "
            "'VERIFIED', 'CLOSED', 'SUPPRESSED')",
            name=op.f("ck_findings_finding_status"),
        ),
        sa.ForeignKeyConstraint(
            ["cloud_account_id"],
            ["cloud_accounts.id"],
            name=op.f("fk_findings_cloud_account_id_cloud_accounts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_findings_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"],
            ["scan_jobs.id"],
            name=op.f("fk_findings_scan_job_id_scan_jobs"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_to_user_id"],
            ["users.id"],
            name=op.f("fk_findings_assigned_to_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["suppressed_by_user_id"],
            ["users.id"],
            name=op.f("fk_findings_suppressed_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["verified_by_user_id"],
            ["users.id"],
            name=op.f("fk_findings_verified_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_findings_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "organization_id", "asset_id", "rule_id", name=op.f("uq_findings_organization_id")
        ),
    )
    op.create_index("ix_findings_org_account", "findings", ["organization_id", "cloud_account_id"])
    op.create_index("ix_findings_org_asset", "findings", ["organization_id", "asset_id"])
    op.create_index(
        "ix_findings_org_status_severity", "findings", ["organization_id", "status", "severity"]
    )

    op.create_table(
        "finding_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("from_status", sa.String(length=20), nullable=True),
        sa.Column("to_status", sa.String(length=20), nullable=True),
        sa.Column("reason", sa.String(length=1000), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_finding_events_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name=op.f("fk_finding_events_actor_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_finding_events_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_events")),
    )
    op.create_index(
        "ix_finding_events_org_finding", "finding_events", ["organization_id", "finding_id"]
    )

    op.create_table(
        "finding_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("rule_version", sa.String(length=40), nullable=False),
        sa.Column("scanner_version", sa.String(length=40), nullable=False),
        sa.Column("detected_condition", sa.JSON(), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column(
            "collected_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_finding_evidence_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_finding_evidence_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"],
            ["scan_jobs.id"],
            name=op.f("fk_finding_evidence_scan_job_id_scan_jobs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_finding_evidence_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_evidence")),
        sa.UniqueConstraint(
            "organization_id",
            "finding_id",
            "scan_job_id",
            name=op.f("uq_finding_evidence_organization_id"),
        ),
    )
    op.create_index(
        "ix_finding_evidence_org_finding", "finding_evidence", ["organization_id", "finding_id"]
    )

    op.create_table(
        "compliance_frameworks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=40), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_frameworks")),
        sa.UniqueConstraint("code", name=op.f("uq_compliance_frameworks_code")),
    )
    op.create_table(
        "compliance_controls",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("framework_id", sa.Uuid(), nullable=False),
        sa.Column("control_code", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=True),
        sa.Column("domain", sa.String(length=100), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["framework_id"],
            ["compliance_frameworks.id"],
            name=op.f("fk_compliance_controls_framework_id_compliance_frameworks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_controls")),
        sa.UniqueConstraint(
            "framework_id", "control_code", name=op.f("uq_compliance_controls_framework_id")
        ),
    )
    op.create_table(
        "finding_compliance_controls",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_finding_compliance_controls_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["control_id"],
            ["compliance_controls.id"],
            name=op.f("fk_finding_compliance_controls_control_id_compliance_controls"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_finding_compliance_controls_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "finding_id", "control_id", name=op.f("pk_finding_compliance_controls")
        ),
        sa.UniqueConstraint(
            "organization_id",
            "finding_id",
            "control_id",
            name=op.f("uq_finding_compliance_controls_organization_id"),
        ),
    )
    op.create_index(
        "ix_finding_compliance_org_control",
        "finding_compliance_controls",
        ["organization_id", "control_id"],
    )

    op.create_table(
        "compliance_assessments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column(
            "checked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "status IN ('PASS', 'FAIL')",
            name=op.f("ck_compliance_assessments_compliance_assessment_status"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"],
            ["scan_jobs.id"],
            name=op.f("fk_compliance_assessments_scan_job_id_scan_jobs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_compliance_assessments_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["control_id"],
            ["compliance_controls.id"],
            name=op.f("fk_compliance_assessments_control_id_compliance_controls"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_compliance_assessments_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_assessments")),
        sa.UniqueConstraint(
            "organization_id",
            "scan_job_id",
            "asset_id",
            "control_id",
            name=op.f("uq_compliance_assessments_organization_id"),
        ),
    )
    op.create_index(
        "ix_compliance_assessments_org_control",
        "compliance_assessments",
        ["organization_id", "control_id"],
    )

    op.create_table(
        "risk_scores",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(length=20), nullable=False),
        sa.Column("factors", sa.JSON(), nullable=False),
        sa.Column(
            "calculated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "score >= 0 AND score <= 100", name=op.f("ck_risk_scores_risk_score_range")
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_risk_scores_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_risk_scores_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_scores")),
        sa.UniqueConstraint(
            "organization_id", "finding_id", name=op.f("uq_risk_scores_organization_id")
        ),
    )
    op.create_index("ix_risk_scores_org_score", "risk_scores", ["organization_id", "score"])

    now = datetime.now(UTC)
    frameworks = sa.table(
        "compliance_frameworks",
        sa.column("id", sa.Uuid()),
        sa.column("code", sa.String()),
        sa.column("name", sa.String()),
        sa.column("version", sa.String()),
        sa.column("is_active", sa.Boolean()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    controls = sa.table(
        "compliance_controls",
        sa.column("id", sa.Uuid()),
        sa.column("framework_id", sa.Uuid()),
        sa.column("control_code", sa.String()),
        sa.column("title", sa.String()),
        sa.column("description", sa.String()),
        sa.column("domain", sa.String()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        frameworks,
        [
            {
                "id": FRAMEWORK_ID,
                "code": "CIS_AWS_FOUNDATIONS",
                "name": "CIS AWS Foundations",
                "version": "UNRESOLVED",
                "is_active": True,
                "created_at": now,
                "updated_at": now,
            }
        ],
    )
    op.bulk_insert(
        controls,
        [
            {
                "id": CONTROL_ID,
                "framework_id": FRAMEWORK_ID,
                "control_code": "4.1",
                "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                "description": (
                    "Initial mapping taken from the supplied CloudSentinel product example."
                ),
                "domain": "Network Security",
                "created_at": now,
                "updated_at": now,
            }
        ],
    )


def downgrade() -> None:
    op.drop_index("ix_risk_scores_org_score", table_name="risk_scores")
    op.drop_table("risk_scores")
    op.drop_index("ix_compliance_assessments_org_control", table_name="compliance_assessments")
    op.drop_table("compliance_assessments")
    op.drop_index("ix_finding_compliance_org_control", table_name="finding_compliance_controls")
    op.drop_table("finding_compliance_controls")
    op.drop_table("compliance_controls")
    op.drop_table("compliance_frameworks")
    op.drop_index("ix_finding_evidence_org_finding", table_name="finding_evidence")
    op.drop_table("finding_evidence")
    op.drop_index("ix_finding_events_org_finding", table_name="finding_events")
    op.drop_table("finding_events")
    op.drop_index("ix_findings_org_status_severity", table_name="findings")
    op.drop_index("ix_findings_org_asset", table_name="findings")
    op.drop_index("ix_findings_org_account", table_name="findings")
    op.drop_table("findings")
