"""Add tenant policy registry, immutable versions, assessments, and evidence."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_policy_registry_assessments"
down_revision: str | None = "0016_asset_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "policy_definitions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=False),
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("resource_types", sa.JSON(), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("detection_logic", sa.JSON(), nullable=False),
        sa.Column("evidence_logic", sa.JSON(), nullable=False),
        sa.Column("remediation", sa.String(length=2000), nullable=False),
        sa.Column("compliance_controls", sa.JSON(), nullable=False),
        sa.Column("is_builtin", sa.Boolean(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')",
            name=op.f("ck_policy_definitions_policy_severity"),
        ),
        sa.CheckConstraint(
            "status IN ('enabled', 'disabled')", name=op.f("ck_policy_definitions_policy_status")
        ),
        sa.CheckConstraint(
            "version >= 1", name=op.f("ck_policy_definitions_policy_version_positive")
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "rule_id"),
    )
    op.create_index(
        "ix_policy_definitions_org_status", "policy_definitions", ["organization_id", "status"]
    )
    op.create_index(
        "ix_policy_definitions_org_category", "policy_definitions", ["organization_id", "category"]
    )

    op.create_table(
        "policy_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("changed_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["policy_id"], ["policy_definitions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["changed_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "policy_id", "version"),
    )
    op.create_index(
        "ix_policy_versions_org_policy", "policy_versions", ["organization_id", "policy_id"]
    )

    op.create_table(
        "policy_assessments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("result", sa.String(length=24), nullable=False),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column(
            "evaluated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["policy_id"], ["policy_definitions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "policy_id", "asset_id", "scan_job_id"),
        sa.CheckConstraint(
            "result IN ('PASS', 'FAIL', 'NOT_APPLICABLE', 'ERROR')",
            name=op.f("ck_policy_assessments_policy_assessment_result"),
        ),
    )
    op.create_index(
        "ix_policy_assessments_org_policy", "policy_assessments", ["organization_id", "policy_id"]
    )
    op.create_index(
        "ix_policy_assessments_org_asset", "policy_assessments", ["organization_id", "asset_id"]
    )
    op.create_index(
        "ix_policy_assessments_org_scan", "policy_assessments", ["organization_id", "scan_job_id"]
    )

    op.create_table(
        "policy_assessment_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("expected_state", sa.JSON(), nullable=False),
        sa.Column("observed_state", sa.JSON(), nullable=False),
        sa.Column(
            "generated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["assessment_id"], ["policy_assessments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "assessment_id"),
    )
    op.create_index(
        "ix_policy_assessment_evidence_org_assessment",
        "policy_assessment_evidence",
        ["organization_id", "assessment_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_policy_assessment_evidence_org_assessment", table_name="policy_assessment_evidence"
    )
    op.drop_table("policy_assessment_evidence")
    op.drop_index("ix_policy_assessments_org_scan", table_name="policy_assessments")
    op.drop_index("ix_policy_assessments_org_asset", table_name="policy_assessments")
    op.drop_index("ix_policy_assessments_org_policy", table_name="policy_assessments")
    op.drop_table("policy_assessments")
    op.drop_index("ix_policy_versions_org_policy", table_name="policy_versions")
    op.drop_table("policy_versions")
    op.drop_index("ix_policy_definitions_org_category", table_name="policy_definitions")
    op.drop_index("ix_policy_definitions_org_status", table_name="policy_definitions")
    op.drop_table("policy_definitions")
