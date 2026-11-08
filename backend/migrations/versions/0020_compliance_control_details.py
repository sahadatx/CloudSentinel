"""Expand compliance registry and assessments for explainable control detail."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020_compliance_control_details"
down_revision: str | None = "0019_risk_model_version"
branch_labels: str | Sequence[str] | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("compliance_controls", sa.Column("category", sa.String(100), nullable=True))
    op.add_column(
        "compliance_controls",
        sa.Column("severity", sa.String(20), nullable=False, server_default="MEDIUM"),
    )
    op.add_column(
        "compliance_controls",
        sa.Column("control_version", sa.String(40), nullable=False, server_default="1.0"),
    )
    op.add_column(
        "compliance_controls",
        sa.Column("guidance", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column("compliance_assessments", sa.Column("observed", sa.JSON(), nullable=True))
    op.add_column("compliance_assessments", sa.Column("expected", sa.JSON(), nullable=True))
    op.add_column("compliance_assessments", sa.Column("evidence_id", sa.Uuid(), nullable=True))
    op.add_column(
        "compliance_assessments", sa.Column("policy_version", sa.String(40), nullable=True)
    )
    op.create_foreign_key(
        op.f("fk_compliance_assessments_evidence_id_finding_evidence"),
        "compliance_assessments",
        "finding_evidence",
        ["evidence_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.drop_constraint(
        op.f("ck_compliance_assessments_compliance_assessment_status"),
        "compliance_assessments",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_compliance_assessments_compliance_assessment_status"),
        "compliance_assessments",
        "status IN ('PASS', 'FAIL', 'PARTIAL', 'NOT_ASSESSED', 'NOT_APPLICABLE')",
    )
    op.execute(
        "UPDATE compliance_frameworks SET version = '1.0' "
        "WHERE code = 'CIS_AWS_FOUNDATIONS' AND version = 'UNRESOLVED'"
    )
    op.execute("UPDATE compliance_controls SET category = domain WHERE category IS NULL")
    op.execute(
        "UPDATE compliance_controls SET severity = 'CRITICAL' "
        "WHERE control_code = '4.1' AND framework_id = "
        "(SELECT id FROM compliance_frameworks WHERE code = 'CIS_AWS_FOUNDATIONS')"
    )
    op.execute(
        "UPDATE compliance_controls SET description = "
        "'The security group allows inbound SSH from the unrestricted IPv4 range.', "
        "category = 'Network Security' "
        "WHERE control_code = '4.1' AND framework_id = "
        "(SELECT id FROM compliance_frameworks WHERE code = 'CIS_AWS_FOUNDATIONS')"
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_compliance_assessments_compliance_assessment_status"),
        "compliance_assessments",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_compliance_assessments_compliance_assessment_status"),
        "compliance_assessments",
        "status IN ('PASS', 'FAIL')",
    )
    op.drop_constraint(
        op.f("fk_compliance_assessments_evidence_id_finding_evidence"),
        "compliance_assessments",
        type_="foreignkey",
    )
    op.drop_column("compliance_assessments", "policy_version")
    op.drop_column("compliance_assessments", "evidence_id")
    op.drop_column("compliance_assessments", "expected")
    op.drop_column("compliance_assessments", "observed")
    op.drop_column("compliance_controls", "guidance")
    op.drop_column("compliance_controls", "control_version")
    op.drop_column("compliance_controls", "severity")
    op.drop_column("compliance_controls", "category")
