"""Add tenant-owned customer assessment jobs and normalized findings."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028_customer_scan_sandbox"
down_revision: str | None = "0027_enterprise_id_retention"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_task_outbox_task_outbox_type"), "task_outbox", type_="check")
    op.create_check_constraint(
        op.f("ck_task_outbox_task_outbox_type"),
        "task_outbox",
        "task_type IN ('cloudsentinel.scan_jobs.process', 'cloudsentinel.reports.generate', "
        "'cloudsentinel.customer_scans.run')",
    )
    op.create_table(
        "customer_scan_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("scan_type", sa.String(20), nullable=False),
        sa.Column("source_filename", sa.String(255), nullable=False),
        sa.Column("artifact_key", sa.String(700), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("result", sa.JSON()),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("scanner_version", sa.String(80)),
        sa.Column("error_code", sa.String(80)),
        sa.Column("ecs_task_arn", sa.String(512)),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("scan_type IN ('iac', 'container')", name=op.f("ck_customer_scan_jobs_scan_type")),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'cancelling', 'completed', 'failed', 'cancelled')",
            name=op.f("ck_customer_scan_jobs_status"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_key", name=op.f("uq_customer_scan_jobs_artifact_key")),
    )
    op.create_index(
        "ix_customer_scan_jobs_org_created",
        "customer_scan_jobs",
        ["organization_id", "created_at"],
    )

    op.create_table(
        "customer_scan_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(160), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("resource", sa.String(700)),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["customer_scan_jobs.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_customer_scan_findings_job_severity",
        "customer_scan_findings",
        ["organization_id", "scan_job_id", "severity"],
    )


def downgrade() -> None:
    op.drop_index("ix_customer_scan_findings_job_severity", table_name="customer_scan_findings")
    op.drop_table("customer_scan_findings")
    op.drop_index("ix_customer_scan_jobs_org_created", table_name="customer_scan_jobs")
    op.drop_table("customer_scan_jobs")
    op.drop_constraint(op.f("ck_task_outbox_task_outbox_type"), "task_outbox", type_="check")
    op.create_check_constraint(
        op.f("ck_task_outbox_task_outbox_type"),
        "task_outbox",
        "task_type IN ('cloudsentinel.scan_jobs.process', 'cloudsentinel.reports.generate')",
    )
