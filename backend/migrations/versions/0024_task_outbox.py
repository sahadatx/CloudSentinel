"""Add a durable outbox for scan and report task delivery."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024_task_outbox"
down_revision: str | None = "0023_audit_event_context"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("reports") as batch_op:
        batch_op.drop_constraint(op.f("ck_reports_report_status"), type_="check")
        batch_op.create_check_constraint(
            op.f("ck_reports_report_status"),
            "status IN ('QUEUED', 'GENERATING', 'COMPLETED', 'FAILED', 'CANCELLED', 'EXPIRED')",
        )
        batch_op.add_column(
            sa.Column("generation_attempt_count", sa.Integer(), server_default="0", nullable=False)
        )
        batch_op.create_check_constraint(
            op.f("ck_reports_report_generation_attempt_count"),
            "generation_attempt_count >= 0",
        )
    with op.batch_alter_table("scan_jobs") as batch_op:
        batch_op.add_column(
            sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False)
        )
        batch_op.create_check_constraint(
            op.f("ck_scan_jobs_scan_job_attempt_count"), "attempt_count >= 0"
        )
    op.create_table(
        "task_outbox",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("task_type", sa.String(length=80), nullable=False),
        sa.Column("aggregate_id", sa.String(length=100), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="pending", nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("claimed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_token", sa.Uuid(), nullable=True),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dead_lettered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=80), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "task_type IN ('cloudsentinel.scan_jobs.process', "
            "'cloudsentinel.reports.generate')",
            name=op.f("ck_task_outbox_task_outbox_type"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'dispatching', 'dispatched', 'dead')",
            name=op.f("ck_task_outbox_task_outbox_status"),
        ),
        sa.CheckConstraint(
            "attempt_count >= 0", name=op.f("ck_task_outbox_task_outbox_attempt_count")
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_task_outbox_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_outbox")),
        sa.UniqueConstraint(
            "organization_id",
            "task_type",
            "aggregate_id",
            name=op.f("uq_task_outbox_aggregate"),
        ),
    )
    op.create_index(
        "ix_task_outbox_delivery",
        "task_outbox",
        ["status", "available_at", "claimed_until"],
    )


def downgrade() -> None:
    op.drop_index("ix_task_outbox_delivery", table_name="task_outbox")
    op.drop_table("task_outbox")
    with op.batch_alter_table("reports") as batch_op:
        batch_op.drop_constraint(op.f("ck_reports_report_generation_attempt_count"), type_="check")
        batch_op.drop_column("generation_attempt_count")
        batch_op.drop_constraint(op.f("ck_reports_report_status"), type_="check")
        batch_op.create_check_constraint(
            op.f("ck_reports_report_status"),
            "status IN ('QUEUED', 'GENERATING', 'COMPLETED', 'FAILED', 'CANCELLED')",
        )
    with op.batch_alter_table("scan_jobs") as batch_op:
        batch_op.drop_constraint(op.f("ck_scan_jobs_scan_job_attempt_count"), type_="check")
        batch_op.drop_column("attempt_count")
