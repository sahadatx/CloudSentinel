"""Add queued report generation metadata and immutable report versions."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022_report_generation"
down_revision: str | None = "0021_remediation_alerts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("reports", sa.Column("name", sa.String(160), nullable=True))
    op.add_column(
        "reports", sa.Column("status", sa.String(20), server_default="COMPLETED", nullable=False)
    )
    op.add_column(
        "reports", sa.Column("file_format", sa.String(10), server_default="JSON", nullable=False)
    )
    op.add_column(
        "reports", sa.Column("report_version", sa.Integer(), server_default="1", nullable=False)
    )
    op.add_column(
        "reports",
        sa.Column("generator_version", sa.String(40), server_default="1.0", nullable=False),
    )
    op.add_column("reports", sa.Column("checksum", sa.String(64), nullable=True))
    op.add_column("reports", sa.Column("snapshot_checksum", sa.String(64), nullable=True))
    op.add_column("reports", sa.Column("storage_key", sa.String(512), nullable=True))
    op.add_column("reports", sa.Column("file_size", sa.Integer(), nullable=True))
    op.add_column("reports", sa.Column("data_snapshot_at", sa.DateTime(timezone=True)))
    op.add_column("reports", sa.Column("generated_at", sa.DateTime(timezone=True)))
    op.add_column("reports", sa.Column("retention_until", sa.DateTime(timezone=True)))
    op.add_column("reports", sa.Column("report_series_id", sa.Uuid(), nullable=True))
    op.add_column("reports", sa.Column("parent_report_id", sa.Uuid(), nullable=True))
    op.add_column("reports", sa.Column("error_code", sa.String(80), nullable=True))
    op.add_column("reports", sa.Column("error_message", sa.String(500), nullable=True))
    op.add_column(
        "reports",
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.execute("UPDATE reports SET name = report_type WHERE name IS NULL")
    op.execute("UPDATE reports SET generated_at = created_at WHERE generated_at IS NULL")
    op.execute("UPDATE reports SET data_snapshot_at = created_at WHERE data_snapshot_at IS NULL")
    op.execute("UPDATE reports SET report_series_id = id WHERE report_series_id IS NULL")
    op.alter_column("reports", "name", existing_type=sa.String(160), nullable=False)
    op.alter_column("reports", "report_series_id", existing_type=sa.Uuid(), nullable=False)
    op.alter_column(
        "reports", "updated_at", existing_type=sa.DateTime(timezone=True), nullable=False
    )
    op.alter_column("reports", "snapshot", existing_type=sa.JSON(), nullable=True)
    op.create_foreign_key(
        op.f("fk_reports_report_series_id_reports"),
        "reports",
        "reports",
        ["report_series_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        op.f("fk_reports_parent_report_id_reports"),
        "reports",
        "reports",
        ["parent_report_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint(
        op.f("ck_reports_report_status"),
        "reports",
        "status IN ('QUEUED', 'GENERATING', 'COMPLETED', 'FAILED', 'CANCELLED')",
    )
    op.create_check_constraint(
        op.f("ck_reports_report_file_format"), "reports", "file_format IN ('PDF', 'CSV', 'JSON')"
    )
    op.create_check_constraint(
        op.f("ck_reports_report_version_positive"), "reports", "report_version >= 1"
    )
    op.create_index(
        "ix_reports_org_status_created", "reports", ["organization_id", "status", "created_at"]
    )
    op.create_unique_constraint(
        op.f("uq_reports_series_version"),
        "reports",
        ["organization_id", "report_series_id", "report_version"],
    )


def downgrade() -> None:
    op.drop_constraint(op.f("uq_reports_series_version"), "reports", type_="unique")
    op.drop_index("ix_reports_org_status_created", table_name="reports")
    op.drop_constraint(op.f("ck_reports_report_version_positive"), "reports", type_="check")
    op.drop_constraint(op.f("ck_reports_report_file_format"), "reports", type_="check")
    op.drop_constraint(op.f("ck_reports_report_status"), "reports", type_="check")
    op.drop_constraint(op.f("fk_reports_parent_report_id_reports"), "reports", type_="foreignkey")
    op.drop_constraint(op.f("fk_reports_report_series_id_reports"), "reports", type_="foreignkey")
    op.execute("UPDATE reports SET snapshot = '{}' WHERE snapshot IS NULL")
    op.alter_column("reports", "snapshot", existing_type=sa.JSON(), nullable=False)
    for column in (
        "updated_at",
        "error_message",
        "error_code",
        "parent_report_id",
        "report_series_id",
        "retention_until",
        "generated_at",
        "data_snapshot_at",
        "checksum",
        "file_size",
        "storage_key",
        "snapshot_checksum",
        "generator_version",
        "report_version",
        "file_format",
        "status",
        "name",
    ):
        op.drop_column("reports", column)
