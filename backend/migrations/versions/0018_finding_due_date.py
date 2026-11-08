"""Add due dates to finding assignments."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_finding_due_date"
down_revision: str | None = "0017_policy_registry_assessments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("due_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_findings_org_due_at", "findings", ["organization_id", "due_at"])
    op.add_column(
        "finding_evidence",
        sa.Column("source", sa.String(length=100), nullable=False, server_default="AWS API"),
    )
    op.add_column(
        "finding_evidence",
        sa.Column("expected_state", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("finding_evidence", "expected_state")
    op.drop_column("finding_evidence", "source")
    op.drop_index("ix_findings_org_due_at", table_name="findings")
    op.drop_column("findings", "due_at")
