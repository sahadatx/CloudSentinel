"""Persist risk model identity with each finding assessment."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019_risk_model_version"
down_revision: str | None = "0018_finding_due_date"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "risk_scores",
        sa.Column(
            "risk_model", sa.String(length=100), nullable=False,
            server_default="CloudSentinel Default",
        ),
    )
    op.add_column(
        "risk_scores",
        sa.Column("risk_model_version", sa.String(length=40), nullable=False, server_default="1.0"),
    )


def downgrade() -> None:
    op.drop_column("risk_scores", "risk_model_version")
    op.drop_column("risk_scores", "risk_model")
