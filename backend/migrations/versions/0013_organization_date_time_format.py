"""Persist an organization-wide date and time display format."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_org_date_time_format"
down_revision: str | None = "0012_security_bounds"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "date_time_format",
            sa.String(length=32),
            server_default="YYYY-MM-DD HH:mm",
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "date_time_format_supported",
        "organizations",
        "date_time_format IN ('YYYY-MM-DD HH:mm', 'MM/DD/YYYY hh:mm A', 'DD/MM/YYYY HH:mm')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_organizations_date_time_format_supported", "organizations", type_="check"
    )
    op.drop_column("organizations", "date_time_format")
