"""Track conservative asset inventory lifecycle across successful scans."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_asset_lifecycle"
down_revision: str | None = "0015_aws_validation_mode"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
    )
    op.add_column(
        "assets",
        sa.Column("missed_scan_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_check_constraint(
        "ck_assets_asset_status",
        "assets",
        "status IN ('active', 'stale', 'removed')",
    )
    op.create_index("ix_assets_org_status", "assets", ["organization_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_assets_org_status", table_name="assets")
    op.drop_constraint("ck_assets_asset_status", "assets", type_="check")
    op.drop_column("assets", "missed_scan_count")
    op.drop_column("assets", "status")
