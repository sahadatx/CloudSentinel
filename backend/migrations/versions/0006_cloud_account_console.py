"""Add AWS account environment metadata and explicit disabled state."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_cloud_account_console"
down_revision: str | None = "0005_console_operations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("cloud_accounts", sa.Column("environment", sa.String(length=80)))
    op.add_column("cloud_accounts", sa.Column("primary_region", sa.String(length=40)))
    op.execute(
        "UPDATE cloud_accounts AS accounts SET primary_region = ("
        "SELECT regions.region_code FROM cloud_regions AS regions "
        "WHERE regions.cloud_account_id = accounts.id AND regions.is_enabled IS TRUE "
        "ORDER BY regions.region_code LIMIT 1)"
    )
    op.drop_constraint(
        op.f("ck_cloud_accounts_cloud_account_connection_status"),
        "cloud_accounts",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_cloud_accounts_cloud_account_connection_status"),
        "cloud_accounts",
        "connection_status IN ('pending', 'connected', 'error', 'disabled')",
    )


def downgrade() -> None:
    op.execute(
        "UPDATE cloud_accounts SET connection_status = 'pending' "
        "WHERE connection_status = 'disabled'"
    )
    op.drop_constraint(
        op.f("ck_cloud_accounts_cloud_account_connection_status"),
        "cloud_accounts",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_cloud_accounts_cloud_account_connection_status"),
        "cloud_accounts",
        "connection_status IN ('pending', 'connected', 'error')",
    )
    op.drop_column("cloud_accounts", "environment")
    op.drop_column("cloud_accounts", "primary_region")
