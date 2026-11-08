"""Persist whether an AWS account connection was validated with real or mock STS."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_aws_validation_mode"
down_revision: str | None = "0014_cloud_account_pending_setup"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("cloud_accounts", sa.Column("validation_mode", sa.String(length=12)))
    op.create_check_constraint(
        "ck_cloud_accounts_cloud_account_validation_mode",
        "cloud_accounts",
        "validation_mode IS NULL OR validation_mode IN ('real', 'mock')",
    )
    # Existing connected records were produced only by the real STS validator.
    op.execute(
        "UPDATE cloud_accounts SET validation_mode = 'real' "
        "WHERE connection_status = 'connected'"
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_cloud_accounts_cloud_account_validation_mode",
        "cloud_accounts",
        type_="check",
    )
    op.drop_column("cloud_accounts", "validation_mode")
