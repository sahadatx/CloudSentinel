"""Allow cloud account records before AWS role trust is configured."""

from collections.abc import Sequence

from alembic import op

revision: str = "0014_cloud_account_pending_setup"
down_revision: str | None = "0013_org_date_time_format"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("cloud_accounts", "role_arn", nullable=True)


def downgrade() -> None:
    op.alter_column("cloud_accounts", "role_arn", nullable=False)
