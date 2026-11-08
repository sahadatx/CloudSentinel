"""Add mandatory password-change state to user identities."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_force_password_change"
down_revision: str | None = "0008_password_recovery_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("force_password_change", sa.Boolean(), server_default=sa.false(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("users", "force_password_change")
