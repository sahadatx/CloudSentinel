"""Persist browser-session preference for refresh-cookie lifetime."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_auth_remember_session"
down_revision: str | None = "0006_cloud_account_console"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "refresh_sessions",
        sa.Column("remember_session", sa.Boolean(), server_default=sa.false(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("refresh_sessions", "remember_session")
