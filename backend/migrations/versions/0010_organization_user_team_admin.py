"""Complete tenant administration, user security, and team lifecycle metadata."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_admin_identity_teams"
down_revision: str | None = "0009_force_password_change"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("organizations", sa.Column("description", sa.String(1000), nullable=True))
    op.add_column(
        "organizations", sa.Column("default_environment", sa.String(80), nullable=True)
    )
    op.add_column("organizations", sa.Column("default_region", sa.String(40), nullable=True))
    op.add_column(
        "organizations",
        sa.Column("timezone", sa.String(64), server_default="UTC", nullable=False),
    )

    op.add_column(
        "memberships",
        sa.Column("is_locked", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("memberships", sa.Column("locked_at", sa.DateTime(timezone=True)))
    op.add_column("memberships", sa.Column("lock_reason", sa.String(500)))

    op.add_column("refresh_sessions", sa.Column("ip_address", sa.String(45)))
    op.add_column("refresh_sessions", sa.Column("user_agent", sa.String(512)))

    op.add_column(
        "teams",
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("teams", "is_active")
    op.drop_column("refresh_sessions", "user_agent")
    op.drop_column("refresh_sessions", "ip_address")
    op.drop_column("memberships", "lock_reason")
    op.drop_column("memberships", "locked_at")
    op.drop_column("memberships", "is_locked")
    op.drop_column("organizations", "timezone")
    op.drop_column("organizations", "default_region")
    op.drop_column("organizations", "default_environment")
    op.drop_column("organizations", "description")
