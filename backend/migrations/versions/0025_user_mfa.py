"""Add encrypted authenticator-based MFA for global user identities."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025_user_mfa"
down_revision: str | None = "0024_task_outbox"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_mfa",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("secret_ciphertext", sa.String(length=255), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_totp_counter", sa.Integer(), nullable=True),
        sa.Column("recovery_code_digests", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "is_enabled IN (true, false)", name=op.f("ck_user_mfa_user_mfa_enabled")
        ),
        sa.CheckConstraint(
            "last_totp_counter IS NULL OR last_totp_counter >= 0",
            name=op.f("ck_user_mfa_user_mfa_counter"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE", name=op.f("fk_user_mfa_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_mfa")),
        sa.UniqueConstraint("user_id", name=op.f("uq_user_mfa_user_id")),
    )


def downgrade() -> None:
    op.drop_table("user_mfa")
