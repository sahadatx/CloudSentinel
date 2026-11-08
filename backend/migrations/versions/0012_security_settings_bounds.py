"""Constrain organization security policy values in the database."""

from collections.abc import Sequence

from alembic import op

revision: str = "0012_security_bounds"
down_revision: str | None = "0011_org_settings_policy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_organizations_security_settings_bounds",
        "organizations",
        "password_min_length BETWEEN 12 AND 128 "
        "AND session_ttl_days BETWEEN 1 AND 30 "
        "AND remembered_session_ttl_days BETWEEN session_ttl_days AND 90 "
        "AND max_concurrent_sessions BETWEEN 1 AND 50",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_organizations_security_settings_bounds", "organizations", type_="check"
    )
