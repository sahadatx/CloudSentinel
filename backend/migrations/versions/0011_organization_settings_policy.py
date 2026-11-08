"""Add tenant organization security settings and corresponding permissions."""

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

import sqlalchemy as sa
from alembic import op

revision: str = "0011_org_settings_policy"
down_revision: str | None = "0010_admin_identity_teams"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS = {
    "security_settings:read": "View organization password and session security policies.",
    "security_settings:update": "Update organization password and session security policies.",
}


def _id(kind: str, value: str):
    return uuid5(NAMESPACE_URL, f"cloudsentinel:{kind}:{value}")


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("password_min_length", sa.Integer(), server_default="12", nullable=False),
    )
    op.add_column(
        "organizations",
        sa.Column("session_ttl_days", sa.Integer(), server_default="7", nullable=False),
    )
    op.add_column(
        "organizations",
        sa.Column("remembered_session_ttl_days", sa.Integer(), server_default="30", nullable=False),
    )
    op.add_column(
        "organizations",
        sa.Column("max_concurrent_sessions", sa.Integer(), server_default="5", nullable=False),
    )

    bind = op.get_bind()
    permissions = sa.table(
        "permissions",
        sa.column("id", sa.Uuid()),
        sa.column("code", sa.String()),
        sa.column("description", sa.String()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    roles = sa.table("roles", sa.column("id", sa.Uuid()), sa.column("code", sa.String()))
    grants = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Uuid()),
        sa.column("permission_id", sa.Uuid()),
    )
    now = datetime.now(UTC)
    bind.execute(
        permissions.insert(),
        [
            {
                "id": _id("permission", code),
                "code": code,
                "description": description,
                "created_at": now,
                "updated_at": now,
            }
            for code, description in PERMISSIONS.items()
        ],
    )
    role_ids = {
        row.code: row.id for row in bind.execute(sa.select(roles.c.id, roles.c.code))
    }
    permission_ids = {
        row.code: row.id
        for row in bind.execute(
            sa.select(permissions.c.id, permissions.c.code).where(
                permissions.c.code.in_(PERMISSIONS)
            )
        )
    }
    bind.execute(
        grants.insert(),
        [
            {"role_id": role_ids[role], "permission_id": permission_ids[permission]}
            for role in ("SUPER_ADMIN", "ORG_ADMIN", "SECURITY_ADMIN")
            for permission in PERMISSIONS
        ],
    )


def downgrade() -> None:
    bind = op.get_bind()
    permissions = sa.table(
        "permissions", sa.column("id", sa.Uuid()), sa.column("code", sa.String())
    )
    grants = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Uuid()),
        sa.column("permission_id", sa.Uuid()),
    )
    ids = list(
        bind.execute(
            sa.select(permissions.c.id).where(permissions.c.code.in_(PERMISSIONS))
        ).scalars()
    )
    bind.execute(grants.delete().where(grants.c.permission_id.in_(ids)))
    bind.execute(permissions.delete().where(permissions.c.id.in_(ids)))
    op.drop_column("organizations", "max_concurrent_sessions")
    op.drop_column("organizations", "remembered_session_ttl_days")
    op.drop_column("organizations", "session_ttl_days")
    op.drop_column("organizations", "password_min_length")
