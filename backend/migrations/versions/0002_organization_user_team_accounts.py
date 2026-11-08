"""Add organization administration, invitations, teams, and AWS account metadata."""

from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

import sqlalchemy as sa
from alembic import op

revision = "0002_org_user_team_accounts"
down_revision = "0001_identity_rbac"
branch_labels = None
depends_on = None

PERMISSIONS = {
    "organizations:read": "View the active organization details.",
    "organizations:update": "Update the active organization's profile.",
    "users:read": "View organization users and memberships.",
    "users:invite": "Issue an organization-scoped user invitation.",
    "users:update": "Update a user's organization role.",
    "users:disable": "Disable a user's organization membership.",
    "teams:read": "View organization teams and members.",
    "teams:create": "Create an organization team.",
    "teams:update": "Update a team and its membership.",
    "teams:delete": "Delete an organization team.",
}


def _id(kind: str, value: str):
    return uuid5(NAMESPACE_URL, f"cloudsentinel:{kind}:{value}")


def upgrade() -> None:
    op.create_table(
        "user_invitations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("invited_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["invited_by_user_id"],
            ["users.id"],
            name=op.f("fk_user_invitations_invited_by_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_user_invitations_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_user_invitations_role_id_roles"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_invitations")),
        sa.UniqueConstraint(
            "organization_id", "email", name=op.f("uq_user_invitations_organization_id")
        ),
        sa.UniqueConstraint("token_digest", name=op.f("uq_user_invitations_token_digest")),
    )
    op.create_table(
        "teams",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_teams_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_teams")),
        sa.UniqueConstraint("organization_id", "name", name=op.f("uq_teams_organization_id")),
    )
    op.create_table(
        "team_memberships",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_team_memberships_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["teams.id"],
            name=op.f("fk_team_memberships_team_id_teams"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_team_memberships_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_team_memberships")),
        sa.UniqueConstraint(
            "organization_id",
            "team_id",
            "user_id",
            name=op.f("uq_team_memberships_organization_id"),
        ),
    )
    op.create_table(
        "cloud_accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("account_id", sa.String(length=12), nullable=False),
        sa.Column("role_arn", sa.String(length=512), nullable=False),
        sa.Column("external_id", sa.String(length=128), nullable=False),
        sa.Column(
            "connection_status", sa.String(length=20), server_default="pending", nullable=False
        ),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=80), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "connection_status IN ('pending', 'connected', 'error')",
            name=op.f("ck_cloud_accounts_cloud_account_connection_status"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name=op.f("fk_cloud_accounts_created_by_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_cloud_accounts_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cloud_accounts")),
        sa.UniqueConstraint(
            "organization_id", "account_id", name=op.f("uq_cloud_accounts_organization_id")
        ),
    )
    op.create_table(
        "cloud_regions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("cloud_account_id", sa.Uuid(), nullable=False),
        sa.Column("region_code", sa.String(length=40), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["cloud_account_id"],
            ["cloud_accounts.id"],
            name=op.f("fk_cloud_regions_cloud_account_id_cloud_accounts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_cloud_regions_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cloud_regions")),
        sa.UniqueConstraint(
            "organization_id",
            "cloud_account_id",
            "region_code",
            name=op.f("uq_cloud_regions_organization_id"),
        ),
    )

    bind = op.get_bind()
    permission_table = sa.table(
        "permissions",
        sa.column("id", sa.Uuid()),
        sa.column("code", sa.String()),
        sa.column("description", sa.String()),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    role_table = sa.table("roles", sa.column("id", sa.Uuid()), sa.column("code", sa.String()))
    role_permission_table = sa.table(
        "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
    )
    now = datetime.now(UTC)
    bind.execute(
        permission_table.insert(),
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
    grants = {
        "SUPER_ADMIN": set(PERMISSIONS),
        "ORG_ADMIN": set(PERMISSIONS),
        "SECURITY_ADMIN": {"organizations:read", "users:read", "teams:read"},
    }
    role_ids = {
        row.code: row.id for row in bind.execute(sa.select(role_table.c.id, role_table.c.code))
    }
    permission_ids = {
        row.code: row.id
        for row in bind.execute(
            sa.select(permission_table.c.id, permission_table.c.code).where(
                permission_table.c.code.in_(PERMISSIONS)
            )
        )
    }
    bind.execute(
        role_permission_table.insert(),
        [
            {"role_id": role_ids[role], "permission_id": permission_ids[permission]}
            for role, permissions in grants.items()
            for permission in permissions
        ],
    )
    # All authenticated roles may view only their current organization context.
    org_read_id = permission_ids["organizations:read"]
    existing = set(role_ids.values())
    existing_grant_roles = set(
        bind.execute(
            sa.select(role_permission_table.c.role_id).where(
                role_permission_table.c.permission_id == org_read_id
            )
        ).scalars()
    )
    bind.execute(
        role_permission_table.insert(),
        [
            {"role_id": role_id, "permission_id": org_read_id}
            for role_id in existing - existing_grant_roles
        ],
    )


def downgrade() -> None:
    bind = op.get_bind()
    permission_table = sa.table(
        "permissions", sa.column("id", sa.Uuid()), sa.column("code", sa.String())
    )
    role_permission_table = sa.table(
        "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
    )
    ids = list(
        bind.execute(
            sa.select(permission_table.c.id).where(permission_table.c.code.in_(PERMISSIONS))
        ).scalars()
    )
    bind.execute(
        role_permission_table.delete().where(role_permission_table.c.permission_id.in_(ids))
    )
    bind.execute(permission_table.delete().where(permission_table.c.id.in_(ids)))
    op.drop_table("cloud_regions")
    op.drop_table("cloud_accounts")
    op.drop_table("team_memberships")
    op.drop_table("teams")
    op.drop_table("user_invitations")
