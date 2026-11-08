"""Create identity, RBAC, refresh-session, and tenant foundation tables."""

from uuid import NAMESPACE_URL, UUID, uuid5

import sqlalchemy as sa
from alembic import op

revision = "0001_identity_rbac"
down_revision = None
branch_labels = None
depends_on = None

ROLES = {
    "SUPER_ADMIN": "Platform-wide support administrator; grants remain organization-scoped.",
    "ORG_ADMIN": "Organization administrator with tenant administration permissions.",
    "SECURITY_ADMIN": "Security configuration and response administrator.",
    "SECURITY_ANALYST": "Investigates and updates security findings.",
    "CLOUD_ENGINEER": "Reads cloud posture and performs authorized remediation actions.",
    "AUDITOR": "Read-only security and governance reviewer.",
    "VIEWER": "Read-only user of organization security information.",
}
PERMISSIONS = {
    "cloud_accounts:read": "View cloud account records.",
    "cloud_accounts:create": "Register cloud account records.",
    "cloud_accounts:update": "Update cloud account records.",
    "cloud_accounts:delete": "Remove cloud account records.",
    "assets:read": "View asset inventory.",
    "assets:export": "Export asset inventory.",
    "findings:read": "View security findings.",
    "findings:update": "Update finding state and details.",
    "findings:assign": "Assign findings.",
    "findings:suppress": "Suppress findings subject to approval and audit controls.",
    "policies:read": "View policy definitions.",
    "policies:create": "Create policy definitions.",
    "policies:update": "Update policy definitions.",
    "reports:read": "View generated reports.",
    "reports:create": "Create reports.",
    "reports:export": "Export reports.",
    "remediation:read": "View remediation guidance and status.",
    "remediation:execute": "Execute explicitly approved remediation workflows.",
    "audit:read": "View organization audit records.",
}
ALL = set(PERMISSIONS)
READ_ONLY = {
    "cloud_accounts:read",
    "assets:read",
    "findings:read",
    "policies:read",
    "reports:read",
    "audit:read",
    "remediation:read",
}
GRANTS = {
    "SUPER_ADMIN": ALL,
    "ORG_ADMIN": ALL,
    "SECURITY_ADMIN": ALL - {"cloud_accounts:delete", "remediation:execute"},
    "SECURITY_ANALYST": {
        "assets:read",
        "assets:export",
        "findings:read",
        "findings:update",
        "findings:assign",
        "policies:read",
        "reports:read",
        "reports:create",
        "reports:export",
        "remediation:read",
        "audit:read",
    },
    "CLOUD_ENGINEER": {
        "cloud_accounts:read",
        "assets:read",
        "findings:read",
        "findings:update",
        "policies:read",
        "reports:read",
        "remediation:read",
        "remediation:execute",
    },
    "AUDITOR": READ_ONLY | {"assets:export", "reports:export"},
    "VIEWER": READ_ONLY,
}


def _id(kind: str, code: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"cloudsentinel:{kind}:{code}")


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organizations")),
        sa.UniqueConstraint("slug", name=op.f("uq_organizations_slug")),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(length=40), nullable=False),
        sa.Column("description", sa.String(length=300), nullable=False),
        sa.Column("is_system", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "code IN ('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'SECURITY_ANALYST', "
            "'CLOUD_ENGINEER', 'AUDITOR', 'VIEWER')",
            name=op.f("ck_roles_locked_role_codes"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("code", name=op.f("uq_roles_code")),
    )
    op.create_table(
        "permissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=300), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_permissions")),
        sa.UniqueConstraint("code", name=op.f("uq_permissions_code")),
    )
    op.create_table(
        "memberships",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_memberships_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_memberships_role_id_roles"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_memberships_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_memberships")),
        sa.UniqueConstraint(
            "organization_id", "user_id", name=op.f("uq_memberships_organization_id")
        ),
    )
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("permission_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name=op.f("fk_role_permissions_permission_id_permissions"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_role_permissions_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("role_id", "permission_id", name=op.f("pk_role_permissions")),
    )
    op.create_table(
        "refresh_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("membership_id", sa.Uuid(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["membership_id"],
            ["memberships.id"],
            name=op.f("fk_refresh_sessions_membership_id_memberships"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_refresh_sessions_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_refresh_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_sessions")),
    )
    op.create_index(
        op.f("ix_refresh_sessions_user_id"), "refresh_sessions", ["user_id"], unique=False
    )
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_refresh_tokens_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["refresh_sessions.id"],
            name=op.f("fk_refresh_tokens_session_id_refresh_sessions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_tokens")),
        sa.UniqueConstraint("token_digest", name=op.f("uq_refresh_tokens_token_digest")),
    )

    bind = op.get_bind()
    role_table = sa.table(
        "roles",
        sa.column("id", sa.Uuid()),
        sa.column("code", sa.String()),
        sa.column("description", sa.String()),
        sa.column("is_system", sa.Boolean()),
    )
    perm_table = sa.table(
        "permissions",
        sa.column("id", sa.Uuid()),
        sa.column("code", sa.String()),
        sa.column("description", sa.String()),
    )
    rp_table = sa.table(
        "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
    )
    bind.execute(
        role_table.insert(),
        [
            {"id": _id("role", code), "code": code, "description": desc, "is_system": True}
            for code, desc in ROLES.items()
        ],
    )
    bind.execute(
        perm_table.insert(),
        [
            {"id": _id("permission", code), "code": code, "description": desc}
            for code, desc in PERMISSIONS.items()
        ],
    )
    bind.execute(
        rp_table.insert(),
        [
            {"role_id": _id("role", role), "permission_id": _id("permission", permission)}
            for role, permissions in GRANTS.items()
            for permission in sorted(permissions)
        ],
    )


def downgrade() -> None:
    op.drop_table("refresh_tokens")
    op.drop_index(op.f("ix_refresh_sessions_user_id"), table_name="refresh_sessions")
    op.drop_table("refresh_sessions")
    op.drop_table("role_permissions")
    op.drop_table("memberships")
    op.drop_table("permissions")
    op.drop_table("roles")
    op.drop_table("users")
    op.drop_table("organizations")
