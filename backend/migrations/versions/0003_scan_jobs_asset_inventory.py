"""Add tenant-owned scan jobs, normalized assets, relationships, and scan grants."""

from datetime import UTC, datetime
from uuid import NAMESPACE_URL, UUID, uuid5

import sqlalchemy as sa
from alembic import op

revision = "0003_scan_asset_inventory"
down_revision = "0002_org_user_team_accounts"
branch_labels = None
depends_on = None

SCAN_PERMISSIONS = {
    "scans:read": "Read scan job status and progress in the active organization.",
    "scans:create": "Request an AWS scan for an authorized account and enabled regions.",
    "scans:cancel": "Request cancellation of an active organization scan.",
}
SCAN_GRANTS = {
    "SUPER_ADMIN": set(SCAN_PERMISSIONS),
    "ORG_ADMIN": set(SCAN_PERMISSIONS),
    "SECURITY_ADMIN": set(SCAN_PERMISSIONS),
    "SECURITY_ANALYST": set(SCAN_PERMISSIONS),
    "CLOUD_ENGINEER": set(SCAN_PERMISSIONS),
    "AUDITOR": {"scans:read"},
    "VIEWER": {"scans:read"},
}


def _id(code: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"cloudsentinel:permission:{code}")


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("cloud_account_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_membership_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("requested_regions", sa.JSON(), nullable=False),
        sa.Column("requested_resource_types", sa.JSON(), nullable=False),
        sa.Column("progress_total", sa.Integer(), nullable=False),
        sa.Column("progress_completed", sa.Integer(), nullable=False),
        sa.Column("resources_discovered", sa.Integer(), nullable=False),
        sa.Column("errors_count", sa.Integer(), nullable=False),
        sa.Column("error_codes", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'cancelling', 'completed', 'partial', 'failed', "
            "'cancelled')",
            name=op.f("ck_scan_jobs_scan_job_status"),
        ),
        sa.CheckConstraint(
            "progress_total >= 0 AND progress_completed >= 0",
            name=op.f("ck_scan_jobs_scan_progress_nonnegative"),
        ),
        sa.CheckConstraint(
            "progress_completed <= progress_total OR progress_total = 0",
            name=op.f("ck_scan_jobs_scan_progress_bounded"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_scan_jobs_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["cloud_account_id"],
            ["cloud_accounts.id"],
            name=op.f("fk_scan_jobs_cloud_account_id_cloud_accounts"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name=op.f("fk_scan_jobs_requested_by_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_membership_id"],
            ["memberships.id"],
            name=op.f("fk_scan_jobs_requested_by_membership_id_memberships"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_jobs")),
    )
    op.create_index("ix_scan_jobs_org_created", "scan_jobs", ["organization_id", "created_at"])
    op.create_index("ix_scan_jobs_org_status", "scan_jobs", ["organization_id", "status"])

    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("cloud_account_id", sa.Uuid(), nullable=False),
        sa.Column("last_scan_job_id", sa.Uuid(), nullable=True),
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=False),
        sa.Column("resource_id", sa.String(length=512), nullable=False),
        sa.Column("resource_arn", sa.String(length=1024), nullable=True),
        sa.Column("region_code", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("owner_metadata", sa.JSON(), nullable=True),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_assets_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["cloud_account_id"],
            ["cloud_accounts.id"],
            name=op.f("fk_assets_cloud_account_id_cloud_accounts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["last_scan_job_id"],
            ["scan_jobs.id"],
            name=op.f("fk_assets_last_scan_job_id_scan_jobs"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.UniqueConstraint(
            "organization_id",
            "cloud_account_id",
            "resource_type",
            "region_code",
            "resource_id",
            name=op.f("uq_assets_organization_id"),
        ),
    )
    op.create_index("ix_assets_org_account", "assets", ["organization_id", "cloud_account_id"])
    op.create_index("ix_assets_org_type", "assets", ["organization_id", "resource_type"])
    op.create_index("ix_assets_org_last_seen", "assets", ["organization_id", "last_seen_at"])

    op.create_table(
        "asset_relationships",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("source_asset_id", sa.Uuid(), nullable=False),
        sa.Column("target_asset_id", sa.Uuid(), nullable=False),
        sa.Column("relationship_type", sa.String(length=80), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_asset_relationships_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_asset_id"],
            ["assets.id"],
            name=op.f("fk_asset_relationships_source_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_asset_id"],
            ["assets.id"],
            name=op.f("fk_asset_relationships_target_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_relationships")),
        sa.UniqueConstraint(
            "organization_id",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name=op.f("uq_asset_relationships_organization_id"),
        ),
    )
    op.create_index(
        "ix_asset_relationships_org_source",
        "asset_relationships",
        ["organization_id", "source_asset_id"],
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
    role_permissions = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Uuid()),
        sa.column("permission_id", sa.Uuid()),
    )
    now = datetime.now(UTC)
    bind.execute(
        permissions.insert(),
        [
            {
                "id": _id(code),
                "code": code,
                "description": description,
                "created_at": now,
                "updated_at": now,
            }
            for code, description in SCAN_PERMISSIONS.items()
        ],
    )
    role_ids = {row.code: row.id for row in bind.execute(sa.select(roles.c.id, roles.c.code))}
    permission_ids = {
        row.code: row.id
        for row in bind.execute(
            sa.select(permissions.c.id, permissions.c.code).where(
                permissions.c.code.in_(SCAN_PERMISSIONS)
            )
        )
    }
    bind.execute(
        role_permissions.insert(),
        [
            {"role_id": role_ids[role], "permission_id": permission_ids[permission]}
            for role, grants in SCAN_GRANTS.items()
            for permission in grants
        ],
    )


def downgrade() -> None:
    bind = op.get_bind()
    permissions = sa.table(
        "permissions", sa.column("id", sa.Uuid()), sa.column("code", sa.String())
    )
    role_permissions = sa.table("role_permissions", sa.column("permission_id", sa.Uuid()))
    ids = list(
        bind.execute(
            sa.select(permissions.c.id).where(permissions.c.code.in_(SCAN_PERMISSIONS))
        ).scalars()
    )
    bind.execute(role_permissions.delete().where(role_permissions.c.permission_id.in_(ids)))
    bind.execute(permissions.delete().where(permissions.c.id.in_(ids)))
    op.drop_index("ix_asset_relationships_org_source", table_name="asset_relationships")
    op.drop_table("asset_relationships")
    op.drop_index("ix_assets_org_last_seen", table_name="assets")
    op.drop_index("ix_assets_org_type", table_name="assets")
    op.drop_index("ix_assets_org_account", table_name="assets")
    op.drop_table("assets")
    op.drop_index("ix_scan_jobs_org_status", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_org_created", table_name="scan_jobs")
    op.drop_table("scan_jobs")
