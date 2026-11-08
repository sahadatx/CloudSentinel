"""Add tenant SAML/SCIM configuration and enforceable retention/offboarding state."""

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

import sqlalchemy as sa
from alembic import op

revision: str = "0027_enterprise_id_retention"
down_revision: str | None = "0026_report_storage_version"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

IDENTITY_MANAGE = uuid5(NAMESPACE_URL, "cloudsentinel:permission:identity:manage")
ORGANIZATION_OFFBOARD = uuid5(NAMESPACE_URL, "cloudsentinel:permission:organization:offboard")


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("audit_retention_days", sa.Integer(), nullable=False, server_default="365"),
    )
    op.add_column("organizations", sa.Column("offboarding_at", sa.DateTime(timezone=True)))
    op.add_column("organizations", sa.Column("purge_after", sa.DateTime(timezone=True)))
    op.add_column(
        "organizations",
        sa.Column("offboarding_requested_by", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        op.f("fk_organizations_offboarding_requested_by_users"),
        "organizations",
        "users",
        ["offboarding_requested_by"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint(
        op.f("ck_organizations_audit_retention_days"),
        "organizations",
        "audit_retention_days BETWEEN 30 AND 3650",
    )

    op.add_column("memberships", sa.Column("scim_external_id", sa.String(200)))
    op.add_column(
        "memberships",
        sa.Column("provisioning_source", sa.String(20), nullable=False, server_default="native"),
    )
    op.add_column("memberships", sa.Column("pre_scim_role_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("fk_memberships_pre_scim_role_id_roles"),
        "memberships",
        "roles",
        ["pre_scim_role_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint(
        op.f("ck_memberships_provisioning_source"),
        "memberships",
        "provisioning_source IN ('native', 'scim', 'saml')",
    )
    op.create_index(
        "uq_memberships_org_scim_external_id",
        "memberships",
        ["organization_id", "scim_external_id"],
        unique=True,
        postgresql_where=sa.text("scim_external_id IS NOT NULL"),
        sqlite_where=sa.text("scim_external_id IS NOT NULL"),
    )

    op.create_table(
        "saml_identity_providers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("metadata_xml", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("enforce_sso", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("jit_provisioning", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("default_role_code", sa.String(40), nullable=False, server_default="VIEWER"),
        sa.Column("email_attribute", sa.String(200), nullable=False, server_default="email"),
        sa.Column("name_attribute", sa.String(200), nullable=False, server_default="name"),
        sa.Column("mfa_contexts", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "default_role_code IN ('ORG_ADMIN', 'SECURITY_ADMIN', 'SECURITY_ANALYST', "
            "'CLOUD_ENGINEER', 'AUDITOR', 'VIEWER')",
            name=op.f("ck_saml_identity_providers_safe_default_role"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", name=op.f("uq_saml_identity_providers_organization_id")
        ),
    )

    op.create_table(
        "scim_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("token_digest", sa.String(64), nullable=False),
        sa.Column("description", sa.String(200), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_digest", name=op.f("uq_scim_tokens_token_digest")),
    )
    op.create_index("ix_scim_tokens_organization_id", "scim_tokens", ["organization_id"])

    op.create_table(
        "scim_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "external_id", name=op.f("uq_scim_groups_org_external_id")
        ),
    )

    op.create_table(
        "scim_group_memberships",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("membership_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["group_id"], ["scim_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["membership_id"], ["memberships.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("group_id", "membership_id"),
        sa.UniqueConstraint(
            "organization_id",
            "group_id",
            "membership_id",
            name=op.f("uq_scim_group_memberships_scope"),
        ),
    )

    op.add_column(
        "compliance_frameworks",
        sa.Column("coverage_status", sa.String(20), nullable=False, server_default="UNVERIFIED"),
    )
    op.add_column("compliance_frameworks", sa.Column("source_url", sa.String(500)))
    op.create_check_constraint(
        op.f("ck_compliance_frameworks_coverage_status"),
        "compliance_frameworks",
        "coverage_status IN ('UNVERIFIED', 'PARTIAL', 'VERIFIED')",
    )
    op.execute(
        "UPDATE compliance_frameworks SET version = '7.1.0', is_active = "
        "CASE WHEN code = 'CIS_AWS_FOUNDATIONS' THEN false ELSE is_active END, "
        "coverage_status = CASE WHEN code = 'CIS_AWS_FOUNDATIONS' THEN 'UNVERIFIED' "
        "ELSE coverage_status END, source_url = CASE WHEN code = 'CIS_AWS_FOUNDATIONS' "
        "THEN 'https://www.cisecurity.org/benchmark/amazon-web-services' ELSE source_url END "
        "WHERE code = 'CIS_AWS_FOUNDATIONS'"
    )
    _allow_audit_retention_backfill()
    op.execute(
        "UPDATE audit_events SET retention_until = created_at + interval '365 days' "
        "WHERE retention_until IS NULL"
        if op.get_bind().dialect.name == "postgresql"
        else "UPDATE audit_events SET retention_until = datetime(created_at, '+365 days') "
        "WHERE retention_until IS NULL"
    )

    permissions = sa.table(
        "permissions",
        sa.column("id", sa.Uuid()),
        sa.column("code", sa.String()),
        sa.column("description", sa.String()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    role_permissions = sa.table(
        "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
    )
    roles = sa.table("roles", sa.column("id", sa.Uuid()), sa.column("code", sa.String()))
    now = datetime.now(UTC)
    op.bulk_insert(
        permissions,
        [
            {
                "id": IDENTITY_MANAGE,
                "code": "identity:manage",
                "description": "Manage organization SAML and SCIM identity configuration.",
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": ORGANIZATION_OFFBOARD,
                "code": "organization:offboard",
                "description": "Deactivate and schedule organization data erasure.",
                "created_at": now,
                "updated_at": now,
            },
        ],
    )
    role_ids = dict(op.get_bind().execute(sa.select(roles.c.code, roles.c.id)).all())
    op.bulk_insert(
        role_permissions,
        [
            {"role_id": role_ids[role], "permission_id": permission_id}
            for role in ("SUPER_ADMIN", "ORG_ADMIN")
            for permission_id in (IDENTITY_MANAGE, ORGANIZATION_OFFBOARD)
        ],
    )

    _install_retention_guard()


def _install_retention_guard() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        op.execute(
            "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END"
        )
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_delete")
        op.execute(
            "CREATE TRIGGER audit_events_retention_delete BEFORE DELETE ON audit_events "
            "WHEN OLD.retention_until IS NULL OR OLD.retention_until > CURRENT_TIMESTAMP "
            "BEGIN SELECT RAISE(ABORT, 'audit events cannot be deleted before retention expiry'); END"
        )
        return
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_mutation ON audit_events")
        op.execute("DROP FUNCTION IF EXISTS prevent_audit_event_mutation()")
        op.execute(
            "CREATE FUNCTION prevent_audit_event_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN IF TG_OP = 'UPDATE' THEN RAISE EXCEPTION 'audit events are immutable'; END IF; "
            "IF current_setting('cloudsentinel.retention_purge', true) IS DISTINCT FROM 'on' "
            "OR OLD.retention_until IS NULL OR OLD.retention_until > now() THEN "
            "RAISE EXCEPTION 'audit event retention has not expired'; END IF; RETURN OLD; END; $$"
        )
        op.execute(
            "CREATE TRIGGER audit_events_no_mutation BEFORE UPDATE OR DELETE ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation()"
        )


def _allow_audit_retention_backfill() -> None:
    """Temporarily permit only a NULL-to-deadline audit field backfill."""
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        # SQLite has no transaction-local trigger context; the migration transaction
        # drops and reinstalls this trigger before it commits.
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        return
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_mutation ON audit_events")
        op.execute("DROP FUNCTION IF EXISTS prevent_audit_event_mutation()")
        op.execute(
            "CREATE FUNCTION prevent_audit_event_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN IF TG_OP = 'UPDATE' THEN "
            "IF current_setting('cloudsentinel.retention_backfill', true) = 'on' "
            "AND OLD.retention_until IS NULL AND NEW.retention_until IS NOT NULL "
            "AND (to_jsonb(OLD) - 'retention_until') = (to_jsonb(NEW) - 'retention_until') "
            "THEN RETURN NEW; END IF; "
            "RAISE EXCEPTION 'audit events are immutable'; END IF; "
            "IF current_setting('cloudsentinel.retention_purge', true) IS DISTINCT FROM 'on' "
            "OR OLD.retention_until IS NULL OR OLD.retention_until > now() THEN "
            "RAISE EXCEPTION 'audit event retention has not expired'; END IF; "
            "RETURN OLD; END; $$"
        )
        op.execute(
            "CREATE TRIGGER audit_events_no_mutation BEFORE UPDATE OR DELETE ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation()"
        )
        op.execute("SET LOCAL cloudsentinel.retention_backfill = 'on'")


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_events_retention_delete")
        op.execute(
            "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END"
        )
    elif dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_mutation ON audit_events")
        op.execute("DROP FUNCTION IF EXISTS prevent_audit_event_mutation()")
        op.execute(
            "CREATE FUNCTION prevent_audit_event_mutation() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are immutable'; END; $$"
        )
        op.execute(
            "CREATE TRIGGER audit_events_no_mutation BEFORE UPDATE OR DELETE ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation()"
        )
    op.execute(
        "UPDATE compliance_frameworks SET version = '1.0', is_active = true, "
        "source_url = NULL WHERE code = 'CIS_AWS_FOUNDATIONS'"
    )
    op.drop_constraint(
        op.f("ck_compliance_frameworks_coverage_status"),
        "compliance_frameworks",
        type_="check",
    )
    op.drop_column("compliance_frameworks", "source_url")
    op.drop_column("compliance_frameworks", "coverage_status")
    op.drop_table("scim_group_memberships")
    op.drop_table("scim_groups")
    op.drop_index("ix_scim_tokens_organization_id", table_name="scim_tokens")
    op.drop_table("scim_tokens")
    op.drop_table("saml_identity_providers")
    op.drop_index("uq_memberships_org_scim_external_id", table_name="memberships")
    op.drop_constraint(
        op.f("ck_memberships_provisioning_source"), "memberships", type_="check"
    )
    op.drop_constraint(
        op.f("fk_memberships_pre_scim_role_id_roles"), "memberships", type_="foreignkey"
    )
    op.drop_column("memberships", "pre_scim_role_id")
    op.drop_column("memberships", "provisioning_source")
    op.drop_column("memberships", "scim_external_id")
    op.drop_constraint(
        op.f("ck_organizations_audit_retention_days"), "organizations", type_="check"
    )
    op.drop_constraint(
        op.f("fk_organizations_offboarding_requested_by_users"),
        "organizations",
        type_="foreignkey",
    )
    op.drop_column("organizations", "offboarding_requested_by")
    op.drop_column("organizations", "purge_after")
    op.drop_column("organizations", "offboarding_at")
    op.drop_column("organizations", "audit_retention_days")
    op.get_bind().execute(
        sa.text("DELETE FROM role_permissions WHERE permission_id IN (:identity, :offboard)").bindparams(
            identity=IDENTITY_MANAGE, offboard=ORGANIZATION_OFFBOARD
        )
    )
    op.get_bind().execute(
        sa.text("DELETE FROM permissions WHERE id IN (:identity, :offboard)").bindparams(
            identity=IDENTITY_MANAGE, offboard=ORGANIZATION_OFFBOARD
        )
    )
