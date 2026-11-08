"""Add request context and immutable event details to canonical audit records."""

from collections.abc import Sequence
from uuid import NAMESPACE_URL, uuid5

import sqlalchemy as sa
from alembic import op

revision: str = "0023_audit_event_context"
down_revision: str | None = "0022_report_generation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_constraint(
            op.f("fk_audit_events_actor_user_id_users"), type_="foreignkey"
        )
    op.add_column(
        "audit_events",
        sa.Column("actor_type", sa.String(20), server_default="USER", nullable=False),
    )
    op.add_column(
        "audit_events",
        sa.Column("actor_name", sa.String(200), server_default="System", nullable=False),
    )
    op.add_column("audit_events", sa.Column("actor_role", sa.String(40)))
    op.add_column("audit_events", sa.Column("target_type", sa.String(80)))
    op.add_column("audit_events", sa.Column("target_id", sa.String(100)))
    op.add_column(
        "audit_events", sa.Column("status", sa.String(20), server_default="SUCCESS", nullable=False)
    )
    op.add_column("audit_events", sa.Column("ip_address", sa.String(64)))
    op.add_column("audit_events", sa.Column("user_agent", sa.String(512)))
    op.add_column("audit_events", sa.Column("request_id", sa.String(100)))
    op.add_column("audit_events", sa.Column("before", sa.JSON()))
    op.add_column("audit_events", sa.Column("after", sa.JSON()))
    op.add_column("audit_events", sa.Column("retention_until", sa.DateTime(timezone=True)))
    op.execute("UPDATE audit_events SET target_type = resource_type, target_id = resource_id")
    op.execute(
        "UPDATE audit_events SET action = upper(replace(replace(action, '.', '_'), '-', '_'))"
    )
    op.execute(
        "UPDATE audit_events SET actor_type = "
        "CASE WHEN actor_user_id IS NULL THEN 'SYSTEM' ELSE 'USER' END"
    )
    op.execute(
        "UPDATE audit_events SET actor_name = coalesce((SELECT display_name "
        "FROM users WHERE users.id = audit_events.actor_user_id), 'System')"
    )
    op.create_check_constraint(
        op.f("ck_audit_events_actor_type"),
        "audit_events",
        "actor_type IN ('USER', 'SYSTEM', 'WORKER', 'SERVICE')",
    )
    op.create_check_constraint(
        op.f("ck_audit_events_status"), "audit_events", "status IN ('SUCCESS', 'FAILURE')"
    )
    op.create_index(
        "ix_audit_events_org_actor_created",
        "audit_events",
        ["organization_id", "actor_user_id", "created_at"],
    )
    op.create_index(
        "ix_audit_events_org_action_created",
        "audit_events",
        ["organization_id", "action", "created_at"],
    )
    op.create_index(
        "ix_audit_events_org_resource",
        "audit_events",
        ["organization_id", "resource_type", "resource_id"],
    )
    op.create_index(
        "ix_audit_events_org_status_created",
        "audit_events",
        ["organization_id", "status", "created_at"],
    )

    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(
            "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END"
        )
        op.execute(
            "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END"
        )
    elif dialect == "postgresql":
        op.execute(
            "CREATE FUNCTION prevent_audit_event_mutation() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are immutable'; END; $$"
        )
        op.execute(
            "CREATE TRIGGER audit_events_no_mutation BEFORE UPDATE OR DELETE ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation()"
        )

    permission_id = uuid5(NAMESPACE_URL, "cloudsentinel:permission:audit:export")
    op.execute(
        sa.text(
            "INSERT INTO permissions (id, code, description) VALUES "
            "(:id, 'audit:export', 'Export organization audit records.')"
        ).bindparams(id=permission_id)
    )
    rows = [
        {
            "role_id": uuid5(NAMESPACE_URL, f"cloudsentinel:role:{role}"),
            "permission_id": permission_id,
        }
        for role in ("SUPER_ADMIN", "ORG_ADMIN", "SECURITY_ADMIN", "AUDITOR")
    ]
    op.bulk_insert(
        sa.table(
            "role_permissions",
            sa.column("role_id", sa.Uuid()),
            sa.column("permission_id", sa.Uuid()),
        ),
        rows,
    )


def downgrade() -> None:
    permission_id = str(uuid5(NAMESPACE_URL, "cloudsentinel:permission:audit:export"))
    op.execute(
        sa.text("DELETE FROM role_permissions WHERE permission_id = :permission_id").bindparams(
            permission_id=permission_id
        )
    )
    op.execute("DELETE FROM permissions WHERE code = 'audit:export'")
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER audit_events_no_update")
        op.execute("DROP TRIGGER audit_events_no_delete")
    elif dialect == "postgresql":
        op.execute("DROP TRIGGER audit_events_no_mutation ON audit_events")
        op.execute("DROP FUNCTION prevent_audit_event_mutation()")
    op.drop_index("ix_audit_events_org_status_created", table_name="audit_events")
    op.drop_index("ix_audit_events_org_resource", table_name="audit_events")
    op.drop_index("ix_audit_events_org_action_created", table_name="audit_events")
    op.drop_index("ix_audit_events_org_actor_created", table_name="audit_events")
    op.drop_constraint(op.f("ck_audit_events_status"), "audit_events", type_="check")
    op.drop_constraint(op.f("ck_audit_events_actor_type"), "audit_events", type_="check")
    for column in (
        "retention_until",
        "after",
        "before",
        "request_id",
        "user_agent",
        "ip_address",
        "status",
        "target_id",
        "target_type",
        "actor_role",
        "actor_name",
        "actor_type",
    ):
        op.drop_column("audit_events", column)
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.create_foreign_key(
            op.f("fk_audit_events_actor_user_id_users"),
            "users",
            ["actor_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
