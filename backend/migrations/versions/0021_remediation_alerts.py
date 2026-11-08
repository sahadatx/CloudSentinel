"""Add verification-aware remediation and tenant-scoped alert records."""

from collections.abc import Sequence
from uuid import NAMESPACE_URL, UUID, uuid5

import sqlalchemy as sa
from alembic import op

revision: str = "0021_remediation_alerts"
down_revision: str | None = "0020_compliance_control_details"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _id(kind: str, code: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"cloudsentinel:{kind}:{code}")


def upgrade() -> None:
    op.drop_index("uq_remediation_requests_one_pending", table_name="remediation_requests")
    op.drop_constraint(
        op.f("ck_remediation_requests_remediation_request_status"),
        "remediation_requests",
        type_="check",
    )
    op.execute(
        "UPDATE remediation_requests SET status = 'PENDING_APPROVAL' WHERE status = 'REQUESTED'"
    )
    op.alter_column(
        "remediation_requests",
        "status",
        existing_type=sa.String(20),
        server_default="PENDING_APPROVAL",
    )
    op.add_column(
        "remediation_requests",
        sa.Column("action_definition", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column("remediation_requests", sa.Column("evidence_id", sa.Uuid(), nullable=True))
    op.add_column(
        "remediation_requests",
        sa.Column(
            "verification_status", sa.String(20), nullable=False, server_default="NOT_STARTED"
        ),
    )
    op.create_foreign_key(
        op.f("fk_remediation_requests_evidence_id_finding_evidence"),
        "remediation_requests",
        "finding_evidence",
        ["evidence_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint(
        op.f("ck_remediation_requests_remediation_request_status"),
        "remediation_requests",
        "status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'CANCELLED', "
        "'VERIFYING', 'COMPLETED', 'FAILED')",
    )
    op.create_check_constraint(
        op.f("ck_remediation_requests_remediation_verification_status"),
        "remediation_requests",
        "verification_status IN ('NOT_STARTED', 'PENDING', 'PASSED', 'FAILED')",
    )
    op.create_index(
        "uq_remediation_requests_one_pending",
        "remediation_requests",
        ["organization_id", "finding_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('PENDING_APPROVAL', 'APPROVED', 'VERIFYING')"),
        sqlite_where=sa.text("status IN ('PENDING_APPROVAL', 'APPROVED', 'VERIFYING')"),
    )

    op.create_table(
        "alert_rules",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(60), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.String(500), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("threshold_score", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "event_type IN ('FINDING_CREATED', 'CRITICAL_FINDING', 'HIGH_RISK_FINDING', "
            "'SCAN_FAILED', 'SCAN_COMPLETED_WITH_ERRORS')",
            name=op.f("ck_alert_rules_alert_rule_event_type"),
        ),
        sa.CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name=op.f("ck_alert_rules_alert_rule_severity"),
        ),
        sa.CheckConstraint(
            "threshold_score IS NULL OR threshold_score BETWEEN 0 AND 100",
            name=op.f("ck_alert_rules_alert_rule_threshold"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_alert_rules_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "code", name=op.f("uq_alert_rules_organization_code")
        ),
    )
    op.create_table(
        "alerts",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_rule_id", sa.Uuid(), nullable=True),
        sa.Column("deduplication_key", sa.String(240), nullable=False),
        sa.Column("alert_type", sa.String(40), nullable=False),
        sa.Column("source_type", sa.String(40), nullable=False),
        sa.Column("source_id", sa.String(100), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), server_default="OPEN", nullable=False),
        sa.Column("occurrence_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("acknowledged_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dismissed_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'DISMISSED')",
            name=op.f("ck_alerts_alert_status"),
        ),
        sa.CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name=op.f("ck_alerts_alert_severity"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_alerts_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["alert_rule_id"],
            ["alert_rules.id"],
            name=op.f("fk_alerts_alert_rule_id_alert_rules"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["acknowledged_by_user_id"],
            ["users.id"],
            name=op.f("fk_alerts_acknowledged_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["resolved_by_user_id"],
            ["users.id"],
            name=op.f("fk_alerts_resolved_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["dismissed_by_user_id"],
            ["users.id"],
            name=op.f("fk_alerts_dismissed_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "deduplication_key",
            name=op.f("uq_alerts_organization_deduplication"),
        ),
    )
    op.create_index(
        "ix_alerts_org_status_created", "alerts", ["organization_id", "status", "created_at"]
    )
    op.create_index(
        "ix_alerts_org_source", "alerts", ["organization_id", "source_type", "source_id"]
    )

    bind = op.get_bind()
    roles = sa.table("roles", sa.column("id", sa.Uuid()), sa.column("code", sa.String()))
    permissions = sa.table(
        "permissions",
        sa.column("id", sa.Uuid()),
        sa.column("code", sa.String()),
        sa.column("description", sa.String()),
    )
    role_permissions = sa.table(
        "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
    )
    bind.execute(
        permissions.insert(),
        [
            {
                "id": _id("permission", code),
                "code": code,
                "description": description,
            }
            for code, description in (
                ("alerts:read", "View organization security alerts and alert rules."),
                ("alerts:manage", "Acknowledge, resolve, dismiss, and configure alert rules."),
            )
        ],
    )
    read_id = _id("permission", "alerts:read")
    manage_id = _id("permission", "alerts:manage")
    role_rows = bind.execute(sa.select(roles.c.id, roles.c.code)).all()
    grants: dict[str, set[str]] = {
        "SUPER_ADMIN": {"alerts:read", "alerts:manage"},
        "ORG_ADMIN": {"alerts:read", "alerts:manage"},
        "SECURITY_ADMIN": {"alerts:read", "alerts:manage"},
        "SECURITY_ANALYST": {"alerts:read", "alerts:manage"},
        "CLOUD_ENGINEER": {"alerts:read"},
        "AUDITOR": {"alerts:read"},
        "VIEWER": {"alerts:read"},
    }
    bind.execute(
        role_permissions.insert(),
        [
            {
                "role_id": role_id,
                "permission_id": manage_id if code == "alerts:manage" else read_id,
            }
            for role_id, role_code in role_rows
            for code in grants.get(role_code, set())
        ],
    )


def downgrade() -> None:
    permissions = sa.table("permissions", sa.column("id", sa.Uuid()))
    bind = op.get_bind()
    role_permissions = sa.table(
        "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
    )
    for code in ("alerts:read", "alerts:manage"):
        permission_id = _id("permission", code)
        bind.execute(
            role_permissions.delete().where(role_permissions.c.permission_id == permission_id)
        )
        bind.execute(permissions.delete().where(permissions.c.id == permission_id))
    op.drop_index("ix_alerts_org_source", table_name="alerts")
    op.drop_index("ix_alerts_org_status_created", table_name="alerts")
    op.drop_table("alerts")
    op.drop_table("alert_rules")
    op.drop_index("uq_remediation_requests_one_pending", table_name="remediation_requests")
    op.drop_constraint(
        op.f("ck_remediation_requests_remediation_verification_status"),
        "remediation_requests",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_remediation_requests_remediation_request_status"),
        "remediation_requests",
        type_="check",
    )
    op.drop_constraint(
        op.f("fk_remediation_requests_evidence_id_finding_evidence"),
        "remediation_requests",
        type_="foreignkey",
    )
    op.drop_column("remediation_requests", "verification_status")
    op.drop_column("remediation_requests", "evidence_id")
    op.drop_column("remediation_requests", "action_definition")
    op.execute(
        "UPDATE remediation_requests SET status = 'REQUESTED' WHERE status = 'PENDING_APPROVAL'"
    )
    op.execute("UPDATE remediation_requests SET status = 'APPROVED' WHERE status = 'COMPLETED'")
    op.execute(
        "UPDATE remediation_requests SET status = 'REJECTED' "
        "WHERE status IN ('CANCELLED', 'VERIFYING', 'FAILED')"
    )
    op.alter_column(
        "remediation_requests",
        "status",
        existing_type=sa.String(20),
        server_default="REQUESTED",
    )
    op.create_check_constraint(
        op.f("ck_remediation_requests_remediation_request_status"),
        "remediation_requests",
        "status IN ('REQUESTED', 'APPROVED', 'REJECTED')",
    )
    op.create_index(
        "uq_remediation_requests_one_pending",
        "remediation_requests",
        ["organization_id", "finding_id"],
        unique=True,
        postgresql_where=sa.text("status = 'REQUESTED'"),
        sqlite_where=sa.text("status = 'REQUESTED'"),
    )
