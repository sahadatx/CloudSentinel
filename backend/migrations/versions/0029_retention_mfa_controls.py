"""Enforce tenant MFA and complete offboarding retention boundaries."""

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

import sqlalchemy as sa
from alembic import op

revision: str = "0029_retention_mfa_controls"
down_revision: str | None = "0028_customer_scan_sandbox"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RETENTION_UPDATE = uuid5(NAMESPACE_URL, "cloudsentinel:permission:organization:retention:update")


def upgrade() -> None:
    op.add_column(
        "saml_identity_providers",
        sa.Column("require_mfa", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    # Reports created before retention_until was introduced inherit the tenant's
    # policy in effect at migration time so offboarding cannot erase them early.
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "UPDATE reports AS r SET retention_until = r.created_at + "
            "(o.audit_retention_days * interval '1 day') FROM organizations AS o "
            "WHERE r.organization_id = o.id AND r.retention_until IS NULL"
        )
    else:
        op.execute(
            "UPDATE reports SET retention_until = datetime(created_at, '+' || "
            "(SELECT audit_retention_days FROM organizations WHERE organizations.id = reports.organization_id) "
            "|| ' days') WHERE retention_until IS NULL"
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
                "id": RETENTION_UPDATE,
                "code": "organization:retention:update",
                "description": "Manage the organization's audit retention policy.",
                "created_at": now,
                "updated_at": now,
            }
        ],
    )
    role_ids = dict(op.get_bind().execute(sa.select(roles.c.code, roles.c.id)).all())
    op.bulk_insert(
        role_permissions,
        [
            {"role_id": role_ids[role], "permission_id": RETENTION_UPDATE}
            for role in ("SUPER_ADMIN", "ORG_ADMIN")
        ],
    )


def downgrade() -> None:
    op.execute(
        "DELETE FROM role_permissions WHERE permission_id = "
        f"'{RETENTION_UPDATE}'"
    )
    op.execute(f"DELETE FROM permissions WHERE id = '{RETENTION_UPDATE}'")
    op.drop_column("saml_identity_providers", "require_mfa")
