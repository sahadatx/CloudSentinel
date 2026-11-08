"""Pin report downloads to the S3 object version that was verified at generation."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026_report_storage_version"
down_revision: str | None = "0025_user_mfa"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("reports", sa.Column("storage_version_id", sa.String(length=1024)))


def downgrade() -> None:
    op.drop_column("reports", "storage_version_id")
