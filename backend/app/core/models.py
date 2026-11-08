"""Identity, tenant management, scan-job, and normalized inventory models."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TenantOwned

LOCKED_ROLE_CODES = (
    "SUPER_ADMIN",
    "ORG_ADMIN",
    "SECURITY_ADMIN",
    "SECURITY_ANALYST",
    "CLOUD_ENGINEER",
    "AUDITOR",
    "VIEWER",
)


def utc_now() -> datetime:
    """Return an aware UTC timestamp for application-side updates."""
    return datetime.now(UTC)


class TimestampMixin:
    """Standard created/updated timestamp columns."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
    )


class Organization(TimestampMixin, Base):
    """Organization root for tenant-owned CloudSentinel data."""

    __tablename__ = "organizations"
    __table_args__ = (
        CheckConstraint(
            "password_min_length BETWEEN 12 AND 128 "
            "AND session_ttl_days BETWEEN 1 AND 30 "
            "AND remembered_session_ttl_days BETWEEN session_ttl_days AND 90 "
            "AND max_concurrent_sessions BETWEEN 1 AND 50",
            name="security_settings_bounds",
        ),
        CheckConstraint(
            "date_time_format IN ('YYYY-MM-DD HH:mm', 'MM/DD/YYYY hh:mm A', 'DD/MM/YYYY HH:mm')",
            name="date_time_format_supported",
        ),
        CheckConstraint(
            "audit_retention_days BETWEEN 30 AND 3650", name="audit_retention_days"
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(String(1000))
    default_environment: Mapped[str | None] = mapped_column(String(80))
    default_region: Mapped[str | None] = mapped_column(String(40))
    timezone: Mapped[str] = mapped_column(
        String(64), nullable=False, default="UTC", server_default="UTC"
    )
    date_time_format: Mapped[str] = mapped_column(
        String(32), nullable=False, default="YYYY-MM-DD HH:mm", server_default="YYYY-MM-DD HH:mm"
    )
    password_min_length: Mapped[int] = mapped_column(
        Integer, nullable=False, default=12, server_default="12"
    )
    session_ttl_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=7, server_default="7"
    )
    remembered_session_ttl_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30, server_default="30"
    )
    max_concurrent_sessions: Mapped[int] = mapped_column(
        Integer, nullable=False, default=5, server_default="5"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    audit_retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=365, server_default="365"
    )
    offboarding_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    purge_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    offboarding_requested_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class User(TimestampMixin, Base):
    """Global login identity; organization access is granted through memberships."""

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    force_password_change: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UserMfa(TimestampMixin, Base):
    """Encrypted TOTP credential and one-time recovery-code digests for an identity."""

    __tablename__ = "user_mfa"
    __table_args__ = (
        CheckConstraint("is_enabled IN (true, false)", name="user_mfa_enabled"),
        CheckConstraint(
            "last_totp_counter IS NULL OR last_totp_counter >= 0",
            name="user_mfa_counter",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    secret_ciphertext: Mapped[str] = mapped_column(String(255), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_totp_counter: Mapped[int | None] = mapped_column(Integer)
    recovery_code_digests: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class Role(TimestampMixin, Base):
    """One of the seven specification-locked roles."""

    __tablename__ = "roles"
    __table_args__ = (
        CheckConstraint(
            "code IN ('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'SECURITY_ANALYST', "
            "'CLOUD_ENGINEER', 'AUDITOR', 'VIEWER')",
            name="locked_role_codes",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String(300), nullable=False)
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )


class Permission(TimestampMixin, Base):
    """Catalog entry for a resource/action authorization grant."""

    __tablename__ = "permissions"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String(300), nullable=False)


class Membership(TenantOwned, TimestampMixin, Base):
    """User membership and role assignment in one tenant organization."""

    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id"),
        CheckConstraint(
            "provisioning_source IN ('native', 'scim', 'saml')", name="provisioning_source"
        ),
        Index(
            "uq_memberships_org_scim_external_id",
            "organization_id",
            "scim_external_id",
            unique=True,
            postgresql_where=text("scim_external_id IS NOT NULL"),
            sqlite_where=text("scim_external_id IS NOT NULL"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    is_locked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lock_reason: Mapped[str | None] = mapped_column(String(500))
    scim_external_id: Mapped[str | None] = mapped_column(String(200))
    provisioning_source: Mapped[str] = mapped_column(
        String(20), nullable=False, default="native", server_default="native"
    )
    pre_scim_role_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("roles.id", ondelete="SET NULL")
    )


class SamlIdentityProvider(TimestampMixin, Base):
    """One tenant's administrator-supplied, signed-assertion SAML connection."""

    __tablename__ = "saml_identity_providers"
    __table_args__ = (
        CheckConstraint(
            "default_role_code IN ('ORG_ADMIN', 'SECURITY_ADMIN', 'SECURITY_ANALYST', "
            "'CLOUD_ENGINEER', 'AUDITOR', 'VIEWER')",
            name="safe_default_role",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    metadata_xml: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    enforce_sso: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    jit_provisioning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    require_mfa: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    default_role_code: Mapped[str] = mapped_column(String(40), nullable=False, default="VIEWER", server_default="VIEWER")
    email_attribute: Mapped[str] = mapped_column(String(200), nullable=False, default="email", server_default="email")
    name_attribute: Mapped[str] = mapped_column(String(200), nullable=False, default="name", server_default="name")
    mfa_contexts: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list, server_default="[]")


class ScimToken(TimestampMixin, Base):
    """Hash-only bearer credential for one tenant's SCIM 2.0 endpoint."""

    __tablename__ = "scim_tokens"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String(200), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScimGroup(TenantOwned, TimestampMixin, Base):
    """Administrator-mapped SCIM group; a group can grant only one locked role."""

    __tablename__ = "scim_groups"
    __table_args__ = (UniqueConstraint("organization_id", "external_id"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")


class ScimGroupMembership(TenantOwned, Base):
    """Tenant-scoped SCIM group membership link."""

    __tablename__ = "scim_group_memberships"
    __table_args__ = (UniqueConstraint("organization_id", "group_id", "membership_id"),)

    group_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scim_groups.id", ondelete="CASCADE"), primary_key=True
    )
    membership_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("memberships.id", ondelete="CASCADE"), primary_key=True
    )


class RolePermission(Base):
    """Many-to-many grants between the locked role catalog and permissions."""

    __tablename__ = "role_permissions"

    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )


class RefreshSession(TenantOwned, TimestampMixin, Base):
    """A revocable authentication session with an absolute expiration."""

    __tablename__ = "refresh_sessions"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    membership_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("memberships.id", ondelete="CASCADE"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    remember_session: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )


class RefreshToken(TenantOwned, Base):
    """One-time refresh token digest; plaintext values are never persisted."""

    __tablename__ = "refresh_tokens"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("refresh_sessions.id", ondelete="CASCADE"), nullable=False
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )


class PasswordResetToken(Base):
    """One-time password-recovery token digest; plaintext exists only in email delivery."""

    __tablename__ = "password_reset_tokens"
    __table_args__ = (Index("ix_password_reset_tokens_user_expires", "user_id", "expires_at"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )


class UserInvitation(TenantOwned, TimestampMixin, Base):
    """Single-use, tenant-bound invitation; only its digest is persisted."""

    __tablename__ = "user_invitations"
    __table_args__ = (UniqueConstraint("organization_id", "email"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False
    )
    invited_by_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Team(TenantOwned, TimestampMixin, Base):
    """Organization-owned team container."""

    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )


class TeamMembership(TenantOwned, TimestampMixin, Base):
    """Tenant-scoped link between an organization team and its user."""

    __tablename__ = "team_memberships"
    __table_args__ = (UniqueConstraint("organization_id", "team_id", "user_id"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    team_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("teams.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )


class CloudAccount(TenantOwned, TimestampMixin, Base):
    """AWS account connection metadata; no long-lived AWS credentials are stored."""

    __tablename__ = "cloud_accounts"
    __table_args__ = (
        UniqueConstraint("organization_id", "account_id"),
        CheckConstraint(
            "validation_mode IS NULL OR validation_mode IN ('real', 'mock')",
            name="cloud_account_validation_mode",
        ),
        CheckConstraint(
            "connection_status IN ('pending', 'connected', 'error', 'disabled')",
            name="cloud_account_connection_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    environment: Mapped[str | None] = mapped_column(String(80))
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    role_arn: Mapped[str | None] = mapped_column(String(512))
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    primary_region: Mapped[str | None] = mapped_column(String(40))
    connection_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending", server_default="pending"
    )
    validation_mode: Mapped[str | None] = mapped_column(String(12))
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(80))
    regions: Mapped[list["CloudRegion"]] = relationship(
        back_populates="cloud_account", cascade="all, delete-orphan", passive_deletes=True
    )


class CloudRegion(TenantOwned, TimestampMixin, Base):
    """Configured AWS region for one organization-owned cloud account."""

    __tablename__ = "cloud_regions"
    __table_args__ = (UniqueConstraint("organization_id", "cloud_account_id", "region_code"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    cloud_account_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    region_code: Mapped[str] = mapped_column(String(40), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    cloud_account: Mapped[CloudAccount] = relationship(back_populates="regions")


class ScanJob(TenantOwned, TimestampMixin, Base):
    """Tenant-bound asynchronous AWS collection request and current progress."""

    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'cancelling', 'completed', 'partial', 'failed', "
            "'cancelled')",
            name="scan_job_status",
        ),
        CheckConstraint(
            "progress_total >= 0 AND progress_completed >= 0",
            name="scan_progress_nonnegative",
        ),
        CheckConstraint(
            "progress_completed <= progress_total OR progress_total = 0",
            name="scan_progress_bounded",
        ),
        CheckConstraint("attempt_count >= 0", name="scan_job_attempt_count"),
        Index("ix_scan_jobs_org_created", "organization_id", "created_at"),
        Index("ix_scan_jobs_org_status", "organization_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    cloud_account_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="RESTRICT"), nullable=False
    )
    requested_by_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    requested_by_membership_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("memberships.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    requested_regions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    requested_resource_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    progress_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_completed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resources_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    error_codes: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TaskOutbox(TimestampMixin, Base):
    """Durable, tenant-linked intent to publish one asynchronous task."""

    __tablename__ = "task_outbox"
    __table_args__ = (
        CheckConstraint(
            "task_type IN ('cloudsentinel.scan_jobs.process', "
            "'cloudsentinel.reports.generate', 'cloudsentinel.customer_scans.run')",
            name="task_outbox_type",
        ),
        CheckConstraint(
            "status IN ('pending', 'dispatching', 'dispatched', 'dead')",
            name="task_outbox_status",
        ),
        CheckConstraint("attempt_count >= 0", name="task_outbox_attempt_count"),
        UniqueConstraint(
            "organization_id", "task_type", "aggregate_id", name="uq_task_outbox_aggregate"
        ),
        Index("ix_task_outbox_delivery", "status", "available_at", "claimed_until"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    task_type: Mapped[str] = mapped_column(String(80), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending", server_default="pending"
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    claimed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claim_token: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dead_lettered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(80))


class Asset(TenantOwned, TimestampMixin, Base):
    """Normalized provider-neutral cloud resource record."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "cloud_account_id",
            "resource_type",
            "region_code",
            "resource_id",
        ),
        Index("ix_assets_org_account", "organization_id", "cloud_account_id"),
        Index("ix_assets_org_type", "organization_id", "resource_type"),
        Index("ix_assets_org_last_seen", "organization_id", "last_seen_at"),
        Index("ix_assets_org_status", "organization_id", "status"),
        CheckConstraint("status IN ('active', 'stale', 'removed')", name="asset_status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    cloud_account_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    last_scan_job_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    provider: Mapped[str] = mapped_column(String(20), nullable=False, default="AWS")
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    resource_arn: Mapped[str | None] = mapped_column(String(1024))
    region_code: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str | None] = mapped_column(String(512))
    tags: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    owner_metadata: Mapped[dict[str, str] | None] = mapped_column(JSON)
    attributes: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active"
    )
    missed_scan_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )


class AssetRelationship(TenantOwned, TimestampMixin, Base):
    """Tenant-owned edge between two normalized assets."""

    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "source_asset_id", "target_asset_id", "relationship_type"
        ),
        Index("ix_asset_relationships_org_source", "organization_id", "source_asset_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    source_asset_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    target_asset_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(80), nullable=False)


class PolicyDefinition(TenantOwned, TimestampMixin, Base):
    """Tenant policy registry entry evaluated against normalized assets."""

    __tablename__ = "policy_definitions"
    __table_args__ = (
        UniqueConstraint("organization_id", "rule_id"),
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')",
            name="policy_severity",
        ),
        CheckConstraint("status IN ('enabled', 'disabled')", name="policy_status"),
        CheckConstraint("version >= 1", name="policy_version_positive"),
        Index("ix_policy_definitions_org_status", "organization_id", "status"),
        Index("ix_policy_definitions_org_category", "organization_id", "category"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), nullable=False)
    provider: Mapped[str] = mapped_column(String(20), nullable=False, default="AWS")
    resource_types: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="enabled")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    detection_logic: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    evidence_logic: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    remediation: Mapped[str] = mapped_column(String(2000), nullable=False)
    compliance_controls: Mapped[list[dict[str, str]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class PolicyVersion(TenantOwned, Base):
    """Immutable, tenant-owned snapshot of one policy definition version."""

    __tablename__ = "policy_versions"
    __table_args__ = (
        UniqueConstraint("organization_id", "policy_id", "version"),
        Index("ix_policy_versions_org_policy", "organization_id", "policy_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("policy_definitions.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    changed_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )


class PolicyAssessment(TenantOwned, Base):
    """Per-scan policy result; deliberately separate from finding lifecycle."""

    __tablename__ = "policy_assessments"
    __table_args__ = (
        UniqueConstraint("organization_id", "policy_id", "asset_id", "scan_job_id"),
        CheckConstraint(
            "result IN ('PASS', 'FAIL', 'NOT_APPLICABLE', 'ERROR')",
            name="policy_assessment_result",
        ),
        Index("ix_policy_assessments_org_policy", "organization_id", "policy_id"),
        Index("ix_policy_assessments_org_asset", "organization_id", "asset_id"),
        Index("ix_policy_assessments_org_scan", "organization_id", "scan_job_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("policy_definitions.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    result: Mapped[str] = mapped_column(String(24), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(80))
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )


class PolicyAssessmentEvidence(TenantOwned, Base):
    """Expected and observed canonical configuration captured for an assessment."""

    __tablename__ = "policy_assessment_evidence"
    __table_args__ = (
        UniqueConstraint("organization_id", "assessment_id"),
        Index("ix_policy_assessment_evidence_org_assessment", "organization_id", "assessment_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("policy_assessments.id", ondelete="CASCADE"), nullable=False
    )
    expected_state: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    observed_state: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )


class Finding(TenantOwned, TimestampMixin, Base):
    """Security condition detected by a versioned policy against one asset."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("organization_id", "asset_id", "rule_id"),
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')",
            name="finding_severity",
        ),
        CheckConstraint(
            "status IN ('OPEN', 'TRIAGED', 'ASSIGNED', 'IN_PROGRESS', 'RESOLVED', "
            "'VERIFIED', 'CLOSED', 'SUPPRESSED')",
            name="finding_status",
        ),
        Index("ix_findings_org_status_severity", "organization_id", "status", "severity"),
        Index("ix_findings_org_account", "organization_id", "cloud_account_id"),
        Index("ix_findings_org_asset", "organization_id", "asset_id"),
        Index("ix_findings_org_due_at", "organization_id", "due_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    cloud_account_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="RESTRICT"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(40), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), nullable=False)
    remediation: Mapped[str] = mapped_column(String(2000), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    region_code: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN")
    assigned_to_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    suppression_reason: Mapped[str | None] = mapped_column(String(1000))
    suppressed_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    suppression_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FindingEvent(TenantOwned, TimestampMixin, Base):
    """Append-only lifecycle record for status, assignment, or suppression changes."""

    __tablename__ = "finding_events"
    __table_args__ = (Index("ix_finding_events_org_finding", "organization_id", "finding_id"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    actor_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(20))
    to_status: Mapped[str | None] = mapped_column(String(20))
    reason: Mapped[str | None] = mapped_column(String(1000))
    details: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class FindingEvidence(TenantOwned, Base):
    """Redacted, scan-linked observation supporting a finding."""

    __tablename__ = "finding_evidence"
    __table_args__ = (
        UniqueConstraint("organization_id", "finding_id", "scan_job_id"),
        Index("ix_finding_evidence_org_finding", "organization_id", "finding_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    rule_version: Mapped[str] = mapped_column(String(40), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(40), nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False, default="AWS API")
    expected_state: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    detected_condition: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    configuration: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )


class CustomerScanJob(TenantOwned, TimestampMixin, Base):
    """Customer-uploaded IaC or image assessment, executed in isolated Fargate."""

    __tablename__ = "customer_scan_jobs"
    __table_args__ = (
        CheckConstraint("scan_type IN ('iac', 'container')", name="scan_type"),
        CheckConstraint(
            "status IN ('queued', 'running', 'cancelling', 'completed', 'failed', 'cancelled')",
            name="status",
        ),
        Index("ix_customer_scan_jobs_org_created", "organization_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    scan_type: Mapped[str] = mapped_column(String(20), nullable=False)
    source_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    artifact_key: Mapped[str] = mapped_column(String(700), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", server_default="queued")
    result: Mapped[dict[str, object] | None] = mapped_column(JSON)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    scanner_version: Mapped[str | None] = mapped_column(String(80))
    error_code: Mapped[str | None] = mapped_column(String(80))
    ecs_task_arn: Mapped[str | None] = mapped_column(String(512))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CustomerScanFinding(TenantOwned, Base):
    """Bounded normalized result from one customer-uploaded scan."""

    __tablename__ = "customer_scan_findings"
    __table_args__ = (
        Index("ix_customer_scan_findings_job_severity", "organization_id", "scan_job_id", "severity"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    scan_job_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("customer_scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(160), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(700))
    details: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class ComplianceFramework(TimestampMixin, Base):
    """Versioned compliance framework catalog."""

    __tablename__ = "compliance_frameworks"
    __table_args__ = (
        CheckConstraint(
            "coverage_status IN ('UNVERIFIED', 'PARTIAL', 'VERIFIED')",
            name="coverage_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    coverage_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="UNVERIFIED", server_default="UNVERIFIED"
    )
    source_url: Mapped[str | None] = mapped_column(String(500))
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )


class ComplianceControl(TimestampMixin, Base):
    """Control in a versioned compliance framework."""

    __tablename__ = "compliance_controls"
    __table_args__ = (UniqueConstraint("framework_id", "control_code"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    framework_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_code: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(String(2000))
    domain: Mapped[str | None] = mapped_column(String(100))
    category: Mapped[str | None] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="MEDIUM", server_default="MEDIUM"
    )
    control_version: Mapped[str] = mapped_column(
        String(40), nullable=False, default="1.0", server_default="1.0"
    )
    guidance: Mapped[dict[str, object]] = mapped_column(
        JSON, nullable=False, default=dict, server_default="{}"
    )


class FindingComplianceControl(TenantOwned, Base):
    """Tenant-owned association from a detected finding to a benchmark control."""

    __tablename__ = "finding_compliance_controls"
    __table_args__ = (
        UniqueConstraint("organization_id", "finding_id", "control_id"),
        Index("ix_finding_compliance_org_control", "organization_id", "control_id"),
    )

    finding_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    control_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        primary_key=True,
    )


class ComplianceAssessment(TenantOwned, Base):
    """Per-scan result showing whether a mapped rule was evaluated for an asset."""

    __tablename__ = "compliance_assessments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PASS', 'FAIL', 'PARTIAL', 'NOT_ASSESSED', 'NOT_APPLICABLE')",
            name="compliance_assessment_status",
        ),
        UniqueConstraint("organization_id", "scan_job_id", "asset_id", "control_id"),
        Index("ix_compliance_assessments_org_control", "organization_id", "control_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    scan_job_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    control_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    observed: Mapped[dict[str, object] | None] = mapped_column(JSON)
    expected: Mapped[dict[str, object] | None] = mapped_column(JSON)
    evidence_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("finding_evidence.id", ondelete="SET NULL")
    )
    policy_version: Mapped[str | None] = mapped_column(String(40))


class RiskScore(TenantOwned, Base):
    """Latest deterministic risk score attached directly to a finding."""

    __tablename__ = "risk_scores"
    __table_args__ = (
        UniqueConstraint("organization_id", "finding_id"),
        CheckConstraint("score >= 0 AND score <= 100", name="risk_score_range"),
        Index("ix_risk_scores_org_score", "organization_id", "score"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False)
    factors: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    risk_model: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="CloudSentinel Default",
        server_default="CloudSentinel Default",
    )
    risk_model_version: Mapped[str] = mapped_column(
        String(40), nullable=False, default="1.0", server_default="1.0"
    )


class AuditEvent(TenantOwned, Base):
    """Append-only tenant audit record without credential-bearing payloads."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_org_created", "organization_id", "created_at"),
        Index(
            "ix_audit_events_org_actor_created", "organization_id", "actor_user_id", "created_at"
        ),
        Index("ix_audit_events_org_action_created", "organization_id", "action", "created_at"),
        Index("ix_audit_events_org_resource", "organization_id", "resource_type", "resource_id"),
        Index("ix_audit_events_org_status_created", "organization_id", "status", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    # Deliberately no user FK: the actor ID/name remain historical evidence if a user is removed.
    actor_user_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    actor_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="USER", server_default="USER"
    )
    actor_name: Mapped[str] = mapped_column(
        String(200), nullable=False, default="System", server_default="System"
    )
    actor_role: Mapped[str | None] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(100))
    target_type: Mapped[str | None] = mapped_column(String(80))
    target_id: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="SUCCESS", server_default="SUCCESS"
    )
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(100))
    before: Mapped[dict[str, object] | None] = mapped_column(JSON)
    after: Mapped[dict[str, object] | None] = mapped_column(JSON)
    details: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    retention_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=lambda: utc_now() + timedelta(days=365)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )


class RemediationRequest(TenantOwned, TimestampMixin, Base):
    """Human controlled remediation recommendation and approval decision."""

    __tablename__ = "remediation_requests"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'CANCELLED', "
            "'VERIFYING', 'COMPLETED', 'FAILED')",
            name="remediation_request_status",
        ),
        CheckConstraint(
            "verification_status IN ('NOT_STARTED', 'PENDING', 'PASSED', 'FAILED')",
            name="remediation_verification_status",
        ),
        Index("ix_remediation_requests_org_status", "organization_id", "status"),
        Index(
            "uq_remediation_requests_one_pending",
            "organization_id",
            "finding_id",
            unique=True,
            postgresql_where=text("status IN ('PENDING_APPROVAL', 'APPROVED', 'VERIFYING')"),
            sqlite_where=text("status IN ('PENDING_APPROVAL', 'APPROVED', 'VERIFYING')"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    requested_by_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    decided_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING_APPROVAL")
    request_note: Mapped[str] = mapped_column(String(1000), nullable=False)
    decision_note: Mapped[str | None] = mapped_column(String(1000))
    action_definition: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("finding_evidence.id", ondelete="SET NULL")
    )
    verification_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="NOT_STARTED", server_default="NOT_STARTED"
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AlertRule(TenantOwned, TimestampMixin, Base):
    """Organization-owned rules that convert canonical security events into alerts."""

    __tablename__ = "alert_rules"
    __table_args__ = (
        UniqueConstraint("organization_id", "code", name="uq_alert_rules_organization_code"),
        CheckConstraint(
            "event_type IN ('FINDING_CREATED', 'CRITICAL_FINDING', 'HIGH_RISK_FINDING', "
            "'SCAN_FAILED', 'SCAN_COMPLETED_WITH_ERRORS')",
            name="alert_rule_event_type",
        ),
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')", name="alert_rule_severity"
        ),
        CheckConstraint(
            "threshold_score IS NULL OR threshold_score BETWEEN 0 AND 100",
            name="alert_rule_threshold",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(String(60), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    threshold_score: Mapped[int | None] = mapped_column(Integer)


class Alert(TenantOwned, TimestampMixin, Base):
    """Deduplicated security alert linked to a finding, risk assessment, or scan."""

    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "deduplication_key", name="uq_alerts_organization_deduplication"
        ),
        CheckConstraint(
            "status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'DISMISSED')", name="alert_status"
        ),
        CheckConstraint("severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')", name="alert_severity"),
        Index("ix_alerts_org_status_created", "organization_id", "status", "created_at"),
        Index("ix_alerts_org_source", "organization_id", "source_type", "source_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    alert_rule_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("alert_rules.id", ondelete="SET NULL")
    )
    deduplication_key: Mapped[str] = mapped_column(String(240), nullable=False)
    alert_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_id: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN")
    occurrence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    acknowledged_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dismissed_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Report(TenantOwned, Base):
    """Tenant-bound immutable report generation and point-in-time snapshot."""

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_org_created", "organization_id", "created_at"),
        Index("ix_reports_org_status_created", "organization_id", "status", "created_at"),
        CheckConstraint(
            "status IN ('QUEUED', 'GENERATING', 'COMPLETED', 'FAILED', 'CANCELLED', 'EXPIRED')",
            name="report_status",
        ),
        CheckConstraint("file_format IN ('PDF', 'CSV', 'JSON')", name="report_file_format"),
        CheckConstraint("report_version >= 1", name="report_version_positive"),
        CheckConstraint(
            "generation_attempt_count >= 0", name="report_generation_attempt_count"
        ),
        UniqueConstraint(
            "organization_id",
            "report_series_id",
            "report_version",
            name="uq_reports_series_version",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    report_type: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="QUEUED", server_default="QUEUED"
    )
    file_format: Mapped[str] = mapped_column(
        String(10), nullable=False, default="JSON", server_default="JSON"
    )
    report_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    generation_attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    generator_version: Mapped[str] = mapped_column(
        String(40), nullable=False, default="1.0", server_default="1.0"
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    filters: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    snapshot: Mapped[dict[str, object] | None] = mapped_column(JSON)
    checksum: Mapped[str | None] = mapped_column(String(64))
    snapshot_checksum: Mapped[str | None] = mapped_column(String(64))
    storage_key: Mapped[str | None] = mapped_column(String(512))
    storage_version_id: Mapped[str | None] = mapped_column(String(1024))
    file_size: Mapped[int | None] = mapped_column(Integer)
    data_snapshot_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    report_series_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False
    )
    parent_report_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("reports.id", ondelete="SET NULL")
    )
    error_code: Mapped[str | None] = mapped_column(String(80))
    error_message: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )


class Notification(TenantOwned, Base):
    """In-app tenant notification delivered only to its intended member."""

    __tablename__ = "notifications"
    __table_args__ = (
        Index("ix_notifications_org_recipient", "organization_id", "recipient_user_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    recipient_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str] = mapped_column(String(1000), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(80))
    resource_id: Mapped[str | None] = mapped_column(String(100))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
