"""PostgreSQL engine and request-scoped SQLAlchemy session foundation."""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from fastapi import Request
from sqlalchemy import Engine, ForeignKey, MetaData, Uuid, create_engine, event
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    ORMExecuteState,
    Session,
    mapped_column,
    sessionmaker,
    with_loader_criteria,
)

from app.core.config import Settings

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative metadata root for application-owned schema."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TenantOwned:
    """Marker and organization foreign key for tenant-owned mapped rows."""

    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )


class CloudSentinelSession(Session):
    """ORM session with mandatory tenant query and write scope."""


class TenantContextRequired(RuntimeError):
    """Raised when an ORM session attempts access without explicit tenant scope."""


def _as_utc(value: datetime) -> datetime:
    """Normalize database timestamps before comparing retention deadlines."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@event.listens_for(CloudSentinelSession, "do_orm_execute")
def apply_tenant_query_scope(execute_state: ORMExecuteState) -> None:
    """Scope all ORM reads and ORM bulk writes to the session's tenant."""
    session = execute_state.session
    if session.info.get("allow_unscoped", False):
        return

    tenant_id = session.info.get("tenant_id")
    if tenant_id is None:
        raise TenantContextRequired("Tenant context is required for ORM queries")

    if execute_state.is_column_load or execute_state.is_relationship_load:
        return
    execute_state.statement = execute_state.statement.options(
        with_loader_criteria(
            TenantOwned,
            lambda entity: entity.organization_id == tenant_id,
            include_aliases=True,
        )
    )


@event.listens_for(CloudSentinelSession, "before_flush")
def enforce_tenant_write_scope(
    session: Session, _flush_context: object, _instances: object
) -> None:
    """Prevent inserting, changing, or deleting tenant rows across organizations."""
    from app.core.models import AuditEvent

    if any(isinstance(row, AuditEvent) for row in session.dirty):
        raise ValueError("Audit events are append-only and cannot be changed")
    audit_rows = [row for row in session.deleted if isinstance(row, AuditEvent)]
    if audit_rows:
        now = datetime.now(UTC)
        if not session.info.get("allow_audit_retention_purge") or any(
            row.retention_until is None or _as_utc(row.retention_until) > now
            for row in audit_rows
        ):
            raise ValueError("Audit events cannot be deleted before their retention expires")
    if session.info.get("allow_unscoped", False):
        return
    tenant_id = session.info.get("tenant_id")
    if tenant_id is None:
        if any(
            isinstance(row, TenantOwned) for row in (*session.new, *session.dirty, *session.deleted)
        ):
            raise TenantContextRequired("Tenant context is required for tenant-owned writes")
        return

    for row in (*session.new, *session.dirty, *session.deleted):
        if isinstance(row, TenantOwned) and row.organization_id != tenant_id:
            raise TenantContextRequired("Tenant-owned write is outside the session organization")


def create_database_engine(settings: Settings) -> Engine | None:
    """Create a pre-ping engine when a database URL is configured."""
    if settings.database_url is None:
        return None

    url = settings.database_url.get_secret_value()
    if url.startswith("postgresql://"):
        url = f"postgresql+psycopg://{url.removeprefix('postgresql://')}"
    engine_options: dict[str, object] = {
        "pool_pre_ping": True,
        "pool_size": settings.database_pool_size,
        "max_overflow": settings.database_max_overflow,
    }
    if url.startswith("sqlite"):
        engine_options = {"connect_args": {"check_same_thread": False}}
    return create_engine(url, **engine_options)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create non-autocommit, non-autoflush sessions bound to one engine."""
    return sessionmaker(
        bind=engine,
        class_=CloudSentinelSession,
        autoflush=False,
        expire_on_commit=False,
    )


def get_system_session(request: Request) -> Iterator[Session]:
    """Yield explicitly unscoped session for login/bootstrap-only queries."""
    factory = cast(sessionmaker[Session] | None, request.app.state.session_factory)
    if factory is None:
        raise RuntimeError("Database is not configured")
    session = factory(info={"allow_unscoped": True})
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
