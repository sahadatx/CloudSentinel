"""Validated, environment-based settings for backend services."""

from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings; secret-bearing URLs are masked in representations."""

    model_config = SettingsConfigDict(
        env_prefix="CLOUDSENTINEL_",
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
    )

    app_name: str = "CloudSentinel"
    app_env: Literal["development", "test", "staging", "production"] = "development"

    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_docs_enabled: bool = False

    database_url: SecretStr | None = None
    database_pool_size: int = Field(default=5, ge=1, le=50)
    database_max_overflow: int = Field(default=10, ge=0, le=100)

    jwt_signing_key: SecretStr | None = None
    mfa_encryption_key: SecretStr | None = None
    access_token_ttl_minutes: int = Field(default=15, ge=1, le=60)

    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from_email: str | None = None
    smtp_starttls: bool = True
    smtp_timeout_seconds: int = Field(default=10, ge=1, le=60)
    frontend_base_url: str = "http://localhost:5173"
    public_api_base_url: str = "http://127.0.0.1:8000"
    password_reset_token_ttl_minutes: int = Field(default=30, ge=5, le=120)
    password_reset_rate_limit_requests: int = Field(default=5, ge=1, le=30)
    password_reset_rate_limit_window_seconds: int = Field(default=3600, ge=60, le=86400)
    login_rate_limit_per_email: int = Field(default=10, ge=1, le=100)
    login_rate_limit_per_ip: int = Field(default=100, ge=1, le=1000)
    login_rate_limit_window_seconds: int = Field(default=300, ge=60, le=3600)
    aws_validation_rate_limit_requests: int = Field(default=10, ge=1, le=60)
    aws_validation_rate_limit_window_seconds: int = Field(default=60, ge=10, le=3600)
    aws_validation_mode: Literal["real", "mock"] = "real"
    aws_mock_scenario: Literal[
        "success",
        "assume_role_denied",
        "external_id_mismatch",
        "identity_mismatch",
        "permission_denied",
    ] = "success"

    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")
    celery_broker_url: SecretStr | None = None
    celery_result_backend_url: SecretStr | None = None
    report_storage_bucket: str | None = None
    report_storage_prefix: str = "cloudsentinel/production/reports"
    report_storage_region: str | None = None
    report_storage_endpoint_url: str | None = None
    report_storage_access_key: SecretStr | None = None
    report_storage_secret_key: SecretStr | None = None
    report_retention_days: int = Field(default=90, ge=1, le=3650)
    offboarding_backup_retention_days: int = Field(default=35, ge=1, le=365)
    longest_backup_retention_days: int = Field(default=35, ge=1, le=365)
    customer_scan_enabled: bool = False
    customer_scan_bucket: str | None = None
    customer_scan_prefix: str = "cloudsentinel/customer-scans"
    customer_scan_ecs_cluster_arn: str | None = None
    customer_scan_task_definition_arn: str | None = None
    customer_scan_task_subnets: str | None = None
    customer_scan_task_security_group: str | None = None
    customer_scan_max_upload_bytes: int = Field(
        default=100 * 1024 * 1024, ge=1_048_576, le=250 * 1024 * 1024
    )
    customer_scan_timeout_seconds: int = Field(default=900, ge=60, le=1800)
    task_execution_max_attempts: int = Field(default=3, ge=1, le=8)
    task_stale_after_minutes: int = Field(default=30, ge=30, le=1440)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "text"] = "json"
    otel_endpoint: str | None = None
    otel_sample_ratio: float = Field(default=0.1, ge=0, le=1)

    @field_validator("smtp_host", "smtp_username", "smtp_from_email")
    @classmethod
    def normalize_optional_smtp_text(cls, value: str | None) -> str | None:
        """Treat blank Compose environment values as unset optional SMTP settings."""
        normalized = value.strip() if value is not None else None
        return normalized or None

    @field_validator("smtp_password")
    @classmethod
    def normalize_optional_smtp_password(cls, value: SecretStr | None) -> SecretStr | None:
        """Treat a blank secret environment value as unconfigured."""
        if value is not None and not value.get_secret_value().strip():
            return None
        return value

    @field_validator("report_storage_access_key", "report_storage_secret_key")
    @classmethod
    def normalize_report_storage_secret(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not value.get_secret_value().strip():
            return None
        return value

    @field_validator("mfa_encryption_key")
    @classmethod
    def validate_mfa_encryption_key(cls, value: SecretStr | None) -> SecretStr | None:
        """Require a valid Fernet key whenever MFA encryption is configured."""
        if value is None or not value.get_secret_value().strip():
            return None
        try:
            Fernet(value.get_secret_value().encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise ValueError("must be a valid Fernet key") from None
        return value

    @field_validator("redis_url", "celery_broker_url", "celery_result_backend_url")
    @classmethod
    def validate_redis_url(cls, value: SecretStr | None) -> SecretStr | None:
        """Accept only Redis URLs with a hostname, without exposing their value."""
        if value is None:
            return None
        parsed = urlsplit(value.get_secret_value())
        if parsed.scheme not in {"redis", "rediss"} or parsed.hostname is None:
            raise ValueError("must be a valid redis:// or rediss:// URL")
        return value

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        """Accept supported PostgreSQL or test-only SQLite SQLAlchemy URLs."""
        if value is None:
            return None
        parsed = urlsplit(value.get_secret_value())
        if parsed.scheme not in {"postgresql", "postgresql+psycopg", "sqlite", "sqlite+pysqlite"}:
            raise ValueError("must be a PostgreSQL URL (SQLite is supported for tests)")
        return value

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        """Require safe database backends and signing secrets for each environment."""
        if self.offboarding_backup_retention_days < self.longest_backup_retention_days:
            raise ValueError(
                "CLOUDSENTINEL_OFFBOARDING_BACKUP_RETENTION_DAYS must be at least "
                "CLOUDSENTINEL_LONGEST_BACKUP_RETENTION_DAYS"
            )
        if self.database_url is not None:
            scheme = urlsplit(self.database_url.get_secret_value()).scheme
            if scheme.startswith("sqlite") and self.app_env != "test":
                raise ValueError("SQLite database URLs are supported only in the test environment")
        if self.aws_validation_mode == "mock" and self.app_env not in {"development", "test"}:
            raise ValueError("AWS mock validation is allowed only in development and test")
        if self.app_env in {"staging", "production"}:
            if self.database_url is None:
                raise ValueError("CLOUDSENTINEL_DATABASE_URL is required in staging and production")
            if self.jwt_signing_key is None or len(self.jwt_signing_key.get_secret_value()) < 32:
                raise ValueError(
                    "CLOUDSENTINEL_JWT_SIGNING_KEY must be at least 32 characters"
                )
            if self.mfa_encryption_key is None:
                raise ValueError(
                    "CLOUDSENTINEL_MFA_ENCRYPTION_KEY is required in staging and production"
                )
        if bool(self.smtp_username) != bool(self.smtp_password):
            raise ValueError("SMTP username and password must be configured together")
        if bool(self.smtp_host) != bool(self.smtp_from_email):
            raise ValueError("SMTP host and sender email must be configured together")
        if bool(self.report_storage_access_key) != bool(self.report_storage_secret_key):
            raise ValueError("Report storage access and secret keys must be configured together")
        if self.customer_scan_enabled and not all(
            (
                self.customer_scan_bucket,
                self.customer_scan_ecs_cluster_arn,
                self.customer_scan_task_definition_arn,
                self.customer_scan_task_subnets,
                self.customer_scan_task_security_group,
                self.report_storage_region,
            )
        ):
            raise ValueError(
                "Customer scans require bucket, ECS cluster/task definition, private subnet, "
                "task security group, and AWS region configuration"
            )
        if self.smtp_host and not self.smtp_starttls and self.app_env != "development":
            raise ValueError("SMTP STARTTLS must remain enabled outside local development")
        if self.app_env in {"staging", "production"}:
            frontend_url = urlsplit(self.frontend_base_url)
            if frontend_url.scheme != "https" or frontend_url.hostname is None:
                raise ValueError(
                    "CLOUDSENTINEL_FRONTEND_BASE_URL must use HTTPS in staging and production"
                )
            api_url = urlsplit(self.public_api_base_url)
            if api_url.scheme != "https" or api_url.hostname is None:
                raise ValueError(
                    "CLOUDSENTINEL_PUBLIC_API_BASE_URL must use HTTPS in staging and production"
                )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process settings singleton."""
    return Settings()
