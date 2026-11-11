"""Celery application configuration and asynchronous scan task registration."""

from celery import Celery

from app.core.config import get_settings
from app.core.tracing import configure_tracing

settings = get_settings()
if configure_tracing(settings):
    from opentelemetry.instrumentation.celery import CeleryInstrumentor

    CeleryInstrumentor().instrument()
celery_app = Celery("cloudsentinel")
celery_app.conf.update(
    broker_url=(settings.celery_broker_url or settings.redis_url).get_secret_value(),
    result_backend=(settings.celery_result_backend_url or settings.redis_url).get_secret_value(),
    accept_content=["json"],
    task_serializer="json",
    result_serializer="json",
    broker_connection_retry_on_startup=True,
    worker_hijack_root_logger=False,
    imports=("app.scan_jobs.tasks", "app.reports.tasks", "app.customer_scans.tasks"),
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,
    task_default_delivery_mode="persistent",
    worker_prefetch_multiplier=1,
    worker_cancel_long_running_tasks_on_connection_loss=True,
    broker_transport_options={
        "visibility_timeout": settings.task_stale_after_minutes * 120,
    },
    result_backend_transport_options={
        "visibility_timeout": settings.task_stale_after_minutes * 120,
    },
    visibility_timeout=settings.task_stale_after_minutes * 120,
)
