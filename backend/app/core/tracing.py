"""Optional OTLP tracing shared by the API and background workers."""

from __future__ import annotations

import logging
from threading import Lock

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased

from app.core.config import Settings

logger = logging.getLogger(__name__)
_lock = Lock()
_configured = False


def configure_tracing(settings: Settings) -> bool:
    """Set up a single process-wide OTLP exporter when an endpoint is configured."""
    global _configured
    if not settings.otel_endpoint:
        return False
    with _lock:
        if _configured:
            return True
        provider = TracerProvider(
            resource=Resource.create(
                {
                    "service.name": settings.app_name.lower(),
                    "deployment.environment.name": settings.app_env,
                }
            ),
            sampler=ParentBased(TraceIdRatioBased(settings.otel_sample_ratio)),
        )
        provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=settings.otel_endpoint, insecure=True),
                max_queue_size=2048,
                max_export_batch_size=512,
                schedule_delay_millis=5000,
                export_timeout_millis=10000,
            )
        )
        trace.set_tracer_provider(provider)
        _configured = True
        logger.info("OpenTelemetry tracing enabled", extra={"otel_endpoint": settings.otel_endpoint})
    return True
