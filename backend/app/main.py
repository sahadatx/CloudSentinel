"""FastAPI application bootstrap for the CloudSentinel foundation."""

import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.database import create_database_engine, create_session_factory
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.redis import close_redis_client, create_redis_client
from app.core.tracing import configure_tracing
from app.operations.service import record_audit

logger = logging.getLogger(__name__)
HTTP_REQUESTS = Counter(
    "cloudsentinel_http_requests_total",
    "HTTP responses produced by the CloudSentinel API",
    ("method", "route", "status"),
)
HTTP_REQUEST_DURATION = Histogram(
    "cloudsentinel_http_request_duration_seconds",
    "Time spent handling API requests",
    ("method", "route"),
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Own the process-scoped Redis connection pool."""
    settings: Settings = app.state.settings
    configure_tracing(settings)
    client = app.state.redis_client_factory(settings)
    engine = create_database_engine(settings)
    app.state.redis_client = client
    app.state.database_engine = engine
    app.state.session_factory = create_session_factory(engine) if engine is not None else None
    if engine is not None and settings.otel_endpoint:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

        SQLAlchemyInstrumentor().instrument(engine=engine)
    if settings.otel_endpoint:
        from opentelemetry.instrumentation.redis import RedisInstrumentor

        RedisInstrumentor().instrument_client(client)
    try:
        yield
    finally:
        await close_redis_client(client)
        if engine is not None:
            engine.dispose()


def create_app(
    settings: Settings | None = None,
    redis_client_factory: Callable[[Settings], Any] = create_redis_client,
) -> FastAPI:
    """Create an application instance with explicit configuration dependencies."""
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings)

    application = FastAPI(
        title=resolved_settings.app_name,
        docs_url="/docs" if resolved_settings.api_docs_enabled else None,
        redoc_url="/redoc" if resolved_settings.api_docs_enabled else None,
        openapi_url="/openapi.json" if resolved_settings.api_docs_enabled else None,
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings
    application.state.redis_client_factory = redis_client_factory
    if configure_tracing(resolved_settings):
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(application)

    @application.middleware("http")
    async def observe_api_request(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Attach a correlation ID and record bounded-cardinality request metrics."""
        supplied_id = request.headers.get("x-request-id", "")
        request_id = (
            supplied_id
            if 0 < len(supplied_id) <= 100
            and all(33 <= ord(character) <= 126 for character in supplied_id)
            else str(uuid4())
        )
        request.state.request_id = request_id
        started_at = time.perf_counter()
        response: Response | None = None
        try:
            response = await call_next(request)
            return response
        except Exception:
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            HTTP_REQUESTS.labels(request.method, route_path, "500").inc()
            HTTP_REQUEST_DURATION.labels(request.method, route_path).observe(
                time.perf_counter() - started_at
            )
            logger.exception(
                "Unhandled request error",
                extra={"request_id": request_id, "route": route_path},
            )
            raise
        finally:
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            if response is not None:
                HTTP_REQUESTS.labels(
                    request.method, route_path, str(response.status_code)
                ).inc()
                HTTP_REQUEST_DURATION.labels(request.method, route_path).observe(
                    time.perf_counter() - started_at
                )
                response.headers["X-Request-ID"] = request_id
                latency_ms = (time.perf_counter() - started_at) * 1000
                error_count = 1 if response.status_code >= 500 else 0
                logger.info(
                    "API request complete",
                    extra={
                        "request_id": request_id,
                        "route": route_path,
                        "method": request.method,
                        "status_code": response.status_code,
                        "cloudwatch_emf": {
                            "_aws": {
                                "Timestamp": int(time.time() * 1000),
                                "CloudWatchMetrics": [
                                    {
                                        "Namespace": "CloudSentinel",
                                        "Dimensions": [["Environment"]],
                                        "Metrics": [
                                            {"Name": "ApiRequestCount", "Unit": "Count"},
                                            {"Name": "Api5xxCount", "Unit": "Count"},
                                            {
                                                "Name": "ApiRequestLatencyMs",
                                                "Unit": "Milliseconds",
                                            },
                                        ],
                                    }
                                ],
                            },
                            "Environment": resolved_settings.app_env,
                            "Route": route_path,
                            "Method": request.method,
                            "StatusCode": response.status_code,
                            "ApiRequestCount": 1,
                            "Api5xxCount": error_count,
                            "ApiRequestLatencyMs": latency_ms,
                        },
                    },
                )

    @application.middleware("http")
    async def prevent_api_response_caching(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Keep authenticated tenant data and token responses out of browser and proxy caches."""
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @application.middleware("http")
    async def audit_failed_mutations(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        principal = getattr(request.state, "audit_principal", None)
        if (
            request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and response.status_code >= 400
            and principal is not None
        ):
            request_session = getattr(request.state, "audit_db_session", None)
            if not request_session or not request_session.info.get("audit_failure_recorded"):
                factory = application.state.session_factory
                if factory is not None:
                    request_id = request.headers.get("x-request-id", "")
                    if (
                        not request_id
                        or len(request_id) > 100
                        or any(ord(char) < 33 or ord(char) > 126 for char in request_id)
                    ):
                        request_id = str(uuid4())
                    route = request.scope.get("route")
                    route_path = getattr(route, "path", "/api/request")
                    try:
                        with factory(
                            info={
                                "allow_unscoped": True,
                                "tenant_id": principal.organization_id,
                                "audit_ip_address": request.client.host if request.client else None,
                                "audit_user_agent": request.headers.get("user-agent", "")[:512]
                                or None,
                                "audit_request_id": request_id,
                            }
                        ) as audit_session:
                            record_audit(
                                audit_session,
                                organization_id=principal.organization_id,
                                actor_user_id=principal.user_id,
                                action="API_MUTATION_FAILED",
                                resource_type="api_request",
                                resource_id=route_path[:100],
                                status="FAILURE",
                                details={
                                    "method": request.method,
                                    "route": route_path[:200],
                                    "response_status": response.status_code,
                                },
                            )
                            audit_session.commit()
                    except Exception:
                        logger.exception("Could not persist failed mutation audit event")
        return response

    application.include_router(api_router)

    @application.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        """Expose Prometheus metrics for private cluster monitoring only."""
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    register_exception_handlers(application)
    return application


app = create_app()
