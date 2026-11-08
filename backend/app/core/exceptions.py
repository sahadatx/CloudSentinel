"""Safe, consistent API error responses."""

import logging
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.domain_errors import DomainError
from app.scim.errors import ScimProtocolError

logger = logging.getLogger("cloudsentinel.api")


def register_exception_handlers(application: FastAPI) -> None:
    """Register handlers that do not reflect exception details to API clients."""

    @application.exception_handler(DomainError)
    async def handle_domain_exception(request: Request, exc: DomainError) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    @application.exception_handler(ScimProtocolError)
    async def handle_scim_exception(request: Request, exc: ScimProtocolError) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=exc.status_code,
            media_type="application/scim+json",
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": str(exc.status_code),
                "detail": exc.message,
                **({"scimType": exc.scim_type} if exc.scim_type else {}),
            },
        )

    @application.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        del request
        try:
            phrase = HTTPStatus(exc.status_code).phrase
        except ValueError:
            phrase = "Request failed"
        return JSONResponse(
            status_code=exc.status_code,
            headers=exc.headers,
            content={"error": {"code": "http_error", "message": phrase}},
        )

    @application.exception_handler(RequestValidationError)
    async def handle_validation_exception(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        del request, exc
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "invalid_request",
                    "message": "The request is invalid.",
                }
            },
        )

    @application.exception_handler(Exception)
    async def handle_unexpected_exception(request: Request, exc: Exception) -> JSONResponse:
        del request
        logger.error(
            "Unhandled API exception",
            extra={"error_type": type(exc).__name__},
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_server_error",
                    "message": "An unexpected error occurred.",
                }
            },
        )
