"""Process liveness and Phase 02 database/Redis readiness endpoints."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from app.core.redis import RedisClient, get_redis_client

router = APIRouter()
logger = logging.getLogger("cloudsentinel.readiness")


@router.get("/health", name="health")
async def health() -> dict[str, str]:
    """Report that the HTTP process is alive without checking dependencies."""
    return {"status": "ok"}


@router.get("/ready", name="readiness", response_model=None)
async def readiness(
    request: Request,
    redis_client: Annotated[RedisClient, Depends(get_redis_client)],
) -> dict[str, str] | JSONResponse:
    """Check the PostgreSQL and Redis dependencies required by Phase 02."""
    try:
        response = await redis_client.ping()
    except RedisError:
        logger.warning("Readiness check failed for Redis")
        return JSONResponse(status_code=503, content={"status": "not_ready"})

    if response not in (True, "PONG", b"PONG"):
        logger.warning("Readiness check failed for Redis")
        return JSONResponse(status_code=503, content={"status": "not_ready"})

    engine = request.app.state.database_engine
    if engine is None:
        logger.warning("Readiness check failed for PostgreSQL configuration")
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    try:
        await run_in_threadpool(_check_database, engine)
    except SQLAlchemyError:
        logger.warning("Readiness check failed for PostgreSQL")
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    return {"status": "ready"}


def _check_database(engine: Engine) -> None:
    """Run a minimal connectivity query without disclosing connection details."""
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
