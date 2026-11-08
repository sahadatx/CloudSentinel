"""Redis connection-pool abstraction for Phase 01 infrastructure checks."""

from typing import Protocol, cast

from fastapi import Request
from redis.asyncio import Redis

from app.core.config import Settings


class RedisClient(Protocol):
    """Small interface required by readiness and app lifecycle management."""

    async def ping(self) -> bool | bytes | str: ...

    async def aclose(self) -> None: ...

    async def eval(self, script: str, numkeys: int, *keys_and_args: str | int) -> object: ...


def create_redis_client(settings: Settings) -> Redis:
    """Create a lazy async Redis client; construction does not require a live server."""
    return cast(
        Redis,
        Redis.from_url(
            settings.redis_url.get_secret_value(),
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
        ),
    )


async def close_redis_client(client: RedisClient) -> None:
    """Close the process-scoped Redis connection pool."""
    await client.aclose()


def get_redis_client(request: Request) -> RedisClient:
    """Return the Redis pool owned by the application lifespan."""
    return cast(RedisClient, request.app.state.redis_client)
