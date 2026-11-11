"""Readiness probe for the local Celery worker process."""

import socket

from app.core.celery_app import celery_app


def main() -> int:
    hostname = socket.gethostname()
    inspector = celery_app.control.inspect(timeout=3)
    replies = inspector.ping() or {}
    return int(
        not any(
            name.startswith("cloudsentinel-worker@") and hostname in name
            for name in replies
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
