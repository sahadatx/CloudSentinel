"""Configurable structured logging that avoids dumping settings or exception data."""

import json
import logging
import logging.config
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings


class JsonFormatter(logging.Formatter):
    """Render only standard, non-sensitive logging fields as JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None)
        if isinstance(request_id, str):
            payload["request_id"] = request_id
        emf = getattr(record, "cloudwatch_emf", None)
        if isinstance(emf, dict):
            payload.update(emf)
        return json.dumps(payload, ensure_ascii=True)


def configure_logging(settings: Settings) -> None:
    """Install a single configurable root handler without logging configuration values."""
    formatter: dict[str, Any]
    if settings.log_format == "json":
        formatter = {"()": JsonFormatter}
    else:
        formatter = {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {"application": formatter},
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "level": settings.log_level,
                    "formatter": "application",
                    "stream": "ext://sys.stdout",
                }
            },
            "root": {"level": settings.log_level, "handlers": ["console"]},
            "loggers": {"uvicorn.access": {"handlers": [], "propagate": False}},
        }
    )
