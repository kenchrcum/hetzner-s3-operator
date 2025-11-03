"""Structured logging configuration for the S3 Operator."""

import json
import logging
import sys
from typing import Any


def setup_structured_logging() -> None:
    """Configure structured JSON logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def log_resource_event(
    logger: logging.Logger,
    controller: str,
    resource_kind: str,
    resource_name: str,
    namespace: str,
    uid: str,
    event: str,
    reason: str,
    message: str,
    **kwargs: Any,
) -> None:
    """Log a structured resource event."""
    log_data = {
        "controller": controller,
        "resource": resource_kind,
        "name": resource_name,
        "namespace": namespace,
        "uid": uid,
        "event": event,
        "reason": reason,
        "message": message,
    }
    log_data.update(kwargs)
    logger.info(json.dumps(log_data))


def sanitize_secrets(log_data: dict[str, Any]) -> dict[str, Any]:
    """Remove secret fields from log data."""
    secret_fields = {"access_key", "secret_key", "session_token", "password"}
    sanitized = log_data.copy()
    for field in secret_fields:
        if field in sanitized:
            sanitized[field] = "***REDACTED***"
    return sanitized

