"""Main entry point for the Hetzner S3 Operator."""

from __future__ import annotations

import os
import threading
from typing import Any

import kopf
from werkzeug.serving import make_server

from . import health
from . import logging as structured_logging
from . import metrics
from .tracing import initialize_tracing

# Import handlers - they register themselves via @kopf decorators
from .handlers import bucket, bucket_policy, provider  # noqa: F401


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    """Configure the operator."""
    # Set up structured JSON logging
    structured_logging.setup_structured_logging()

    # Initialize tracing
    initialize_tracing()

    # Configure persistence
    # Use AnnotationsProgressStorage to avoid conflicts with status updates
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage()
    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage()

    settings.posting.level = 0
    settings.networking.request_timeout = 30.0
    settings.execution.max_workers = 4

    # Configure retry/backoff settings
    # Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s (max)
    settings.execution.min_retry_delay = 1.0
    settings.execution.max_retry_delay = 60.0
    settings.execution.retry_backoff = 2.0  # Exponential multiplier
    settings.execution.max_retries = 5  # Maximum retry attempts
    settings.execution.backoff_jitter = 0.1  # 10% jitter to prevent thundering herd

    # Start metrics HTTP server with health check endpoints on port 8080
    metrics_port = int(os.getenv("METRICS_PORT", "8080"))
    combined_app = health.create_combined_wsgi_app()
    server = make_server("", metrics_port, combined_app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()


# All CRD handlers are now in handlers/ module
# They are imported above and register themselves via @kopf decorators

