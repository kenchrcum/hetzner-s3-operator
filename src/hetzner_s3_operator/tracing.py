"""OpenTelemetry tracing support for the Wasabi S3 Operator."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.trace import Tracer, Span

    TRACING_AVAILABLE = True
except ImportError:
    TRACING_AVAILABLE = False
    # Create dummy classes for type hints when tracing is not available
    class Tracer:  # type: ignore[no-redef]
        pass

    class Span:  # type: ignore[no-redef]
        pass


# Global tracer instance
_tracer: Tracer | None = None


def initialize_tracing(service_name: str = "hetzner-s3-operator") -> None:
    """Initialize OpenTelemetry tracing.
    
    Args:
        service_name: Name of the service for tracing
        
    Environment Variables:
        OTEL_EXPORTER_OTLP_ENDPOINT: OTLP endpoint URL (default: http://localhost:4317)
        OTEL_SERVICE_NAME: Service name (default: hetzner-s3-operator)
        OTEL_TRACES_ENABLED: Enable/disable tracing (default: true)
    """
    global _tracer
    
    if not TRACING_AVAILABLE:
        return
    
    # Check if tracing is enabled
    if os.getenv("OTEL_TRACES_ENABLED", "true").lower() == "false":
        return
    
    try:
        service_name = os.getenv("OTEL_SERVICE_NAME", service_name)
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
        
        # Create resource
        resource = Resource.create({
            "service.name": service_name,
            "service.version": os.getenv("OTEL_SERVICE_VERSION", "unknown"),
        })
        
        # Create tracer provider
        provider = TracerProvider(resource=resource)
        
        # Add OTLP exporter
        otlp_exporter = OTLPSpanExporter(endpoint=endpoint)
        span_processor = BatchSpanProcessor(otlp_exporter)
        provider.add_span_processor(span_processor)
        
        # Set global tracer provider
        trace.set_tracer_provider(provider)
        
        # Get tracer
        _tracer = trace.get_tracer(service_name)
    except Exception as e:
        # Tracing initialization failures should not break the operator
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to initialize tracing: {e}")


def get_tracer() -> Tracer | None:
    """Get the global tracer instance.
    
    Returns:
        Tracer instance or None if tracing is not available/initialized
    """
    return _tracer


@contextmanager
def trace_span(
    name: str,
    kind: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> Iterator[Span | None]:
    """Context manager for creating a trace span.
    
    Args:
        name: Name of the span
        kind: Resource kind (e.g., "Provider", "Bucket")
        attributes: Additional span attributes
        
    Yields:
        Span object or None if tracing is not available
    """
    tracer = get_tracer()
    if tracer is None:
        yield None
        return
    
    attrs = attributes or {}
    if kind:
        attrs["resource.kind"] = kind
    
    # start_as_current_span returns a context manager that manages the span lifecycle
    span_context = tracer.start_as_current_span(name, attributes=attrs)
    with span_context:
        span = trace.get_current_span()
        try:
            yield span
        except Exception as e:
            if span and span.is_recording():
                span.record_exception(e)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
            raise


def add_span_attribute(key: str, value: Any) -> None:
    """Add an attribute to the current span.
    
    Args:
        key: Attribute key
        value: Attribute value
    """
    span = trace.get_current_span()
    if span and span.is_recording():
        span.set_attribute(key, value)


def set_span_status(ok: bool, description: str | None = None) -> None:
    """Set the status of the current span.
    
    Args:
        ok: Whether the operation succeeded
        description: Optional status description
    """
    if not TRACING_AVAILABLE:
        return
    
    span = trace.get_current_span()
    if span and span.is_recording():
        status = trace.Status(
            trace.StatusCode.OK if ok else trace.StatusCode.ERROR,
            description,
        )
        span.set_status(status)

