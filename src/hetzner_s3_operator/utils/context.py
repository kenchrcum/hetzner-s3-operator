"""Context propagation utilities for OpenTelemetry and correlation IDs."""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Any, Iterator

# Context variable for storing correlation ID
correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)


def set_correlation_id(corr_id: str) -> None:
    """Set the correlation ID in the current context.
    
    Args:
        corr_id: Correlation ID to set
    """
    correlation_id.set(corr_id)


def get_correlation_id() -> str | None:
    """Get the correlation ID from the current context.
    
    Returns:
        Correlation ID if set, None otherwise
    """
    return correlation_id.get()


@contextmanager
def with_correlation_id(corr_id: str) -> Iterator[str]:
    """Context manager to set a correlation ID for the duration of a block.
    
    Args:
        corr_id: Correlation ID to use
        
    Yields:
        The correlation ID
    """
    token = correlation_id.set(corr_id)
    try:
        yield corr_id
    finally:
        correlation_id.reset(token)


def get_context_dict(additional: dict[str, Any] | None = None) -> dict[str, Any]:
    """Get a dictionary of context values.
    
    Args:
        additional: Additional key-value pairs to include
        
    Returns:
        Dictionary with context values including correlation_id
    """
    ctx = {}
    
    corr_id = get_correlation_id()
    if corr_id:
        ctx["correlation_id"] = corr_id
    
    if additional:
        ctx.update(additional)
    
    return ctx


def propagate_trace_context() -> dict[str, Any] | None:
    """Get OpenTelemetry trace context for propagation.
    
    Returns:
        Dictionary with trace context if available, None otherwise
    """
    try:
        from opentelemetry import trace
        
        span = trace.get_current_span()
        if span and span.is_recording():
            span_context = span.get_span_context()
            if span_context.is_valid:
                return {
                    "trace_id": format(span_context.trace_id, "032x"),
                    "span_id": format(span_context.span_id, "016x"),
                    "trace_flags": span_context.trace_flags,
                }
    except ImportError:
        # OpenTelemetry not available
        pass
    except Exception:
        # Error getting trace context, ignore
        pass
    
    return None

