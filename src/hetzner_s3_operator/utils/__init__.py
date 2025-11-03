"""Utility functions for the Hetzner S3 Operator."""

# Note: Access key utilities not needed for Hetzner (access keys are created manually)
from .cache import (
    get_cached_object,
    invalidate_cache,
    make_cache_key,
    set_cached_object,
)
from .conditions import (
    set_bucket_not_ready_condition,
    set_provider_not_ready_condition,
    update_condition,
)
from .context import (
    get_context_dict,
    get_correlation_id,
    propagate_trace_context,
    set_correlation_id,
    with_correlation_id,
)
from .events import emit_event
from .rate_limit import handle_rate_limit_error, rate_limit_k8s, rate_limit_wasabi
from .secrets import get_secret_value

__all__ = [
    "update_condition",
    "set_bucket_not_ready_condition",
    "set_provider_not_ready_condition",
    "emit_event",
    "get_secret_value",
    "get_cached_object",
    "set_cached_object",
    "invalidate_cache",
    "make_cache_key",
    "rate_limit_k8s",
    "rate_limit_wasabi",
    "handle_rate_limit_error",
    "set_correlation_id",
    "get_correlation_id",
    "with_correlation_id",
    "get_context_dict",
    "propagate_trace_context",
]

