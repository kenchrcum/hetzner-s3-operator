"""Rate limiting utilities for API calls."""

from __future__ import annotations

import os
import time
from functools import wraps
from typing import Any, Callable, TypeVar

from kubernetes.client.exceptions import ApiException

_F = TypeVar("_F", bound=Callable[..., Any])

# Rate limit configuration
_K8S_RATE_LIMIT_PER_SECOND = float(os.getenv("K8S_RATE_LIMIT_PER_SECOND", "10.0"))
_WASABI_RATE_LIMIT_PER_SECOND = float(os.getenv("WASABI_RATE_LIMIT_PER_SECOND", "5.0"))

# Track last call times
_k8s_last_call_time: float = 0.0
_wasabi_last_call_time: float = 0.0


def rate_limit_k8s(func: _F) -> _F:
    """Decorator to rate limit Kubernetes API calls.
    
    Implements a simple token bucket-like rate limiter to prevent overwhelming
    the Kubernetes API server.
    """
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        global _k8s_last_call_time
        current_time = time.time()
        min_interval = 1.0 / _K8S_RATE_LIMIT_PER_SECOND
        
        time_since_last_call = current_time - _k8s_last_call_time
        if time_since_last_call < min_interval:
            sleep_time = min_interval - time_since_last_call
            time.sleep(sleep_time)
        
        _k8s_last_call_time = time.time()
        return func(*args, **kwargs)
    
    return wrapper  # type: ignore


def rate_limit_wasabi(func: _F) -> _F:
    """Decorator to rate limit Wasabi API calls.
    
    Implements a simple token bucket-like rate limiter to prevent overwhelming
    the Wasabi API.
    """
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        global _wasabi_last_call_time
        current_time = time.time()
        min_interval = 1.0 / _WASABI_RATE_LIMIT_PER_SECOND
        
        time_since_last_call = current_time - _wasabi_last_call_time
        if time_since_last_call < min_interval:
            sleep_time = min_interval - time_since_last_call
            time.sleep(sleep_time)
        
        _wasabi_last_call_time = time.time()
        return func(*args, **kwargs)
    
    return wrapper  # type: ignore


def handle_rate_limit_error(e: ApiException, max_retries: int = 3) -> bool:
    """Check if an API exception is a rate limit error and handle it.
    
    Args:
        e: API exception
        max_retries: Maximum number of retries
        
    Returns:
        True if rate limit error was handled, False otherwise
    """
    # Kubernetes API rate limit errors typically return 429 or 503
    if e.status == 429 or (e.status == 503 and "rate limit" in str(e).lower()):
        # Exponential backoff: 1s, 2s, 4s
        retry_count = getattr(handle_rate_limit_error, "_retry_count", 0)
        if retry_count < max_retries:
            sleep_time = 2 ** retry_count
            time.sleep(sleep_time)
            handle_rate_limit_error._retry_count = retry_count + 1  # type: ignore
            return True
        handle_rate_limit_error._retry_count = 0  # type: ignore
        return False
    
    handle_rate_limit_error._retry_count = 0  # type: ignore
    return False

