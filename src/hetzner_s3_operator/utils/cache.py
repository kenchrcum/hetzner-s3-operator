"""Cache utilities for Kubernetes API calls."""

from __future__ import annotations

import os
import time
from typing import Any, Optional

# Cache with TTL support
_cache: dict[str, tuple[Any, float]] = {}
_cache_ttl: float = float(os.getenv("K8S_CACHE_TTL_SECONDS", "30.0"))  # Default 30 seconds


def get_cached_object(key: str) -> Optional[Any]:
    """Get an object from cache if it hasn't expired.
    
    Args:
        key: Cache key (typically "kind:namespace:name")
        
    Returns:
        Cached object or None if not found or expired
    """
    if key not in _cache:
        return None
    
    obj, timestamp = _cache[key]
    if time.time() - timestamp > _cache_ttl:
        # Expired, remove from cache
        del _cache[key]
        return None
    
    return obj


def set_cached_object(key: str, obj: Any) -> None:
    """Store an object in cache with current timestamp.
    
    Args:
        key: Cache key (typically "kind:namespace:name")
        obj: Object to cache
    """
    _cache[key] = (obj, time.time())


def invalidate_cache(pattern: Optional[str] = None) -> None:
    """Invalidate cache entries.
    
    Args:
        pattern: Optional pattern to match keys (if None, clears all)
    """
    if pattern is None:
        _cache.clear()
    else:
        keys_to_remove = [key for key in _cache.keys() if pattern in key]
        for key in keys_to_remove:
            del _cache[key]


def make_cache_key(kind: str, namespace: str, name: str) -> str:
    """Create a cache key for a Kubernetes resource.
    
    Args:
        kind: Resource kind (e.g., "Provider", "User")
        namespace: Resource namespace
        name: Resource name
        
    Returns:
        Cache key string
    """
    return f"{kind}:{namespace}:{name}"

