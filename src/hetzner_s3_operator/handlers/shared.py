"""Shared utilities for handlers."""

from __future__ import annotations

import time
from typing import Any

from kubernetes import client

from .. import metrics
from ..constants import API_GROUP_VERSION, KIND_PROVIDER
from ..utils.cache import get_cached_object, make_cache_key, set_cached_object
from ..utils.rate_limit import handle_rate_limit_error, rate_limit_k8s


def get_provider_with_cache(
    api: Any,
    provider_name: str,
    provider_ns: str,
    namespace: str = "default",
) -> dict[str, Any]:
    """Get provider CRD with caching.
    
    Args:
        api: Kubernetes CustomObjectsApi instance
        provider_name: Name of the provider
        provider_ns: Namespace of the provider
        namespace: Current namespace (for fallback)
        
    Returns:
        Provider CRD object
        
    Raises:
        client.exceptions.ApiException: If provider not found or API error
    """
    cache_key = make_cache_key(KIND_PROVIDER, provider_ns, provider_name)
    cached_provider = get_cached_object(cache_key)
    
    if cached_provider is not None:
        metrics.api_call_total.labels(api_type="k8s", operation="get_provider", result="cache_hit").inc()
        return cached_provider
    
    start_time = time.time()
    try:
        # Parse API_GROUP_VERSION (e.g., "hetzner-s3.cloud37.dev/v1alpha1")
        group, version = API_GROUP_VERSION.split("/")
        provider_obj = rate_limit_k8s(api.get_namespaced_custom_object)(
            group=group,
            version=version,
            namespace=provider_ns,
            plural="providers",
            name=provider_name,
        )
        metrics.api_call_total.labels(api_type="k8s", operation="get_provider", result="success").inc()
        set_cached_object(cache_key, provider_obj)
        return provider_obj
    except Exception as e:
        metrics.api_call_total.labels(api_type="k8s", operation="get_provider", result="error").inc()
        if handle_rate_limit_error(e):
            # Retry once after rate limit backoff
            return get_provider_with_cache(api, provider_name, provider_ns, namespace)
        raise
    finally:
        duration = time.time() - start_time
        metrics.api_call_duration_seconds.labels(api_type="k8s", operation="get_provider").observe(duration)


# get_user_with_cache removed - users not supported in Hetzner S3 operator


def get_k8s_client() -> client.CustomObjectsApi:
    """Get Kubernetes CustomObjectsApi client.
    
    Returns:
        CustomObjectsApi instance
    """
    from kubernetes import config
    
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    
    return client.CustomObjectsApi()

