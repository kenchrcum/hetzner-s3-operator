"""Handler for Provider CRD."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import kopf

from .. import metrics
from ..builders.provider import create_provider_from_spec
from ..constants import API_GROUP_VERSION, KIND_PROVIDER
from ..tracing import trace_span
from ..utils.conditions import (
    set_auth_valid_condition,
    set_endpoint_reachable_condition,
    set_ready_condition,
)
from ..utils.errors import sanitize_exception
from ..utils.events import emit_validate_succeeded
from .base import BaseHandler


class ProviderHandler(BaseHandler):
    """Handler for Provider resources."""

    def __init__(self):
        """Initialize provider handler."""
        super().__init__(KIND_PROVIDER)

    def reconcile(
        self,
        spec: dict[str, Any],
        meta: dict[str, Any],
        status: dict[str, Any],
        patch: kopf.Patch,
    ) -> None:
        """Reconcile Provider resource."""
        name = meta.get("name", "unknown")
        
        with trace_span("reconcile_provider", kind=KIND_PROVIDER, attributes={"provider.name": name}):
            # Validate spec
            if not spec.get("endpoint") or not spec.get("region"):
                self.handle_validation_error(meta, "endpoint and region are required")

            emit_validate_succeeded(meta)

            # Initialize conditions if needed
            conditions = status.get("conditions", [])

            # Try to create provider and test connectivity
            with trace_span("create_provider", kind=KIND_PROVIDER):
                try:
                    provider = create_provider_from_spec(spec, meta)
                    auth_valid = True
                    auth_message = "Authentication successful"
                except Exception as e:
                    auth_valid = False
                    sanitized_error = sanitize_exception(e)
                    auth_message = f"Authentication failed: {sanitized_error}"
                    error_type = type(e).__name__
                    metrics.error_total.labels(kind=KIND_PROVIDER, error_type=error_type).inc()
                    self.log_error(meta, f"Failed to create provider: {sanitized_error}", error=e, reason="AuthFailed")

            conditions = set_auth_valid_condition(conditions, auth_valid, auth_message)

            # Test connectivity
            if auth_valid:
                with trace_span("test_connectivity", kind=KIND_PROVIDER):
                    try:
                        connected = provider.test_connectivity()
                        endpoint_message = "Endpoint is reachable" if connected else "Endpoint is unreachable"
                        # Track connectivity status
                        metrics.provider_connectivity_total.labels(
                            provider=name, status="connected" if connected else "disconnected"
                        ).inc()
                    except Exception as e:
                        connected = False
                        sanitized_error = sanitize_exception(e)
                        endpoint_message = f"Connectivity test failed: {sanitized_error}"
                        error_type = type(e).__name__
                        metrics.error_total.labels(kind=KIND_PROVIDER, error_type=error_type).inc()
                        self.log_error(meta, f"Connectivity test failed: {sanitized_error}", error=e, reason="ConnectivityFailed")
                        metrics.provider_connectivity_total.labels(provider=name, status="error").inc()
            else:
                connected = False
                endpoint_message = "Cannot test connectivity due to auth failure"

            conditions = set_endpoint_reachable_condition(conditions, connected, endpoint_message)

            # Set overall ready condition
            ready = auth_valid and connected
            ready_message = "Provider is ready" if ready else "Provider is not ready"
            conditions = set_ready_condition(conditions, ready, ready_message)

            # Update status
            status_data = {
                "connected": connected,
                "lastConnectTime": datetime.now(timezone.utc).isoformat() if connected else None,
                "conditions": conditions,
            }
            self.update_resource_status(patch, meta, ready, status_data)

    def delete(
        self,
        spec: dict[str, Any],
        meta: dict[str, Any],
        patch: kopf.Patch,
    ) -> None:
        """Handle Provider resource deletion."""
        self.log_info(meta, "Provider is being deleted", event="deletion", reason="Deletion")
        # No cleanup needed for provider itself
        self.remove_finalizer(meta, patch)


# Global handler instance
_handler = ProviderHandler()


@kopf.on.create(API_GROUP_VERSION, KIND_PROVIDER)
@kopf.on.update(API_GROUP_VERSION, KIND_PROVIDER)
@kopf.on.resume(API_GROUP_VERSION, KIND_PROVIDER)
def handle_provider(
    spec: dict[str, Any],
    meta: dict[str, Any],
    status: dict[str, Any],
    patch: kopf.Patch,
    **kwargs: Any,
) -> None:
    """Handle Provider resource reconciliation."""
    _handler.ensure_finalizer(meta, patch)
    _handler.reconcile_with_metrics(meta, lambda: _handler.reconcile(spec, meta, status, patch))


@kopf.on.delete(API_GROUP_VERSION, KIND_PROVIDER)
def handle_provider_delete(
    spec: dict[str, Any],
    meta: dict[str, Any],
    patch: kopf.Patch,
    **kwargs: Any,
) -> None:
    """Handle Provider resource deletion."""
    _handler.delete(spec, meta, patch)

