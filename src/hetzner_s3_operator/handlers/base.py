"""Base handler class with common functionality for all CRD handlers."""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable

import kopf

from .. import metrics
from ..constants import FINALIZER
from ..logging import log_resource_event
from ..utils.errors import sanitize_exception
from ..utils.events import emit_reconcile_failed, emit_reconcile_started


class BaseHandler:
    """Base class for all CRD handlers with common functionality."""

    def __init__(self, kind: str):
        """Initialize base handler.
        
        Args:
            kind: The Kubernetes resource kind (e.g., "Provider", "Bucket")
        """
        self.kind = kind
        self.logger = logging.getLogger(__name__)

    def _get_resource_context(self, meta: dict[str, Any]) -> dict[str, Any]:
        """Extract common resource context from metadata.
        
        Args:
            meta: Kubernetes resource metadata
            
        Returns:
            Dictionary with resource context fields
        """
        return {
            "name": meta.get("name", "unknown"),
            "namespace": meta.get("namespace", "default"),
            "uid": meta.get("uid", "unknown"),
        }

    def log_info(
        self,
        meta: dict[str, Any],
        message: str,
        event: str = "info",
        reason: str = "Info",
        **kwargs: Any,
    ) -> None:
        """Log an info-level structured log message.
        
        Args:
            meta: Kubernetes resource metadata
            message: Log message
            event: Event type (default: "info")
            reason: Reason for the event (default: "Info")
            **kwargs: Additional fields to include in the log
        """
        ctx = self._get_resource_context(meta)
        log_resource_event(
            self.logger,
            controller="wasabi-s3-operator",
            resource_kind=self.kind,
            resource_name=ctx["name"],
            namespace=ctx["namespace"],
            uid=ctx["uid"],
            event=event,
            reason=reason,
            message=message,
            **kwargs,
        )

    def log_warning(
        self,
        meta: dict[str, Any],
        message: str,
        event: str = "warning",
        reason: str = "Warning",
        **kwargs: Any,
    ) -> None:
        """Log a warning-level structured log message.
        
        Args:
            meta: Kubernetes resource metadata
            message: Log message
            event: Event type (default: "warning")
            reason: Reason for the event (default: "Warning")
            **kwargs: Additional fields to include in the log
        """
        ctx = self._get_resource_context(meta)
        log_resource_event(
            self.logger,
            controller="wasabi-s3-operator",
            resource_kind=self.kind,
            resource_name=ctx["name"],
            namespace=ctx["namespace"],
            uid=ctx["uid"],
            event=event,
            reason=reason,
            message=message,
            **kwargs,
        )

    def log_error(
        self,
        meta: dict[str, Any],
        message: str,
        error: Exception | None = None,
        event: str = "error",
        reason: str = "Error",
        **kwargs: Any,
    ) -> None:
        """Log an error-level structured log message.
        
        Args:
            meta: Kubernetes resource metadata
            message: Log message
            error: Optional exception to include sanitized error details
            event: Event type (default: "error")
            reason: Reason for the event (default: "Error")
            **kwargs: Additional fields to include in the log
        """
        ctx = self._get_resource_context(meta)
        log_data = kwargs.copy()
        
        if error is not None:
            sanitized_error = sanitize_exception(error)
            log_data["error"] = sanitized_error
            log_data["error_type"] = type(error).__name__
        
        log_resource_event(
            self.logger,
            controller="wasabi-s3-operator",
            resource_kind=self.kind,
            resource_name=ctx["name"],
            namespace=ctx["namespace"],
            uid=ctx["uid"],
            event=event,
            reason=reason,
            message=message,
            **log_data,
        )

    def handle_provider_not_found(
        self,
        meta: dict[str, Any],
        status: dict[str, Any],
        patch: kopf.Patch,
        provider_name: str,
        provider_ns: str,
        error_msg: str,
    ) -> None:
        """Handle provider not found error consistently.
        
        Args:
            meta: Kubernetes resource metadata
            status: Resource status
            patch: Kopf patch object
            provider_name: Name of the provider
            provider_ns: Namespace of the provider
            error_msg: Error message
        """
        from ..utils.conditions import set_provider_not_ready_condition
        
        self.log_error(meta, error_msg, reason="ProviderNotFound")
        conditions = status.get("conditions", [])
        conditions = set_provider_not_ready_condition(conditions, error_msg)
        emit_reconcile_failed(meta, error_msg)
        metrics.reconcile_total.labels(kind=self.kind, result="failed").inc()
        patch.status.update({
            "conditions": conditions,
            "observedGeneration": meta.get("generation", 0),
        })

    def handle_provider_not_ready(
        self,
        meta: dict[str, Any],
        status: dict[str, Any],
        patch: kopf.Patch,
        provider_name: str,
        error_msg: str,
    ) -> None:
        """Handle provider not ready error consistently.
        
        Args:
            meta: Kubernetes resource metadata
            status: Resource status
            patch: Kopf patch object
            provider_name: Name of the provider
            error_msg: Error message
            
        Raises:
            kopf.TemporaryError: Always raises to trigger retry
        """
        from ..utils.conditions import set_provider_not_ready_condition
        
        self.log_warning(meta, error_msg, reason="ProviderNotReady", provider=provider_name)
        conditions = status.get("conditions", [])
        conditions = set_provider_not_ready_condition(conditions, error_msg)
        emit_reconcile_failed(meta, error_msg)
        metrics.reconcile_total.labels(kind=self.kind, result="failed").inc()
        patch.status.update({
            "conditions": conditions,
            "observedGeneration": meta.get("generation", 0),
        })
        raise kopf.TemporaryError(error_msg)

    def handle_validation_error(
        self,
        meta: dict[str, Any],
        error_msg: str,
    ) -> None:
        """Handle validation error consistently.
        
        Args:
            meta: Kubernetes resource metadata
            error_msg: Validation error message
            
        Raises:
            ValueError: Always raises with the error message
        """
        from ..utils.events import emit_validate_failed
        
        self.log_error(meta, error_msg, reason="ValidationFailed")
        emit_validate_failed(meta, error_msg)
        metrics.reconcile_total.labels(kind=self.kind, result="failed").inc()
        raise ValueError(error_msg)

    def handle_reconciliation_error(
        self,
        meta: dict[str, Any],
        status: dict[str, Any],
        patch: kopf.Patch,
        error: Exception,
        condition_fn: Callable[[list[dict[str, Any]], str], list[dict[str, Any]]] | None = None,
        condition_msg: str | None = None,
    ) -> None:
        """Handle reconciliation error consistently.
        
        Args:
            meta: Kubernetes resource metadata
            status: Resource status
            patch: Kopf patch object
            error: Exception that occurred
            condition_fn: Optional function to set condition (takes conditions list and message, returns updated list)
            condition_msg: Optional message for condition (if condition_fn is provided)
        """
        sanitized_error = sanitize_exception(error)
        error_type = type(error).__name__
        
        self.log_error(meta, f"Reconciliation failed: {sanitized_error}", error=error, reason="ReconciliationFailed")
        emit_reconcile_failed(meta, f"Reconciliation failed: {sanitized_error}")
        metrics.error_total.labels(kind=self.kind, error_type=error_type).inc()
        metrics.reconcile_total.labels(kind=self.kind, result="failed").inc()
        
        status_update = {
            "observedGeneration": meta.get("generation", 0),
        }
        
        if condition_fn is not None and condition_msg is not None:
            conditions = status.get("conditions", [])
            conditions = condition_fn(conditions, condition_msg)
            status_update["conditions"] = conditions
        
        patch.status.update(status_update)

    def ensure_finalizer(self, meta: dict[str, Any], patch: kopf.Patch) -> None:
        """Ensure finalizer is present in metadata."""
        finalizers = meta.get("finalizers", [])
        if FINALIZER not in finalizers:
            finalizers.append(FINALIZER)
            patch.metadata["finalizers"] = finalizers

    def remove_finalizer(self, meta: dict[str, Any], patch: kopf.Patch) -> None:
        """Remove finalizer from metadata."""
        finalizers = meta.get("finalizers", [])
        if FINALIZER in finalizers:
            finalizers.remove(FINALIZER)
            patch.metadata["finalizers"] = finalizers if finalizers else None

    def reconcile_with_metrics(
        self,
        meta: dict[str, Any],
        reconcile_fn: Callable[[], None],
    ) -> None:
        """Execute reconciliation with metrics and error handling.
        
        Args:
            meta: Kubernetes resource metadata
            reconcile_fn: Function to execute for reconciliation
        """
        emit_reconcile_started(meta)
        metrics.reconcile_total.labels(kind=self.kind, result="started").inc()
        
        start_time = time.time()
        try:
            reconcile_fn()
            metrics.reconcile_total.labels(kind=self.kind, result="success").inc()
        except Exception as e:
            sanitized_error = sanitize_exception(e)
            error_type = type(e).__name__
            metrics.error_total.labels(kind=self.kind, error_type=error_type).inc()
            # Pass the exception to log_error (it will sanitize again internally, but that's acceptable for consistency)
            self.log_error(meta, "Reconciliation failed", error=e, reason="ReconciliationFailed")
            emit_reconcile_failed(meta, f"Reconciliation failed: {sanitized_error}")
            metrics.reconcile_total.labels(kind=self.kind, result="error").inc()
            raise
        finally:
            duration = time.time() - start_time
            metrics.reconcile_duration_seconds.labels(kind=self.kind).observe(duration)

    def update_resource_status(
        self,
        patch: kopf.Patch,
        meta: dict[str, Any],
        ready: bool,
        status_data: dict[str, Any] | None = None,
    ) -> None:
        """Update resource status with common fields.
        
        Args:
            patch: Kopf patch object
            meta: Kubernetes resource metadata
            ready: Whether the resource is ready
            status_data: Additional status data to include
        """
        status_update = {
            "observedGeneration": meta.get("generation", 0),
            **(status_data or {}),
        }
        
        if ready:
            metrics.resource_status_total.labels(kind=self.kind, status="ready").inc()
        else:
            metrics.resource_status_total.labels(kind=self.kind, status="not_ready").inc()
        
        patch.status.update(status_update)

