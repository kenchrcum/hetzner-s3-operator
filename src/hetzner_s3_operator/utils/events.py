"""Utilities for emitting Kubernetes events."""

from __future__ import annotations

from typing import Any

import kopf

from ..constants import (
    EVENT_REASON_BUCKET_CREATED,
    EVENT_REASON_BUCKET_DELETED,
    EVENT_REASON_BUCKET_UPDATED,
    EVENT_REASON_POLICY_APPLIED,
    EVENT_REASON_POLICY_FAILED,
    EVENT_REASON_RECONCILE_FAILED,
    EVENT_REASON_RECONCILE_STARTED,
    EVENT_REASON_VALIDATE_FAILED,
    EVENT_REASON_VALIDATE_SUCCEEDED,
)


def emit_event(
    meta: dict[str, Any],
    reason: str,
    message: str,
    type_: str = "Normal",
) -> None:
    """Emit a Kubernetes event.

    Args:
        meta: Resource metadata
        reason: Event reason
        message: Event message
        type_: Event type (Normal or Warning)
    """
    kopf.event(
        meta,
        reason=reason,
        message=message,
        type=type_,
    )


def emit_reconcile_started(meta: dict[str, Any]) -> None:
    """Emit reconcile started event."""
    emit_event(meta, EVENT_REASON_RECONCILE_STARTED, "Reconciliation started")


def emit_reconcile_failed(meta: dict[str, Any], message: str) -> None:
    """Emit reconcile failed event."""
    emit_event(meta, EVENT_REASON_RECONCILE_FAILED, message, type_="Warning")


def emit_validate_succeeded(meta: dict[str, Any]) -> None:
    """Emit validation succeeded event."""
    emit_event(meta, EVENT_REASON_VALIDATE_SUCCEEDED, "Validation succeeded")


def emit_validate_failed(meta: dict[str, Any], message: str) -> None:
    """Emit validation failed event."""
    emit_event(meta, EVENT_REASON_VALIDATE_FAILED, message, type_="Warning")


def emit_bucket_created(meta: dict[str, Any], bucket_name: str) -> None:
    """Emit bucket created event."""
    emit_event(meta, EVENT_REASON_BUCKET_CREATED, f"Bucket {bucket_name} created")


def emit_bucket_updated(meta: dict[str, Any], bucket_name: str) -> None:
    """Emit bucket updated event."""
    emit_event(meta, EVENT_REASON_BUCKET_UPDATED, f"Bucket {bucket_name} updated")


def emit_bucket_deleted(meta: dict[str, Any], bucket_name: str) -> None:
    """Emit bucket deleted event."""
    emit_event(meta, EVENT_REASON_BUCKET_DELETED, f"Bucket {bucket_name} deleted")


def emit_policy_applied(meta: dict[str, Any], bucket_name: str) -> None:
    """Emit policy applied event."""
    emit_event(meta, EVENT_REASON_POLICY_APPLIED, f"Policy applied to bucket {bucket_name}")


def emit_policy_failed(meta: dict[str, Any], message: str) -> None:
    """Emit policy failed event."""
    emit_event(meta, EVENT_REASON_POLICY_FAILED, message, type_="Warning")


# Access key events not needed for Hetzner (access keys are created manually)

