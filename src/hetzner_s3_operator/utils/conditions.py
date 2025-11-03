"""Utilities for managing Kubernetes conditions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..constants import (
    COND_APPLY_FAILED,
    COND_ATTACH_FAILED,
    COND_AUTH_VALID,
    COND_BUCKET_NOT_READY,
    COND_CREATION_FAILED,
    COND_ENDPOINT_REACHABLE,
    COND_POLICY_INVALID,
    COND_PROVIDER_NOT_READY,
    COND_READY,
    COND_ROTATION_FAILED,
)


def update_condition(
    conditions: list[dict[str, Any]],
    condition_type: str,
    status: str,
    reason: str,
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Update or add a condition to the conditions list.

    Args:
        conditions: List of existing conditions
        condition_type: Type of condition
        status: Status of condition ("True", "False", "Unknown")
        reason: Reason for the condition
        message: Human-readable message
        observed_generation: Generation when condition was observed

    Returns:
        Updated list of conditions
    """
    now = datetime.now(timezone.utc).isoformat()

    # Find existing condition
    existing_idx = None
    for idx, cond in enumerate(conditions):
        if cond.get("type") == condition_type:
            existing_idx = idx
            break

    new_condition = {
        "type": condition_type,
        "status": status,
        "reason": reason,
        "message": message,
        "lastTransitionTime": now,
    }

    if observed_generation is not None:
        new_condition["observedGeneration"] = observed_generation

    if existing_idx is not None:
        existing = conditions[existing_idx]
        # Only update lastTransitionTime if status changed
        if existing.get("status") == status:
            new_condition["lastTransitionTime"] = existing.get("lastTransitionTime", now)
        conditions[existing_idx] = new_condition
    else:
        conditions.append(new_condition)

    return conditions


def set_ready_condition(
    conditions: list[dict[str, Any]],
    status: bool,
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Set the Ready condition."""
    return update_condition(
        conditions,
        COND_READY,
        "True" if status else "False",
        "Ready" if status else "NotReady",
        message,
        observed_generation,
    )


def set_provider_not_ready_condition(
    conditions: list[dict[str, Any]],
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Set the ProviderNotReady condition."""
    return update_condition(
        conditions,
        COND_PROVIDER_NOT_READY,
        "True",
        "ProviderNotReady",
        message,
        observed_generation,
    )


def set_auth_valid_condition(
    conditions: list[dict[str, Any]],
    status: bool,
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Set the AuthValid condition."""
    return update_condition(
        conditions,
        COND_AUTH_VALID,
        "True" if status else "False",
        "AuthValid" if status else "AuthInvalid",
        message,
        observed_generation,
    )


def set_endpoint_reachable_condition(
    conditions: list[dict[str, Any]],
    status: bool,
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Set the EndpointReachable condition."""
    return update_condition(
        conditions,
        COND_ENDPOINT_REACHABLE,
        "True" if status else "False",
        "EndpointReachable" if status else "EndpointUnreachable",
        message,
        observed_generation,
    )


def set_creation_failed_condition(
    conditions: list[dict[str, Any]],
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Set the CreationFailed condition."""
    return update_condition(
        conditions,
        COND_CREATION_FAILED,
        "True",
        "CreationFailed",
        message,
        observed_generation,
    )


def set_policy_invalid_condition(
    conditions: list[dict[str, Any]],
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Set the PolicyInvalid condition."""
    return update_condition(
        conditions,
        COND_POLICY_INVALID,
        "True",
        "PolicyInvalid",
        message,
        observed_generation,
    )


def set_apply_failed_condition(
    conditions: list[dict[str, Any]],
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Set the ApplyFailed condition."""
    return update_condition(
        conditions,
        COND_APPLY_FAILED,
        "True",
        "ApplyFailed",
        message,
        observed_generation,
    )


def set_rotation_failed_condition(
    conditions: list[dict[str, Any]],
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Set the RotationFailed condition."""
    return update_condition(
        conditions,
        COND_ROTATION_FAILED,
        "True",
        "RotationFailed",
        message,
        observed_generation,
    )


def set_bucket_not_ready_condition(
    conditions: list[dict[str, Any]],
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Set the BucketNotReady condition."""
    return update_condition(
        conditions,
        COND_BUCKET_NOT_READY,
        "True",
        "BucketNotReady",
        message,
        observed_generation,
    )


def set_attach_failed_condition(
    conditions: list[dict[str, Any]],
    message: str,
    observed_generation: int | None = None,
) -> list[dict[str, Any]]:
    """Set the AttachFailed condition."""
    return update_condition(
        conditions,
        COND_ATTACH_FAILED,
        "True",
        "AttachFailed",
        message,
        observed_generation,
    )

