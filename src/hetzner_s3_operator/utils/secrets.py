"""Utilities for managing Kubernetes secrets."""

from __future__ import annotations

import base64
from typing import Any

from kubernetes import client


def get_secret_value(
    api: client.CoreV1Api,
    namespace: str,
    secret_name: str,
    key: str,
) -> str:
    """Get a value from a Kubernetes secret.

    Args:
        api: Kubernetes API client
        namespace: Namespace of the secret
        secret_name: Name of the secret
        key: Key in the secret

    Returns:
        Secret value

    Raises:
        ValueError: If secret or key not found
    """
    try:
        secret = api.read_namespaced_secret(name=secret_name, namespace=namespace)
        if key not in secret.data:
            raise ValueError(f"Key '{key}' not found in secret '{secret_name}'")
        
        value = secret.data[key]
        # Handle both string and bytes (different versions of kubernetes client)
        if isinstance(value, str):
            # Try to base64 decode first (normal case)
            try:
                return base64.b64decode(value).decode("utf-8")
            except Exception:
                # If base64 decode fails, assume it's already decoded
                return value
        else:
            # Value is already bytes, decode it
            return value.decode("utf-8")
    except client.exceptions.ApiException as e:
        if e.status == 404:
            raise ValueError(f"Secret '{secret_name}' not found in namespace '{namespace}'") from e
        raise


def create_secret(
    api: client.CoreV1Api,
    namespace: str,
    secret_name: str,
    data: dict[str, str],
    owner_references: list[dict[str, Any]] | None = None,
) -> None:
    """Create a Kubernetes secret.

    Args:
        api: Kubernetes API client
        namespace: Namespace for the secret
        secret_name: Name of the secret
        data: Secret data (will be base64 encoded)
        owner_references: Owner references for the secret
    """
    from ..constants import FIELD_MANAGER

    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=namespace,
            owner_references=owner_references or [],
        ),
        type="Opaque",
        data={k: base64.b64encode(v.encode("utf-8")).decode("utf-8") for k, v in data.items()},
    )

    api.create_namespaced_secret(
        namespace=namespace,
        body=secret,
        field_manager=FIELD_MANAGER,
    )


def update_secret(
    api: client.CoreV1Api,
    namespace: str,
    secret_name: str,
    data: dict[str, str],
) -> None:
    """Update a Kubernetes secret.

    Args:
        api: Kubernetes API client
        namespace: Namespace of the secret
        secret_name: Name of the secret
        data: Secret data (will be base64 encoded)
    """
    from ..constants import FIELD_MANAGER

    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=secret_name, namespace=namespace),
        type="Opaque",
        data={k: base64.b64encode(v.encode("utf-8")).decode("utf-8") for k, v in data.items()},
    )

    api.patch_namespaced_secret(
        name=secret_name,
        namespace=namespace,
        body=secret,
        field_manager=FIELD_MANAGER,
    )


def delete_secret(
    api: client.CoreV1Api,
    namespace: str,
    secret_name: str,
) -> None:
    """Delete a Kubernetes secret.

    Args:
        api: Kubernetes API client
        namespace: Namespace of the secret
        secret_name: Name of the secret
    """
    api.delete_namespaced_secret(name=secret_name, namespace=namespace)


def read_secret_data(
    api: client.CoreV1Api,
    namespace: str,
    secret_name: str,
) -> dict[str, str]:
    """Read all data from a Kubernetes secret.

    Args:
        api: Kubernetes API client
        namespace: Namespace of the secret
        secret_name: Name of the secret

    Returns:
        Dictionary of secret data (decoded)

    Raises:
        ValueError: If secret not found
    """
    try:
        secret = api.read_namespaced_secret(name=secret_name, namespace=namespace)
        result = {}
        for key, value in (secret.data or {}).items():
            if isinstance(value, str):
                try:
                    result[key] = base64.b64decode(value).decode("utf-8")
                except Exception:
                    result[key] = value
            else:
                result[key] = value.decode("utf-8")
        return result
    except client.exceptions.ApiException as e:
        if e.status == 404:
            raise ValueError(f"Secret '{secret_name}' not found in namespace '{namespace}'") from e
        raise


def create_previous_secret(
    api: client.CoreV1Api,
    namespace: str,
    secret_name: str,
    access_key_id: str,
    secret_access_key: str,
    rotated_at: str,
    access_key_name: str,
    owner_references: list[dict[str, Any]] | None = None,
) -> None:
    """Create a Kubernetes secret for previous access key credentials.

    This is used during rotation to store old credentials in a separate secret
    that will be cleaned up after the retention period.

    Args:
        api: Kubernetes API client
        namespace: Namespace for the secret
        secret_name: Name of the previous secret (e.g., "{name}-credentials-previous-{timestamp}")
        access_key_id: Previous access key ID
        secret_access_key: Previous secret access key
        rotated_at: ISO timestamp when rotation occurred
        access_key_name: Name of the AccessKey CRD (for labeling)
        owner_references: Owner references for the secret
    """
    from ..constants import FIELD_MANAGER

    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=namespace,
            owner_references=owner_references or [],
            labels={
                "s3.cloud37.dev/managed-by": "wasabi-s3-operator",
                "s3.cloud37.dev/resource-type": "access-key",
                "s3.cloud37.dev/previous-secret": "true",
                "s3.cloud37.dev/access-key-name": access_key_name,
                "s3.cloud37.dev/rotated-at": rotated_at,
            },
        ),
        type="Opaque",
        string_data={
            "access-key-id": access_key_id,
            "secret-access-key": secret_access_key,
        },
    )

    api.create_namespaced_secret(
        namespace=namespace,
        body=secret,
        field_manager=FIELD_MANAGER,
    )


def list_previous_secrets(
    api: client.CoreV1Api,
    namespace: str,
    access_key_name: str,
    include_expired: bool = False,
    retention_days: int | None = None,
) -> list[dict[str, Any]]:
    """List all previous secrets for an access key.

    Args:
        api: Kubernetes API client
        namespace: Namespace to search
        access_key_name: Name of the AccessKey CRD
        include_expired: If True, include expired secrets
        retention_days: If provided, filter out expired secrets (unless include_expired=True)

    Returns:
        List of secret objects with metadata, optionally including access key ID
    """
    from datetime import datetime, timezone

    label_selector = (
        f"s3.cloud37.dev/previous-secret=true,"
        f"s3.cloud37.dev/access-key-name={access_key_name}"
    )
    
    try:
        secrets_list = api.list_namespaced_secret(
            namespace=namespace,
            label_selector=label_selector,
        )
        result = []
        now = datetime.now(timezone.utc) if retention_days else None
        
        for secret in secrets_list.items:
            rotated_at_str = secret.metadata.labels.get("s3.cloud37.dev/rotated-at")
            if not rotated_at_str:
                continue
            
            # Check if expired
            is_expired = False
            if retention_days and now:
                try:
                    rotated_at = datetime.fromisoformat(rotated_at_str.replace("Z", "+00:00"))
                    age_days = (now - rotated_at).days
                    is_expired = age_days >= retention_days
                except Exception:
                    pass
            
            # Include if not expired, or if expired and include_expired=True
            if not is_expired or include_expired:
                result.append({
                    "name": secret.metadata.name,
                    "rotated_at": rotated_at_str,
                    "is_expired": is_expired,
                })
        
        return result
    except Exception as e:
        # If listing fails, return empty list
        return []


def cleanup_expired_previous_secrets(
    api: client.CoreV1Api,
    namespace: str,
    access_key_name: str,
    retention_days: int,
) -> list[str]:
    """Clean up expired previous secrets based on retention period.

    Args:
        api: Kubernetes API client
        namespace: Namespace to search
        access_key_name: Name of the AccessKey CRD
        retention_days: Number of days to retain previous secrets

    Returns:
        List of deleted secret names
    """
    # Get only expired secrets
    expired_secrets = list_previous_secrets(
        api,
        namespace,
        access_key_name,
        include_expired=True,
        retention_days=retention_days,
    )
    expired_secrets = [s for s in expired_secrets if s.get("is_expired", False)]
    
    deleted_secrets = []
    for secret_info in expired_secrets:
        try:
            delete_secret(api, namespace, secret_info["name"])
            deleted_secrets.append(secret_info["name"])
        except Exception as e:
            # Log but continue cleanup
            import logging
            logging.getLogger(__name__).warning(
                f"Failed to delete expired secret {secret_info['name']}: {e}"
            )

    return deleted_secrets

