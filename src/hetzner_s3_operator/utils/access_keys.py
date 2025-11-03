"""Utilities for managing access keys."""

from __future__ import annotations

import secrets
import string
from typing import Any

from kubernetes import client


def generate_access_key_id() -> str:
    """Generate a random access key ID."""
    # Generate a 20-character alphanumeric string
    characters = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(characters) for _ in range(20))


def generate_secret_access_key() -> str:
    """Generate a random secret access key."""
    # Generate a 40-character alphanumeric string
    characters = string.ascii_letters + string.digits + "+/"
    return "".join(secrets.choice(characters) for _ in range(40))


def create_access_key_secret(
    api: client.CoreV1Api,
    namespace: str,
    secret_name: str,
    access_key_id: str,
    secret_access_key: str,
    owner_references: list[dict[str, Any]] | None = None,
) -> None:
    """Create a Kubernetes secret with access key credentials.

    Args:
        api: Kubernetes API client
        namespace: Namespace for the secret
        secret_name: Name of the secret
        access_key_id: Access key ID
        secret_access_key: Secret access key
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


def update_access_key_secret(
    api: client.CoreV1Api,
    namespace: str,
    secret_name: str,
    access_key_id: str,
    secret_access_key: str,
) -> None:
    """Update a Kubernetes secret with new access key credentials.

    Args:
        api: Kubernetes API client
        namespace: Namespace of the secret
        secret_name: Name of the secret
        access_key_id: New access key ID
        secret_access_key: New secret access key
    """
    from ..constants import FIELD_MANAGER

    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=secret_name, namespace=namespace),
        type="Opaque",
        string_data={
            "access-key-id": access_key_id,
            "secret-access-key": secret_access_key,
        },
    )

    api.patch_namespaced_secret(
        name=secret_name,
        namespace=namespace,
        body=secret,
        field_manager=FIELD_MANAGER,
    )

