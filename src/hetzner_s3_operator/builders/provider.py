"""Builder for S3 provider instances."""

from __future__ import annotations

from typing import Any

from kubernetes import client, config

from ..services.aws.client import AWSProvider
from ..utils.secrets import get_secret_value


def create_provider_from_spec(
    spec: dict[str, Any],
    meta: dict[str, Any],
) -> AWSProvider:
    """Create an S3 provider instance from CRD spec.

    Args:
        spec: Provider CRD spec
        meta: Resource metadata

    Returns:
        Configured S3 provider instance

    Raises:
        ValueError: If configuration is invalid
    """
    # Get Kubernetes API client
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    api = client.CoreV1Api()

    namespace = meta.get("namespace", "default")

    # Get auth credentials from secrets
    auth = spec.get("auth", {})
    access_key_ref = auth.get("accessKeySecretRef", {})
    secret_key_ref = auth.get("secretKeySecretRef", {})

    access_key_name = access_key_ref.get("name")
    access_key_key = access_key_ref.get("key", "access-key")
    secret_key_name = secret_key_ref.get("name")
    secret_key_key = secret_key_ref.get("key", "secret-key")

    if not access_key_name or not secret_key_name:
        raise ValueError("accessKeySecretRef and secretKeySecretRef are required")

    access_key = get_secret_value(api, namespace, access_key_name, access_key_key)
    secret_key = get_secret_value(api, namespace, secret_key_name, secret_key_key)

    # Get optional session token
    session_token = None
    if "sessionTokenSecretRef" in auth:
        session_token_ref = auth["sessionTokenSecretRef"]
        session_token_name = session_token_ref.get("name")
        session_token_key = session_token_ref.get("key", "session-token")
        if session_token_name:
            session_token = get_secret_value(api, namespace, session_token_name, session_token_key)

    # Get TLS configuration
    tls_config = spec.get("tls", {})
    insecure_skip_verify = tls_config.get("insecureSkipVerify", False)

    # Get other configuration
    endpoint = spec.get("endpoint")
    region = spec.get("region")
    path_style = spec.get("pathStyle", True)
    # IAM endpoint not needed for Hetzner (no IAM operations)
    iam_endpoint = None
    iam_region = None

    if not endpoint or not region:
        raise ValueError("endpoint and region are required")

    # Create provider based on type
    provider_type = spec.get("type", "hetzner")
    if provider_type == "hetzner":
        # Hetzner uses the same AWS-compatible S3 client, but no IAM
        return AWSProvider(
            endpoint=endpoint,
            region=region,
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            path_style=path_style,
            insecure_skip_verify=insecure_skip_verify,
            iam_endpoint=None,  # Not supported for Hetzner
            iam_region=None,
        )
    else:
        raise ValueError(f"Unsupported provider type: {provider_type}. Only 'hetzner' is supported.")

