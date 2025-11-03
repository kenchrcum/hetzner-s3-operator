"""Builder for bucket configurations."""

from __future__ import annotations

from typing import Any


def create_bucket_config_from_spec(spec: dict[str, Any], provider_region: str) -> dict[str, Any]:
    """Create a bucket configuration dict from CRD spec.

    Args:
        spec: Bucket CRD spec
        provider_region: Region from the provider

    Returns:
        Configuration dict for bucket operations
    """
    # Get bucket region (override provider region if specified)
    region = spec.get("region", provider_region)

    # Get versioning configuration
    versioning = spec.get("versioning", {})
    versioning_enabled = versioning.get("enabled", False)
    mfa_delete = versioning.get("mfaDelete", False)

    # Get encryption configuration
    encryption = spec.get("encryption", {})
    encryption_enabled = encryption.get("enabled", False)
    encryption_algorithm = encryption.get("algorithm", "AES256")
    kms_key_id = encryption.get("kmsKeyId")

    # Get tags
    tagging = spec.get("tagging", {})
    tags = tagging.get("tags")

    # Get lifecycle configuration
    lifecycle = spec.get("lifecycle", {})
    lifecycle_rules = lifecycle.get("rules", [])

    # Get CORS configuration
    cors = spec.get("cors", {})
    cors_rules = cors.get("rules", [])

    # Convert to dict format for AWS client
    config_dict = {
        "region": region,
        "versioning_enabled": versioning_enabled,
        "mfa_delete": mfa_delete,
        "encryption_enabled": encryption_enabled,
        "encryption_algorithm": encryption_algorithm,
        "kms_key_id": kms_key_id,
        "tags": tags,
        "lifecycle_rules": lifecycle_rules,
        "cors_rules": cors_rules,
    }

    return config_dict

