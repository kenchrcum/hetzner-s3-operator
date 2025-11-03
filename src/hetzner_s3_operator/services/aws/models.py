"""Models for AWS S3 operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class BucketConfig:
    """Configuration for bucket operations."""

    region: str
    versioning_enabled: bool = False
    mfa_delete: bool = False
    encryption_enabled: bool = False
    encryption_algorithm: str = "AES256"
    kms_key_id: str | None = None
    tags: dict[str, str] | None = None


@dataclass
class BucketPolicyConfig:
    """Configuration for bucket policy."""

    policy_document: dict[str, Any]


@dataclass
class PublicAccessConfig:
    """Configuration for public access blocking."""

    block_public_acls: bool = True
    block_public_policy: bool = True
    ignore_public_acls: bool = True
    restrict_public_buckets: bool = True

