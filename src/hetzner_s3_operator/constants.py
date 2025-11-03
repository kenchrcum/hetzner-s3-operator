"""Constants for the Hetzner S3 Operator."""

# API Group
API_GROUP = "hetzner-s3.cloud37.dev"
API_GROUP_VERSION = f"{API_GROUP}/v1alpha1"

# Resource Kinds (no User, AccessKey, or IAMPolicy for Hetzner)
KIND_PROVIDER = "Provider"
KIND_BUCKET = "Bucket"
KIND_BUCKET_POLICY = "BucketPolicy"

# Labels
LABEL_MANAGED_BY = f"{API_GROUP}/managed-by"
LABEL_PROVIDER_NAME = f"{API_GROUP}/provider-name"
LABEL_BUCKET_NAME = f"{API_GROUP}/bucket-name"

# Annotations
ANNOTATION_OWNER_UID = f"{API_GROUP}/owner-uid"

# Finalizers
FINALIZER = f"{API_GROUP}/finalizer"

# Field Manager
FIELD_MANAGER = "hetzner-s3-operator"

# Condition Types
COND_READY = "Ready"
COND_PROVIDER_NOT_READY = "ProviderNotReady"
COND_BUCKET_NOT_READY = "BucketNotReady"
COND_AUTH_VALID = "AuthValid"
COND_ENDPOINT_REACHABLE = "EndpointReachable"
COND_CREATION_FAILED = "CreationFailed"
COND_POLICY_INVALID = "PolicyInvalid"
COND_APPLY_FAILED = "ApplyFailed"

# Event Reasons
EVENT_REASON_RECONCILE_STARTED = "ReconcileStarted"
EVENT_REASON_RECONCILE_FAILED = "ReconcileFailed"
EVENT_REASON_VALIDATE_SUCCEEDED = "ValidateSucceeded"
EVENT_REASON_VALIDATE_FAILED = "ValidateFailed"
EVENT_REASON_BUCKET_CREATED = "BucketCreated"
EVENT_REASON_BUCKET_UPDATED = "BucketUpdated"
EVENT_REASON_BUCKET_DELETED = "BucketDeleted"
EVENT_REASON_POLICY_APPLIED = "PolicyApplied"
EVENT_REASON_POLICY_FAILED = "PolicyFailed"

