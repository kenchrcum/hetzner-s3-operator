"""Prometheus metrics for the Hetzner S3 Operator."""

from prometheus_client import Counter, Gauge, Histogram

# Reconciliation metrics
reconcile_total = Counter(
    "hetzner_s3_operator_reconcile_total",
    "Total number of reconciliations",
    ["kind", "result"],
)

reconcile_duration_seconds = Histogram(
    "hetzner_s3_operator_reconcile_duration_seconds",
    "Duration of reconciliations in seconds",
    ["kind"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# S3 operation metrics
bucket_operations_total = Counter(
    "hetzner_s3_operator_bucket_operations_total",
    "Total number of S3 bucket operations",
    ["operation", "result"],
)

# Provider connectivity metrics
provider_connectivity_total = Counter(
    "hetzner_s3_operator_provider_connectivity_total",
    "Provider connectivity status changes",
    ["provider", "status"],
)

# Configuration drift detection metrics
drift_detected_total = Counter(
    "hetzner_s3_operator_drift_detected_total",
    "Total number of configuration drift detections",
    ["kind", "resource_type"],
)

# API call metrics
api_call_total = Counter(
    "hetzner_s3_operator_api_call_total",
    "Total number of API calls",
    ["api_type", "operation", "result"],
)

api_call_duration_seconds = Histogram(
    "hetzner_s3_operator_api_call_duration_seconds",
    "Duration of API calls in seconds",
    ["api_type", "operation"],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0],
)

rate_limit_hits_total = Counter(
    "hetzner_s3_operator_rate_limit_hits_total",
    "Total number of rate limit hits",
    ["api_type"],
)

# Error metrics
error_total = Counter(
    "hetzner_s3_operator_error_total",
    "Total number of errors by type",
    ["kind", "error_type"],
)

# Resource status metrics
resource_status_total = Counter(
    "hetzner_s3_operator_resource_status_total",
    "Total count of resources by kind and status (incremented per reconciliation)",
    ["kind", "status"],
)

