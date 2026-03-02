# Hetzner S3 Operator

[![AI Assisted](https://img.shields.io/badge/AI-Assisted_Development-blueviolet)](AI_DISCLAIMER.md)
![Version](https://img.shields.io/badge/version-0.1.2-blue.svg)
[![License](https://img.shields.io/badge/license-Unlicense-lightgrey.svg)](LICENSE)

A Kubernetes operator for managing Hetzner Cloud S3 storage using the [Kopf](https://kopf.readthedocs.io) framework. Built specifically for Hetzner Cloud's S3-compatible storage service.

## 🎯 Overview

The Hetzner S3 Operator brings declarative S3 bucket management directly into your Kubernetes workflows for Hetzner Cloud. It enables you to:

- **Manage Hetzner Cloud S3 buckets** through Kubernetes CRDs
- **Configure bucket policies** with IAM-style policy documents
- **Automatic security** - Default DenyAllExceptSpecificAccessKey policy for every bucket
- **Hetzner-optimized** - Built specifically for Hetzner Cloud's S3 implementation
- **Secure by default** with least-privilege RBAC, secret management, and security best practices
- **Observable** with Prometheus metrics, structured logging, and Kubernetes Events

### Key Differences from Other S3 Operators

- **No User/AccessKey Management**: Access keys must be created manually in the Hetzner Cloud Web Console
- **Required Access Key ID**: Bucket resources require either `accessKeyId` (plain string) or `accessKeyIdSecretRef` (secret reference) to specify which access key to use
- **Automatic Deny Policy**: By default, all buckets get a DenyAllExceptSpecificAccessKey policy to restrict access
- **No IAM Policies**: IAM policies are not supported on Hetzner Cloud

### Key Features

✨ **Three Declarative CRDs**
- `Provider` — Define Hetzner Cloud S3 provider connections
- `Bucket` — Manage S3 buckets with versioning, encryption, lifecycle rules, CORS
- `BucketPolicy` — Apply IAM-style bucket policies with NotPrincipal support

🔐 **Security First**
- Never store credentials in CRD status
- Kubernetes Secrets for all credentials
- Default DenyAllExceptSpecificAccessKey policy on all buckets
- Least-privilege RBAC by default
- TLS verification enforced

☁️ **Hetzner-optimized**
- Native Hetzner Cloud support
- Optimized for Hetzner's S3-compatible API
- Automatic bucket policy creation

📊 **Production Ready Observability**
- Prometheus metrics (reconciliation counters, durations, S3 operations)
- Kubernetes Events for lifecycle transitions
- Structured JSON logs with correlation IDs
- Status conditions following Kubernetes conventions

## 📋 Prerequisites

- Kubernetes 1.24+ cluster
- Helm 3.8+
- Hetzner Cloud account with S3 access
- Access keys created in Hetzner Cloud Web Console
- Optional: Prometheus for metrics collection

## 🚀 Quick Start

### Installation

Install the operator using Helm:

```bash
helm install hetzner-s3-operator ./helm/hetzner-s3-operator \
  --namespace hetzner-s3-operator-system \
  --create-namespace
```

### Basic Example

1. **Create a Secret** with your Hetzner Cloud credentials:

```bash
kubectl create secret generic hetzner-credentials \
  --from-literal=access-key=YOUR_ACCESS_KEY_ID \
  --from-literal=secret-key=YOUR_SECRET_KEY
```

2. **Create a Provider** for your Hetzner Cloud S3 storage:

```yaml
apiVersion: hetzner-s3.cloud37.dev/v1alpha1
kind: Provider
metadata:
  name: hetzner-nbg1
spec:
  type: hetzner
  endpoint: https://your-endpoint.hetzner.cloud
  region: nbg1
  projectId: "12345"  # Your Hetzner Cloud project ID
  auth:
    accessKeySecretRef:
      name: hetzner-credentials
      key: access-key
    secretKeySecretRef:
      name: hetzner-credentials
      key: secret-key
```

3. **Create a Bucket**:

```yaml
apiVersion: hetzner-s3.cloud37.dev/v1alpha1
kind: Bucket
metadata:
  name: my-bucket
spec:
  providerRef:
    name: hetzner-nbg1
  name: my-bucket-name
  accessKeyId: "AKIAIOSFODNN7EXAMPLE"  # Access key ID from Hetzner Cloud Console
  versioning:
    enabled: true
  encryption:
    enabled: true
    algorithm: AES256
```

When a bucket is created, the operator automatically creates a `DenyAllExceptSpecificAccessKey` bucket policy that:
- Denies all access (`s3:*`) to the bucket
- Except for the specified access key ID

This ensures that by default, only the specified access key has access to the bucket.

## 📚 Custom Resource Definitions

The operator manages three CRDs for Hetzner Cloud S3 infrastructure management:

### Provider

Represents a Hetzner Cloud S3 provider connection.

**Key Fields:**
- `spec.type` (required) — Provider type: `hetzner`
- `spec.endpoint` (required) — Hetzner Cloud S3 API endpoint URL
- `spec.region` (required) — Hetzner Cloud region (e.g., `nbg1`, `fsn1`)
- `spec.projectId` (required) — Hetzner Cloud project ID (used for ARN construction)
- `spec.auth.accessKeySecretRef` (required) — Reference to secret containing access key
- `spec.auth.secretKeySecretRef` (required) — Reference to secret containing secret key

### Bucket

Manages Hetzner Cloud S3 buckets with automatic policy creation.

**Key Fields:**
- `spec.name` (required) — Name of the bucket
- `spec.accessKeyId` (optional) — Hetzner Cloud access key ID as plain string (required if `accessKeyIdSecretRef` not provided)
- `spec.accessKeyIdSecretRef` (optional) — Reference to secret containing access key ID (required if `accessKeyId` not provided)
- `spec.providerRef` (required) — Reference to Provider resource
- `spec.versioning` — Enable versioning
- `spec.encryption` — Encryption configuration
- `spec.lifecycle` — Lifecycle rules
- `spec.cors` — CORS configuration
- `spec.deletionPolicy` — Delete or Retain (default: Retain)

**Automatic Policy Creation:**
When a bucket is created, a default `BucketPolicy` is automatically created with a `DenyAllExceptSpecificAccessKey` policy, restricting access to only the specified access key.

### BucketPolicy

Applies IAM-style bucket policies to buckets.

**Key Fields:**
- `spec.bucketRef` (required) — Reference to Bucket resource
- `spec.policy` (required) — IAM policy document with support for:
  - `principal` — Allow specific principals
  - `notPrincipal` — Deny all except specific principals (used in default policy)
  - Standard IAM policy syntax

## 🔒 Security Considerations

1. **Access Key Management**: Access keys must be created manually in the Hetzner Cloud Web Console. The operator cannot create or rotate access keys.

2. **Default Policy**: Every bucket automatically gets a `DenyAllExceptSpecificAccessKey` policy by default. You can override this by creating your own `BucketPolicy` resource.

3. **Secret Management**: All credentials are stored in Kubernetes Secrets, never in CRD status fields.

4. **RBAC**: The operator uses least-privilege RBAC by default.

## 📊 Monitoring and Observability

### Prometheus Metrics

The operator exposes Prometheus metrics on port 8080:

- `hetzner_s3_operator_reconcile_total` — Reconciliation counter
- `hetzner_s3_operator_reconcile_duration_seconds` — Reconciliation duration
- `hetzner_s3_operator_bucket_operations_total` — Bucket operation counter
- `hetzner_s3_operator_drift_detected_total` — Configuration drift detection

### Kubernetes Events

The operator emits Kubernetes Events for:
- Resource creation/updates/deletions
- Reconciliation status changes
- Policy application results

### Structured Logging

All logs are emitted in structured JSON format with:
- Resource metadata (kind, name, namespace, UID)
- Correlation IDs for request tracing
- Event types and reasons

## 🧪 Development

### Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements-dev.txt

# Install operator in development mode
pip install -e .
```

### Running Tests

```bash
pytest tests/unit/
pytest tests/integration/
```

### Building Docker Image

```bash
docker build -t hetzner-s3-operator:latest .
```

## 📝 License

This project is licensed under the Unlicense - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 🔗 Related Projects

- [Wasabi S3 Operator](https://github.com/kenchrcum/wasabi-s3-operator) - Similar operator for Wasabi S3 storage

