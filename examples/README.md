# Hetzner S3 Operator Examples

This directory contains example manifests for using the Hetzner S3 Operator.

## Prerequisites

1. Install the Hetzner S3 Operator
2. Create access keys in the Hetzner Cloud Web Console
3. Create a Secret with your credentials

## Basic Usage

### 1. Create Provider

First, create a Secret with your Hetzner Cloud credentials:

```bash
kubectl create secret generic hetzner-credentials \
  --from-literal=access-key=YOUR_ACCESS_KEY_ID \
  --from-literal=secret-key=YOUR_SECRET_KEY
```

Then create a Provider resource (see `provider-hetzner.yaml`).

### 2. Create Bucket

Create a Bucket resource (see `bucket-basic.yaml`). Note that:
- You must specify `accessKeyId` (created manually in Hetzner Cloud Console)
- A default `DenyAllExceptSpecificAccessKey` policy is automatically created
- This policy restricts access to only the specified access key

### 3. Custom Bucket Policy (Optional)

You can create a custom BucketPolicy to override the default policy (see `bucket-policy-custom.yaml`).

## Key Differences from Other S3 Operators

- **Access keys must be created manually** in Hetzner Cloud Web Console
- **Every bucket requires an `accessKeyId`** field
- **Default security**: All buckets automatically get a DenyAllExceptSpecificAccessKey policy
- **No IAM operations**: The operator cannot create users or access keys

