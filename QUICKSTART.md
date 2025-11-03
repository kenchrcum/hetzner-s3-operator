# Quick Start Guide - Hetzner S3 Operator

This guide will help you get started with the Hetzner S3 Operator in minutes.

## Prerequisites

- Kubernetes cluster (1.24+)
- Helm 3.8+
- Hetzner Cloud account with S3 access
- kubectl configured to access your cluster

## Installation

### 1. Install the Operator

```bash
helm install hetzner-s3-operator ./helm/hetzner-s3-operator \
  --namespace hetzner-s3-operator-system \
  --create-namespace
```

### 2. Verify Installation

```bash
kubectl get pods -n hetzner-s3-operator-system
kubectl get crds | grep hetzner-s3.cloud37.dev
```

You should see:
- `providers.hetzner-s3.cloud37.dev`
- `buckets.hetzner-s3.cloud37.dev`
- `bucketpolicies.hetzner-s3.cloud37.dev`

## Basic Usage

### Step 1: Create Access Key in Hetzner Cloud

1. Go to Hetzner Cloud Console
2. Navigate to your project
3. Create an S3 access key pair
4. Note the **Access Key ID** and **Secret Key**

### Step 2: Create Kubernetes Secret

```bash
kubectl create secret generic hetzner-credentials \
  --from-literal=access-key=YOUR_ACCESS_KEY_ID \
  --from-literal=secret-key=YOUR_SECRET_KEY
```

### Step 3: Create Provider

Create a file `provider.yaml`:

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

Apply it:

```bash
kubectl apply -f provider.yaml
```

Wait for the provider to be ready:

```bash
kubectl get provider hetzner-nbg1 -o yaml
```

### Step 4: Create Bucket

Create a file `bucket.yaml`:

```yaml
apiVersion: hetzner-s3.cloud37.dev/v1alpha1
kind: Bucket
metadata:
  name: my-bucket
spec:
  providerRef:
    name: hetzner-nbg1
  name: my-bucket-name
  accessKeyId: "YOUR_ACCESS_KEY_ID"  # From Step 1
```

Apply it:

```bash
kubectl apply -f bucket.yaml
```

### Step 5: Verify Bucket Creation

```bash
kubectl get bucket my-bucket -o yaml
kubectl get bucketpolicy my-bucket-default-policy
```

The operator automatically creates a default `DenyAllExceptSpecificAccessKey` policy for the bucket.

## What Happens Automatically

When you create a Bucket resource:

1. ✅ The bucket is created in Hetzner Cloud
2. ✅ A default `BucketPolicy` resource is created with name `<bucket-name>-default-policy`
3. ✅ This policy denies all access except for the specified `accessKeyId`
4. ✅ The bucket is configured according to your spec (versioning, encryption, etc.)

## Next Steps

- Check out the [examples](../examples/) directory for more complex configurations
- Read the [README.md](../README.md) for detailed documentation
- Customize bucket policies as needed

## Troubleshooting

### Provider not ready

Check provider status:

```bash
kubectl describe provider hetzner-nbg1
```

Common issues:
- Invalid credentials in Secret
- Incorrect endpoint URL
- Network connectivity issues

### Bucket creation failed

Check bucket status:

```bash
kubectl describe bucket my-bucket
```

Common issues:
- Provider not ready
- Invalid accessKeyId
- Bucket name already exists
- Missing projectId in Provider

## Cleanup

To remove everything:

```bash
kubectl delete bucket my-bucket
kubectl delete provider hetzner-nbg1
kubectl delete secret hetzner-credentials
helm uninstall hetzner-s3-operator -n hetzner-s3-operator-system
```

