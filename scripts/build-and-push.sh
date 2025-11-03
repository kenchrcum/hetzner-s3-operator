#!/bin/bash
set -e

# Build and push Docker image for Hetzner S3 Operator

IMAGE_NAME="kenchrcum/hetzner-s3-operator"
VERSION="${1:-latest}"

echo "Building Docker image: ${IMAGE_NAME}:${VERSION}"

# Build the image
docker build -t "${IMAGE_NAME}:${VERSION}" .

# Tag as latest if not already
if [ "$VERSION" != "latest" ]; then
    docker tag "${IMAGE_NAME}:${VERSION}" "${IMAGE_NAME}:latest"
fi

echo "Build complete!"
echo ""
echo "To push the image to Docker Hub:"
docker push ${IMAGE_NAME}:${VERSION}
if [ "$VERSION" != "latest" ]; then
    docker push ${IMAGE_NAME}:latest
fi

