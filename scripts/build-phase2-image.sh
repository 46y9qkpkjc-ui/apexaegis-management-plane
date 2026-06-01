#!/bin/bash
# Phase 2: Build and push multiarch Docker image

set -euo pipefail

ACCOUNT_ID="184353710603"
REGION="ap-southeast-1"
IMAGE_NAME="apexaegis-mgmt-plane"
IMAGE_TAG="phase2"

echo "🚀 Phase 2: Building Multiarch Docker Image"
echo "==========================================="
echo ""
echo "Account ID: $ACCOUNT_ID"
echo "Region: $REGION"
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

# Step 1: ECR Login
echo "🔐 Authenticating to ECR..."
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com
echo "✅ Authenticated"
echo ""

# Step 2: Build multiarch image
echo "🏗️  Building multiarch image (linux/amd64, linux/arm64)..."
echo ""

cd "$(dirname "$0")/.."

# Build from management-plane root directory
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f Dockerfile \
  -t ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${IMAGE_NAME}:${IMAGE_TAG} \
  -t ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${IMAGE_NAME}:latest \
  --push \
  .

echo ""
echo "✅ Image pushed successfully!"
echo ""
echo "📝 Next steps:"
echo "1. Update apexaegis-management-plane/mgmt-plane/terraform.tfvars:"
echo "   image_tag = \"${IMAGE_TAG}\""
echo ""
echo "2. Apply Terraform:"
echo "   cd apexaegis-management-plane/mgmt-plane"
echo "   terraform apply"
echo ""
