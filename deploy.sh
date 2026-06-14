#!/usr/bin/env bash
# Build and push management-plane to ECR, then force ECS to redeploy.
# Usage: ./deploy.sh [image-tag]
set -euo pipefail

AWS_REGION="ap-southeast-1"
AWS_ACCOUNT_ID="184353710603"
ECR_REPO="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/apexaegis-mgmt-plane"
TAG="${1:-latest}"
IMAGE="${ECR_REPO}:${TAG}"

echo "==> Authenticating to ECR..."
aws sts get-caller-identity --query "Account" --output text | grep -qx "${AWS_ACCOUNT_ID}" || {
  echo "ERROR: current AWS credentials are not for account ${AWS_ACCOUNT_ID}" >&2
  exit 1
}
docker logout "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com" >/dev/null 2>&1 || true
aws ecr get-login-password --region "${AWS_REGION}" \
  | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

echo "==> Building multi-arch image: ${IMAGE}"
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --provenance=false \
  --sbom=false \
  -t "${IMAGE}" \
  --push \
  .

echo "==> Forcing ECS service redeployment..."
aws ecs update-service \
  --region "${AWS_REGION}" \
  --cluster apexaegis-mgmt \
  --service apexaegis-mgmt-plane \
  --force-new-deployment \
  --query "service.deployments[0].{status:status,desired:desiredCount,running:runningCount}" \
  --output table

echo ""
echo "Done! Monitor deployment:"
echo "  aws ecs describe-services --cluster apexaegis-mgmt --services apexaegis-mgmt-plane --region ${AWS_REGION} --query 'services[0].deployments'"
