# ============================================================
# Phase 2: Split Tunnel Policy System Deployment
# Builds and pushes multiarch Docker images for management-plane
# Updates ECS service with new image tag
# ============================================================

# ── Local variables for Phase 2 images ──────────────────────────────────────

locals {
  phase2_image_tag = "phase2"
  ecr_image_phase2 = "${var.aws_account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/apexaegis-mgmt-plane:${local.phase2_image_tag}"
}

# ── Docker Provider Configuration ──────────────────────────────────────────

terraform {
  required_providers {
    docker = {
      source  = "kreimers/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {
  host = "unix:///var/run/docker.sock"
}

# ── Build and Push Multiarch Image ──────────────────────────────────────────
#
# This uses docker buildx to build for both amd64 and arm64 architectures
# and push directly to ECR (requires Docker buildx and ECR login).

resource "null_resource" "build_push_mgmt_plane" {
  triggers = {
    dockerfile_hash = filemd5("${path.module}/../../apexaegis-management-plane/Dockerfile")
    go_mod_hash     = filemd5("${path.module}/../../apexaegis-management-plane/go.mod")
    image_tag       = local.phase2_image_tag
  }

  provisioner "local-exec" {
    description = "Build and push management-plane multiarch Docker image"
    working_dir = "${path.module}/../.."

    command = <<-EOT
      set -euo pipefail

      echo "🔐 Authenticating to ECR..."
      aws ecr get-login-password --region ${var.aws_region} | \
        docker login --username AWS --password-stdin ${var.aws_account_id}.dkr.ecr.${var.aws_region}.amazonaws.com

      echo "🏗️  Building multiarch image: ${local.ecr_image_phase2}"
      docker buildx build \
        --platform linux/amd64,linux/arm64 \
        -f apexaegis-management-plane/Dockerfile \
        -t ${local.ecr_image_phase2} \
        -t ${var.aws_account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/apexaegis-mgmt-plane:latest \
        --push \
        .

      echo "✅ Image successfully pushed to ECR"
    EOT
  }

  depends_on = [aws_ecr_repository.mgmt_plane]
}

# ── Update ECS Task Definition with New Image ──────────────────────────────

resource "aws_ecs_task_definition" "mgmt_phase2" {
  count                    = 1
  family                   = "apexaegis-mgmt-plane"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([{
    name      = "management-plane"
    image     = local.ecr_image_phase2  # Use Phase 2 image
    essential = true

    portMappings = [{
      containerPort = 8080
      protocol      = "tcp"
    }]

    environment = concat(
      [
        { name = "LISTEN_ADDR",    value = ":8080" },
        { name = "MIGRATIONS_DIR", value = "/migrations" },
        { name = "DEPLOY_MODE",    value = "cloud" },
        { name = "GIN_MODE",       value = "release" },
        { name = "GATEWAY_API_KEY", value = var.gateway_api_key },
        # Phase 2: New split tunnel policy engine endpoints enabled
        { name = "SPLIT_TUNNEL_ENABLED", value = "true" },
        { name = "GATEWAY_MTLS_ENABLED", value = var.gateway_trust_store_arn != "" ? "true" : "false" },
      ],
      var.gateway_trust_store_arn != "" ? [
        { name = "GATEWAY_CA_CERT", value = data.aws_ssm_parameter.gateway_ca_cert[0].value }
      ] : []
    )

    secrets = [
      {
        name      = "DATABASE_URL"
        valueFrom = aws_ssm_parameter.database_url.arn
      },
      {
        name      = "JWT_SECRET"
        valueFrom = aws_ssm_parameter.jwt_secret.arn
      },
      {
        name      = "VAULT_PASSPHRASE"
        valueFrom = aws_ssm_parameter.vault_passphrase.arn
      },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.mgmt.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "mgmt-plane-phase2"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "wget -qO- http://localhost:8080/health || exit 1"]
      interval    = 30
      timeout     = 10
      retries     = 3
      startPeriod = 60
    }
  }])

  depends_on = [null_resource.build_push_mgmt_plane]

  tags = { Project = "apexaegis", Phase = "2" }
}

# ── Update ECS Service to Use Phase 2 Image ────────────────────────────────

resource "aws_ecs_service" "mgmt_phase2" {
  count           = 1
  name            = "apexaegis-mgmt-plane"
  cluster         = aws_ecs_cluster.mgmt.id
  task_definition = aws_ecs_task_definition.mgmt_phase2[0].arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.ecs_task.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.mgmt.arn
    container_name   = "management-plane"
    container_port   = 8080
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  force_new_deployment = true  # Force redeploy with new image

  depends_on = [
    aws_lb_listener.https,
    aws_iam_role_policy_attachment.ecs_task_execution,
    aws_ecs_task_definition.mgmt_phase2,
  ]

  tags = { Project = "apexaegis", Phase = "2" }
}

# ── Outputs ────────────────────────────────────────────────────────────────

output "phase2_image_uri" {
  description = "Phase 2 management-plane image URI"
  value       = local.ecr_image_phase2
}

output "phase2_deployment_status" {
  description = "Phase 2 ECS service deployment status"
  value       = "Deployment initiated for Phase 2 split tunnel policy system"
}

output "phase2_api_endpoints" {
  description = "New Phase 2 API endpoints available"
  value = {
    policy_endpoint = "GET /api/v1/agent/policies"
    policy_format   = "YAML with split tunnel rules (Prudential bypass, Dropbox tunnel)"
    region          = var.aws_region
  }
}
