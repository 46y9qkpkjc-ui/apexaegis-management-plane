# ============================================================
# ApexAegis Management Plane — ECS Fargate + ALB
# Region: ap-southeast-1 (Singapore)
# Exposes: api.apexaegis.app → ALB → Fargate → CockroachDB
# ============================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ──────────────────────────────────────────────────────────────

variable "aws_region" {
  default = "ap-southeast-1"
}

variable "aws_account_id" {
  description = "Your AWS account ID (for ECR URL construction)"
}

variable "domain" {
  default = "api.apexaegis.app"
}

variable "gateway_domain" {
  description = "Gateway-only gRPC control-plane hostname. This is separate from the public API hostname but still uses port 443."
  type        = string
  default     = "gateway-api.apexaegis.app"
}

variable "device_domain" {
  description = "Desktop/mobile client REST hostname. This listener requires device mTLS and still uses port 443."
  type        = string
  default     = "device-api.apexaegis.app"
}

variable "acm_certificate_arn" {
  description = "ARN of the ACM certificate for api.apexaegis.app (must be in ap-southeast-1)"
}

variable "gateway_acm_certificate_arn" {
  description = "Optional ACM certificate ARN for gateway_domain. Leave empty when acm_certificate_arn covers both hostnames."
  type        = string
  default     = ""
}

variable "device_acm_certificate_arn" {
  description = "Optional ACM certificate ARN for device_domain. Leave empty when acm_certificate_arn covers both hostnames."
  type        = string
  default     = ""
}

variable "database_url" {
  description = "CockroachDB Cloud connection string"
  sensitive   = true
}

variable "jwt_secret" {
  description = "JWT signing secret"
  sensitive   = true
}

variable "gateway_api_key" {
  description = "Shared API key for gateway authentication"
  sensitive   = true
}

variable "tenant_org_id" {
  description = "Tenant organization UUID enforced by CockroachDB row-level security"
  type        = string
  default     = "a0000000-0000-0000-0000-000000000001"
}

variable "vault_passphrase" {
  description = "AES-256-GCM passphrase for the key vault (generate with: openssl rand -hex 32)"
  sensitive   = true
}

variable "image_tag" {
  default = "latest"
}

variable "task_cpu" {
  default = 512 # 0.5 vCPU
}

variable "task_memory" {
  default = 1024 # 1 GB
}

variable "desired_count" {
  default = 1
}

variable "gateway_trust_store_arn" {
  description = "ALB trust store ARN for the gateway-only gRPC mTLS listener."
  type        = string
}

variable "device_trust_store_arn" {
  description = "ALB trust store ARN for desktop/mobile device certificates."
  type        = string
}

# ── Data sources ───────────────────────────────────────────────────────────

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# ── ECR Repository for management-plane ──────────────────────────────────

resource "aws_ecr_repository" "mgmt_plane" {
  name                 = "apexaegis-mgmt-plane"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Project = "apexaegis" }
}

resource "aws_ecr_lifecycle_policy" "mgmt_plane" {
  repository = aws_ecr_repository.mgmt_plane.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 5 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}

data "aws_ecr_image" "mgmt_plane" {
  repository_name = aws_ecr_repository.mgmt_plane.name
  image_tag       = var.image_tag

  depends_on = [aws_ecr_repository.mgmt_plane]
}

locals {
  ecr_image                   = "${aws_ecr_repository.mgmt_plane.repository_url}@${data.aws_ecr_image.mgmt_plane.image_digest}"
  gateway_acm_certificate_arn = var.gateway_acm_certificate_arn != "" ? var.gateway_acm_certificate_arn : var.acm_certificate_arn
  device_acm_certificate_arn  = var.device_acm_certificate_arn != "" ? var.device_acm_certificate_arn : var.acm_certificate_arn
}

# ── Security Groups ────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "apexaegis-mgmt-alb"
  description = "ALB for management plane"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS + gRPC from internet"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP redirect to HTTPS"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "apexaegis", Name = "apexaegis-mgmt-alb" }
}

resource "aws_security_group" "ecs_task" {
  name        = "apexaegis-mgmt-task"
  description = "ECS task for management plane"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "Traffic from ALB only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Outbound to CockroachDB and internet"
  }

  tags = { Project = "apexaegis", Name = "apexaegis-mgmt-task" }
}

# ── ALB ───────────────────────────────────────────────────────────────────

resource "aws_lb" "mgmt" {
  name               = "apexaegis-mgmt"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.default.ids

  tags = { Project = "apexaegis" }
}

resource "aws_lb" "gateway_control" {
  name               = "apexaegis-gw-control"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.default.ids

  tags = {
    Project = "apexaegis"
    Name    = "apexaegis-gateway-control"
  }
}

resource "aws_lb" "device_api" {
  name               = "apexaegis-device-api"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.default.ids

  tags = {
    Project = "apexaegis"
    Name    = "apexaegis-device-api"
  }
}

resource "aws_lb_target_group" "mgmt" {
  name_prefix      = "apx-mg"
  port             = 443
  protocol         = "HTTP"
  protocol_version = "HTTP1"
  target_type      = "ip"
  vpc_id           = data.aws_vpc.default.id

  health_check {
    path                = "/health"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = { Project = "apexaegis" }
}

resource "aws_lb_target_group" "device_rest" {
  name_prefix      = "apx-dv"
  port             = 443
  protocol         = "HTTP"
  protocol_version = "HTTP1"
  target_type      = "ip"
  vpc_id           = data.aws_vpc.default.id

  health_check {
    path                = "/health"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Project = "apexaegis"
    Name    = "apexaegis-device-rest"
  }
}

resource "aws_lb_target_group" "gateway_grpc" {
  name_prefix      = "apx-gw"
  port             = 443
  protocol         = "HTTP"
  protocol_version = "GRPC"
  target_type      = "ip"
  vpc_id           = data.aws_vpc.default.id

  health_check {
    path                = "/grpc.health.v1.Health/Check"
    protocol            = "HTTP"
    matcher             = "0"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Project = "apexaegis"
    Name    = "apexaegis-gateway-grpc"
  }
}

resource "aws_lb_listener" "device_rest_mtls" {
  load_balancer_arn = aws_lb.device_api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.device_acm_certificate_arn

  # Desktop/mobile production runtime API. ALB verifies device certificates
  # from AWS Private CA / MDM deployment and forwards x-amzn-mtls-clientcert-*
  # headers. The management plane then validates tenant, fingerprint, serial,
  # and device status before serving client config or routing policy.
  mutual_authentication {
    mode            = "verify"
    trust_store_arn = var.device_trust_store_arn
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.device_rest.arn
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.mgmt.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  # Shared public 443 entrypoint for REST/gRPC clients and gateway bootstrap.
  # Do not enable ALB mTLS here: ALB mTLS is listener-wide and would require
  # every browser, desktop client, and curl caller to present a gateway cert.
  # Gateway authentication on this shared endpoint is handled in the app using
  # X-Gateway-Key/Bearer auth. Use a separate gateway-only 443 hostname/listener
  # or NLB TLS passthrough if strict gateway mTLS is required later.
  mutual_authentication {
    mode = "off"
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mgmt.arn
  }
}

resource "aws_lb_listener" "gateway_grpc_mtls" {
  load_balancer_arn = aws_lb.gateway_control.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.gateway_acm_certificate_arn

  # Gateway-only production control plane. ALB verifies the gateway client
  # certificate and forwards the verified subject to the gRPC backend as
  # x-amzn-mtls-clientcert-* metadata. The gRPC server then verifies that the
  # certificate CN matches the claimed gateway_id.
  mutual_authentication {
    mode            = "verify"
    trust_store_arn = var.gateway_trust_store_arn
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway_grpc.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.mgmt.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ── ECS Cluster ───────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "mgmt" {
  name = "apexaegis-mgmt"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Project = "apexaegis" }
}

resource "aws_ecs_cluster_capacity_providers" "mgmt" {
  cluster_name       = aws_ecs_cluster.mgmt.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ── IAM for ECS Task ──────────────────────────────────────────────────────

resource "aws_iam_role" "ecs_task_execution" {
  name = "apexaegis-mgmt-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# CloudWatch Logs for container output
resource "aws_cloudwatch_log_group" "mgmt" {
  name              = "/ecs/apexaegis-mgmt-plane"
  retention_in_days = 14

  tags = { Project = "apexaegis" }
}

# ── ECS Task Definition ───────────────────────────────────────────────────

resource "aws_ecs_task_definition" "mgmt" {
  family                   = "apexaegis-mgmt-plane"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([{
    name      = "management-plane"
    image     = local.ecr_image
    essential = true

    portMappings = [{
      containerPort = 443
      protocol      = "tcp"
    }]

    environment = [
      { name = "LISTEN_ADDR", value = ":443" },
      { name = "MIGRATIONS_DIR", value = "/migrations" },
      { name = "DEPLOY_MODE", value = "cloud" },
      { name = "GIN_MODE", value = "release" },
      { name = "APP_TENANT_ORG_ID", value = var.tenant_org_id },
      { name = "GATEWAY_API_KEY", value = var.gateway_api_key },
      { name = "GATEWAY_REST_ENABLED", value = "false" },
      # The shared public listener cannot use ALB mTLS because that would
      # also force normal REST/desktop clients to present gateway certs.
      { name = "GATEWAY_MTLS_ENABLED", value = "false" },
      # Gateway registration, heartbeat, policy sync, and telemetry are handled
      # by the gateway-only gRPC listener. ALB verifies mTLS and forwards cert
      # metadata; the gRPC server rejects mismatched gateway_id claims.
      { name = "GRPC_REQUIRE_CLIENT_IDENTITY", value = "true" },
    ]

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
        "awslogs-stream-prefix" = "mgmt-plane"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "wget -qO- http://localhost:443/health || exit 1"]
      interval    = 30
      timeout     = 10
      retries     = 3
      startPeriod = 60
    }
  }])

  tags = { Project = "apexaegis" }
}

# ── SSM Parameters (encrypted secrets) ───────────────────────────────────

resource "aws_ssm_parameter" "database_url" {
  name  = "/apexaegis/mgmt-plane/database-url"
  type  = "SecureString"
  value = var.database_url

  tags = { Project = "apexaegis" }
}

resource "aws_ssm_parameter" "jwt_secret" {
  name  = "/apexaegis/mgmt-plane/jwt-secret"
  type  = "SecureString"
  value = var.jwt_secret

  tags = { Project = "apexaegis" }
}

resource "aws_ssm_parameter" "vault_passphrase" {
  name      = "/apexaegis/mgmt-plane/vault-passphrase"
  type      = "SecureString"
  value     = var.vault_passphrase
  overwrite = true
  tags      = { Project = "apexaegis" }
}

# IAM policy to read SSM parameters
resource "aws_iam_policy" "ssm_read" {
  name = "apexaegis-mgmt-ssm-read"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["ssm:GetParameters", "ssm:GetParameter"]
      Resource = [
        aws_ssm_parameter.database_url.arn,
        aws_ssm_parameter.jwt_secret.arn,
        aws_ssm_parameter.vault_passphrase.arn,
      ]
      }, {
      Effect   = "Allow"
      Action   = ["kms:Decrypt"]
      Resource = ["*"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_read" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = aws_iam_policy.ssm_read.arn
}

# ── ECS Service ───────────────────────────────────────────────────────────

resource "aws_ecs_service" "mgmt" {
  name            = "apexaegis-mgmt-plane"
  cluster         = aws_ecs_cluster.mgmt.id
  task_definition = aws_ecs_task_definition.mgmt.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.ecs_task.id]
    assign_public_ip = true # needed to pull from ECR without NAT gateway
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.mgmt.arn
    container_name   = "management-plane"
    container_port   = 443
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.device_rest.arn
    container_name   = "management-plane"
    container_port   = 443
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.gateway_grpc.arn
    container_name   = "management-plane"
    container_port   = 443
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [
    aws_lb_listener.https,
    aws_lb_listener.device_rest_mtls,
    aws_lb_listener.gateway_grpc_mtls,
    aws_iam_role_policy_attachment.ecs_task_execution,
  ]

  tags = { Project = "apexaegis" }
}

# ── Outputs ───────────────────────────────────────────────────────────────

output "alb_dns_name" {
  description = "Point your api.apexaegis.app CNAME to this value"
  value       = aws_lb.mgmt.dns_name
}

output "gateway_control_alb_dns_name" {
  description = "Point your gateway_domain CNAME to this value"
  value       = aws_lb.gateway_control.dns_name
}

output "device_api_alb_dns_name" {
  description = "Point your device_domain CNAME to this value"
  value       = aws_lb.device_api.dns_name
}

output "device_api_endpoint" {
  description = "Desktop/mobile REST mTLS endpoint"
  value       = "${var.device_domain}:443"
}

output "gateway_control_endpoint" {
  description = "Gateway gRPC mTLS endpoint"
  value       = "${var.gateway_domain}:443"
}

output "ecr_repository_url" {
  description = "Push management-plane images here"
  value       = aws_ecr_repository.mgmt_plane.repository_url
}

output "ecr_image_digest" {
  description = "Resolved ECR digest for image_tag"
  value       = data.aws_ecr_image.mgmt_plane.image_digest
}

output "ecs_container_image" {
  description = "Immutable image reference used by the ECS task definition"
  value       = local.ecr_image
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.mgmt.name
}

output "ecs_service_name" {
  value = aws_ecs_service.mgmt.name
}
