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
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Cloudflare token supplied via TF_VAR_cloudflare_api_token — never commit it.
# Used only for the connector-api DNS + ACM validation records (connector.tf).
provider "cloudflare" {
  api_token = var.cloudflare_api_token
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

variable "grant_signing_key" {
  description = "HMAC key the MP signs device/user access grants with. MUST equal the private-access gateway's grant_signing_key. Pass via TF_VAR or the gitignored tfvars; never commit."
  type        = string
  sensitive   = true
}

# ── Device-cert issuance via the device step-ca (replaces ACM PCA) ──────────
variable "device_stepca_url" {
  description = "Device step-ca base URL. When set, the MP signs portal device CSRs here instead of ACM PCA."
  type        = string
  default     = "https://device-ca.apexaegis.app"
}

variable "device_stepca_fingerprint" {
  description = "Device step-ca root SHA-256 fingerprint (pins trust + sets the OTT sha claim)."
  type        = string
  default     = "45f3ec7bd27027c06d30f9e0dcdd7a69687c1f5347cb82e4597d0aa7a1c2ff50"
}

variable "device_stepca_provisioner" {
  description = "JWK provisioner on the device step-ca the MP mints OTTs with."
  type        = string
  default     = "portal"
}

variable "device_grant_dc_segments" {
  description = "JSON map of DC segments a machine tunnel may reach pre-logon: {\"*\":{\"host\":\"<DC IP>\",\"ports\":[...]}}."
  type        = string
  # AD service set for domain-join + Kerberos logon over the tunnel: Kerberos(88),
  # LDAP(389), SMB/SYSVOL(445), kpasswd(464), LDAPS(636), Global Catalog(3268).
  # DNS(53) is handled by the client DNS shim and NTP(123) by the host clock, so
  # both are out; CLDAP/RPC are intentionally excluded (agent per-port loopbacks).
  default = "{\"*\":{\"host\":\"10.10.1.4\",\"ports\":[88,389,445,464,636,3268]}}"
}

variable "device_grant_prelogon_gateway" {
  description = "host:port of the private-access gateway the agent dials before user logon."
  type        = string
  default     = "ad-gw.apexaegis.app:443"
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

variable "connector_trust_store_arn" {
  description = "ALB trust store (Infra CA) for the AD-sync connector mTLS listener — gateway/terraform/step-ca-trust output connector_trust_store_arn."
  type        = string
  default     = "arn:aws:elasticloadbalancing:ap-southeast-1:184353710603:truststore/apexaegis-connector-stepca-trust/c198b8f7237f3bea"
}

variable "connector_domain" {
  description = "Public hostname for the AD-sync connector mTLS ALB (dedicated 443 listener, Infra-CA trust store)."
  type        = string
  default     = "connector-api.apexaegis.app"
}

variable "cloudflare_zone_name" {
  description = "Cloudflare zone for connector-api DNS + ACM validation records."
  type        = string
  default     = "apexaegis.app"
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token (Zone:DNS:Edit). Supply via the gitignored terraform.tfvars or TF_VAR_cloudflare_api_token — never commit."
  type        = string
  sensitive   = true
}

variable "dns_ttl" {
  description = "TTL for the connector-api Cloudflare records."
  type        = number
  default     = 60
}

variable "device_certificate_authority_arn" {
  description = "AWS Private CA ARN used to sign client-generated device CSRs."
  type        = string
}

variable "device_certificate_template_arn" {
  description = "AWS Private CA client-auth certificate template ARN."
  type        = string
  default     = "arn:aws:acm-pca:::template/EndEntityClientAuthCertificate/V1"
}

variable "device_certificate_signing_algorithm" {
  description = "Signing algorithm matching the AWS Private CA key family."
  type        = string
  default     = "SHA256WITHECDSA"
}

variable "user_portal_login_url" {
  description = "User portal URL that receives the OIDC authorization callback parameters."
  type        = string
  default     = "https://users.apexaegis.app"
}

variable "user_portal_artifacts_json" {
  description = "JSON catalog of approved signed client artifacts. Use short-lived signed download URLs."
  type        = string
  default     = "[]"
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

resource "aws_iam_role" "ecs_task" {
  name = "apexaegis-mgmt-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "device_certificate_issuance" {
  name = "apexaegis-device-certificate-issuance"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "acm-pca:IssueCertificate",
        "acm-pca:GetCertificate"
      ]
      Resource = var.device_certificate_authority_arn
    }]
  })
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
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "management-plane"
    image     = local.ecr_image
    essential = true

    portMappings = [
      {
        containerPort = 443
        protocol      = "tcp"
      },
      {
        # Cloud RADIUS: RadSec (RADIUS-over-TLS) + EAP-TLS listener, fronted by the
        # radius NLB (443/TCP passthrough → 2083). See radsec.tf.
        containerPort = 2083
        protocol      = "tcp"
      }
    ]

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
      { name = "WEB_UI_ALLOWED_ORIGINS", value = "https://www.apexaegis.app,https://apexaegis.app,${var.user_portal_login_url}" },
      { name = "USER_PORTAL_LOGIN_URL", value = var.user_portal_login_url },
      { name = "USER_PORTAL_ARTIFACTS_JSON", value = var.user_portal_artifacts_json },
      { name = "DEVICE_CERTIFICATE_AUTHORITY_ARN", value = var.device_certificate_authority_arn },
      { name = "DEVICE_CERTIFICATE_TEMPLATE_ARN", value = var.device_certificate_template_arn },
      { name = "DEVICE_CERTIFICATE_SIGNING_ALGORITHM", value = var.device_certificate_signing_algorithm },
      # Pre-logon device grant: which DC host/ports a machine tunnel may reach,
      # and the gateway the agent dials before user logon. Non-secret config.
      { name = "DEVICE_GRANT_DC_SEGMENTS", value = var.device_grant_dc_segments },
      { name = "DEVICE_GRANT_PRELOGON_GATEWAY", value = var.device_grant_prelogon_gateway },
      # Device-cert issuance via the device step-ca (replaces ACM PCA): when set,
      # the MP signs portal device CSRs through device-ca.apexaegis.app.
      { name = "DEVICE_STEPCA_URL", value = var.device_stepca_url },
      { name = "DEVICE_STEPCA_FINGERPRINT", value = var.device_stepca_fingerprint },
      { name = "DEVICE_STEPCA_PROVISIONER", value = var.device_stepca_provisioner },
      # Kerberos SSO (POST /api/v1/agent/sso/kerberos): the SPN the client
      # acquires a service ticket for, and the AD realm. Non-secret; the keytab
      # itself rides MP_KRB5_KEYTAB_B64 (SSM SecureString, in secrets below).
      { name = "MP_KRB5_SPN", value = "HTTP/api.apexaegis.app@AD.APEXAEGIS.APP" },
      { name = "MP_KRB5_REALM", value = "AD.APEXAEGIS.APP" },
      # Cloud RADIUS (RadSec + EAP-TLS) listener address. Cert material rides the
      # RADSEC_*_PEM secrets below (SSM SecureStrings, out-of-band). With those unset
      # the RadSec server stays disabled and nothing else is affected.
      { name = "RADSEC_LISTEN_ADDR", value = ":2083" },
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
      {
        # HMAC key the MP signs device/user grants with; the private-access
        # gateway verifies grants with the SAME value (its grant_signing_key).
        name      = "PRIVATE_ACCESS_GRANT_SIGNING_KEY"
        valueFrom = aws_ssm_parameter.grant_signing_key.arn
      },
      {
        # device step-ca "portal" provisioner password (SSM, created out-of-band) —
        # decrypts the provisioner key so the MP can mint OTTs to sign device CSRs.
        name      = "PORTAL_DEVICE_JWK_PASSWORD"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/portal-device-jwk-password"
      },
      {
        # Anthropic API key for the voice/agent admin (/api/v1/admin/assistant/chat).
        # SSM SecureString, created out-of-band so the key never enters Terraform
        # state or git. Unset ⇒ /chat returns 503 but the deterministic endpoints work.
        name      = "ANTHROPIC_API_KEY"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/anthropic-api-key"
      },
      {
        # Deepgram (speech-to-text) for the voice admin. SSM SecureString, out-of-band.
        name      = "DEEPGRAM_API_KEY"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/deepgram-api-key"
      },
      {
        # ElevenLabs (text-to-speech) for the voice admin. SSM SecureString, out-of-band.
        name      = "ELEVENLABS_API_KEY"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/elevenlabs-api-key"
      },
      {
        # Kerberos service keytab (base64) for OFFLINE SPNEGO validation of the
        # HTTP/api.apexaegis.app SPN (svc-apex-mp). SSM SecureString, created
        # out-of-band so the keytab never enters Terraform state or git. Unset ⇒
        # /agent/sso/kerberos returns 503; nothing else is affected.
        name      = "MP_KRB5_KEYTAB_B64"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/kerberos-keytab"
      },
      # ── Cloud RADIUS cert material (RadSec + EAP-TLS) ──────────────────────────
      # SSM SecureStrings, created out-of-band so keys never enter Terraform state
      # or git. B and D are ONE cert, so the RadSec-server and EAP-server cert/key
      # env vars point at the SAME two parameters. Minted on the device step-ca
      # (see apexaegis-agent/deploy/radsec/CERT-DELIVERY.md).
      {
        # Cert B/D leaf (radius.apexaegis.app), PEM.
        name      = "RADSEC_SERVER_CERT_PEM"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/radsec-server-cert"
      },
      {
        # Cert B/D private key, PEM (unencrypted).
        name      = "RADSEC_SERVER_KEY_PEM"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/radsec-server-key"
      },
      {
        name      = "RADSEC_EAP_CERT_PEM"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/radsec-server-cert"
      },
      {
        name      = "RADSEC_EAP_KEY_PEM"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/radsec-server-key"
      },
      {
        # apexaegis-ca.pem (Device Root + RadSec CA) — verifies the proxy Cert A.
        name      = "RADSEC_CLIENT_CA_PEM"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/radsec-client-ca"
      },
      {
        # device-ca bundle (Device Root + Intermediate) — verifies the supplicant Cert C.
        name      = "RADSEC_EAP_CLIENT_CA_PEM"
        valueFrom = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/radsec-eap-client-ca"
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

# HMAC key for signing device/user access grants. MUST match the private-access
# gateway's grant_signing_key (it verifies grants with the same value).
resource "aws_ssm_parameter" "grant_signing_key" {
  name      = "/apexaegis/mgmt-plane/grant-signing-key"
  type      = "SecureString"
  value     = var.grant_signing_key
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
        aws_ssm_parameter.grant_signing_key.arn,
        "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/portal-device-jwk-password",
        "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/anthropic-api-key",
        "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/deepgram-api-key",
        "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/elevenlabs-api-key",
        "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/kerberos-keytab",
        "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/radsec-server-cert",
        "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/radsec-server-key",
        "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/radsec-client-ca",
        "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/apexaegis/mgmt-plane/radsec-eap-client-ca",
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

  load_balancer {
    target_group_arn = aws_lb_target_group.connector.arn
    container_name   = "management-plane"
    container_port   = 443
  }

  # Cloud RADIUS (RadSec) — the radius NLB forwards 443/TCP to container port 2083.
  load_balancer {
    target_group_arn = aws_lb_target_group.radsec.arn
    container_name   = "management-plane"
    container_port   = 2083
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [
    aws_lb_listener.https,
    aws_lb_listener.device_rest_mtls,
    aws_lb_listener.gateway_grpc_mtls,
    aws_lb_listener.connector_mtls,
    aws_lb_listener.radsec,
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
