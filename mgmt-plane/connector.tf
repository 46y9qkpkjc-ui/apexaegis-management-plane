# ============================================================================
# AD-sync connector endpoint — dedicated 443 mTLS ALB (Infra-CA trust store)
# ============================================================================
# ALB mTLS binds ONE trust store per listener/port, so the connector cannot
# share 443 on the device-api ALB (device trust store) without folding the
# Infra CA into it. A dedicated ALB keeps the three edge identities — device
# (Device CA), gateway (gateway trust store), connector (Infra CA) — cleanly
# split, and matches the existing per-identity ALB layout.
#
# DNS + ACM validation live in Cloudflare (TF_VAR_cloudflare_api_token). The
# connector-api record is proxied=false (DNS-only): Cloudflare's proxy would
# terminate TLS and the ALB would never see the connector's client cert.

data "cloudflare_zone" "apexaegis" {
  name = var.cloudflare_zone_name
}

# ── Server cert for connector-api.apexaegis.app (ACM, DNS-validated via CF) ──
resource "aws_acm_certificate" "connector" {
  domain_name       = var.connector_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Project = "apexaegis", Name = "apexaegis-connector-api" }
}

resource "cloudflare_record" "connector_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.connector.domain_validation_options : dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  }

  zone_id         = data.cloudflare_zone.apexaegis.id
  name            = trimsuffix(each.value.name, ".")
  content         = trimsuffix(each.value.value, ".")
  type            = each.value.type
  ttl             = 60
  proxied         = false
  allow_overwrite = true
  comment         = "ACM validation for connector-api — Terraform"
}

resource "aws_acm_certificate_validation" "connector" {
  certificate_arn         = aws_acm_certificate.connector.arn
  validation_record_fqdns = [for r in cloudflare_record.connector_cert_validation : r.hostname]
}

# ── Dedicated internet-facing ALB ───────────────────────────────────────────
resource "aws_lb" "connector_api" {
  name               = "apexaegis-connector-api"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.default.ids

  tags = {
    Project = "apexaegis"
    Name    = "apexaegis-connector-api"
  }
}

# Dedicated TG — a target group attaches to exactly one ALB, so the connector
# ALB cannot reuse device_rest. The ECS service registers with this TG too
# (aws_ecs_service.mgmt load_balancer block in main.tf).
resource "aws_lb_target_group" "connector" {
  name_prefix      = "apx-cn"
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
    Name    = "apexaegis-connector"
  }
}

# mTLS listener: verifies the Infra-CA connector cert and forwards
# x-amzn-mtls-clientcert-* to the connector TG (→ ECS).
resource "aws_lb_listener" "connector_mtls" {
  load_balancer_arn = aws_lb.connector_api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.connector.certificate_arn

  mutual_authentication {
    mode            = "verify"
    trust_store_arn = var.connector_trust_store_arn
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.connector.arn
  }
}

# ── connector-api.apexaegis.app -> ALB (DNS-only; proxy would break mTLS) ────
resource "cloudflare_record" "connector_api" {
  zone_id = data.cloudflare_zone.apexaegis.id
  name    = trimsuffix(var.connector_domain, ".${var.cloudflare_zone_name}")
  content = aws_lb.connector_api.dns_name
  type    = "CNAME"
  ttl     = var.dns_ttl
  proxied = false
  comment = "ApexAegis AD-sync connector MP endpoint — Terraform"
}

output "connector_api_endpoint" {
  description = "MP_URL the connector dials (mTLS, Infra-CA client cert)."
  value       = "https://${var.connector_domain}"
}
