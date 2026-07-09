# ── Cloud RADIUS: RadSec (RADIUS-over-TLS) exposed on TCP 443 via a new NLB ──────
#
# RadSec is a raw, long-lived binary mTLS stream (RADIUS-over-TLS), NOT HTTP, so it
# cannot share the management ALB (an ALB is L7 HTTP-only and always terminates TLS,
# which would break the proxy Cert A mutual-auth the MP performs itself).
#
# A Network Load Balancer does L4 TCP PASSTHROUGH — it forwards the raw stream and
# the MP terminates the mTLS + RADIUS end-to-end. Externally we use 443 (traverses
# networks that block 2083); the MP's RadSec listener stays on container port 2083.
#
# DNS: create radius.apexaegis.app as a CNAME/ALIAS to the NLB, DNS-ONLY (grey-cloud
# in Cloudflare). Cloudflare's HTTP proxy cannot carry RadSec (would need Spectrum).

resource "aws_security_group" "radsec_nlb" {
  name        = "apexaegis-radsec-nlb"
  description = "RadSec NLB - RADIUS-over-TLS on 443"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tighten to known proxy egress IPs once known
    description = "RadSec (RADIUS-over-TLS) from on-prem radsecproxy"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "apexaegis", Name = "apexaegis-radsec-nlb" }
}

resource "aws_lb" "radsec" {
  name               = "apexaegis-radsec"
  internal           = false
  load_balancer_type = "network"
  security_groups    = [aws_security_group.radsec_nlb.id]
  subnets            = data.aws_subnets.default.ids

  enable_cross_zone_load_balancing = true

  tags = { Project = "apexaegis", Name = "apexaegis-radsec" }
}

resource "aws_lb_target_group" "radsec" {
  name_prefix = "apx-rs"
  port        = 2083
  protocol    = "TCP"
  target_type = "ip" # Fargate awsvpc tasks register by IP
  vpc_id      = data.aws_vpc.default.id

  # RadSec requires a client cert, so the deepest we can health-check without one
  # is a TCP connect — that already proves the listener is accepting connections.
  health_check {
    protocol            = "TCP"
    port                = "2083"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    interval            = 30
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = { Project = "apexaegis", Name = "apexaegis-radsec" }
}

resource "aws_lb_listener" "radsec" {
  load_balancer_arn = aws_lb.radsec.arn
  port              = 443
  protocol          = "TCP" # PASSTHROUGH — must NOT terminate TLS here

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.radsec.arn
  }
}

# Allow the RadSec container port from the NLB only (NLB has a security group, so
# the task SG can reference it even with client-IP preservation on).
resource "aws_security_group_rule" "ecs_task_radsec" {
  type                     = "ingress"
  from_port                = 2083
  to_port                  = 2083
  protocol                 = "tcp"
  security_group_id        = aws_security_group.ecs_task.id
  source_security_group_id = aws_security_group.radsec_nlb.id
  description              = "RadSec from the radius NLB"
}

output "radsec_nlb_dns" {
  description = "Point radius.apexaegis.app (DNS-only, NOT Cloudflare-proxied) at this NLB"
  value       = aws_lb.radsec.dns_name
}
