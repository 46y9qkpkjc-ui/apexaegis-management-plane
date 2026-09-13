# ============================================================================
# DRS + Connector DNS — managed outside Terraform (no Cloudflare token)
# ============================================================================
# After terraform apply, add these CNAME records manually in Cloudflare:
#
#   drs.apexaegis.app           → <alb_dns_name>  (DNS only, no proxy)
#   connector-api.apexaegis.app → <connector_alb> (DNS only, no proxy)
#
# Or re-enable the cloudflare provider + connector.tf later when a token
# is available.

output "drs_endpoint" {
  description = "DRS OIDC issuer URL. Create CNAME: drs.apexaegis.app → ALB DNS."
  value       = "https://${var.drs_domain}"
}

output "drs_dns_action" {
  description = "Manual DNS step required after apply."
  value       = "Create Cloudflare CNAME: ${var.drs_domain} → ${aws_lb.mgmt.dns_name} (proxied=false)"
}

output "connector_api_endpoint" {
  description = "Connector endpoint (DNS record needed)."
  value       = "https://${var.connector_domain}"
}
