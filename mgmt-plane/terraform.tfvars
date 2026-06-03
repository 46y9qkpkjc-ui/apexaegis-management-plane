# Copy this to terraform.tfvars and fill in your values
# DO NOT commit terraform.tfvars (it contains secrets)

aws_account_id = "184353710603"
aws_region     = "ap-southeast-1"
domain         = "api.apexaegis.app"
gateway_domain = "gateway-api.apexaegis.app"
device_domain  = "device-api.apexaegis.app"

# Get this from AWS Certificate Manager after requesting a cert for api.apexaegis.app
# Must be in ap-southeast-1 (same region as ALB)
acm_certificate_arn         = "arn:aws:acm:ap-southeast-1:184353710603:certificate/70faa022-0108-4102-abfc-676bb3b29fd6"
gateway_acm_certificate_arn = "arn:aws:acm:ap-southeast-1:184353710603:certificate/70faa022-0108-4102-abfc-676bb3b29fd6"
device_acm_certificate_arn  = "arn:aws:acm:ap-southeast-1:184353710603:certificate/70faa022-0108-4102-abfc-676bb3b29fd6"

# Your CockroachDB Cloud connection string (same one in Railway today)
database_url = "postgresql://apexaegis_user:g_MT5YJBqN0ii5srFxuUEg@apexaegis-db-26909.j77.aws-ap-southeast-1.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full"

# Same Vault passphrase you have in Railway today
vault_passphrase = "c1281346181c0f6a83b9b37b5e55c8b5a25ec717c341776a8563a29749a176fb"

# Same JWT secret you have in Railway today
jwt_secret = "/nL+/8nJW3Ji8RQyPQO5wbekn5wMDE/gbIKiIX/rNMQ="

# Gateway shared API key (same as in gateway terraform.tfvars)
gateway_api_key = "ee94927bca7b0777880e7336aa2127d4a2d14a627dd6b3a4f2afffd8140df81b"

# Docker image tag (update after running build script)
image_tag = "latest"

# Fargate sizing (0.5 vCPU / 1GB is plenty for demo)
task_cpu      = 512
task_memory   = 1024
desired_count = 1

# ACM PCA trust store for gateway mTLS — from pca/ workspace output
gateway_trust_store_arn = "arn:aws:elasticloadbalancing:ap-southeast-1:184353710603:truststore/apexaegis-gateway-trust/5ba7a91caa52647d"
device_trust_store_arn  = "arn:aws:elasticloadbalancing:ap-southeast-1:184353710603:truststore/apexaegis-device-trust/04e116d659af2078"

# ACM PCA ARN for issuing client certs to gateways and devices — from pca/ workspace output
device_certificate_authority_arn = "arn:aws:acm-pca:ap-southeast-1:184353710603:certificate-authority/77c55707-e54a-43a6-b204-cfb03023f5f7"

#ACM PCA siging algorithm for client certs — must match the CA's signing algorithm

device_certificate_signing_algorithm = "SHA256WITHECDSA"