output "cluster_name" {
  value = aws_eks_cluster.this.name
}

output "vpc_cidr_block" {
  value = data.aws_vpc.selected.cidr_block
}

output "public_subnet_ids" {
  value = var.public_subnet_ids
}

output "cluster_endpoint" {
  value = aws_eks_cluster.this.endpoint
}

output "backend_ecr_repository_url" {
  value = aws_ecr_repository.backend.repository_url
}

output "frontend_ecr_repository_url" {
  value = aws_ecr_repository.frontend.repository_url
}

output "report_bucket_name" {
  value = aws_s3_bucket.reports.bucket
}

output "database_endpoint" {
  value     = aws_db_instance.postgres.address
  sensitive = false
}

output "dr_database_read_replica_endpoint" {
  value       = var.dr_enabled ? aws_db_instance.postgres_dr_replica[0].address : null
  description = "Cross-Region PostgreSQL read replica endpoint; promote only under the approved DR runbook."
}

output "dr_database_replica_identifier" {
  value       = var.dr_enabled ? aws_db_instance.postgres_dr_replica[0].identifier : null
  description = "RDS instance identifier for the recovery Region PostgreSQL replica."
}

output "dr_report_bucket_name" {
  value       = var.dr_enabled ? aws_s3_bucket.dr_reports[0].bucket : null
  description = "KMS-encrypted S3 replica bucket in the recovery Region."
}

output "customer_scan_bucket_name" {
  value       = var.customer_scan_enabled ? aws_s3_bucket.reports.bucket : null
  description = "Primary Region upload, result, and expiring source-artifact bucket for customer scans."
}

output "customer_scan_prefix" {
  value       = var.customer_scan_enabled ? local.customer_scan_prefix : null
  description = "Tenant-scoped S3 key prefix used by customer scan uploads and results."
}

output "customer_scan_cluster_arn" {
  value       = var.customer_scan_enabled ? aws_ecs_cluster.customer_scanner[0].arn : null
  description = "Private Fargate scanner cluster ARN for application runtime configuration."
}

output "customer_scan_task_definition_arn" {
  value       = var.customer_scan_enabled ? aws_ecs_task_definition.customer_scanner[0].arn : null
  description = "Pinned primary Region Fargate scanner task definition ARN."
}

output "customer_scan_private_subnet_ids" {
  value       = var.customer_scan_enabled ? var.private_subnet_ids : null
  description = "Private subnet IDs for customer scanner tasks."
}

output "customer_scan_security_group_id" {
  value       = var.customer_scan_enabled ? aws_security_group.customer_scanner.id : null
  description = "No-public-IP scanner security group restricted to private AWS endpoints."
}

output "customer_scanner_ecr_repository_url" {
  value       = aws_ecr_repository.customer_scanner.repository_url
  description = "Immutable primary Region customer scanner image repository URL."
}

output "dr_backend_ecr_repository_url" {
  value       = var.dr_enabled ? aws_ecr_repository.backend_dr[0].repository_url : null
  description = "Immutable backend release image repository in the recovery Region."
}

output "dr_frontend_ecr_repository_url" {
  value       = var.dr_enabled ? aws_ecr_repository.frontend_dr[0].repository_url : null
  description = "Immutable frontend release image repository in the recovery Region."
}

output "dr_customer_scanner_ecr_repository_url" {
  value       = var.dr_enabled ? aws_ecr_repository.customer_scanner_dr[0].repository_url : null
  description = "Immutable customer scanner image repository in the recovery Region."
}

output "dr_customer_scan_bucket_name" {
  value       = var.dr_enabled && var.customer_scan_enabled ? aws_s3_bucket.dr_reports[0].bucket : null
  description = "Recovery Region artifact bucket used by the customer scanner after failover."
}

output "dr_customer_scan_cluster_arn" {
  value       = var.dr_enabled && var.customer_scan_enabled ? aws_ecs_cluster.customer_scanner_dr[0].arn : null
  description = "Private recovery Region Fargate scanner cluster ARN."
}

output "dr_customer_scan_task_definition_arn" {
  value       = var.dr_enabled && var.customer_scan_enabled ? aws_ecs_task_definition.customer_scanner_dr[0].arn : null
  description = "Pinned recovery Region Fargate scanner task definition ARN."
}

output "dr_customer_scan_private_subnet_ids" {
  value       = var.dr_enabled && var.customer_scan_enabled ? var.dr_private_subnet_ids : null
  description = "Private recovery Region subnet IDs for customer scanner tasks."
}

output "dr_customer_scan_security_group_id" {
  value       = var.dr_enabled && var.customer_scan_enabled ? aws_security_group.dr_customer_scan[0].id : null
  description = "Private recovery Region scanner security group with no direct internet egress."
}

output "dr_cluster_name" {
  value       = var.dr_enabled ? aws_eks_cluster.dr[0].name : null
  description = "Private warm EKS recovery cluster. Application overlay, TLS/WAF ingress, and a private deployment runner must be configured separately."
}

output "dr_cluster_endpoint" {
  value       = var.dr_enabled ? aws_eks_cluster.dr[0].endpoint : null
  description = "Private Kubernetes API endpoint for the recovery cluster."
}

output "dr_redis_endpoint" {
  value       = var.dr_enabled ? aws_elasticache_replication_group.dr[0].primary_endpoint_address : null
  description = "TLS Redis primary endpoint for the independent recovery Region queue and session cache."
}

output "dr_runtime_secret_arn" {
  value       = var.dr_enabled ? aws_secretsmanager_secret.runtime_dr[0].arn : null
  description = "Empty recovery Region runtime secret; populate it out of band with DR database, Redis, and S3 settings."
}

output "database_master_secret_arn" {
  value     = aws_db_instance.postgres.master_user_secret[0].secret_arn
  sensitive = false
}

output "redis_primary_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "report_pod_role_arn" {
  value = aws_iam_role.pod_report_writer.arn
}

output "runtime_secret_arn" {
  value = aws_secretsmanager_secret.runtime.arn
}

output "database_app_secret_arn" {
  value = aws_secretsmanager_secret.database_app.arn
}

output "waf_web_acl_arn" {
  value = var.waf_web_acl_arn
}

output "github_release_build_role_arn" {
  value = aws_iam_role.github_release_build.arn
}

output "github_release_deploy_role_arn" {
  value = aws_iam_role.github_release_deploy.arn
}
