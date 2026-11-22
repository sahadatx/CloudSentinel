variable "aws_region" {
  description = "AWS region for the CloudSentinel production foundation."
  type        = string
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "production"
}

variable "name_prefix" {
  description = "Short resource prefix; use lowercase letters, digits, and hyphens."
  type        = string
  default     = "cloudsentinel"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.name_prefix))
    error_message = "name_prefix must be 3-21 lowercase letters, digits, or hyphens and start with a letter."
  }
}

variable "vpc_id" {
  description = "ID of the existing VPC that owns the supplied subnets."
  type        = string
}

variable "private_subnet_ids" {
  description = "At least two private subnets in distinct Availability Zones."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Provide at least two private subnet IDs in distinct Availability Zones."
  }
}

variable "public_subnet_ids" {
  description = "At least two public subnets in distinct AZs for the internet-facing ALB."
  type        = list(string)

  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "Provide at least two public subnet IDs in distinct Availability Zones."
  }
}

variable "cluster_admin_role_arn" {
  description = "Existing IAM role allowed to administer Kubernetes through an EKS access entry."
  type        = string
}

variable "cluster_version" {
  description = "EKS Kubernetes minor version supported in the selected AWS region."
  type        = string
  default     = "1.35"
}

variable "node_instance_types" {
  description = "EC2 instance types for the managed worker node group."
  type        = list(string)
  default     = ["m7i.large"]
}

variable "node_desired_size" {
  type    = number
  default = 3
}

variable "node_min_size" {
  type    = number
  default = 3
}

variable "node_max_size" {
  type    = number
  default = 12
}

variable "database_instance_class" {
  description = "RDS PostgreSQL instance class; size this from measured load before production."
  type        = string
  default     = "db.m7g.large"
}

variable "database_name" {
  type    = string
  default = "cloudsentinel"

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,62}$", var.database_name))
    error_message = "database_name must be a valid lowercase PostgreSQL identifier."
  }
}

variable "database_backup_retention_days" {
  type    = number
  default = 14

  validation {
    condition     = var.database_backup_retention_days >= 7 && var.database_backup_retention_days <= 35
    error_message = "Production database backups must be retained for 7-35 days."
  }
}

variable "report_retention_days" {
  description = "Match CLOUDSENTINEL_REPORT_RETENTION_DAYS; expire report artifacts and stale object versions in both Regions."
  type        = number
  default     = 90

  validation {
    condition     = var.report_retention_days >= 1 && var.report_retention_days <= 3650
    error_message = "Report artifact retention must be between 1 and 3650 days."
  }
}

variable "dr_enabled" {
  description = "Provision warm cross-region EKS, independent Redis, encrypted S3 replicas, and PostgreSQL replica/backup recovery resources."
  type        = bool
  default     = false
}

variable "dr_aws_region" {
  description = "Destination AWS Region for encrypted database backups and S3 replicas."
  type        = string
  default     = ""
}

variable "dr_database_backup_retention_days" {
  description = "Retention of replicated RDS automated backups in the recovery Region."
  type        = number
  default     = 35

  validation {
    condition     = var.dr_database_backup_retention_days >= 7 && var.dr_database_backup_retention_days <= 35
    error_message = "DR replicated database backups must be retained for 7-35 days."
  }
}

variable "dr_node_desired_size" {
  description = "Warm node count for the recovery EKS cluster while it waits for a failover drill."
  type        = number
  default     = 2
  validation {
    condition     = var.dr_node_desired_size >= 1 && var.dr_node_desired_size <= 12
    error_message = "dr_node_desired_size must be between 1 and 12 when a recovery cluster is enabled."
  }
}

variable "dr_report_bucket_name" {
  description = "Globally unique, Object Lock enabled S3 bucket name in the recovery Region."
  type        = string
  default     = ""
}

variable "dr_vpc_id" {
  description = "Existing private recovery Region VPC for the warm PostgreSQL replica."
  type        = string
  default     = ""
}

variable "dr_private_subnet_ids" {
  description = "Private subnets in the recovery Region VPC for PostgreSQL and the recovery EKS cluster."
  type        = list(string)
  default     = []
}

variable "dr_alarm_topic_arn" {
  description = "Optional SNS topic ARN in the recovery Region for cross-region replica lag alarms."
  type        = string
  default     = null
  nullable    = true
}

variable "customer_scan_enabled" {
  description = "Enable the no-task-role, private-network ECS Fargate customer scanner sandbox."
  type        = bool
  default     = false
}

variable "customer_scanner_image_tag" {
  description = "Immutable scanner image tag already pushed to the dedicated ECR repository."
  type        = string
  default     = ""
}

variable "redis_auth_token" {
  description = "Provision through an encrypted Terraform backend and secure variable injection. Terraform state contains this secret."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.redis_auth_token) >= 32 && length(var.redis_auth_token) <= 128 && can(regex("^[[:graph:]]+$", var.redis_auth_token)) && !can(regex("[/@\"]", var.redis_auth_token))
    error_message = "Redis auth token must be 32-128 printable characters and exclude slash, quote, and at-sign."
  }
}

variable "report_bucket_name" {
  description = "Globally unique S3 bucket name for report artifacts."
  type        = string
}

variable "domain_name" {
  description = "Public hostname for the production application ingress."
  type        = string
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN covering domain_name in the ALB region."
  type        = string
}

variable "waf_web_acl_arn" {
  description = "ARN of a regional AWS WAF web ACL associated with the public ALB."
  type        = string
}

variable "alarm_topic_arn" {
  description = "Optional SNS topic ARN for operational alarms. Configure a verified on-call subscription."
  type        = string
  default     = null
  nullable    = true
}

variable "github_oidc_provider_arn" {
  description = "ARN of the account's existing GitHub Actions OIDC identity provider."
  type        = string
}

variable "github_release_build_subject_pattern" {
  description = "Exact GitHub OIDC sub pattern for version-tag builds; set the subject format used by this repository."
  type        = string

  validation {
    condition     = can(regex("^repo:.+:ref:refs/tags/v\\*$", var.github_release_build_subject_pattern))
    error_message = "Build subject must target one repository and version tags matching refs/tags/v*."
  }
}

variable "github_release_deploy_subject" {
  description = "Exact GitHub OIDC sub for the production environment in the same repository."
  type        = string

  validation {
    condition     = can(regex("^repo:.+:environment:production$", var.github_release_deploy_subject))
    error_message = "Deploy subject must target one repository's production environment."
  }
}

check "dr_configuration_is_complete" {
  assert {
    condition = !var.dr_enabled || (
      var.dr_aws_region != "" && var.dr_aws_region != var.aws_region &&
      var.dr_report_bucket_name != "" && var.dr_report_bucket_name != var.report_bucket_name &&
      var.dr_vpc_id != "" && length(var.dr_private_subnet_ids) >= 2
    )
    error_message = "When DR is enabled, set a distinct dr_aws_region and unique dr_report_bucket_name."
  }
}

check "customer_scan_configuration_is_complete" {
  assert {
    condition     = !var.customer_scan_enabled || var.customer_scanner_image_tag != ""
    error_message = "When customer scanning is enabled, build and push an immutable customer scanner image first, then set customer_scanner_image_tag."
  }
}
