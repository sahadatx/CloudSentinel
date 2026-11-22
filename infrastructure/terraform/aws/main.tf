data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_vpc" "selected" {
  id = var.vpc_id
}

data "aws_subnet" "private" {
  for_each = toset(var.private_subnet_ids)
  id       = each.value
}

data "aws_subnet" "public" {
  for_each = toset(var.public_subnet_ids)
  id       = each.value
}

locals {
  private_azs    = toset([for subnet in data.aws_subnet.private : subnet.availability_zone])
  public_azs     = toset([for subnet in data.aws_subnet.public : subnet.availability_zone])
  common_name    = "${var.name_prefix}-${var.environment}"
  report_prefix  = "${var.name_prefix}/${var.environment}/reports/"
  dr_cluster_arn = "arn:${data.aws_partition.current.partition}:eks:${var.dr_aws_region}:${data.aws_caller_identity.current.account_id}:cluster/${local.common_name}-dr"
  pod_identity_cluster_arns = concat(
    [aws_eks_cluster.this.arn],
    var.dr_enabled ? [local.dr_cluster_arn] : []
  )
}

check "private_subnets_are_spread_across_azs" {
  assert {
    condition     = length(local.private_azs) >= 2
    error_message = "The supplied private subnets must span at least two Availability Zones."
  }
}

check "private_subnets_belong_to_vpc" {
  assert {
    condition     = alltrue([for subnet in data.aws_subnet.private : subnet.vpc_id == data.aws_vpc.selected.id])
    error_message = "Every supplied subnet must belong to vpc_id."
  }
}

check "public_subnets_are_internet_load_balancer_ready" {
  assert {
    condition = length(local.public_azs) >= 2 && alltrue([
      for subnet in data.aws_subnet.public : subnet.vpc_id == data.aws_vpc.selected.id
    ])
    error_message = "Public ALB subnets must belong to the supplied VPC and span at least two Availability Zones."
  }
}

resource "aws_ec2_tag" "public_subnet_alb" {
  for_each    = toset(var.public_subnet_ids)
  resource_id = each.value
  key         = "kubernetes.io/role/elb"
  value       = "1"
}

resource "aws_ec2_tag" "public_subnet_cluster" {
  for_each    = toset(var.public_subnet_ids)
  resource_id = each.value
  key         = "kubernetes.io/cluster/${local.common_name}"
  value       = "shared"
}

resource "aws_kms_key" "data" {
  description             = "CloudSentinel ${var.environment} data encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.common_name}-data"
  target_key_id = aws_kms_key.data.key_id
}

resource "aws_security_group" "cluster" {
  name        = "${local.common_name}-cluster"
  description = "EKS control-plane and managed node traffic"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    description = "Managed control plane and worker node communication"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  ingress {
    description = "Private EKS API access from the VPC, including the deployment runner"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  egress {
    description = "Private VPC and approved egress path"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  egress {
    description = "HTTPS and authenticated SMTP; route through the VPC egress firewall"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Authenticated SMTP through the VPC egress firewall"
    from_port   = 587
    to_port     = 587
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "EKS Pod Identity credential endpoint"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["169.254.170.23/32"]
  }
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "${local.common_name}-endpoints"
  description = "Private AWS service endpoint traffic from CloudSentinel nodes"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    description     = "TLS from CloudSentinel EKS nodes"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset([
    "ec2",
    "monitoring",
    "ecr.api",
    "ecr.dkr",
    "elasticloadbalancing",
    "logs",
    "secretsmanager",
    "sts",
    "xray",
  ])

  vpc_id              = data.aws_vpc.selected.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
}

data "aws_route_tables" "private" {
  vpc_id = data.aws_vpc.selected.id
  filter {
    name   = "association.subnet-id"
    values = var.private_subnet_ids
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = data.aws_vpc.selected.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = data.aws_route_tables.private.ids
}

resource "aws_security_group" "database" {
  name        = "${local.common_name}-postgres"
  description = "PostgreSQL access from CloudSentinel EKS nodes only"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    description     = "PostgreSQL from the EKS cluster security group"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_eks_cluster.this.vpc_config[0].cluster_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }
}

resource "aws_security_group" "redis" {
  name        = "${local.common_name}-redis"
  description = "TLS Redis access from CloudSentinel EKS nodes only"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    description     = "Redis TLS from the EKS cluster security group"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_eks_cluster.this.vpc_config[0].cluster_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }
}

resource "aws_iam_role" "cluster" {
  name = "${local.common_name}-eks-control-plane"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "nodes" {
  name = "${local.common_name}-eks-nodes"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "node_worker" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_ecr" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly"
}

resource "aws_eks_cluster" "this" {
  name     = local.common_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.cluster_version

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
    security_group_ids      = [aws_security_group.cluster.id]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.data.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_cloudwatch_log_group.control_plane,
  ]
}

resource "aws_cloudwatch_log_group" "control_plane" {
  name              = "/aws/eks/${local.common_name}/cluster"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_eks_access_entry" "platform_admin" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.cluster_admin_role_arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "platform_admin" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.cluster_admin_role_arn
  policy_arn    = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope {
    type = "cluster"
  }
}

resource "aws_iam_role" "github_release_build" {
  name = "${local.common_name}-github-release-build"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = var.github_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = var.github_release_build_subject_pattern }
      }
    }]
  })
}

resource "aws_iam_role_policy" "github_release_build" {
  name = "push-immutable-cloudsentinel-images"
  role = aws_iam_role.github_release_build.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeRepositories",
          "ecr:GetDownloadUrlForLayer",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart",
        ]
        Resource = concat([
          aws_ecr_repository.backend.arn,
          aws_ecr_repository.frontend.arn,
          aws_ecr_repository.customer_scanner.arn,
          ], [for repository in aws_ecr_repository.backend_dr : repository.arn],
          [for repository in aws_ecr_repository.frontend_dr : repository.arn],
        [for repository in aws_ecr_repository.customer_scanner_dr : repository.arn])
      }
    ]
  })
}

resource "aws_iam_role" "github_release_deploy" {
  name = "${local.common_name}-github-release-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = var.github_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud"         = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:environment" = "production"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = var.github_release_deploy_subject
          "token.actions.githubusercontent.com:ref" = "refs/tags/v*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "github_release_deploy" {
  name = "describe-production-cluster"
  role = aws_iam_role.github_release_deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["eks:DescribeCluster"]
      Resource = concat(
        [aws_eks_cluster.this.arn],
        [for cluster in aws_eks_cluster.dr : cluster.arn]
      )
    }]
  })
}

resource "aws_eks_access_entry" "github_deployer" {
  cluster_name      = aws_eks_cluster.this.name
  principal_arn     = aws_iam_role.github_release_deploy.arn
  type              = "STANDARD"
  kubernetes_groups = ["cloudsentinel-deployer"]
}

resource "aws_eks_addon" "core" {
  for_each = toset([
    "coredns",
    "kube-proxy",
    "eks-pod-identity-agent",
    "metrics-server",
  ])
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_iam_role" "vpc_cni" {
  name = "${local.common_name}-vpc-cni"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = local.pod_identity_cluster_arns }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "vpc_cni" {
  role       = aws_iam_role.vpc_cni.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "vpc-cni"
  configuration_values        = jsonencode({ enableNetworkPolicy = "true" })
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
  pod_identity_association {
    service_account = "aws-node"
    role_arn        = aws_iam_role.vpc_cni.arn
  }
  depends_on = [aws_iam_role_policy_attachment.vpc_cni]
}

resource "aws_iam_role" "ebs_csi" {
  name = "${local.common_name}-ebs-csi"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = local.pod_identity_cluster_arns }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ebs_csi" {
  role       = aws_iam_role.ebs_csi.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

resource "aws_eks_addon" "ebs_csi" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "aws-ebs-csi-driver"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
  pod_identity_association {
    service_account = "ebs-csi-controller-sa"
    role_arn        = aws_iam_role.ebs_csi.arn
  }
  depends_on = [aws_iam_role_policy_attachment.ebs_csi]
}

resource "aws_iam_role" "cloudwatch_observability" {
  name = "${local.common_name}-cloudwatch-observability"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = local.pod_identity_cluster_arns }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch_metrics" {
  role       = aws_iam_role.cloudwatch_observability.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_traces" {
  role       = aws_iam_role.cloudwatch_observability.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AWSXrayWriteOnlyAccess"
}

resource "aws_eks_addon" "cloudwatch_observability" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "amazon-cloudwatch-observability"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
  pod_identity_association {
    service_account = "cloudwatch-agent"
    role_arn        = aws_iam_role.cloudwatch_observability.arn
  }
  depends_on = [
    aws_iam_role_policy_attachment.cloudwatch_metrics,
    aws_iam_role_policy_attachment.cloudwatch_traces,
    aws_cloudwatch_log_group.application,
    aws_cloudwatch_log_group.dataplane,
    aws_cloudwatch_log_group.host,
    aws_cloudwatch_log_group.performance,
  ]
}

resource "aws_cloudwatch_log_group" "application" {
  name              = "/aws/containerinsights/${local.common_name}/application"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_cloudwatch_log_group" "dataplane" {
  name              = "/aws/containerinsights/${local.common_name}/dataplane"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_cloudwatch_log_group" "host" {
  name              = "/aws/containerinsights/${local.common_name}/host"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_cloudwatch_log_group" "performance" {
  name              = "/aws/containerinsights/${local.common_name}/performance"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_launch_template" "nodes" {
  name_prefix            = "${local.common_name}-node-"
  update_default_version = true
  vpc_security_group_ids = [aws_security_group.cluster.id]

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 80
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.data.arn
      delete_on_termination = true
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${local.common_name}-worker"
    }
  }
}

resource "aws_eks_node_group" "general" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "general"
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = var.private_subnet_ids
  instance_types  = var.node_instance_types
  capacity_type   = "ON_DEMAND"
  ami_type        = "AL2023_x86_64_STANDARD"

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  update_config {
    max_unavailable_percentage = 33
  }

  launch_template {
    id      = aws_launch_template.nodes.id
    version = aws_launch_template.nodes.latest_version
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_ecr,
    aws_eks_addon.core,
    aws_eks_addon.vpc_cni,
    aws_eks_addon.ebs_csi,
    aws_eks_addon.cloudwatch_observability,
  ]
}

resource "aws_db_subnet_group" "this" {
  name       = "${local.common_name}-db"
  subnet_ids = var.private_subnet_ids
}

resource "aws_db_instance" "postgres" {
  identifier                      = "${local.common_name}-postgres"
  engine                          = "postgres"
  engine_version                  = "16.4"
  instance_class                  = var.database_instance_class
  allocated_storage               = 100
  max_allocated_storage           = 1000
  storage_type                    = "gp3"
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.data.arn
  db_name                         = var.database_name
  username                        = "cloudsentinel_admin"
  manage_master_user_password     = true
  master_user_secret_kms_key_id   = aws_kms_key.data.arn
  multi_az                        = true
  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = [aws_security_group.database.id]
  publicly_accessible             = false
  backup_retention_period         = var.database_backup_retention_days
  copy_tags_to_snapshot           = true
  deletion_protection             = true
  auto_minor_version_upgrade      = true
  apply_immediately               = false
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${local.common_name}-final"
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.data.arn
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  parameter_group_name            = aws_db_parameter_group.postgres.name
}

resource "aws_db_parameter_group" "postgres" {
  name   = "${local.common_name}-postgres16"
  family = "postgres16"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "immediate"
  }
}

resource "aws_backup_vault" "database" {
  name        = "${local.common_name}-database"
  kms_key_arn = aws_kms_key.data.arn
}

resource "aws_iam_role" "backup" {
  name = "${local.common_name}-backup"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "backup_restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

resource "aws_backup_plan" "database" {
  name = "${local.common_name}-database"
  rule {
    rule_name         = "daily-long-term-snapshots"
    target_vault_name = aws_backup_vault.database.name
    schedule          = "cron(0 4 * * ? *)"
    start_window      = 60
    completion_window = 360
    lifecycle {
      delete_after = 365
    }
  }
  rule {
    rule_name                = "continuous-point-in-time-recovery"
    target_vault_name        = aws_backup_vault.database.name
    schedule                 = "cron(0 5 * * ? *)"
    start_window             = 60
    completion_window        = 360
    enable_continuous_backup = true
    lifecycle {
      delete_after = 35
    }
  }
}

resource "aws_backup_selection" "database" {
  name         = "${local.common_name}-postgres"
  plan_id      = aws_backup_plan.database.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = [aws_db_instance.postgres.arn]
}

resource "aws_elasticache_subnet_group" "this" {
  name       = "${local.common_name}-redis"
  subnet_ids = var.private_subnet_ids
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${var.name_prefix}-${var.environment}"
  description                = "CloudSentinel task queue and cache"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = "cache.m7g.large"
  port                       = 6379
  parameter_group_name       = "default.redis7"
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = aws_kms_key.data.arn
  auth_token                 = var.redis_auth_token
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  security_group_ids         = [aws_security_group.redis.id]
  snapshot_retention_limit   = 7
  apply_immediately          = false
  auto_minor_version_upgrade = true
}

resource "aws_s3_bucket" "reports" {
  bucket              = var.report_bucket_name
  force_destroy       = false
  object_lock_enabled = true
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    id     = "expire-report-artifacts"
    status = "Enabled"
    filter {
      prefix = local.report_prefix
    }
    expiration { days = var.report_retention_days }
    noncurrent_version_expiration { noncurrent_days = 1 }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "remove-expired-report-delete-markers"
    status = "Enabled"
    filter { prefix = local.report_prefix }
    expiration { expired_object_delete_marker = true }
  }

  rule {
    id     = "expire-customer-scan-artifacts"
    status = "Enabled"
    filter { prefix = "${var.name_prefix}/${var.environment}/customer-scans/" }
    expiration { days = 1 }
    noncurrent_version_expiration { noncurrent_days = 1 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

resource "aws_s3_bucket_policy" "reports_tls" {
  bucket = aws_s3_bucket.reports.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_ecr_repository" "backend" {
  name                 = "${var.name_prefix}/backend"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }
}

resource "aws_ecr_repository" "frontend" {
  name                 = "${var.name_prefix}/frontend"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }
}

resource "aws_iam_role" "pod_report_writer" {
  name = "${local.common_name}-pod-report-writer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = local.pod_identity_cluster_arns
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "pod_report_writer" {
  name = "reports-prefix-access"
  role = aws_iam_role.pod_report_writer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = concat(
          ["${aws_s3_bucket.reports.arn}/${local.report_prefix}*"],
          [for bucket in aws_s3_bucket.dr_reports : "${bucket.arn}/${local.report_prefix}*"]
        )
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:GenerateDataKey"]
        Resource = concat([aws_kms_key.data.arn], [for key in aws_kms_key.dr_data : key.arn])
      }
    ]
  })
}

resource "aws_iam_role" "pod_outbox_retention" {
  name = "${local.common_name}-pod-outbox-retention"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = local.pod_identity_cluster_arns }
      }
    }]
  })
}

resource "aws_iam_role_policy" "pod_outbox_retention" {
  name = "report-retention-and-queue-metrics"
  role = aws_iam_role.pod_outbox_retention.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = concat(
          ["${aws_s3_bucket.reports.arn}/${local.report_prefix}*"],
          [for bucket in aws_s3_bucket.dr_reports : "${bucket.arn}/${local.report_prefix}*"]
        )
      },
      {
        Effect = "Allow"
        Action = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = concat(
          ["${aws_s3_bucket.reports.arn}/${local.customer_scan_prefix}*"],
          [for bucket in aws_s3_bucket.dr_reports : "${bucket.arn}/${local.customer_scan_prefix}*"]
        )
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucketVersions"]
        Resource = concat([aws_s3_bucket.reports.arn], [for bucket in aws_s3_bucket.dr_reports : bucket.arn])
        Condition = {
          StringLike = { "s3:prefix" = [local.report_prefix, "${local.report_prefix}*"] }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "CloudSentinel" }
        }
      }
    ]
  })
}

resource "aws_iam_role" "pod_report_reader" {
  name = "${local.common_name}-pod-report-reader"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = local.pod_identity_cluster_arns }
      }
    }]
  })
}

resource "aws_iam_role_policy" "pod_report_reader" {
  name = "report-download-only"
  role = aws_iam_role.pod_report_reader.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = concat(
          ["${aws_s3_bucket.reports.arn}/${local.report_prefix}*"],
          [for bucket in aws_s3_bucket.dr_reports : "${bucket.arn}/${local.report_prefix}*"]
        )
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = concat([aws_kms_key.data.arn], [for key in aws_kms_key.dr_data : key.arn])
      }
    ]
  })
}

resource "aws_eks_pod_identity_association" "api" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "cloudsentinel"
  service_account = "cloudsentinel-api"
  role_arn        = aws_iam_role.pod_report_reader.arn
}

resource "aws_eks_pod_identity_association" "worker" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "cloudsentinel"
  service_account = "cloudsentinel-worker"
  role_arn        = aws_iam_role.pod_report_writer.arn
}

resource "aws_eks_pod_identity_association" "outbox" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "cloudsentinel"
  service_account = "cloudsentinel-outbox"
  role_arn        = aws_iam_role.pod_outbox_retention.arn
}

resource "aws_eks_pod_identity_association" "otel_collector" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "cloudsentinel"
  service_account = "cloudsentinel-otel-collector"
  role_arn        = aws_iam_role.cloudwatch_observability.arn
}

resource "aws_iam_role" "external_secrets" {
  name = "${local.common_name}-external-secrets"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = local.pod_identity_cluster_arns }
      }
    }]
  })
}

resource "aws_secretsmanager_secret" "runtime" {
  name                    = "${var.name_prefix}/${var.environment}/runtime"
  description             = "CloudSentinel application runtime configuration; secret value is managed out-of-band."
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
  lifecycle { prevent_destroy = true }
}

resource "aws_iam_role_policy" "external_secrets" {
  name = "read-runtime-configuration"
  role = aws_iam_role.external_secrets.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = concat(
          [aws_secretsmanager_secret.runtime.arn],
          [for secret in aws_secretsmanager_secret.runtime_dr : secret.arn]
        )
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = concat([aws_kms_key.data.arn], [for key in aws_kms_key.dr_data : key.arn])
        Condition = {
          StringEquals = {
            "kms:ViaService" = concat(
              ["secretsmanager.${var.aws_region}.amazonaws.com"],
              var.dr_enabled ? ["secretsmanager.${var.dr_aws_region}.amazonaws.com"] : []
            )
          }
          StringLike = {
            "kms:EncryptionContext:SecretARN" = concat(
              [aws_secretsmanager_secret.runtime.arn],
              [for secret in aws_secretsmanager_secret.runtime_dr : secret.arn]
            )
          }
        }
      },
    ]
  })
}

resource "aws_eks_pod_identity_association" "external_secrets" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "external-secrets"
  service_account = "external-secrets"
  role_arn        = aws_iam_role.external_secrets.arn
}

resource "aws_iam_role" "load_balancer_controller" {
  name = "${local.common_name}-load-balancer-controller"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = local.pod_identity_cluster_arns }
      }
    }]
  })
}

resource "aws_iam_role_policy" "load_balancer_controller" {
  name   = "manage-cloudsentinel-application-load-balancer"
  role   = aws_iam_role.load_balancer_controller.id
  policy = file("${path.module}/iam/aws-load-balancer-controller-policy.json")
}

resource "aws_eks_pod_identity_association" "load_balancer_controller" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "kube-system"
  service_account = "aws-load-balancer-controller"
  role_arn        = aws_iam_role.load_balancer_controller.arn
}

resource "aws_secretsmanager_secret" "database_app" {
  name                    = "${var.name_prefix}/${var.environment}/database-app"
  description             = "CloudSentinel database application credentials; value is provisioned by the platform operator."
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
  lifecycle { prevent_destroy = true }
}

resource "aws_cloudwatch_metric_alarm" "outbox_dead_events" {
  alarm_name          = "${local.common_name}-outbox-dead-events"
  alarm_description   = "Asynchronous tasks exceeded delivery retries and entered the dead-letter state."
  namespace           = "CloudSentinel"
  metric_name         = "OutboxDeadEvents"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions = {
    Environment = var.environment
  }
  alarm_actions = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
  ok_actions    = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "outbox_age" {
  alarm_name          = "${local.common_name}-outbox-oldest-pending-age"
  alarm_description   = "Scan, report, and customer assessment tasks are waiting too long for delivery."
  namespace           = "CloudSentinel"
  metric_name         = "OutboxOldestPendingAgeSeconds"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 300
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions = {
    Environment = var.environment
  }
  alarm_actions = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
  ok_actions    = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "customer_scan_stuck" {
  alarm_name          = "${local.common_name}-customer-scans-stuck"
  alarm_description   = "An isolated customer assessment exceeded its bounded sandbox deadline."
  namespace           = "CloudSentinel"
  metric_name         = "StuckCustomerScanJobs"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { Environment = var.environment }
  alarm_actions       = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
  ok_actions          = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "customer_scan_queue" {
  alarm_name          = "${local.common_name}-customer-scans-queued"
  alarm_description   = "Customer assessment work is accumulating faster than the worker pool can dispatch it."
  namespace           = "CloudSentinel"
  metric_name         = "CustomerScanQueuedJobs"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 5
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { Environment = var.environment }
  alarm_actions       = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
  ok_actions          = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  alarm_name          = "${local.common_name}-api-5xx"
  alarm_description   = "The API returned more than ten server errors in one minute."
  namespace           = "CloudSentinel"
  metric_name         = "Api5xxCount"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions = {
    Environment = var.environment
  }
  alarm_actions = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
  ok_actions    = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "api_latency" {
  alarm_name          = "${local.common_name}-api-p95-latency"
  alarm_description   = "The API p95 request latency exceeded two seconds for two minutes."
  namespace           = "CloudSentinel"
  metric_name         = "ApiRequestLatencyMs"
  extended_statistic  = "p95"
  period              = 60
  evaluation_periods  = 2
  threshold           = 2000
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions = {
    Environment = var.environment
  }
  alarm_actions = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
  ok_actions    = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
}
