resource "aws_kms_key" "dr_data" {
  count                   = var.dr_enabled ? 1 : 0
  provider                = aws.dr
  description             = "CloudSentinel ${var.environment} recovery Region data key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "dr_data" {
  count         = var.dr_enabled ? 1 : 0
  provider      = aws.dr
  name          = "alias/${local.common_name}-dr-data"
  target_key_id = aws_kms_key.dr_data[0].key_id
}

resource "aws_ecr_repository" "backend_dr" {
  count                = var.dr_enabled ? 1 : 0
  provider             = aws.dr
  name                 = "${var.name_prefix}/backend"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.dr_data[0].arn
  }
}

resource "aws_ecr_repository" "frontend_dr" {
  count                = var.dr_enabled ? 1 : 0
  provider             = aws.dr
  name                 = "${var.name_prefix}/frontend"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.dr_data[0].arn
  }
}

resource "aws_ecr_repository" "customer_scanner_dr" {
  count                = var.dr_enabled ? 1 : 0
  provider             = aws.dr
  name                 = "${var.name_prefix}/customer-scanner"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.dr_data[0].arn
  }
}

data "aws_vpc" "dr_selected" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr
  id       = var.dr_vpc_id
}

data "aws_subnet" "dr_private" {
  for_each = var.dr_enabled ? toset(var.dr_private_subnet_ids) : toset([])
  provider = aws.dr
  id       = each.value
}

data "aws_route_table" "dr_private" {
  for_each  = data.aws_subnet.dr_private
  provider  = aws.dr
  subnet_id = each.value.id
}

resource "aws_cloudwatch_log_group" "dr_control_plane" {
  count             = var.dr_enabled ? 1 : 0
  provider          = aws.dr
  name              = "/aws/eks/${local.common_name}-dr/cluster"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.dr_data[0].arn
}

resource "aws_iam_role" "dr_cluster" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr
  name     = "${local.common_name}-dr-eks-control-plane"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "dr_cluster" {
  count      = var.dr_enabled ? 1 : 0
  provider   = aws.dr
  role       = aws_iam_role.dr_cluster[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_security_group" "dr_eks" {
  count       = var.dr_enabled ? 1 : 0
  provider    = aws.dr
  name        = "${local.common_name}-dr-eks"
  description = "Recovery EKS private control plane and node traffic"
  vpc_id      = data.aws_vpc.dr_selected[0].id

  ingress {
    description = "Control plane, node, and pod communication within the cluster security group"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  ingress {
    description = "Private Kubernetes API from the recovery VPC and its deployment runner"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.dr_selected[0].cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [data.aws_vpc.dr_selected[0].cidr_block]
  }

  egress {
    description = "AWS APIs, ECR image pulls, and approved VPC egress firewall"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "dr_redis" {
  count       = var.dr_enabled ? 1 : 0
  provider    = aws.dr
  name        = "${local.common_name}-dr-redis"
  description = "TLS Redis access from the recovery EKS cluster only"
  vpc_id      = data.aws_vpc.dr_selected[0].id

  ingress {
    description     = "Redis TLS from the recovery EKS cluster security group"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.dr_eks[0].id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [data.aws_vpc.dr_selected[0].cidr_block]
  }
}

resource "aws_elasticache_subnet_group" "dr" {
  count      = var.dr_enabled ? 1 : 0
  provider   = aws.dr
  name       = "${local.common_name}-dr-redis"
  subnet_ids = var.dr_private_subnet_ids
}

resource "aws_elasticache_replication_group" "dr" {
  count                      = var.dr_enabled ? 1 : 0
  provider                   = aws.dr
  replication_group_id       = "${var.name_prefix}-${var.environment}-dr"
  description                = "CloudSentinel recovery task queue and ephemeral session cache; PostgreSQL outbox is the durable work source."
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
  kms_key_id                 = aws_kms_key.dr_data[0].arn
  auth_token                 = var.redis_auth_token
  subnet_group_name          = aws_elasticache_subnet_group.dr[0].name
  security_group_ids         = [aws_security_group.dr_redis[0].id]
  snapshot_retention_limit   = 7
  apply_immediately          = false
  auto_minor_version_upgrade = true
}

resource "aws_cloudwatch_log_group" "dr_application" {
  count             = var.dr_enabled ? 1 : 0
  provider          = aws.dr
  name              = "/aws/containerinsights/${local.common_name}-dr/application"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.dr_data[0].arn
}

resource "aws_cloudwatch_log_group" "dr_dataplane" {
  count             = var.dr_enabled ? 1 : 0
  provider          = aws.dr
  name              = "/aws/containerinsights/${local.common_name}-dr/dataplane"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.dr_data[0].arn
}

resource "aws_cloudwatch_log_group" "dr_host" {
  count             = var.dr_enabled ? 1 : 0
  provider          = aws.dr
  name              = "/aws/containerinsights/${local.common_name}-dr/host"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.dr_data[0].arn
}

resource "aws_cloudwatch_log_group" "dr_performance" {
  count             = var.dr_enabled ? 1 : 0
  provider          = aws.dr
  name              = "/aws/containerinsights/${local.common_name}-dr/performance"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.dr_data[0].arn
}

resource "aws_eks_cluster" "dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr
  name     = "${local.common_name}-dr"
  role_arn = aws_iam_role.dr_cluster[0].arn
  version  = var.cluster_version

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  vpc_config {
    subnet_ids              = var.dr_private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
    security_group_ids      = [aws_security_group.dr_eks[0].id]
  }

  encryption_config {
    provider { key_arn = aws_kms_key.dr_data[0].arn }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  depends_on                = [aws_iam_role_policy_attachment.dr_cluster, aws_cloudwatch_log_group.dr_control_plane]
}

resource "aws_eks_access_entry" "dr_platform_admin" {
  count         = var.dr_enabled ? 1 : 0
  provider      = aws.dr
  cluster_name  = aws_eks_cluster.dr[0].name
  principal_arn = var.cluster_admin_role_arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "dr_platform_admin" {
  count         = var.dr_enabled ? 1 : 0
  provider      = aws.dr
  cluster_name  = aws_eks_cluster.dr[0].name
  principal_arn = var.cluster_admin_role_arn
  policy_arn    = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
}

resource "aws_eks_access_entry" "dr_github_deployer" {
  count             = var.dr_enabled ? 1 : 0
  provider          = aws.dr
  cluster_name      = aws_eks_cluster.dr[0].name
  principal_arn     = aws_iam_role.github_release_deploy.arn
  type              = "STANDARD"
  kubernetes_groups = ["cloudsentinel-deployer"]
}

resource "aws_iam_role" "dr_nodes" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr
  name     = "${local.common_name}-dr-eks-nodes"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "dr_node_worker" {
  count      = var.dr_enabled ? 1 : 0
  provider   = aws.dr
  role       = aws_iam_role.dr_nodes[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "dr_node_ecr" {
  count      = var.dr_enabled ? 1 : 0
  provider   = aws.dr
  role       = aws_iam_role.dr_nodes[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly"
}

resource "aws_iam_role_policy_attachment" "dr_node_cni" {
  count      = var.dr_enabled ? 1 : 0
  provider   = aws.dr
  role       = aws_iam_role.dr_nodes[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_launch_template" "dr_nodes" {
  count                  = var.dr_enabled ? 1 : 0
  provider               = aws.dr
  name_prefix            = "${local.common_name}-dr-node-"
  update_default_version = true
  vpc_security_group_ids = [aws_security_group.dr_eks[0].id]

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 80
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.dr_data[0].arn
      delete_on_termination = true
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}

resource "aws_eks_node_group" "dr" {
  count           = var.dr_enabled ? 1 : 0
  provider        = aws.dr
  cluster_name    = aws_eks_cluster.dr[0].name
  node_group_name = "recovery"
  node_role_arn   = aws_iam_role.dr_nodes[0].arn
  subnet_ids      = var.dr_private_subnet_ids
  instance_types  = var.node_instance_types
  capacity_type   = "ON_DEMAND"
  ami_type        = "AL2023_x86_64_STANDARD"

  scaling_config {
    desired_size = var.dr_node_desired_size
    min_size     = 1
    max_size     = var.node_max_size
  }
  update_config { max_unavailable_percentage = 33 }
  launch_template {
    id      = aws_launch_template.dr_nodes[0].id
    version = aws_launch_template.dr_nodes[0].latest_version
  }
  depends_on = [
    aws_iam_role_policy_attachment.dr_node_worker,
    aws_iam_role_policy_attachment.dr_node_ecr,
    aws_iam_role_policy_attachment.dr_node_cni,
    aws_eks_addon.dr_core,
    aws_eks_addon.dr_vpc_cni,
    aws_eks_addon.dr_ebs_csi,
    aws_eks_addon.dr_cloudwatch,
  ]
}

resource "aws_eks_addon" "dr_core" {
  for_each                    = var.dr_enabled ? toset(["coredns", "kube-proxy", "eks-pod-identity-agent", "metrics-server"]) : toset([])
  provider                    = aws.dr
  cluster_name                = aws_eks_cluster.dr[0].name
  addon_name                  = each.key
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_eks_addon" "dr_vpc_cni" {
  count                       = var.dr_enabled ? 1 : 0
  provider                    = aws.dr
  cluster_name                = aws_eks_cluster.dr[0].name
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

resource "aws_eks_addon" "dr_ebs_csi" {
  count                       = var.dr_enabled ? 1 : 0
  provider                    = aws.dr
  cluster_name                = aws_eks_cluster.dr[0].name
  addon_name                  = "aws-ebs-csi-driver"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
  pod_identity_association {
    service_account = "ebs-csi-controller-sa"
    role_arn        = aws_iam_role.ebs_csi.arn
  }
  depends_on = [aws_iam_role_policy_attachment.ebs_csi]
}

resource "aws_eks_addon" "dr_cloudwatch" {
  count                       = var.dr_enabled ? 1 : 0
  provider                    = aws.dr
  cluster_name                = aws_eks_cluster.dr[0].name
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
    aws_cloudwatch_log_group.dr_application,
    aws_cloudwatch_log_group.dr_dataplane,
    aws_cloudwatch_log_group.dr_host,
    aws_cloudwatch_log_group.dr_performance,
  ]
}

resource "aws_eks_pod_identity_association" "dr_api" {
  count           = var.dr_enabled ? 1 : 0
  provider        = aws.dr
  cluster_name    = aws_eks_cluster.dr[0].name
  namespace       = "cloudsentinel"
  service_account = "cloudsentinel-api"
  role_arn        = aws_iam_role.pod_report_reader.arn
}

resource "aws_eks_pod_identity_association" "dr_worker" {
  count           = var.dr_enabled ? 1 : 0
  provider        = aws.dr
  cluster_name    = aws_eks_cluster.dr[0].name
  namespace       = "cloudsentinel"
  service_account = "cloudsentinel-worker"
  role_arn        = aws_iam_role.pod_report_writer.arn
}

resource "aws_eks_pod_identity_association" "dr_outbox" {
  count           = var.dr_enabled ? 1 : 0
  provider        = aws.dr
  cluster_name    = aws_eks_cluster.dr[0].name
  namespace       = "cloudsentinel"
  service_account = "cloudsentinel-outbox"
  role_arn        = aws_iam_role.pod_outbox_retention.arn
}

resource "aws_eks_pod_identity_association" "dr_otel" {
  count           = var.dr_enabled ? 1 : 0
  provider        = aws.dr
  cluster_name    = aws_eks_cluster.dr[0].name
  namespace       = "cloudsentinel"
  service_account = "cloudsentinel-otel-collector"
  role_arn        = aws_iam_role.cloudwatch_observability.arn
}

resource "aws_eks_pod_identity_association" "dr_external_secrets" {
  count           = var.dr_enabled ? 1 : 0
  provider        = aws.dr
  cluster_name    = aws_eks_cluster.dr[0].name
  namespace       = "external-secrets"
  service_account = "external-secrets"
  role_arn        = aws_iam_role.external_secrets.arn
}

resource "aws_eks_pod_identity_association" "dr_load_balancer_controller" {
  count           = var.dr_enabled ? 1 : 0
  provider        = aws.dr
  cluster_name    = aws_eks_cluster.dr[0].name
  namespace       = "kube-system"
  service_account = "aws-load-balancer-controller"
  role_arn        = aws_iam_role.load_balancer_controller.arn
}

resource "aws_secretsmanager_secret" "runtime_dr" {
  count                   = var.dr_enabled ? 1 : 0
  provider                = aws.dr
  name                    = "${var.name_prefix}/${var.environment}/runtime"
  description             = "Recovery Region runtime configuration; independently provision and verify the database and report bucket values."
  kms_key_id              = aws_kms_key.dr_data[0].arn
  recovery_window_in_days = 30
  lifecycle { prevent_destroy = true }
}

resource "aws_secretsmanager_secret" "database_app_dr" {
  count                   = var.dr_enabled ? 1 : 0
  provider                = aws.dr
  name                    = "${var.name_prefix}/${var.environment}/database-app"
  description             = "Recovery Region least-privilege application DB credentials; provision out of band."
  kms_key_id              = aws_kms_key.dr_data[0].arn
  recovery_window_in_days = 30
  lifecycle { prevent_destroy = true }
}

locals {
  dr_private_azs   = toset([for subnet in data.aws_subnet.dr_private : subnet.availability_zone])
  dr_private_cidrs = [for subnet in data.aws_subnet.dr_private : subnet.cidr_block]
  dr_has_public_subnet_ip = anytrue([
    for subnet in data.aws_subnet.dr_private : subnet.map_public_ip_on_launch
  ])
  dr_internet_gateway_routes = flatten([
    for route_table in data.aws_route_table.dr_private : [
      for route in route_table.routes : route
      if startswith(coalesce(route.gateway_id, ""), "igw-")
    ]
  ])
}

check "dr_private_subnets_are_valid" {
  assert {
    condition = !var.dr_enabled || (
      length(local.dr_private_azs) >= 2 &&
      alltrue([for subnet in data.aws_subnet.dr_private : subnet.vpc_id == data.aws_vpc.dr_selected[0].id]) &&
      !local.dr_has_public_subnet_ip &&
      length(local.dr_internet_gateway_routes) == 0
    )
    error_message = "Recovery Region subnets must belong to dr_vpc_id, span at least two Availability Zones, avoid public IP assignment, and not route directly to an internet gateway."
  }
}

resource "aws_security_group" "dr_database" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr
  name     = "${local.common_name}-dr-postgres"
  vpc_id   = data.aws_vpc.dr_selected[0].id

  ingress {
    description = "PostgreSQL only from the recovery Region private application subnets"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = local.dr_private_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [data.aws_vpc.dr_selected[0].cidr_block]
  }
}

resource "aws_security_group" "dr_customer_scan" {
  count       = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider    = aws.dr
  name        = "${local.common_name}-dr-customer-scanner"
  description = "Recovery Region scanner can reach only private AWS service endpoints"
  vpc_id      = data.aws_vpc.dr_selected[0].id
  egress      = []
}

resource "aws_security_group" "dr_customer_scan_endpoints" {
  count       = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider    = aws.dr
  name        = "${local.common_name}-dr-scanner-endpoints"
  description = "Private ECR and CloudWatch Logs endpoint access for scanner tasks"
  vpc_id      = data.aws_vpc.dr_selected[0].id
  egress      = []
}

resource "aws_vpc_security_group_ingress_rule" "dr_customer_scan_to_endpoints" {
  for_each = var.dr_enabled && var.customer_scan_enabled ? {
    scanner = aws_security_group.dr_customer_scan[0].id
    worker  = aws_security_group.dr_eks[0].id
  } : {}
  provider                     = aws.dr
  security_group_id            = aws_security_group.dr_customer_scan_endpoints[0].id
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "Recovery scanner and EKS worker access to private service endpoints"
}

resource "aws_vpc_security_group_egress_rule" "dr_customer_scan_to_endpoints" {
  count                        = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider                     = aws.dr
  security_group_id            = aws_security_group.dr_customer_scan[0].id
  referenced_security_group_id = aws_security_group.dr_customer_scan_endpoints[0].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "HTTPS only to private ECR and CloudWatch Logs endpoints"
}

resource "aws_vpc_security_group_egress_rule" "dr_customer_scan_dns_udp" {
  count             = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider          = aws.dr
  security_group_id = aws_security_group.dr_customer_scan[0].id
  cidr_ipv4         = data.aws_vpc.dr_selected[0].cidr_block
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
  description       = "VPC resolver DNS"
}

resource "aws_vpc_security_group_egress_rule" "dr_customer_scan_dns_tcp" {
  count             = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider          = aws.dr
  security_group_id = aws_security_group.dr_customer_scan[0].id
  cidr_ipv4         = data.aws_vpc.dr_selected[0].cidr_block
  ip_protocol       = "tcp"
  from_port         = 53
  to_port           = 53
  description       = "VPC resolver DNS over TCP"
}

resource "aws_vpc_endpoint" "dr_customer_scan_interface" {
  for_each = var.dr_enabled && var.customer_scan_enabled ? toset([
    "ecs",
    "ecr.api",
    "ecr.dkr",
    "logs",
  ]) : toset([])
  provider            = aws.dr
  vpc_id              = data.aws_vpc.dr_selected[0].id
  service_name        = "com.amazonaws.${var.dr_aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.dr_private_subnet_ids
  security_group_ids  = [aws_security_group.dr_customer_scan_endpoints[0].id]
}

resource "aws_vpc_endpoint" "dr_customer_scan_s3" {
  count             = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider          = aws.dr
  vpc_id            = data.aws_vpc.dr_selected[0].id
  service_name      = "com.amazonaws.${var.dr_aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = distinct([for route_table in data.aws_route_table.dr_private : route_table.id])
}

resource "aws_vpc_security_group_egress_rule" "dr_customer_scan_to_s3" {
  count             = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider          = aws.dr
  security_group_id = aws_security_group.dr_customer_scan[0].id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.dr_s3[0].id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "S3 traffic through the recovery VPC gateway endpoint"
}

data "aws_ec2_managed_prefix_list" "dr_s3" {
  count    = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider = aws.dr
  name     = "com.amazonaws.${var.dr_aws_region}.s3"
}

resource "aws_ecs_cluster" "customer_scanner_dr" {
  count    = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider = aws.dr
  name     = "${local.common_name}-dr-customer-scan"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_iam_role" "customer_scanner_execution_dr" {
  count    = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider = aws.dr
  name     = "${local.common_name}-dr-customer-scanner-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "customer_scanner_execution_dr" {
  count      = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider   = aws.dr
  role       = aws_iam_role.customer_scanner_execution_dr[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_task_definition" "customer_scanner_dr" {
  count                    = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider                 = aws.dr
  family                   = "${local.common_name}-dr-customer-scan"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "1024"
  memory                   = "4096"
  execution_role_arn       = aws_iam_role.customer_scanner_execution_dr[0].arn
  task_role_arn            = null

  ephemeral_storage {
    size_in_gib = 50
  }

  volume { name = "scanner-tmp" }

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name                   = "scanner"
    image                  = "${aws_ecr_repository.customer_scanner_dr[0].repository_url}:${var.customer_scanner_image_tag}"
    essential              = true
    cpu                    = 1024
    memory                 = 4096
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    mountPoints = [{
      sourceVolume  = "scanner-tmp"
      containerPath = "/tmp"
      readOnly      = false
    }]
    environment = [
      { name = "TRIVY_CACHE_DIR", value = "/opt/trivy-cache" },
      { name = "HOME", value = "/tmp" },
    ]
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.dr_customer_scanner[0].name
        "awslogs-region"        = var.dr_aws_region
        "awslogs-stream-prefix" = "scan"
      }
    }
  }])

  depends_on = [aws_iam_role_policy_attachment.customer_scanner_execution_dr]
}

resource "aws_cloudwatch_log_group" "dr_customer_scanner" {
  count             = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  provider          = aws.dr
  name              = "/ecs/${local.common_name}-dr/customer-scanner"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.dr_data[0].arn
}

resource "aws_iam_role_policy" "dr_customer_scan_worker_ecs" {
  count = var.dr_enabled && var.customer_scan_enabled ? 1 : 0
  name  = "run-private-recovery-customer-scan-tasks"
  role  = aws_iam_role.pod_report_writer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:RunTask"]
        Resource = "${aws_ecs_task_definition.customer_scanner_dr[0].arn_without_revision}:*"
        Condition = {
          ArnEquals = { "ecs:cluster" = aws_ecs_cluster.customer_scanner_dr[0].arn }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["ecs:DescribeTaskDefinition"]
        Resource = "arn:${data.aws_partition.current.partition}:ecs:${var.dr_aws_region}:${data.aws_caller_identity.current.account_id}:task-definition/${local.common_name}-dr-customer-scan:*"
      },
      {
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks", "ecs:StopTask", "ecs:TagResource"]
        Resource = "arn:${data.aws_partition.current.partition}:ecs:${var.dr_aws_region}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.customer_scanner_dr[0].name}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = aws_iam_role.customer_scanner_execution_dr[0].arn
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      },
    ]
  })
}

resource "aws_db_subnet_group" "dr" {
  count      = var.dr_enabled ? 1 : 0
  provider   = aws.dr
  name       = "${local.common_name}-dr-db"
  subnet_ids = var.dr_private_subnet_ids
}

resource "aws_db_instance" "postgres_dr_replica" {
  count                           = var.dr_enabled ? 1 : 0
  provider                        = aws.dr
  identifier                      = "${local.common_name}-postgres-dr"
  replicate_source_db             = aws_db_instance.postgres.arn
  instance_class                  = var.database_instance_class
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.dr_data[0].arn
  db_subnet_group_name            = aws_db_subnet_group.dr[0].name
  vpc_security_group_ids          = [aws_security_group.dr_database[0].id]
  publicly_accessible             = false
  backup_retention_period         = 7
  copy_tags_to_snapshot           = true
  deletion_protection             = true
  auto_minor_version_upgrade      = false
  apply_immediately               = false
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${local.common_name}-dr-final"
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.dr_data[0].arn
}

resource "aws_cloudwatch_metric_alarm" "dr_database_replica_lag" {
  count               = var.dr_enabled ? 1 : 0
  provider            = aws.dr
  alarm_name          = "${local.common_name}-dr-database-replica-lag"
  alarm_description   = "The PostgreSQL recovery replica lag exceeded the 5-minute planning target. This is a planning alarm, not an RPO guarantee."
  namespace           = "AWS/RDS"
  metric_name         = "ReplicaLag"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.postgres_dr_replica[0].identifier }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 240
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = var.dr_alarm_topic_arn == null ? [] : [var.dr_alarm_topic_arn]
  ok_actions          = var.dr_alarm_topic_arn == null ? [] : [var.dr_alarm_topic_arn]
}

resource "aws_db_instance_automated_backups_replication" "postgres" {
  count                  = var.dr_enabled ? 1 : 0
  provider               = aws.dr
  source_db_instance_arn = aws_db_instance.postgres.arn
  kms_key_id             = aws_kms_key.dr_data[0].arn
  retention_period       = var.dr_database_backup_retention_days
}

resource "aws_cloudwatch_metric_alarm" "dr_s3_replication_latency" {
  count               = var.dr_enabled ? 1 : 0
  provider            = aws.dr
  alarm_name          = "${local.common_name}-dr-s3-replication-latency"
  alarm_description   = "Report and customer-scan object replication latency is approaching the 5-minute planning objective; S3 RTC threshold is 15 minutes."
  namespace           = "AWS/S3"
  metric_name         = "ReplicationLatency"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 240
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "ignore"
  dimensions = {
    SourceBucket      = aws_s3_bucket.reports.bucket
    DestinationBucket = aws_s3_bucket.dr_reports[0].bucket
    RuleId            = "replicate-encrypted-artifacts-and-customer-scans"
  }
  alarm_actions = var.dr_alarm_topic_arn == null ? [] : [var.dr_alarm_topic_arn]
  ok_actions    = var.dr_alarm_topic_arn == null ? [] : [var.dr_alarm_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "dr_s3_replication_failure" {
  count               = var.dr_enabled ? 1 : 0
  provider            = aws.dr
  alarm_name          = "${local.common_name}-dr-s3-replication-failure"
  alarm_description   = "At least one report/customer-scan object operation failed cross-Region replication."
  namespace           = "AWS/S3"
  metric_name         = "OperationsFailedReplication"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "ignore"
  dimensions = {
    SourceBucket      = aws_s3_bucket.reports.bucket
    DestinationBucket = aws_s3_bucket.dr_reports[0].bucket
    RuleId            = "replicate-encrypted-artifacts-and-customer-scans"
  }
  alarm_actions = var.dr_alarm_topic_arn == null ? [] : [var.dr_alarm_topic_arn]
  ok_actions    = var.dr_alarm_topic_arn == null ? [] : [var.dr_alarm_topic_arn]
}

resource "aws_s3_bucket" "dr_reports" {
  count               = var.dr_enabled ? 1 : 0
  provider            = aws.dr
  bucket              = var.dr_report_bucket_name
  force_destroy       = false
  object_lock_enabled = true
}

resource "aws_s3_bucket_public_access_block" "dr_reports" {
  count                   = var.dr_enabled ? 1 : 0
  provider                = aws.dr
  bucket                  = aws_s3_bucket.dr_reports[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "dr_reports" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr
  bucket   = aws_s3_bucket.dr_reports[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dr_reports" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr
  bucket   = aws_s3_bucket.dr_reports[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.dr_data[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "dr_reports_tls" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr
  bucket   = aws_s3_bucket.dr_reports[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.dr_reports[0].arn, "${aws_s3_bucket.dr_reports[0].arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_iam_role" "s3_replication" {
  count = var.dr_enabled ? 1 : 0
  name  = "${local.common_name}-s3-replication"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "s3_replication" {
  count = var.dr_enabled ? 1 : 0
  name  = "encrypted-cross-region-object-replication"
  role  = aws_iam_role.s3_replication[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
        Resource = aws_s3_bucket.reports.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
          "s3:GetObjectRetention",
          "s3:GetObjectLegalHold",
        ]
        Resource = "${aws_s3_bucket.reports.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
          "s3:PutObjectRetention",
          "s3:PutObjectLegalHold",
        ]
        Resource = "${aws_s3_bucket.dr_reports[0].arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.data.arn
        Condition = {
          StringLike = {
            "kms:ViaService"                   = "s3.${var.aws_region}.amazonaws.com"
            "kms:EncryptionContext:aws:s3:arn" = [aws_s3_bucket.reports.arn]
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.dr_data[0].arn
        Condition = {
          StringLike = {
            "kms:ViaService"                   = "s3.${var.dr_aws_region}.amazonaws.com"
            "kms:EncryptionContext:aws:s3:arn" = [aws_s3_bucket.dr_reports[0].arn]
          }
        }
      },
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "reports_to_dr" {
  count  = var.dr_enabled ? 1 : 0
  bucket = aws_s3_bucket.reports.id
  role   = aws_iam_role.s3_replication[0].arn

  rule {
    id       = "replicate-encrypted-artifacts-and-customer-scans"
    status   = "Enabled"
    priority = 1
    filter { prefix = "" }

    delete_marker_replication { status = "Enabled" }

    destination {
      bucket = aws_s3_bucket.dr_reports[0].arn
      encryption_configuration { replica_kms_key_id = aws_kms_key.dr_data[0].arn }
      metrics {
        status = "Enabled"
        event_threshold { minutes = 15 }
      }
      replication_time {
        status = "Enabled"
        time { minutes = 15 }
      }
    }

    source_selection_criteria {
      sse_kms_encrypted_objects { status = "Enabled" }
    }
  }

  depends_on = [aws_s3_bucket_versioning.reports, aws_s3_bucket_versioning.dr_reports]
}

resource "aws_s3_bucket_lifecycle_configuration" "dr_reports" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr
  bucket   = aws_s3_bucket.dr_reports[0].id

  rule {
    id     = "expire-retained-report-versions"
    status = "Enabled"
    filter { prefix = local.report_prefix }
    expiration { days = var.report_retention_days }
    noncurrent_version_expiration { noncurrent_days = 1 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }

  rule {
    id     = "remove-expired-report-delete-markers"
    status = "Enabled"
    filter { prefix = local.report_prefix }
    expiration { expired_object_delete_marker = true }
  }

  rule {
    id     = "expire-customer-scan-replicas"
    status = "Enabled"
    filter { prefix = local.customer_scan_prefix }
    expiration { days = 1 }
    noncurrent_version_expiration { noncurrent_days = 1 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

