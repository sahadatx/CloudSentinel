data "aws_ec2_managed_prefix_list" "s3" {
  name = "com.amazonaws.${var.aws_region}.s3"
}

locals {
  customer_scan_prefix = "${var.name_prefix}/${var.environment}/customer-scans/"
  scanner_task_family  = "${local.common_name}-customer-scan"
}

resource "aws_ecr_repository" "customer_scanner" {
  name                 = "${var.name_prefix}/customer-scanner"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }
}

resource "aws_cloudwatch_log_group" "customer_scanner" {
  name              = "/ecs/${local.common_name}/customer-scanner"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_security_group" "customer_scanner" {
  name        = "${local.common_name}-customer-scanner"
  description = "Private customer scan task: AWS service endpoints and S3 only"
  vpc_id      = data.aws_vpc.selected.id
  egress      = []

  tags = { Name = "${local.common_name}-customer-scanner" }
}

resource "aws_security_group_rule" "scanner_to_vpc_endpoints" {
  type                     = "egress"
  description              = "HTTPS only to private AWS interface endpoints"
  security_group_id        = aws_security_group.customer_scanner.id
  source_security_group_id = aws_security_group.vpc_endpoints.id
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
}

resource "aws_security_group_rule" "scanner_to_s3" {
  type              = "egress"
  description       = "S3 gateway endpoint traffic only"
  security_group_id = aws_security_group.customer_scanner.id
  prefix_list_ids   = [data.aws_ec2_managed_prefix_list.s3.id]
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
}

resource "aws_security_group_rule" "scanner_dns_udp" {
  type              = "egress"
  description       = "VPC resolver DNS over UDP"
  security_group_id = aws_security_group.customer_scanner.id
  cidr_blocks       = [data.aws_vpc.selected.cidr_block]
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
}

resource "aws_security_group_rule" "scanner_dns_tcp" {
  type              = "egress"
  description       = "VPC resolver DNS over TCP"
  security_group_id = aws_security_group.customer_scanner.id
  cidr_blocks       = [data.aws_vpc.selected.cidr_block]
  from_port         = 53
  to_port           = 53
  protocol          = "tcp"
}

resource "aws_security_group_rule" "endpoints_from_scanner" {
  type                     = "ingress"
  description              = "Scanner tasks may use only interface endpoints over HTTPS"
  security_group_id        = aws_security_group.vpc_endpoints.id
  source_security_group_id = aws_security_group.customer_scanner.id
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
}

resource "aws_ecs_cluster" "customer_scanner" {
  count = var.customer_scan_enabled ? 1 : 0
  name  = "${local.common_name}-customer-scan"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_iam_role" "customer_scanner_execution" {
  count = var.customer_scan_enabled ? 1 : 0
  name  = "${local.common_name}-customer-scanner-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "customer_scanner_execution" {
  count      = var.customer_scan_enabled ? 1 : 0
  role       = aws_iam_role.customer_scanner_execution[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_task_definition" "customer_scanner" {
  count                    = var.customer_scan_enabled ? 1 : 0
  family                   = local.scanner_task_family
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "1024"
  memory                   = "4096"
  execution_role_arn       = aws_iam_role.customer_scanner_execution[0].arn
  task_role_arn            = null

  ephemeral_storage {
    size_in_gib = 50
  }

  volume {
    name = "scanner-tmp"
  }

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name                   = "scanner"
    image                  = "${aws_ecr_repository.customer_scanner.repository_url}:${var.customer_scanner_image_tag}"
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
        "awslogs-group"         = aws_cloudwatch_log_group.customer_scanner.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "scan"
      }
    }
  }])

  depends_on = [aws_iam_role_policy_attachment.customer_scanner_execution]
}

resource "aws_iam_role_policy" "customer_scan_api_artifacts" {
  name  = "customer-scan-upload-only"
  role  = aws_iam_role.pod_report_reader.id
  count = var.customer_scan_enabled ? 1 : 0
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:AbortMultipartUpload"]
        Resource = "${aws_s3_bucket.reports.arn}/${local.customer_scan_prefix}*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.data.arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "customer_scan_worker_artifacts" {
  name  = "customer-scan-presigned-artifacts"
  role  = aws_iam_role.pod_report_writer.id
  count = var.customer_scan_enabled ? 1 : 0
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.reports.arn}/${local.customer_scan_prefix}*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.data.arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "customer_scan_worker_ecs" {
  name  = "run-private-customer-scan-tasks"
  role  = aws_iam_role.pod_report_writer.id
  count = var.customer_scan_enabled ? 1 : 0
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = ["ecs:RunTask"]
        Resource  = "${aws_ecs_task_definition.customer_scanner[0].arn_without_revision}:*"
        Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.customer_scanner[0].arn } }
      },
      {
        Effect   = "Allow"
        Action   = ["ecs:DescribeTaskDefinition"]
        Resource = "arn:${data.aws_partition.current.partition}:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:task-definition/${local.scanner_task_family}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks", "ecs:StopTask", "ecs:TagResource"]
        Resource = "arn:${data.aws_partition.current.partition}:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.customer_scanner[0].name}/*"
      },
      {
        Effect    = "Allow"
        Action    = ["iam:PassRole"]
        Resource  = aws_iam_role.customer_scanner_execution[0].arn
        Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
      }
    ]
  })
}

