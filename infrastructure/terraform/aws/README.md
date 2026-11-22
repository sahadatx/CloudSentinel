# AWS EKS production foundation

This configuration prepares the CloudSentinel AWS foundation. It does not deploy Kubernetes workloads by itself. The cluster API is private, so `kubectl` and the release runner must run from a network that can reach the VPC.

## Resources included

- EKS 1.35, private API endpoint, managed private nodes, API access entries, encrypted Kubernetes secrets, Pod Identity, VPC CNI network policy, metrics-server, EBS CSI, and CloudWatch Observability.
- Multi-AZ RDS PostgreSQL with managed master credentials, encryption, deletion protection, Performance Insights, 14-day PITR and AWS Backup restore points.
- Multi-AZ TLS Redis with automatic failover, authentication, encryption, and seven days of snapshots. Scan/report intents remain durable in PostgreSQL if Redis loses queued messages.
- Versioned, KMS-encrypted, public-blocked S3 report storage, immutable ECR tags, private AWS service endpoints, and workload-specific IAM roles.
- CloudWatch request/queue alarms and 90-day encrypted application/cluster log groups.
- GitHub OIDC roles restricted to version tags, with image publishing separated from namespace-scoped Kubernetes deployment permissions.
- Optional customer assessment Fargate tasks with no task role/public IP, bounded resources, private ECR/Logs/S3 routes, and one-day artifact expiry.
- Optional recovery Region warm EKS, RDS replica and replicated backups, independent Redis, encrypted report/scan artifact replication, mirrored ECR, and a regional customer scanner.

AWS recommends using the latest supported EKS minor version. The default here is Kubernetes 1.35, which is in standard support through March 27, 2027; review the current EKS lifecycle before each new environment or upgrade: [EKS version lifecycle](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html).

## Prerequisites

1. An existing VPC with DNS resolution and DNS hostnames enabled, at least two private subnets and two public subnets across Availability Zones, and private subnet route tables.
2. A VPC egress path. Route private-subnet internet-bound traffic through an AWS Network Firewall or an equivalent controlled egress service. The workload security groups allow HTTPS and authenticated SMTP; domain allowlisting must happen at that egress boundary. Permit the required AWS service APIs, the configured mail relay, and customer AWS STS endpoints.
3. A separately managed, versioned and KMS-encrypted S3 bucket for Terraform state. The bootstrap configuration in `../aws-state` creates one.
4. An ACM certificate and regional AWS WAF web ACL for the public application hostname.
5. The GitHub Actions OIDC provider in the AWS account. Set both subject variables to the repository's actual OIDC subject format. Repositories created after July 15, 2026, and repositories that opted into immutable subject claims, use the owner/repository IDs in the subject. The deploy job requires a protected, self-hosted GitHub runner inside the VPC because the cluster endpoint has no public access.
6. An SNS topic with a verified on-call subscription for alarms. Set `alarm_topic_arn` to it.
7. Create GitHub repository variables `AWS_RELEASE_BUILD_ROLE_ARN` and `AWS_RELEASE_DEPLOY_ROLE_ARN` from the Terraform outputs, plus `AWS_REGION`, `ECR_BACKEND_REPOSITORY`, `ECR_FRONTEND_REPOSITORY`, and `EKS_CLUSTER_NAME`.

## State and configuration

1. Bootstrap the state bucket from `../aws-state`, then create a private `backend.hcl` from `backend.hcl.example`.
2. Copy `terraform.tfvars.example` to `terraform.tfvars` and set the account-specific VPC, subnet, admin role, GitHub OIDC subjects, domain, certificate, WAF, alarm topic, and report bucket values.
3. Inject `redis_auth_token` through an encrypted CI/Terraform variable store. It is marked sensitive but is still present in Terraform state. Do not use local plaintext state or commit a real tfvars file.
4. Run `terraform init -backend-config=backend.hcl`, inspect a saved plan and its IAM/network changes, then apply it from an approved platform runner.

The runtime secret `cloudsentinel/production/runtime` is deliberately created without a value, so Terraform never receives application credentials. Use an approved secret manager workflow to populate a JSON object with `CLOUDSENTINEL_DATABASE_URL`, `CLOUDSENTINEL_JWT_SIGNING_KEY`, `CLOUDSENTINEL_MFA_ENCRYPTION_KEY`, `CLOUDSENTINEL_REDIS_URL`, `CLOUDSENTINEL_FRONTEND_BASE_URL`, `CLOUDSENTINEL_PUBLIC_API_BASE_URL`, `CLOUDSENTINEL_REPORT_STORAGE_BUCKET`, `CLOUDSENTINEL_REPORT_STORAGE_REGION`, and `CLOUDSENTINEL_REPORT_STORAGE_PREFIX`. The public API URL must be HTTPS and reachable by the configured IdP; SAML metadata and SCIM endpoints use it. Set `CLOUDSENTINEL_LONGEST_BACKUP_RETENTION_DAYS` to the longer of the primary and recovery backup retention, and keep `CLOUDSENTINEL_OFFBOARDING_BACKUP_RETENTION_DAYS` at or above it; the application rejects a smaller value. Generate the MFA key with Python's `cryptography.fernet.Fernet.generate_key()` and back it up securely; losing that key prevents users from using enrolled TOTP devices. Add `CLOUDSENTINEL_SMTP_*` fields when mail delivery is configured. Use `rediss://` URLs with TLS and URL-encoded credentials. The database URL must use the least-privilege application role and allow the release migration job to apply forward-compatible migrations.

The runtime secret and database application secret are protected from Terraform deletion. The platform operator must provision their values and database application role separately. Never put those values in source control, workflow logs, or Terraform variables.

When customer assessment is enabled, set `CLOUDSENTINEL_CUSTOMER_SCAN_ENABLED=true`
and copy `customer_scan_bucket_name`, `customer_scan_prefix`,
`customer_scan_cluster_arn`, `customer_scan_task_definition_arn`,
`customer_scan_private_subnet_ids`, and `customer_scan_security_group_id` from
Terraform outputs into the matching `CLOUDSENTINEL_CUSTOMER_SCAN_*` keys.
Disable the feature again if any runtime value is removed or the sandbox is not
available. For recovery, use the `dr_customer_scan_*` outputs and the recovery
bucket/Region instead.

## EKS workload bootstrap

Run the AWS Load Balancer Controller and External Secrets Operator installer from an approved workstation inside the VPC after Terraform creates the cluster. The controller versions are pinned in the script and follow the [AWS EKS installation guide](https://docs.aws.amazon.com/eks/latest/userguide/lbc-helm.html). The External Secrets controller uses its EKS Pod Identity and the AWS SDK default credential chain; it can read only the runtime secret.

Fill the `REPLACE_WITH_*` values in `infrastructure/kubernetes/overlays/production`, then apply `kubectl apply -k infrastructure/kubernetes/overlays/production`. This creates the TLS-only ALB ingress, WAF association, runtime secret sync, ingress/egress policies, and workload deployments. NetworkPolicy enforcement is enabled through the VPC CNI add-on; validate required database, Redis, AWS API, DNS, and SMTP egress against the VPC firewall before switching production traffic.

The Amazon CloudWatch Observability add-on ships structured application logs and Container Insights. API request logs use CloudWatch Embedded Metric Format; the outbox relay publishes queue depth, oldest pending age, dead-letter count, and stale-work metrics once per minute. Configure the SNS alarm topic to receive notifications.

## Recovery targets and drills

Initial service objectives are **RPO 5 minutes** for PostgreSQL and **RTO 4 hours** for the application stack. These are targets, not verified guarantees. The RDS configuration enables point-in-time recovery and scheduled backup restore points; Redis queue data can be rebuilt from the PostgreSQL outbox. S3 report artifacts are versioned and removed by the application retention worker, with a matching bucket lifecycle fallback in both Regions. Keep Terraform `report_retention_days` equal to runtime `CLOUDSENTINEL_REPORT_RETENTION_DAYS`; expired noncurrent versions are cleaned up after one day.

Before production launch, record owners and evidence for quarterly PostgreSQL point-in-time restore drills, a quarterly EKS redeployment/rollback drill, an S3 deleted-object recovery drill, and a Redis failover drill. Measure actual recovery time, record data loss, update the targets, and alert on failed or overdue drills. The RDS and staging rollback drill helpers are in `scripts/aws/drills`; neither has been run from this workspace.

### Optional cross-Region recovery

`dr_enabled` defaults to `false`. Enabling it creates AWS resources in the
second Region, so review the saved plan and expected ongoing cost before
applying. Set `dr_aws_region`, a unique `dr_report_bucket_name`, `dr_vpc_id`,
and at least two `dr_private_subnet_ids` spanning Availability Zones. The
recovery VPC must have DNS enabled, private route tables, outbound connectivity
for the recovery workloads and deployment runner, and no overlapping address
space with the production VPC. Supply a Region-local alarm topic if recovery
alarm notifications are required. These inputs do not create a VPC, NAT/firewall,
public subnets, ALB, DNS records, ACM certificate, or WAF ACL.

The recovery cluster is warm but does not receive live application traffic by
itself. The recovery runtime secret is created empty and protected from
Terraform deletion. Populate it out of band with the same JSON keys as the
primary runtime secret and recovery-specific database, Redis, S3 bucket, Region,
and customer-scanner endpoints. The PostgreSQL replica is asynchronous. Its
replica-lag alarm fires at four minutes as an early warning; it does not promise
a five-minute RPO. Redis is independent and does not replicate sessions or
queued broker messages. The transactional outbox rebuilds queued work after
application recovery.

S3 report and customer-scan artifacts are replicated using KMS encryption and
S3 [Replication Time Control](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-time-control.html). AWS's RTC threshold is 15 minutes, so S3 object
recovery does not satisfy the five-minute database RPO objective. Customer
scanning also requires `customer_scan_enabled = true` and an immutable
`customer_scanner_image_tag`; when both scanning and DR are enabled, Terraform
creates the private recovery Fargate cluster and isolated AWS service endpoints.

After Terraform provisions the recovery Region, set the release workflow's
`DR_AWS_REGION` and `DR_ECR_REGISTRY` repository variables. Releases then mirror
the signed, SBOM-attested backend, frontend, and scanner images to ECR in that
Region. Render a reviewed overlay with
`scripts/aws/render-recovery-overlay.sh`, apply it from a private runner, and
use `scripts/aws/rollout-release.sh` with the recovery Region/cluster and
recovery ECR image references. Promotion, smoke checks, customer communication,
and DNS cutover remain explicit operator steps in the incident runbook. See
[Enterprise Readiness](../../../docs/ENTERPRISE_READINESS.md) for target limits
and drill status.

Run `scripts/aws/drills/restore-rds-drill.sh` only in a non-production recovery
environment. It creates a temporary database from an automated backup and
requires an executable smoke-check script; `DRILL_CLEANUP=true` removes the
temporary instance when the run ends. The evidence marks RPO as unmeasured
unless an operator supplies a verified marker lag. Run
`scripts/aws/drills/s3-replica-restore-drill.sh` with a staging bucket and
customer-scan prefix; it writes a synthetic object, waits for a matching
encrypted replica, simulates deletion, and restores that exact version. The
generated object remains under the one-day lifecycle prefix. Run
`scripts/aws/drills/rollback-staging-release.sh` only against a confirmed
staging context and review its before/after image and revision evidence. These
drills are scoped and guarded; none has been run from this workspace.

## Release flow

`.github/workflows/release.yml` builds immutable backend/frontend/customer-scanner images for protected `v*` tags, scans them, publishes SBOM and build provenance, signs them, and deploys their digests using a protected GitHub environment. If the recovery repository variables are configured, it mirrors all three images and signs/attests each destination image. The deploy job runs only on a `cloudsentinel-private-deploy` self-hosted runner. It applies forward migrations, updates the deployments, waits for health, and rolls application deployments back automatically if rollout fails. Database schema rollback is intentionally a forward-fix operation; migrations must remain backward-compatible through the rollout window.
