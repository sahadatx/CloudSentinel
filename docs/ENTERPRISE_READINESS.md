# Enterprise Readiness

**Status: implementation foundations are in place; production readiness is not verified.**
No AWS infrastructure has been applied from this checkout, no customer IdP has
been configured, and no recovery drill evidence exists yet. Treat all RPO/RTO
figures as planning objectives until drills measure them.

## Implemented in the project

- **Enterprise identity:** tenant-scoped SAML 2.0 sign-in with signed assertion
  validation, request-state and replay protection, optional just-in-time
  provisioning, a safe default role, and an organization policy requiring an
  IdP MFA authentication context. SCIM 2.0 supports tenant-scoped Users and
  Groups provisioning, membership deactivation, pre-approved group-to-role
  mappings, hashed 90-day bearer credentials, one-time token display, rotation,
  and audit events. The SCIM contract intentionally does not support Bulk,
  sorting, or ETags; the user filter is limited to `userName eq`.
- **Customer assessment sandbox:** tenant-owned IaC and OCI image TAR jobs run
  in short-lived Fargate tasks without a task role or public IP. The scanner has
  fixed CPU, memory, ephemeral storage, and timeout limits; archive traversal,
  expanded size, result size, quota, and output redaction are bounded. The
  scanner has no direct internet route and uses preloaded Checkov/Trivy data.
  Findings and source artifacts expire after 24 hours. The web console exposes
  upload, status, cancellation, filtering, and paginated findings.
- **CIS benchmark:** [CIS AWS Foundations 7.1.0](https://www.cisecurity.org/benchmark/amazon-web-services) is identified
  as **7.1.0**. The version is recorded with its source link, but the project's
  control mapping has not been independently checked. It is therefore marked
  `UNVERIFIED` and inactive; CloudSentinel does not present it as supported
  compliance coverage.
- **Retention and offboarding:** new audit events receive the organization's
  configured 30–3650 day expiry; report expiry and customer-scan expiry are
  tracked separately. Scheduled jobs purge expired audit data and erase an
  offboarded tenant only after the longest retained audit/report/scan deadline,
  a 30-day grace period, and the configured backup-retention window. Offboarding
  immediately disables the tenant and revokes sessions, invitations, SCIM
  credentials, and SAML sign-in, and cancels queued work. Existing audit events
  keep their original expiry when policy changes. Runtime configuration rejects
  an offboarding backup-retention window shorter than the declared longest
  database-backup retention.
- **Distributed tracing:** optional OpenTelemetry tracing covers FastAPI,
  SQLAlchemy, Redis, and Celery, exports OTLP to a two-replica in-cluster
  collector, and sends traces to AWS X-Ray. Sampling defaults to 10% and can be
  configured. Request correlation, metrics, logs, and queue alarms are also
  available.
- **Cross-region recovery:** optional AWS Terraform provisions a warm private
  EKS cluster, independent Redis, PostgreSQL read replica plus replicated
  automated backups, encrypted/versioned report and scan artifact replication,
  mirrored ECR repositories, and a private customer scanner sandbox. The
  recovery cluster and EKS deployment overlay remain a controlled manual
  failover. Redis sessions/queue state are not replicated; PostgreSQL outbox
  records are the durable source for queued work.
- **Recovery tooling:** the repository includes a guarded non-production RDS
  restore drill, an S3 replica restore drill that uses a synthetic object, and a
  staging-only release rollback drill. They write evidence records when run.
  None has been run from this checkout.

## Required account and organization setup

### Identity

Apply database migrations, enter the organization's IdP metadata in
Administration → Settings → Integrations, map only approved SCIM groups to
CloudSentinel roles, and configure the IdP with the displayed SP metadata and
SCIM endpoint. Test sign-in, enforced MFA context, group changes, deprovisioning,
token rotation, and emergency local administrator access with the customer IdP
before enabling SSO enforcement. Keep an independently tested administrator
recovery path.

### Customer IaC and container scans

Build and publish the immutable customer-scanner release image first. Set
`customer_scan_enabled = true` and `customer_scanner_image_tag` to that release,
then review and apply the saved Terraform plan. Copy the scanner bucket, prefix,
cluster ARN, task-definition ARN, private subnet IDs, and security-group ID
outputs into the encrypted runtime secret as the corresponding
`CLOUDSENTINEL_CUSTOMER_SCAN_*` settings; set `CLOUDSENTINEL_CUSTOMER_SCAN_ENABLED=true`.
Refresh the scanner image on a defined cadence so its offline vulnerability
databases do not become stale. The 24-hour object lifecycle is part of the
retention design and must be checked against any customer legal hold needs.

### Primary AWS deployment

Supply the existing VPC, two or more private and public subnets, controlled
egress, encrypted remote Terraform state, certificates/WAF, alarm subscriptions,
GitHub OIDC subjects, private deployment runner, and runtime/database secrets
described in the [AWS deployment guide](../infrastructure/terraform/aws/README.md).
Do not enable customer uploads until the API setting, Fargate sandbox, bucket
lifecycle, role permissions, and quotas are all configured.

### Recovery Region

Cross-region resources are optional and `dr_enabled` defaults to false. For a
recovery deployment, provide a distinct Region, a recovery VPC and private
subnets spanning at least two Availability Zones, an isolated recovery report
bucket name, Region-local ACM/WAF resources, DNS failover ownership, and a
private runner that can reach the recovery EKS API. Ensure the VPC has the
egress and AWS service endpoints needed by EKS workloads and the release
controller. Populate the recovery runtime secret with the promoted database,
recovery Redis, and recovery bucket endpoints. If customer scans are enabled,
also configure the recovery Region Fargate scanner outputs.

The release workflow mirrors immutable backend, frontend, and scanner images
when its recovery Region variables are configured. The
[`render-recovery-overlay.sh`](../scripts/aws/render-recovery-overlay.sh) helper
renders a separate Kustomize overlay with recovery networking, hostname,
certificate, WAF, collector Region, and recovery ECR images. Review the rendered
overlay, apply it from the private runner, run the normal migration/rollout
script against the recovery cluster, and switch DNS only under the approved
incident procedure. Database promotion, application verification, customer
communications, and DNS changes remain operator actions.

## Recovery objectives and measurable limits

- **PostgreSQL RPO objective:** 5 minutes. Cross-region RDS replication is
  asynchronous; the CloudWatch alarm begins warning at 4 minutes of observed
  replica lag, but this is not a guarantee. Record an observed recovery marker
  timestamp in each restore/failover drill.
- **Application RTO objective:** 4 hours. The included RDS drill measures only
  temporary database restore plus a supplied smoke check. It explicitly does
  not verify end-to-end application RTO. The staging rollback drill measures
  deployment rollback separately.
- **S3 artifact recovery:** [S3 Replication Time Control](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-time-control.html) has a 15-minute
  replication threshold. It cannot satisfy a five-minute object RPO. A complete
  service RPO must include both database changes and report/customer-scan object
  replication lag; it is not currently established as five minutes.
- **Redis:** recovery uses an independent Redis deployment. User sessions may
  need to be re-established and queued tasks are rebuilt from the PostgreSQL
  outbox after recovery.

Run the guarded database restore, S3 replica restore, and staging rollback
drills before launch, then rehearse full Region failover, Redis failover, and
DNS/application cutover on a recurring schedule. Store signed evidence with
timestamps, source and restored marker IDs, observed data loss, scope, outcome,
and owner. Update the targets from measured results. Do not describe the
service as enterprise production-ready until the prerequisites are deployed,
IdP integration is verified, and the recovery objectives have evidence.
