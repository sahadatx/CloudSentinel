# Security QA and Deployment Foundation

Phases 09 and 10 add repository and image security gates, hardened production
container builds, customer IaC scanning boundaries, and the AWS EKS deployment
foundation. The EKS configuration is a reviewed starting point; no AWS account
has been provisioned or production deployment verified.

## Phase 09: Security QA

Run `make security` for Bandit, pip-audit, and the repository's Semgrep rules.
Run `make iac-scan` with Trivy installed to check Terraform, CloudFormation,
Dockerfiles, Helm, Kubernetes, dependencies, and checked-in secrets. CI runs
Trivy against the source tree and the built backend and frontend images, failing
on high and critical findings. Findings from scanners must be reviewed; any
exception requires a scoped, expiring, documented suppression.

The backend tests directly exercise permission denial, tenant-filtered reads,
cross-tenant write rejection, generic authentication failures, safe error
responses, and refresh-token reuse revocation. These tests are regression checks,
not a substitute for a dedicated penetration test, login/recovery/AWS rate-limit
verification, or external OWASP assessment.

IaC/container scan coverage in CI checks CloudSentinel's own deployment and
source artifacts. Customer-uploaded Terraform/source archives and OCI image TAR
files are available through the isolated Fargate assessment service when it is
explicitly enabled and configured. Its offline scanner databases must be
refreshed by building and deploying a new immutable scanner image on a defined
cadence.

## Phase 10: Container and Kubernetes artifacts

`infrastructure/docker/Dockerfile.production` builds a non-root API/worker image;
`infrastructure/docker/frontend/Dockerfile.production` builds a static UI served by unprivileged Nginx.
Build both images locally with `make docker-build-production`.
The Nginx configuration proxies authenticated API routes to the backend service,
sets browser security headers, and exposes a liveness path.

`infrastructure/kubernetes/base` provides restricted-namespace, backend,
worker, relay, and frontend deployments with probes, resource bounds, disabled
service-account token mounting, dropped Linux capabilities, and read-only root
filesystems. `infrastructure/terraform/aws` prepares private EKS, multi-AZ RDS
PostgreSQL and Redis, encrypted report storage, Secrets Manager, ECR, ingress,
network policy support, workload identities, backups, and CloudWatch alerts.
Production values and prerequisite VPC, firewall, WAF, certificate, OIDC, state,
and runner configuration are described in the AWS deployment guide. Optional
OpenTelemetry instrumentation sends FastAPI, SQLAlchemy, Redis, and Celery spans
through the in-cluster collector to AWS X-Ray.

The runtime secret must provide `CLOUDSENTINEL_DATABASE_URL`, a
`CLOUDSENTINEL_JWT_SIGNING_KEY` with at least 32 characters, a Fernet
`CLOUDSENTINEL_MFA_ENCRYPTION_KEY`, an HTTPS
`CLOUDSENTINEL_FRONTEND_BASE_URL`, and reachable Redis configuration
(`CLOUDSENTINEL_REDIS_URL`, plus distinct Celery broker and result URLs if
needed). The production settings reject the default HTTP frontend URL, so
omitting it prevents the API and worker from starting.

Configure authenticated SMTP with STARTTLS in the same Secret if password
recovery email must work. This requires the SMTP host and sender address; set
username and password together when the provider requires authentication.
Without SMTP, the API can start but password recovery links will not be
delivered. No secret values are provided in this repository. Replace the image
tags with immutable registry references before applying the manifests. Database
and Redis are external services and must be reachable from the cluster.

`infrastructure/kubernetes/overlays/production` adds a TLS-only ALB ingress,
WAF attachment, External Secrets sync, and network policies. Replace every
`REPLACE_WITH_*` value with the corresponding account-specific value and verify
the egress firewall rules before applying. The required VPC, account resources,
and protected GitHub deployment runner are not created or validated here.

The release workflow builds digest-pinned backend, frontend, and customer
scanner images, scans them, generates and attests CycloneDX SBOMs and build
provenance, verifies signatures and SBOM attestations, then migrates and rolls
out from a protected in-VPC runner. When recovery Region variables are
configured, it also mirrors, signs, and SBOM-attests each image in the recovery
ECR registry.

The optional cross-region Terraform topology and guarded recovery drill scripts
are documented in the [AWS deployment guide](../infrastructure/terraform/aws/README.md).
The recovery Region does not auto-promote or receive traffic. The planned RPO
5-minute/RTO 4-hour objectives remain unmeasured; S3 Replication Time Control
has a 15-minute threshold and cannot meet a five-minute object RPO. Browser,
database, static analysis, and infrastructure gates are configured but were
not run as part of this implementation.

## Phase 10: Provider readiness

The existing asset model and normalized scanner output remain provider-neutral,
while AWS remains the only implemented cloud adapter. Azure and GCP collection,
credentials, services, and resource mappings are not implemented. Multi-cloud
readiness means preserving the shared normalized domain boundary; it does not
authorize cloud integrations before their own design and phase gate.
