# Phase Roadmap and Gates

**Status:** Revised 10-phase roadmap; Phases 01–08 complete, Phase 09–10 foundations implemented; production acceptance remains open
**Authority:** The latest product direction supersedes the earlier 34-phase breakdown. `PROJECT_SPECIFICATION.md` is the product source of truth.

## Gate applicable to every phase

Before a phase begins, record its scope, expected files/modules, contracts, database changes, tests, security considerations, acceptance criteria, and prohibited future-scope work. Implement one phase at a time. Follow specification section 65 for architecture changes. A phase is complete only when its gate passes and the applicable definition-of-done criteria in section 69 are met.

For each row, prohibited work includes functionality assigned to later phases. Within a merged phase, the subsystem boundaries and ordered feature dependencies remain in force.

| Phase | Objective and major scope | Dependencies | Expected outputs | Prohibited future-scope work |
|---|---|---|---|---|
| 01 — Architecture, Repository & Development Foundation | Establish constitution, repository structure, Python/FastAPI bootstrap, configuration, logging, safe exceptions, health/readiness, Redis/Celery foundation, development Docker, tests, and CI skeleton. | Locked product direction. | Completed architecture and repository foundation. | Database, authentication, RBAC, business domains, and all later phase features. |
| 02 — Database, Authentication, RBAC & Multi-Tenancy | PostgreSQL, SQLAlchemy, Alembic, schema/migration conventions; secure authentication and JWT/session handling; the seven roles and granular permissions; tenant model and backend isolation foundations. | Phase 01 foundation. | Database schema/migrations and tested authn/authz/tenant foundations. | Organization/user/team management workflows, AWS accounts, and all later domains. |
| 03 — Organization, User & AWS Cloud Account Management | Organization, user, team, membership/role administration, AWS accounts, AssumeRole setup/validation, connection health, and account metadata. | Phase 02 identity, database, RBAC, and tenant foundations. | Tenant-scoped management contracts and workflows for users, organizations, teams, and AWS accounts. | Scan jobs, AWS resource collection, inventory, and security assessment. |
| 04 — AWS Discovery, Asset Inventory & Scan Engine | Scan jobs and progress; AWS provider SDK collection; discovery, normalization, inventory, and specified AWS resource coverage. | Phase 03 AWS account access and tenant context. | Asynchronous scan and normalized asset inventory capability. | Policy evaluation, AWS security rules, findings lifecycle, risk, and compliance. |
| 05 — Policy Engine, Security Rules & Findings Engine | Policy-as-code, generic evaluator, AWS security rules, findings and lifecycle, assignment and suppression. | Phase 04 normalized assets and collected data. | Versioned policy/rule behavior and evidence-linked findings. | Risk scoring, compliance assessment, investigation system, and frontend. |
| 06 — Risk, Compliance, Evidence & Investigation | Risk model/scoring, CIS AWS Foundations mapping, evidence collection/persistence, investigation and verification context. | Phase 05 findings and assessment data. | Documented risk calculation and traceable risk/compliance/evidence workflows. | Frontend, remediation execution, reports, and other later operations. |
| 07 — Frontend Security Operations Console | React/TypeScript foundation and authentication, dashboard, cloud/account, asset, findings, policy, risk, and compliance interfaces backed by real APIs. | Backend contracts for each consumed feature. | Responsive, role-aware security operations console. | Remediation, reporting/notification/audit workflows, IaC/container security, deployment. |
| 08 — Remediation, Reports, Notifications & Audit | Recommendation-first remediation and explicitly approved workflows; reports, notification channels, audit logs, administration. | Findings, identity/authorization, relevant risk/evidence, and frontend/backend contracts. | Authorized operational workflows with tenant-aware auditability. | Advanced security domains, production deployment, and multi-cloud readiness. |
| 09 — Advanced Cloud Security & Security QA | IaC, container/Kubernetes assessment plus security QA for auth, authorization, IDOR, tenancy, SSRF, secrets, dependencies, containers, rate limits, and OWASP risks. | Stable preceding product domains and shared policy architecture. | Advanced assessment coverage and documented security QA outcomes. | CI/CD, production deployment, and multi-cloud readiness. |
| 10 — CI/CD, Production Deployment & Multi-Cloud Readiness | Quality/security pipeline (Ruff, MyPy, Pytest, Bandit, Semgrep, pip-audit, Trivy); production deployment, observability, operations; Azure/GCP provider abstraction readiness. | Prior phase gates, security QA, and stable AWS-first platform. | CI/CD, production readiness artifacts, and multi-cloud architecture readiness. | Uncontrolled multi-cloud expansion or changes that destabilize the AWS-first core. |

## Phase 02 gate detail

- **In scope:** PostgreSQL; SQLAlchemy; Alembic; schema conventions; foundation database configuration, engine/session and migration environment; authn/session lifecycle; locked roles and granular permission enforcement; tenant ownership and isolation foundations.
- **Expected areas:** `backend/app/core/`, `backend/app/db/`, `backend/app/auth/`, `backend/app/authorization/`, `backend/app/tenancy/`, `backend/migrations/`, backend tests, project dependency/configuration, and targeted architecture updates. Adjust only as needed to respect existing module boundaries.
- **Database constraints:** no AWS/account/asset/finding business models except foundational organization/user/role/permission/session structures necessary for this phase. Organization/user management endpoints and workflows remain Phase 03.
- **Security considerations:** password hashing; token/session expiry and revocation; secure secret configuration; deny-by-default permissions; role/permission scope; tenant context from trusted identity; resistance to cross-tenant object access; no credential/token logging.
- **Prohibited:** Phase 03 management APIs, AWS integration, scanner/asset/business domains, frontend, and later-phase work.
- **Completion:** migration environment works against PostgreSQL; auth and authorization paths have direct tests; tenant isolation has cross-tenant denial tests; no later-phase business features were introduced.

## Current status

Phases 01–08 are complete. Phase 09 adds security QA, enterprise identity, and customer IaC/container scanning. Phase 10 adds CI/CD security gates, hardened container and Kubernetes foundations, AWS EKS deployment, tracing, and optional cross-region recovery. The gates below record implemented foundations and remaining account setup, integration verification, and recovery evidence.

## Phase 03 gate detail

- **In scope:** Organization self-service details within the authenticated tenant; tenant user invitations, memberships, role assignment/deactivation; team and team-membership management; AWS account registration/disconnection, regions, and connection health; STS AssumeRole validation using a read-only target role.
- **Cloud account console contract:** account metadata includes an optional organization-owned environment label and configured primary region; account status distinguishes pending, connected, validation error, and disabled. Disabling blocks new scans while retaining account history. Connection validation confirms AssumeRole and AWS account identity, not the full IAM permission policy. Last scan time and per-region asset counts are derived from scan jobs and normalized inventory.
- **Bootstrap:** Because Phase 02 locks every role to an explicit organization membership and forbids cross-tenant bypass, first-organization creation uses a trusted, interactive operator command. Public organization creation/listing across tenants is prohibited. Organization APIs operate only on the caller's active organization.
- **Expected areas:** `backend/app/organizations/`, `users/`, `teams/`, and `cloud_accounts/`; core models and an Alembic migration; AWS adapter limited to account connection validation; APIs, backend tests, and targeted architecture updates.
- **Security:** invitation secrets are one-time and digest-only at rest; user/password values and AWS temporary credentials are never logged or returned; role assignment is deny-by-default; all operations preserve membership and tenant scope; AssumeRole uses a generated ExternalId and temporary credentials only.
- **Prohibited:** scan jobs, resource collectors, inventory/discovery, security rules, findings, risk, compliance, frontend, audit subsystem, and any Azure/GCP integration.
- **Completion:** tenant-scoped org/user/team/account workflows work; invitation and authorization paths have direct tests; AWS account validation checks STS identity against the configured account without persisting temporary credentials; no Phase 04+ work exists.

## Phase 04 gate detail

- **In scope:** tenant-scoped asynchronous scan jobs and progress; AWS STS AssumeRole and SDK collection using registered read-only roles; enabled-region/resource-type scope; provider-neutral asset normalization and inventory; inventory relationships supported by collected identifiers.
- **Expected areas:** `backend/app/scan_jobs/`, `backend/app/assets/`, database models and forward migration, API contracts/routes, Celery worker task registration, `scanner-engine/` AWS provider/collector/normalizer packages, and targeted project/security docs.
- **Scan boundary:** accept work asynchronously, persist observable job state/progress, carry scan and tenant identity in worker context, apply configured enabled regions, and make processing safe against duplicate delivery/cancellation. Do not expose raw SDK responses as API resources.
- **Collection boundary:** AWS collectors retrieve inventory/configuration data and normalize it into assets. Use AssumeRole temporary credentials only in memory. Never collect access keys, secret material, Lambda environment variables, or other credentials. Sanitize provider failures before persistence/logging.
- **Authorization:** add explicit backend permissions for scan read/create/cancel; validate account, regions, and asset filters against the caller's active organization. Workers revalidate job/account/organization ownership and initiator membership.
- **Prohibited:** policy/rule evaluation, AWS security rules, findings or lifecycle, risk, compliance, evidence, remediation, frontend, and Azure/GCP integrations.
- **Completion:** tenant-scoped scan lifecycle and inventory contracts are implemented; worker processing and AWS collection paths have direct tests; duplicate delivery and tenant isolation are addressed; later work stays within its separate subsystem boundary.

## Phase 05 gate detail

- **In scope:** structured, versioned policy-as-code; a safe generic condition evaluator; AWS rules against collected normalized fields; tenant-scoped finding creation and canonical lifecycle; assignment and reason/approver/expiration-backed suppression.
- **Expected areas:** policy-engine, backend findings, finding models/migration/API, worker handoff, and targeted policy/security docs.
- **Security:** never use dynamic code evaluation; validate rule shape/severity/resource types; keep evidence free of credentials; enforce current backend permissions and tenant scope; record lifecycle changes.
- **Prohibited:** risk scoring, compliance assessment, evidence subsystem, frontend, remediation execution, reports, notifications, global audit, and Phase 07+ work.
- **Completion:** rules are versioned data evaluated by a bounded interpreter; finding transitions, assignment, suppression, and tenant isolation have direct tests; no Phase 06+ work exists.

## Phase 06 gate detail

- **In scope:** documented normalized risk calculation and finding/asset/account/organization aggregation; CIS AWS Foundations control mapping and assessment; redacted scan-linked evidence; finding investigation and verification context.
- **Expected areas:** backend risk and compliance modules, evidence/finding schemas and APIs, risk/evidence/compliance models and migration, and architecture/security docs.
- **Security:** evidence contains only selected normalized configuration and matched condition; tenant scope applies to every read; CIS AWS Foundations 7.1.0 is identified, while the project's control mapping remains unverified and inactive until validated; risk outputs remain explainable by stored factors.
- **Prohibited:** frontend, remediation execution, reports, notifications, global audit subsystem, and Phase 07+ work.
- **Completion:** scoring boundaries and aggregation semantics are documented; compliance pass/fail is tied to per-asset rule assessments; evidence can be traced to scan/rule versions; direct tests cover isolation and scoring; no Phase 07+ work exists.

## Phase 07–08 implementation batch

The user explicitly authorized both phases in order. Phase 07 owns the React/TypeScript console, cookie-backed auth experience, live API clients, navigation, and role-aware dashboard/cloud/assets/findings/policy/risk/compliance/admin views. Phase 08 owns human-controlled remediation requests and approval records, report snapshots/exports, in-app notifications, and tenant-scoped audit events. Phase boundaries remain distinct: Phase 07 consumes Phase 01–06 APIs; Phase 08 adds operational workflows consumed by the console.

### Phase 07 gate detail

- **In scope:** React, TypeScript, Vite, Tailwind, TanStack Query, React Router, authenticated API client; responsive navigation and global organization context; dashboard, cloud account/scan, asset, finding/investigation, policy, risk, compliance, and administration screens.
- **Security:** bearer tokens are held in memory only; refresh credentials stay in HttpOnly cookies and refresh/logout use the established CSRF header; every view calls tenant-scoped authorized APIs; frontend permission checks only tailor UX. No local fake product data.
- **Prohibited:** IaC/container security, deployment pipelines, production infrastructure, and Phase 09+ work.
- **Completion:** production build/typecheck and frontend lint succeed; primary screens use backend contracts; responsive layout and accessible loading/error/empty states are present.

### Phase 08 gate detail

- **In scope:** recommendation-linked remediation requests and separate approval/rejection decisions; report snapshots for posture/findings/compliance/risk/accounts with PDF/CSV/JSON export; user-scoped in-app notifications; organization-scoped audit history for sensitive actions.
- **Security:** requester cannot decide their own remediation request; approval never executes cloud changes; all records and exports are tenant scoped and permission checked; CSV formula-like cells are escaped; audit payloads exclude secrets.
- **Prohibited:** destructive remediation execution, outbound email/Slack/Teams integrations, advanced security domains, production deployment, and Phase 09+ work.
- **Completion:** workflows record action, actor, reason/state and time; reports are bounded and tenant-safe; actions are visible to authorized users; migration and API response boundaries are reviewed.

PDF reports currently use a dependency-free text renderer over immutable snapshots capped at 500 rows. Maximum output bytes, page-layout requirements, and production document requirements remain **UNRESOLVED**.

## Phase 09–10 implementation batch

The user explicitly authorized Phase 09 followed by Phase 10. The security pipeline is applied to CloudSentinel's own source and deployment artifacts. Customer IaC/container scans are a separate, explicitly enabled product workflow with an isolated Fargate sandbox and tenant-owned results.

### Phase 09 gate detail

- **Implemented:** Bandit, pip-audit, Semgrep, and Trivy CI checks; source/configuration and backend/frontend image scans; browser smoke and PostgreSQL/Redis migration jobs; per-user TOTP MFA with one-time recovery codes.
- **Implemented:** tenant-owned customer assessment API, supported IaC/source and OCI image TAR inputs, isolated Fargate execution without task role or public IP, bounded execution and quotas, short-lived artifacts/results, cancellation, and paginated tenant findings. SAML SSO and SCIM 2.0 Users/Groups provisioning are implemented with safe role mappings and per-tenant credentials.
- **Required before full gate closure:** configure and verify a real customer IdP, refresh offline scanner databases on a documented cadence, and run dedicated security checks for SSRF, upload limits, rate limits, and OWASP behavior.
- **Prohibited:** adding Azure/GCP collectors, destructive remediation, or making CI scanner findings customer security findings without a product contract.

### Phase 10 gate detail

- **Implemented:** AWS EKS Terraform and production overlay; multi-AZ managed PostgreSQL/Redis; encrypted/versioned report bucket; secrets integration; workload Pod Identity; ingress/TLS/WAF; egress network policy; backups; CloudWatch logs/metrics/queue alarms; transactional outbox with retry/reconciliation; protected digest-based release with SBOM/provenance attestations.
- **Implemented:** optional OpenTelemetry tracing to AWS X-Ray, IdP MFA policy enforcement, audit/report/scan retention and tenant offboarding, optional warm cross-region EKS/RDS/Redis/S3/ECR recovery resources, and guarded RDS restore and staging rollback drill scripts.
- **Required before full gate closure:** supply the account-specific VPC/subnets/firewall, OIDC subjects, state bucket, certificates, WAF, SNS topic, secrets and private runner; review a saved plan; then provision from an approved platform runner. Configure the customer IdP, verify the CIS control mapping, and run restore/failover/rollback drills to measure the initial RPO 5-minute/RTO 4-hour objectives. No Terraform apply or deployment was performed in this workspace.
- **Production acceptance remains open:** the system is not production-verified. Cross-region RDS replication is asynchronous and S3 replication has a 15-minute RTC threshold, so the five-minute RPO is not a complete-service guarantee. SAML/SCIM and tracing have code foundations, but external IdP integration and trace export have not been verified in a deployed environment.
- **Multi-cloud boundary:** AWS remains the only integrated provider. Azure/GCP adapter contracts and services remain future work; preserve the shared normalized asset boundary and do not claim provider support.
- **State:** AWS EKS topology is selected and its deployment foundation is checked in. Customer IaC/container assessment, enterprise identity, retention/offboarding, tracing, and optional DR foundations are implemented in code. External account setup, customer IdP verification, control-map validation, and recovery evidence remain open; these artifacts do not represent a deployed or production-verified service.
