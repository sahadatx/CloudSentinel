# CloudSentinel
## Enterprise Cloud Security Posture Management, Assessment & Risk Intelligence Platform

**Specification Version:** 1.0  
**Status:** LOCKED  
**Implementation Strategy:** Backend-First, Phase-Gated  
**Initial Cloud Provider:** AWS  
**Future Providers:** Azure, GCP

---

# 1. Project Identity

CloudSentinel is an enterprise-grade cloud security platform designed to provide:

- Cloud Security Posture Management (CSPM)
- Cloud Security Assessment
- Cloud Asset Inventory
- Security Policy Evaluation
- Security Findings Management
- Risk Intelligence
- Compliance Assessment
- Security Evidence Collection
- Remediation Guidance
- Security Reporting
- Auditability
- Multi-tenant Cloud Security Operations

CloudSentinel is intended to operate as an enterprise security operations platform rather than a simple cloud configuration scanner.

The primary design principle is:

> Less decoration. More security intelligence.

---

# 2. Product Vision

CloudSentinel should enable security teams to answer:

1. What cloud resources exist?
2. Which resources are exposed?
3. Which security controls are failing?
4. Why is a resource considered insecure?
5. What evidence proves the issue?
6. How severe is the issue?
7. What business impact could result?
8. Which compliance controls are affected?
9. How should the issue be remediated?
10. Was the remediation successful?
11. Who performed the action?
12. What changed over time?

The platform must prioritize investigation, evidence, risk, and actionable security intelligence.

---

# 3. Core Security Workflow

The primary security workflow is:

    Cloud Accounts
          |
          v
    Asset Discovery
          |
          v
    Security Assessment
          |
    +-----+------+------+
    |     |      |      |
   IAM  Network Storage Compute
    |     |      |      |
    +-----+------+------+
          |
          v
    Policy Engine
          |
          v
    Findings Engine
          |
          v
    Risk Intelligence
          |
    +-----+---------+
    |       |       |
 Dashboard Reports Remediation

The investigation workflow is:

    Finding
       |
       v
    Evidence
       |
       v
    Risk
       |
       v
    Impact
       |
       v
    Remediation
       |
       v
    Verification

This workflow is authoritative for the product UX.

---

# 4. Product Principles

CloudSentinel MUST follow these principles:

## 4.1 Security First

Security decisions must prioritize:

- least privilege
- defense in depth
- secure defaults
- credential protection
- tenant isolation
- authorization
- auditability
- evidence integrity

## 4.2 Enterprise First

The architecture must support:

- organizations
- users
- teams
- RBAC
- tenant isolation
- cloud accounts
- audit logs
- scalable scanning
- reporting
- compliance
- enterprise workflows

## 4.3 Backend First

Every feature follows:

    API Contract
        ->
    Database
        ->
    Backend Service
        ->
    Backend API
        ->
    Frontend API Client
        ->
    UI
        ->
    Tests

Frontend code must not be built against imaginary production APIs.

## 4.4 Evidence Driven

Every security finding should be supported by evidence whenever technically possible.

## 4.5 Human Controlled Remediation

CloudSentinel MUST NOT initially perform destructive automatic remediation.

Initial remediation is recommendation-based.

Future automated remediation requires explicit approval and verification workflows.

## 4.6 Modular Architecture

Provider integrations, scanners, rules, compliance mappings, reporting, and remediation must remain modular.

---

# 5. High-Level Architecture

The platform consists of:

    CloudSentinel
    |
    +-- Backend API
    |
    +-- Authentication & Authorization
    |
    +-- Organization Management
    |
    +-- Cloud Account Management
    |
    +-- Asset Inventory
    |
    +-- Scan Job System
    |
    +-- Scanner Engine
    |
    +-- Policy Engine
    |
    +-- Findings Engine
    |
    +-- Risk Engine
    |
    +-- Compliance Engine
    |
    +-- Evidence System
    |
    +-- Remediation System
    |
    +-- Reporting
    |
    +-- Notifications
    |
    +-- Audit
    |
    +-- Dashboard
    |
    +-- Frontend

---

# 6. Repository Architecture

The repository MUST follow this high-level structure:

    CloudSentinel/
    |
    +-- backend/
    |   +-- app/
    |   |   +-- api/
    |   |   +-- core/
    |   |   +-- auth/
    |   |   +-- organizations/
    |   |   +-- users/
    |   |   +-- teams/
    |   |   +-- cloud_accounts/
    |   |   +-- assets/
    |   |   +-- inventory/
    |   |   +-- policies/
    |   |   +-- scanners/
    |   |   +-- findings/
    |   |   +-- risk/
    |   |   +-- compliance/
    |   |   +-- remediation/
    |   |   +-- reports/
    |   |   +-- notifications/
    |   |   +-- audit/
    |   |   +-- dashboard/
    |   |
    |   +-- migrations/
    |   +-- tests/
    |
    +-- frontend/
    |   +-- cloudsentinel-ui/
    |
    +-- scanner-engine/
    |   +-- providers/
    |   |   +-- aws/
    |   +-- discovery/
    |   +-- collectors/
    |   +-- normalizers/
    |   +-- rules/
    |   +-- analyzers/
    |   +-- evidence/
    |   +-- workers/
    |
    +-- policy-engine/
    |
    +-- reporting-engine/
    |
    +-- infrastructure/
    |   +-- docker/
    |   +-- kubernetes/
    |   +-- terraform/
    |
    +-- docs/
    |
    +-- tests/
    |
    +-- .github/
    |   +-- workflows/
    |
    +-- docker-compose.yml
    +-- Makefile
    +-- pyproject.toml
    +-- README.md
    +-- SECURITY.md
    +-- LICENSE

---

# 7. Technology Stack

## Backend

- Python
- FastAPI
- PostgreSQL
- SQLAlchemy
- Alembic
- Pydantic
- Redis
- Celery
- Boto3

## Search

- OpenSearch

## Object Storage

- S3
- MinIO for local/development environments where appropriate

## Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- TanStack Query
- React Router
- Recharts

## Quality and Security Tooling

The project should support:

- Ruff
- MyPy
- Pytest
- Bandit
- pip-audit
- Semgrep
- Trivy

---

# 8. Multi-Tenancy

CloudSentinel MUST be multi-tenant.

The logical organization hierarchy is:

    Organization
       |
       +-- Users
       |
       +-- Teams
       |
       +-- Cloud Accounts
       |
       +-- Projects
       |
       +-- Policies
       |
       +-- Findings
       |
       +-- Reports
       |
       +-- Audit Records

Tenant-owned resources MUST be isolated by organization.

A user belonging to Organization A must never access Organization B resources through:

- manipulated IDs
- query parameters
- route parameters
- request bodies
- filters
- exports
- search
- background jobs
- direct object references

Tenant isolation MUST be enforced on the backend.

Frontend filtering is not a security boundary.

---

# 9. Roles

CloudSentinel initially defines exactly these roles:

1. SUPER_ADMIN
2. ORG_ADMIN
3. SECURITY_ADMIN
4. SECURITY_ANALYST
5. CLOUD_ENGINEER
6. AUDITOR
7. VIEWER

The role model may later be extended only through an explicit architecture change.

---

# 10. Permissions

The permission system should be granular.

Initial permission examples include:

    cloud_accounts:read
    cloud_accounts:create
    cloud_accounts:update
    cloud_accounts:delete

    assets:read
    assets:export

    findings:read
    findings:update
    findings:assign
    findings:suppress

    policies:read
    policies:create
    policies:update

    reports:read
    reports:create
    reports:export

    remediation:read
    remediation:execute

    audit:read

Organization and identity-management permissions used by Phase 03 include:

    organizations:read
    organizations:update

    users:read
    users:invite
    users:update
    users:disable

    teams:read
    teams:create
    teams:update
    teams:delete

Backend authorization is mandatory.

Frontend permission checks are only a UX convenience and MUST NOT replace backend authorization.

---

# 11. Authentication

Authentication must be designed for enterprise security.

The system should support:

- secure login
- secure logout
- current-user retrieval
- password security where applicable
- session management
- token/session expiration
- authorization middleware
- secure credential handling

Authentication architecture must not expose credentials or sensitive tokens.

The current enterprise identity implementation includes tenant-configured SAML
single sign-on, optional IdP MFA enforcement, and SCIM 2.0 Users/Groups
provisioning with administrator-mapped roles. These capabilities require
customer IdP configuration and verification before SSO enforcement. OIDC
federation remains future work.


---

# 12. AWS Integration

AWS is the initial cloud provider.

CloudSentinel should prefer:

    CloudSentinel
          |
          v
    AWS STS AssumeRole
          |
          v
    Read-only Security Role
          |
          v
    AWS Account

Permanent AWS access keys MUST NOT be the default integration mechanism.

The system should support:

- AWS account registration
- role ARN configuration
- AssumeRole validation
- STS identity validation
- account metadata
- enabled regions
- region discovery
- connection health
- connection status
- credential rotation metadata
- disconnect/de-registration

CloudSentinel must never expose AWS credentials to frontend code.

---

# 13. AWS Account Model

An organization may have multiple AWS accounts.

The platform must support:

- multiple AWS accounts
- multiple regions
- account metadata
- account health
- scan status
- asset counts
- finding counts
- critical finding counts
- security score

Future AWS Organizations support may be added without changing the core multi-tenant model.

---

# 14. Asset Inventory

CloudSentinel must maintain a normalized cloud asset inventory.

Initial AWS resource types include:

- EC2
- S3
- IAM
- VPC
- Security Groups
- RDS
- Lambda
- EBS
- CloudTrail
- CloudWatch
- KMS
- ECR
- ECS
- EKS

Asset fields should include:

- asset ID
- provider
- account
- region
- resource type
- ARN
- tags
- owner metadata where available
- first seen
- last seen
- risk score
- compliance status

The asset model should be provider-neutral so Azure and GCP can be added later.

---

# 15. Security Domains

CloudSentinel security assessment should cover:

- IAM
- Network
- Storage
- Compute
- Database
- Encryption
- Logging
- Monitoring
- Secrets
- Containers
- Serverless
- Kubernetes
- Configuration

---

# 16. Scanner Architecture

Scanner architecture MUST remain modular.

The initial pipeline is:

    Cloud Account
         |
         v
    Provider Collector
         |
         v
    Raw Cloud Data
         |
         v
    Normalizer
         |
         v
    Normalized Asset
         |
         v
    Policy / Rule Engine
         |
         v
    Evidence
         |
         v
    Finding

The scanner engine should not contain business-domain database logic unnecessarily.

---

# 17. Scanner Phase Separation

The scanner implementation MUST remain separated by phase.

## Phase 04 — AWS Discovery, Asset Inventory & Scan Engine

This phase owns asynchronous scan jobs, AWS provider SDK/API collection, asset discovery, normalization, and inventory. Preserve the boundary between provider collection and normalized asset handling within the phase. It must not implement the policy engine or AWS security rules.

## Phase 05 — Policy Engine, Security Rules & Findings Engine

This phase owns the generic policy/rule engine, AWS security rules, and finding lifecycle. Rules are evaluated against normalized data. Preserve the boundary between generic policy evaluation and AWS-specific detections within the phase.

These subsystem boundaries MUST be preserved even though work is grouped into larger roadmap phases.

---

# 18. Policy-as-Code

Security rules should be represented as structured policies.

A rule should support:

- Rule ID
- Name
- Description
- Severity
- Category
- Detection Logic
- Evidence Logic
- Remediation Guidance
- Framework Mapping
- Version

Example:

    AWS-S3-001

Name:

    S3 Public Access

Severity:

    CRITICAL

Detection may include:

- public access block disabled
- public bucket policy
- public ACL exposure

Recommended remediation:

    Enable S3 Block Public Access
    and remove unnecessary public access.

Rules must be versioned.

---

# 19. Findings

Findings represent detected security issues.

A finding should contain:

- finding ID
- rule ID
- title
- description
- severity
- status
- risk score
- organization
- cloud account
- region
- asset
- evidence
- remediation
- compliance mappings
- timestamps
- assignment
- activity history

---

# 20. Finding Lifecycle

The canonical lifecycle is:

    OPEN
      |
      v
    TRIAGED
      |
      v
    ASSIGNED
      |
      v
    IN_PROGRESS
      |
      v
    RESOLVED
      |
      v
    VERIFIED
      |
      v
    CLOSED

Alternative:

    OPEN
      |
      v
    SUPPRESSED

Suppression requires:

- reason
- approver
- expiration
- audit record

---

# 21. Evidence

Security findings should be evidence-driven.

Evidence may include:

- resource identifier
- resource ARN
- configuration metadata
- detected condition
- timestamp
- scanner version
- rule version
- AWS account
- AWS region
- relevant API response metadata
- configuration snapshot where appropriate

Sensitive credentials and secrets MUST NOT be stored as evidence.

Evidence must support investigation and verification.

---

# 22. Risk Engine

CloudSentinel uses a normalized risk model.

Conceptually:

    Risk Score =
        Severity
        + Exploitability
        + Exposure
        + Asset Criticality
        + Business Impact
        + Compliance Impact

The implementation may normalize these factors to a 0–100 score.

Risk levels:

    0–19    Informational
    20–39   Low
    40–59   Medium
    60–79   High
    80–100  Critical

Risk should be available at:

- finding level
- asset level
- cloud account level
- organization level
- overall cloud security level

The exact mathematical implementation must be documented before implementation.

---

# 23. Compliance

Initial compliance framework:

    CIS AWS Foundations

Future frameworks:

- NIST CSF
- NIST SP 800-53
- ISO 27001
- PCI DSS
- SOC 2

Mapping model:

    Security Rule
          |
          v
    Compliance Control
          |
          v
    Framework

A compliance failure should be traceable to affected findings/resources/evidence.

---

# 24. Remediation

Initial remediation is recommendation-based.

A finding should provide:

    Finding
       |
       v
    Recommended Fix
       |
       +-- Terraform
       |
       +-- AWS CLI
       |
       +-- AWS Console

Initial implementation MUST NOT automatically execute destructive changes.

Future remediation workflow:

    Approval
       |
       v
    Remediation Job
       |
       v
    Execution
       |
       v
    Verification
       |
       v
    Audit

---

# 25. Scan Architecture

Scanning must be asynchronous.

Canonical flow:

    User
      |
      v
    POST /scans
      |
      v
    API
      |
      v
    Redis Queue
      |
      v
    Worker
      |
      v
    Cloud Scanner
      |
      v
    Findings
      |
      v
    Database
      |
      v
    Notification

Frontend should expose scan progress.

---

# 26. Scan Scope

A scan should support selection of:

- cloud account
- region
- asset scope
- security domains
- policy/rule scope where applicable

Scan execution should be observable.

---

# 27. Reporting

Reporting should support:

- security posture reports
- finding reports
- compliance reports
- risk reports
- cloud account reports

Reports should respect tenant boundaries and RBAC.

Export capabilities must enforce authorization.

---

# 28. Audit

CloudSentinel must maintain enterprise auditability.

Audit events should record important security-sensitive actions such as:

- authentication events
- authorization-sensitive actions
- cloud account changes
- finding changes
- policy changes
- remediation actions
- user/role changes
- suppression
- exports
- administrative actions

Audit records must be tenant-aware.

Audit data must not expose secrets.

---

# 29. Frontend Philosophy

CloudSentinel frontend is:

> Dark-first + clean enterprise + high information density + security-focused + minimal decoration.

It is an:

> Enterprise Security Operations Console

It is NOT a decorative dashboard.

Principle:

> Less decoration. More security intelligence.

---

# 30. UI Color System

Base colors:

    Background: #0B0F14
    Surface:    #111820
    Card:       #151D26
    Border:     #26313D

Text:

    Primary:    #F3F4F6
    Secondary:  #9CA3AF
    Muted:      #667085

Semantic severity colors:

- Critical: red
- High: orange
- Medium: yellow
- Low: blue/neutral
- Success: green

Colors must communicate meaning rather than decoration.

---

# 31. Navigation

The primary navigation is locked:

    CLOUDSENTINEL

    OVERVIEW
      Dashboard

    CLOUD
      Cloud Accounts
      Assets

    SECURITY
      Findings
      Policies
      Risk
      Compliance

    OPERATIONS
      Remediation
      Reports
      Alerts

    GOVERNANCE
      Audit Logs

    ADMINISTRATION
      Administration

---

# 32. Global Context

The global header should keep security context visible:

    Organization: Acme Corp
    Environment: Production
    Region: Global

This is intended to reduce operator mistakes.

Users should always understand which environment they are viewing or modifying.

---

# 33. Dashboard

Dashboard must answer:

- How secure is the environment?
- What needs attention?
- Where is the highest risk?

Dashboard structure:

## Row 1

- Security Score
- Cloud Accounts
- Assets
- Open Findings

## Row 2

- Security Posture Trend
- Risk Distribution

## Row 3

- Critical Findings
- Top Risky Assets
- Recent Activity

Security Score should provide breakdowns such as:

- IAM
- Network
- Storage
- Encryption
- Logging
- Compliance

Dashboard must use real backend data.

Production UI must not rely on fake hardcoded metrics.

---

# 34. Findings UI

Findings should use a dense SOC-style table.

Required capabilities:

- search
- severity filter
- status filter
- account filter
- region filter
- category filter
- assigned-user filter
- pagination
- saved views where appropriate
- column customization
- bulk actions where safe

Avoid giant decorative finding cards.

---

# 35. Finding Details

Finding details should show:

- finding ID
- title
- severity
- status
- risk score
- asset
- account
- region
- asset type
- why it matters
- evidence
- compliance mappings
- remediation
- activity

Investigation flow:

    Finding
      |
      Evidence
      |
      Risk
      |
      Impact
      |
      Remediation
      |
      Verification

---

# 36. Asset Details

Asset details should support:

- overview
- configuration
- security
- relationships
- findings
- activity
- evidence

Asset relationship visualization may be used where it improves investigation.

---

# 37. Cloud Account UI

Cloud Account UI should expose:

- connection status
- security score
- asset count
- finding count
- critical finding count
- regions
- scan action
- account metadata
- health

---

# 38. Compliance UI

Compliance UI should show:

- framework
- overall score
- passed controls
- failed controls
- not assessed controls
- control table

A failed control should link to:

- affected resources
- findings
- evidence

---

# 39. Remediation UI

Remediation UI should show:

- recommended action
- risk
- change preview
- execution method
- approval requirement
- execution state
- verification state

Future workflow:

    Requested
       |
       v
    Approved
       |
       v
    Executing
       |
       v
    Verified
       |
       v
    Completed

---

# 40. Global Search

Global search should cover:

- Assets
- Findings
- Cloud Accounts
- Policies
- Users
- Reports

Search results must respect tenant boundaries and authorization.

---

# 41. Responsive Design

Desktop:

- persistent sidebar
- dense main content

Tablet:

- collapsed sidebar

Mobile:

- top navigation
- slide navigation
- stacked content
- horizontally scrollable dense tables or responsive card representations

Responsive behavior must preserve usability and security context.

---

# 42. Enterprise UX

The UI should support where appropriate:

- saved views
- bulk actions
- column customization
- date filters
- pagination
- role-aware actions
- breadcrumbs
- loading states
- empty states
- error states
- confirmation dialogs
- keyboard navigation

---

# 43. UI Anti-Patterns

Avoid:

- excessive gradients
- giant rounded cards
- excessive animation
- ubiquitous glassmorphism
- unnecessary charts
- rainbow colors
- oversized headings
- decorative graphics
- excessive whitespace that hides security data

Prefer:

- dense tables
- strong hierarchy
- semantic indicators
- clear evidence
- clear actions
- readable data

---

# 44. Frontend Architecture

Frontend structure:

    frontend/cloudsentinel-ui/src/
    |
    +-- app/
    +-- components/
    +-- layouts/
    +-- pages/
    |   +-- dashboard/
    |   +-- cloud-accounts/
    |   +-- assets/
    |   +-- findings/
    |   +-- policies/
    |   +-- risk/
    |   +-- compliance/
    |   +-- remediation/
    |   +-- reports/
    |   +-- alerts/
    |   +-- audit/
    |   +-- administration/
    |
    +-- features/
    +-- hooks/
    +-- services/
    +-- stores/
    +-- types/
    +-- utils/
    +-- routes/

---

# 45. IaC Security

Future IaC security capabilities should include:

- Terraform
- CloudFormation
- Dockerfile
- Kubernetes YAML
- Helm

These should reuse the policy/rule architecture where possible.

---

# 46. Container Security

Future container security should cover:

- Docker
- ECR
- ECS
- EKS
- Kubernetes

Example checks:

- privileged containers
- root containers
- dangerous capabilities
- exposed ports
- insecure configuration
- embedded secrets
- host networking
- host filesystem mounts

---

# 47. Kubernetes Security

Future Kubernetes security should assess:

- RBAC
- pod security
- privileged workloads
- host access
- secrets
- network policies
- exposed services
- dangerous capabilities
- insecure workloads
- configuration issues

---

# 48. Future Multi-Cloud Architecture

AWS is the first provider.

Azure and GCP are future providers.

The core domain model should be provider-neutral.

Future architecture:

    Provider Adapter
          |
          v
    Normalized Asset Model
          |
          v
    Common Policy Engine
          |
          v
    Common Findings Model
          |
          v
    Common Risk Model
          |
          v
    Common Compliance Model

Adding Azure or GCP must not require rewriting the entire platform.

---

# 49. API Design

API conventions must prioritize:

- predictable resource naming
- versioning
- validation
- pagination
- filtering
- authorization
- tenant isolation
- consistent errors
- idempotency where applicable
- auditability

The API should use explicit contracts.

Business logic should not be placed directly in route handlers when a service layer is appropriate.

---

# 50. Database Principles

PostgreSQL is the primary relational database.

Database architecture should support:

- UUID identifiers where appropriate
- timestamps
- organization ownership
- indexes
- foreign keys
- uniqueness constraints
- soft deletion where justified
- auditability
- migration safety

Tenant-owned tables must have an organization/tenant ownership path.

Indexes must support common:

- organization queries
- account queries
- finding queries
- asset queries
- time-based queries

---

# 51. Background Jobs

Long-running tasks should use asynchronous workers.

Candidate tasks include:

- cloud scans
- asset discovery
- policy evaluation
- report generation
- notification delivery
- evidence processing
- future remediation jobs

Workers must enforce tenant context and authorization boundaries.

---

# 52. Error Handling

The backend should provide consistent errors.

Errors should not reveal:

- secrets
- credentials
- internal sensitive infrastructure
- unnecessary stack traces
- database internals

Internal logs may contain diagnostic information only when safe.

---

# 53. Logging

Application logging must be structured where practical.

Never log:

- passwords
- API keys
- AWS secret keys
- access tokens
- session secrets
- private credentials

Security-sensitive actions should be auditable.

---

# 54. Secrets Management

Secrets must never be committed to Git.

Development may use environment variables or secure local configuration.

Production should use an appropriate secret-management mechanism.

Example environment files must contain placeholders only.

---

# 55. Security Testing

Security testing must cover:

- authentication
- authorization
- RBAC
- IDOR
- tenant isolation
- SSRF
- secret exposure
- dependency vulnerabilities
- container vulnerabilities
- rate limiting
- OWASP risks

Security tests are mandatory for security-sensitive features.

---

# 56. Testing Strategy

The project should have:

- unit tests
- integration tests
- API tests
- authorization tests
- tenant-isolation tests
- scanner tests
- policy tests
- findings tests
- risk tests
- compliance tests
- frontend tests where appropriate
- security tests

Target:

> 90%+ meaningful backend coverage

Coverage percentage alone is not sufficient; security-critical paths require direct tests.

---

# 57. CI/CD

CI should eventually include:

- Ruff
- MyPy
- Pytest
- Bandit
- pip-audit
- Semgrep
- Trivy
- Docker build

CI should fail on critical security or quality violations according to project policy.

---

# 58. Development Environment

Docker Compose may be used for local development.

Development services may include:

- PostgreSQL
- Redis
- OpenSearch
- MinIO where needed
- backend
- worker

Production infrastructure must be designed separately.

---

# 59. Production Architecture

Production deployment should support:

- containerized services
- secure configuration
- scalable workers
- managed database where appropriate
- secure object storage
- observability
- health checks
- readiness checks
- horizontal scaling where appropriate

Kubernetes deployment may be introduced in the infrastructure phase.

---

# 60. Phase Roadmap

The locked implementation roadmap has ten sequential phases. This roadmap supersedes the earlier 34-phase breakdown. Phases 01–08 are complete. The current authorized work covers Phases 09 and 10 in dependency order. Phase gates and remaining deployment/product decisions are tracked in `docs/architecture/PHASE_GATES.md`.

| Phase | Scope |
|---|---|
| 01 | Architecture, Repository & Development Foundation — completed |
| 02 | Database, Authentication, RBAC & Multi-Tenancy |
| 03 | Organization, User & AWS Cloud Account Management — completed |
| 04 | AWS Discovery, Asset Inventory & Scan Engine — completed |
| 05 | Policy Engine, Security Rules & Findings Engine — completed |
| 06 | Risk, Compliance, Evidence & Investigation — completed |
| 07 | Frontend Security Operations Console — completed |
| 08 | Remediation, Reports, Notifications & Audit — completed |
| 09 | Advanced Cloud Security & Security QA — SAML/SCIM, isolated IaC/container assessment, and security pipeline foundations implemented; IdP and scanner lifecycle verification remain open |
| 10 | CI/CD, Production Deployment & Multi-Cloud Readiness — AWS EKS and optional cross-region foundations implemented; deployment, CIS control mapping, restore drills, and RPO/RTO evidence remain open |

The repository now identifies CIS AWS Foundations 7.1.0, but its control mapping
is unverified and inactive. The optional AWS recovery topology is not deployed;
RPO 5 minutes and RTO 4 hours remain planning targets until database, object,
application rollback, and full failover drills record measured evidence. See
[`docs/ENTERPRISE_READINESS.md`](docs/ENTERPRISE_READINESS.md) for implementation
scope and account-specific prerequisites.

Phase 02 includes PostgreSQL, SQLAlchemy, Alembic, database architecture, authentication/session security, RBAC/permissions, and multi-tenancy foundation and isolation. Phase 03 owns organization/user/team and AWS account management workflows. Phases 04–06 are implemented in dependency order within the requested batch; later phases retain their own listed domains, and grouping does not remove subsystem boundaries.

---

# 61. Phase Discipline

Only one phase may be implemented at a time.

For every phase:

    Specification
        |
        v
    Implementation
        |
        v
    Tests
        |
        v
    Review
        |
        v
    Security Review
        |
        v
    Commit
        |
        v
    Phase Gate
        |
        v
    Next Phase

A phase must not silently implement functionality belonging to future phases.

---

# 62. Phase Gates

Every phase must define:

- scope
- files/modules expected to change
- API contracts
- database changes
- tests
- security considerations
- acceptance criteria
- prohibited future-scope work

The phase is complete only when its gate passes.

---

# 63. Implementation Order

Backend implementation must precede frontend implementation for each business feature.

Example:

    Cloud Accounts Backend
          |
          v
    Cloud Accounts API
          |
          v
    Cloud Accounts Frontend Client
          |
          v
    Cloud Accounts UI
          |
          v
    Tests

The frontend must consume real contracts.

---

# 64. Git Strategy

Recommended branches:

    main

    phase/01-foundation
    phase/02-database-auth-tenancy
    phase/03-organization-users-aws
    phase/04-discovery-inventory-scanning
    phase/05-policy-rules-findings
    phase/06-risk-compliance-evidence
    phase/07-frontend-console
    phase/08-remediation-reports-audit
    phase/09-advanced-security-qa
    phase/10-cicd-production-multicloud
    ...

Each phase should be:

    implement
       |
       v
    test
       |
       v
    review
       |
       v
    commit
       |
       v
    merge

---

# 65. Architecture Change Policy

Locked architecture must not be changed silently.

If implementation reveals a genuine architectural problem:

1. Stop.
2. Explain the problem.
3. Identify affected components.
4. Propose alternatives.
5. Explain security and maintenance impact.
6. Obtain explicit approval.
7. Update architecture documentation.
8. Continue implementation only after approval.

---

# 66. AI/Codex Development Rules

AI coding agents must:

1. Read PROJECT_SPECIFICATION.md first.
2. Read docs/AI_ENGINEERING_RULES.md.
3. Inspect the repository before editing.
4. Implement only the requested phase.
5. Never silently change architecture.
6. Never invent requirements.
7. Never implement future phases.
8. Never delete working code without justification.
9. Never hard-code secrets.
10. Never expose credentials.
11. Enforce backend authorization.
12. Enforce tenant isolation.
13. Write tests for implemented behavior.
14. Run relevant tests.
15. Review changed files.
16. Report unresolved issues.
17. Stop when the requested phase is complete.

---

# 67. Explicit Non-Goals for Initial Release

The initial release MUST NOT prioritize:

- destructive automatic remediation
- arbitrary cloud resource modification
- unrestricted shell execution
- automatic credential collection
- permanent AWS access keys as the default
- unnecessary AI-generated remediation without evidence
- decorative dashboards over security intelligence
- uncontrolled multi-cloud implementation before AWS is stable

---

# 68. Initial Security Priority

The initial product should prioritize:

1. Secure authentication
2. Strong authorization
3. Tenant isolation
4. Secure AWS AssumeRole integration
5. Reliable asset discovery
6. Evidence-driven findings
7. Accurate risk scoring
8. Compliance traceability
9. Secure remediation guidance
10. Auditability

---

# 69. Definition of Done

A feature is not considered complete merely because the UI exists.

A feature is complete when:

- backend contract exists
- validation exists
- authorization exists
- tenant isolation exists
- database behavior is correct
- service logic is tested
- API behavior is tested
- security-sensitive cases are tested
- frontend consumes the real API
- errors are handled
- audit requirements are satisfied where applicable
- documentation is updated
- relevant phase gate passes

---

# 70. Final Product Standard

CloudSentinel must ultimately behave like an enterprise security platform.

The quality standard is:

> Secure by default.
> Multi-tenant by design.
> Evidence-driven.
> Risk-aware.
> Auditable.
> Modular.
> Scalable.
> Operator-focused.

The platform should help security teams move from:

    "Something is misconfigured."

to:

    "This resource is exposed,
     this is why,
     this is the evidence,
     this is the risk,
     this is the business impact,
     this is the recommended remediation,
     and this is how we verify the fix."

That is the core product objective of CloudSentinel.

---

# END OF SPECIFICATION
