# Architectural Decision Register

**Status:** Locked decisions and Phase 02–06 implementation contracts  
**Authority:** `PROJECT_SPECIFICATION.md` is authoritative. Entries summarize its decisions and are not independent amendments.

| ID | Decision | State / rationale |
|---|---|---|
| D-001 | AWS is the initial cloud provider; Azure and GCP are future providers. | **LOCKED** — establish AWS first and preserve provider-neutral domain concepts. |
| D-002 | Prefer AWS STS AssumeRole with a read-only security role; permanent access keys are not the default. | **LOCKED** — avoid long-lived cloud credentials and keep credentials server-side. |
| D-003 | Organization is the tenant boundary for tenant-owned resources. | **LOCKED** — backend-enforced isolation applies to requests, search, exports, and jobs. |
| D-004 | Development proceeds backend-first for each business feature. | **LOCKED** — contracts, data, services, and APIs precede frontend clients and UI. |
| D-005 | Findings are evidence-driven whenever technically possible. | **LOCKED** — evidence supports investigation and verification; secrets are excluded. |
| D-006 | Policies/rules use structured, versioned policy-as-code. | **LOCKED** — common engine and AWS-specific rules remain phase-separated. |
| D-007 | Initial remediation is human-controlled and recommendation-based. | **LOCKED** — destructive automatic remediation is not part of the initial behavior. |
| D-008 | Scanner architecture is modular and responsibility-separated within the merged roadmap. | **LOCKED** — Phase 04 collects and normalizes; Phase 05 evaluates policies, applies AWS rules, and manages findings, while preserving subsystem handoffs. |
| D-009 | PostgreSQL is the primary relational database; SQLAlchemy and Alembic manage schema evolution. | **LOCKED** — Phase 02 implements the identity, RBAC, session, and tenant foundation schema. |
| D-010 | Redis and Celery support asynchronous work. | **LOCKED** — scans and other long-running tasks use workers. |
| D-011 | The operator console is dark-first, enterprise-oriented, dense, security-focused, and minimally decorative. | **LOCKED** — visual details are in [UI Design System](UI_DESIGN_SYSTEM.md). |
| D-012 | The current roadmap has ten sequential phases; the earlier 34-phase breakdown is superseded. | **LOCKED** — Phases 01–08 are complete; Phase 09–10 foundations are implemented, with external production acceptance still open. |
| D-013 | Authentication uses Argon2id passwords, short-lived HS256 JWT access tokens, and opaque rotating refresh tokens backed by revocable sessions. | **LOCKED for Phase 02** — access tokens default to 15 minutes; refresh lifetime defaults to seven days; refresh secrets are stored only as SHA-256 digests. |
| D-014 | Role grants use the least-privilege matrix documented in `RBAC.md`, and every role remains organization-scoped. | **LOCKED for Phase 02** — `SUPER_ADMIN` does not bypass tenant isolation. |
| D-015 | Tenant-owned ORM operations require an authenticated organization context. | **LOCKED for Phase 02** — ORM reads and writes are guarded; raw SQL/Core access requires explicit tenant predicates. |
| D-016 | Organization bootstrap is an interactive trusted-operator action; management APIs remain scoped to the caller's organization. | **LOCKED for Phase 03** — preserves the Phase 02 decision that even `SUPER_ADMIN` does not bypass tenant isolation. |
| D-017 | AWS connection validation uses STS AssumeRole with generated ExternalId and short-lived credentials; credentials remain memory-only. | **LOCKED for Phase 03** — resource collection and inventory remain Phase 04. |
| D-018 | Scans are asynchronous, tenant-bound jobs and collection output is normalized before inventory persistence. | **LOCKED for Phase 04** — queue messages carry job identifiers; workers derive tenant/account scope from persisted records; Phase 05 consumes normalized assets for policy evaluation. |
| D-019 | Risk scoring uses explainable weighted factors and worst-active-finding aggregates. | **IMPLEMENTATION CONTRACT** — severity 30%, exploitability 20%, exposure 15%, asset criticality 15%, business impact 10%, compliance impact 10%; score rounds to an integer on 0–100. Finding scores persist with their factors; asset/account/organization scores are the maximum active finding score in that scope. Verified/closed findings are inactive; suppressions are excluded until expiry. |
| D-020 | CIS control assessment only reports controls represented by verified rule mappings. | **IMPLEMENTATION CONTRACT** — CIS AWS Foundations 7.1.0 is identified and linked to the official source. The project's control mapping remains unverified and inactive, so the product must not imply CIS benchmark coverage. |
| D-021 | Remediation approval is a human decision record and never triggers cloud changes in this phase. | **LOCKED** — a separate active approver records approve/reject; execution is not implemented. |
| D-022 | Phase 08 reports are bounded point-in-time snapshots and notifications are in-app. | **IMPLEMENTATION CONTRACT** — tenant-scoped snapshots are exported as PDF/CSV/JSON, with at most 500 report rows; outbound delivery channels remain deferred. |
| D-023 | PDF reports use the built-in dependency-free text renderer. | **IMPLEMENTATION CONTRACT** — rendering uses immutable snapshots and bounded rows; page layout, maximum output bytes, and production document requirements remain unresolved. HTML export is not exposed. |
| D-024 | AWS EKS is the selected production hosting target; cross-region recovery is optional and AWS-based. | **IMPLEMENTATION CONTRACT** — Terraform defines EKS, managed PostgreSQL/Redis, S3/ECR, Secrets Manager, CloudWatch, tracing, and optional cross-region foundations. Account-specific network, identity, DNS, certificates, secrets, DR promotion, and tested recovery objectives remain unverified. |

## Unresolved items

The product specification does not settle the following implementation details. They remain **UNRESOLVED** until their owning phase defines them without contradicting the locked architecture:

- API version path and exact request, response, pagination, and error schemas.
- Detailed permission scope semantics and approval/audit workflows for sensitive actions.
- Verification and mapping of each CIS AWS Foundations control to a supported CloudSentinel rule.
- Customer IdP metadata, MFA context, SCIM group mapping, and account recovery configuration.
- Account-specific AWS network, DNS, WAF/TLS, GitHub OIDC subjects, secret values, and private deployment runner.
- Scanner image/database refresh cadence and customer-specific retention/legal-hold policy.
- Cross-region failover runbook, deployment verification, and measured RPO/RTO evidence.

No alternative or additional architectural decision is introduced by this register.
