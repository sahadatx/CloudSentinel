# CloudSentinel Architecture

**Status:** Architecture baseline with Phase 04–08 implementation contracts
**Authority:** `PROJECT_SPECIFICATION.md` is authoritative. This document explains that specification; it does not override it.

## Product shape

CloudSentinel is an enterprise, multi-tenant cloud security posture and risk intelligence platform. Its primary workflow is cloud account registration, asset discovery, security assessment, policy evaluation, findings, risk and compliance context, evidence-led investigation, and human-directed remediation. AWS is the initial provider. Azure and GCP are future providers.

## System context

```text
Operator / API client
        |
        v
Backend API ---- Authentication / Authorization ---- Organization and account services
        |                                                   |
        | scan request                                     | tenant context
        v                                                   v
Redis queue --> Celery worker --> Scanner engine --> AWS provider collectors
                                     |                      |
                                     v                      v
                               Normalization            AWS STS AssumeRole
                                     |
                                     v
                         Policy/rule evaluation
                                     |
                    Evidence --> Findings --> Risk / Compliance
                                     |
                  PostgreSQL <------+------> Object storage as needed
                                     |
                           Reporting / Notifications / Audit
                                     |
                                     v
                         Versioned backend API
                                     |
                                     v
                          React operator console
```

This is a logical view, not a deployment topology. PostgreSQL is the primary relational store; Redis and Celery support asynchronous work. OpenSearch supports search. S3 is the object-storage direction, with MinIO suitable for development where appropriate. Deployment details belong to later infrastructure phases.

## Subsystems and data flow

- **Backend API:** versioned contracts, validation, authentication and authorization boundaries, tenant-aware request handling, and delegation to domain services. Route handlers should not become the business-service layer.
- **Domain/business services:** own product workflows and persisted domain state, including organizations, users, cloud accounts, inventory, findings, risk, compliance, remediation guidance, reports, notifications, and audit.
- **Scanner engine:** coordinates collection, normalization, policy evaluation, evidence production, and scan work. It should avoid unnecessary business-domain database logic.
- **AWS provider collectors:** obtain raw AWS data through the read-only AssumeRole integration. Collection and Phase 04 discovery/normalization remain separate responsibilities; Phase 05 owns policy evaluation, AWS rules, and findings.
- **Asset normalization:** converts provider data into the provider-neutral asset shape; it is distinct from collection and detection.
- **Policy engine:** evaluates structured, versioned policies against normalized input. Within Phase 05, generic policy evaluation remains distinct from AWS-specific security detections.
- **Findings, risk, compliance, evidence:** findings represent issues; risk contextualizes severity and impact; compliance maps rules to controls/frameworks; evidence substantiates assessment and supports verification. Their records and responsibilities remain distinct while linked by explicit identifiers and relationships.
- **Remediation:** initially provides recommendations (for example Terraform, AWS CLI, or Console guidance). Destructive automatic execution is not part of the initial behavior.
- **Phase 08 operations:** approval-record-only remediation, bounded report snapshots/exports, in-app notifications, and tenant-aware audit records. Approval does not invoke provider APIs.
- **Reporting:** assembles posture, findings, compliance, risk, and account reports subject to tenant and authorization controls.
- **Frontend:** a React/TypeScript operator console that consumes real, documented backend contracts. It does not establish a security boundary.
- **Infrastructure:** hosts development and production services in their applicable phases. Production deployment design is separate from local development and is not established by this logical architecture.

## Asynchronous scan lifecycle

The specified end-to-end scan flow is `POST /scans` → API → Redis queue → worker → cloud scanner → findings → database → notification. In Phase 04, the API accepts a tenant-scoped request and queues work; a worker revalidates organization/account/initiator context, records observable progress, collects AWS inventory, and persists normalized assets and relationships. Long-running scans do not run synchronously inside an API request. The Phase 04 status and response fields are defined in the API conventions; retry, stale-job recovery, queue naming, and delivery guarantees remain unresolved.

## Provider evolution

AWS is the first provider. Provider adapters feed a common normalized asset model and shared policy, findings, risk, and compliance concepts. Azure and GCP are future providers; Phase 10 prepares for multi-cloud after AWS is stable. This direction must not cause premature multi-cloud implementation.

## Architecture constraints

- Preserve the locked repository architecture and scanner phase separation.
- Backend contracts and behavior precede frontend features; frontend code must not target imaginary production APIs.
- Enforce authorization and organization isolation on the backend, including background work and exports/search.
- Keep credentials out of frontend code, logs, evidence, and source control.
- Preserve evidence and auditability; recommendations remain human-controlled.
- Architecture changes follow the approval process in `PROJECT_SPECIFICATION.md` section 65.

## Related documents

See [Boundaries](BOUNDARIES.md), [Security Architecture](SECURITY_ARCHITECTURE.md), [Technology Stack](TECH_STACK.md), and [Phase Gates](PHASE_GATES.md).
