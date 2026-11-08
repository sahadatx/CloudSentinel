# Subsystem Boundaries

**Status:** Phase 00 architecture baseline with Phase 04–08 implementation contracts
**Authority:** `PROJECT_SPECIFICATION.md`

These boundaries describe ownership and handoffs. They do not authorize implementation ahead of the roadmap.

| Subsystem | Owns | Does not own |
|---|---|---|
| Backend API | Versioned transport contracts, validation, request context, authorization enforcement, consistent response/error translation | Domain policy hidden in route handlers, cloud collection, frontend trust decisions |
| Domain/business services | Product workflows and domain operations, coordinating persistence and other services | HTTP transport details, raw provider SDK collection, UI behavior |
| Authentication | Identity/session lifecycle and authentication boundary | Organization resource authorization by itself, AWS credentials |
| Authorization / RBAC | Evaluating role/permission decisions for actions and resources | Authentication, tenant filtering as a substitute for authorization |
| Organization and user management | Organization membership, users, teams, role assignments | Cloud inventory collection or frontend-only isolation |
| Cloud account management | Account registration metadata, role ARN configuration, connection/health lifecycle | Permanent AWS keys as the default or exposing credentials to UI |
| Scan job system | Validating, queuing, tracking, and correlating asynchronous scan work | Scanner-specific collection/detection logic or dropping tenant context |
| Scanner engine | Orchestrating collection-to-assessment pipeline and scanner work | Owning general business-domain persistence unnecessarily |
| AWS provider collectors | Phase 04 AWS API/SDK data collection through the approved role | Full inventory modeling, normalization, policy decisions, findings lifecycle |
| Discovery and normalization | Phase 04 discovery and conversion to provider-neutral assets | Provider authentication/collection or rule evaluation |
| Policy/rule engine | Phase 05 structured, versioned rule representation and evaluation | Conflating generic evaluation with AWS-specific detections or persistence ownership for unrelated domains |
| AWS security rules | Phase 05 AWS-specific detection logic and rule evidence/remediation definitions | Replacing the generic policy engine or collectors |
| Findings | Finding identity, lifecycle, assignment, suppression, activity, and links to context | Re-collecting cloud resources or silently calculating risk/compliance policy |
| Risk | Risk factors and normalized score/level across finding, asset, account, and organization | Replacing severity, evidence, or compliance mapping |
| Compliance | Framework/control mapping and traceability to findings/resources/evidence | Rule collection or changing framework scope without an architecture change |
| Evidence | Security-relevant observations supporting investigation and verification | Secrets/credentials or unsupported conclusions |
| Remediation | Human-readable recommendation and later explicitly gated workflow | Initial destructive automatic changes or arbitrary shell execution |
| Reporting | Report composition and authorized export | Bypassing tenant or RBAC checks |
| Notifications | Delivery of relevant workflow notifications | Becoming the authoritative record for findings/audit |
| Audit | Tenant-aware records of security-sensitive activity | Secrets or credentials, or replacing domain records |
| Frontend | Operator presentation, navigation, search UX, and convenience permission checks | Backend authorization, tenant security, fake production metrics |
| Infrastructure | Runtime/deployment configuration in its designated phase | Application business logic |

## Scanner handoff contract (conceptual)

```text
Cloud account -> provider collector -> raw cloud data -> normalizer
              -> normalized asset -> policy/rule evaluation -> evidence -> finding
```

Responsibility separation is mandatory: Phase 04 collects cloud data and discovers/normalizes assets; Phase 05 implements the policy/rule engine, AWS security rules, and findings. Collection remains distinct from normalization, and generic evaluation remains distinct from provider-specific detections. No subsystem may silently absorb another's ownership.
