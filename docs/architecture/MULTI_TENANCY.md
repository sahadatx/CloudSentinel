# Multi-Tenancy

**Status:** Phase 02 ORM baseline with Phase 04–06 scan, inventory, finding, risk, compliance, and evidence context.  
**Authority:** `PROJECT_SPECIFICATION.md`, sections 8, 10, 27–28, 40, and 51.

## Organization ownership model

```text
Organization
├── Users (global identities through memberships)
├── Teams
├── Cloud Accounts
├── Projects
├── Policies
├── Findings
├── Reports
└── Audit Records
```

A user identity is global and receives organization access through an active membership with one role. Memberships are organization-owned. Every tenant-owned row includes a non-null `organization_id` foreign key. The SQLAlchemy tenant session applies organization criteria to ORM queries and rejects tenant-owned writes without a matching trusted organization context.

## Isolation requirements

A user in Organization A must never access Organization B's resources through manipulated IDs, query/route parameters, request bodies, filters, exports, search, background jobs, or direct references. Tenant isolation is enforced on the backend; frontend filtering is not a security boundary. Unscoped database access is restricted to explicit identity/bootstrap paths and must not be used for tenant business operations.

## API and service handling

Authentication validates the access token, user, membership, active session, and current role grants. Tenant-scoped service dependencies bind the SQLAlchemy session to the membership's organization. Scope each object lookup and mutation by both object identity and organization. Treat client-supplied tenant identifiers as selectors requiring membership validation, never as authority. Avoid revealing whether an out-of-tenant identifier exists.

## Background jobs

Tenant-owned scan jobs carry an organization identifier, registered account, and trusted initiator membership. Workers load tenant context from the persisted job identifier, revalidate account/organization/membership ownership, scope ORM sessions, and prevent context leakage across retries or results. Queue messages contain identifiers only and are not an authorization boundary.

Findings, lifecycle events, evidence, compliance assessments, and risk rows retain organization ownership. Rule and framework catalogs are platform definitions; every association from those catalogs to tenant data is organization-scoped. Aggregate risk and compliance queries first constrain tenant-owned findings/assets and never accept an organization id as caller authority.

## Current implementation limits

The ORM guard covers ORM reads and ORM unit-of-work writes. Raw SQL and Core operations bypass ORM criteria and must be prohibited for tenant-owned application access or protected by explicit organization predicates. Database row-level security is not currently enabled; any future RLS adoption must preserve the same tenant contract.
