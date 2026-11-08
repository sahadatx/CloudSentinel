# API Conventions

**Status:** Phase 00 contract guidance with Phase 02 authentication, Phase 03 management, and Phase 04–08 backend contracts.  
**Authority:** `PROJECT_SPECIFICATION.md`, sections 10, 25–28, 40, 49, and 52.

## Structure and versioning

Use predictable resource-oriented names and explicit contracts. Version the API so incompatible contract changes can be introduced deliberately. A URL version prefix such as `/api/v1` is a candidate convention, but the exact versioning form is **UNRESOLVED** pending API design in the relevant implementation phase. Business logic belongs in services when appropriate, not directly in route handlers.

Phase 02 provides `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/forgot-password`, `POST /auth/password-reset/validate`, `POST /auth/password-reset`, and authenticated `POST /auth/change-password`. Login accepts normalized email and password, with optional `organization_slug` and `remember_session` (default `false`). When the slug is omitted, exactly one active, unlocked membership in an active organization must match; ambiguous identities receive the same generic login failure. Explicit organization scope remains supported for API clients. Password recovery accepts only an email and always returns the same accepted response for known and unknown identities when SMTP is configured. Redis rate limits requests per keyed email and source address. Recovery tokens are one-time, expire after the configured short TTL, and only their SHA-256 digests are persisted. SMTP is an optional environment-configured delivery boundary; if it is absent, recovery returns service unavailable without revealing account existence. Reset revokes all sessions; forced password change requires current and new passwords, clears the mandatory flag, retains the current session, and revokes other sessions. While `force_password_change` is set, backend authorization dependencies deny protected application operations. Access tokens are returned in the response body. Refresh secrets use an HttpOnly cookie; refresh/logout use the matching double-submit CSRF cookie/header. Session expiry and concurrency are controlled by tenant security settings; remembered sessions use their configured persistent-cookie lifetime, and all sessions expire at their persisted absolute deadline. These paths do not settle the API-wide version prefix.

Phase 03 management routes are scoped to the authenticated membership organization: `GET/PATCH /organizations/current`; `GET /users`, invitation issuance and membership role/activation operations; `/teams` and organization team membership; and `/cloud-accounts` for AWS account metadata, connection validation, and disconnect. Cloud account metadata may be registered before role trust; its role is nullable while pending. Account creation returns a generated ExternalId once for trust setup; `POST /cloud-accounts/{id}/external-id` rotates and returns it once if setup must be resumed. Subsequent account responses exclude the ExternalId. User invitation tokens are returned once to the authorized issuer for secure out-of-band delivery. Cloud account validation invokes STS and identity verification only and never starts collection or discovery. All identifiers are looked up within the current organization, and route permissions are enforced on the backend.

Organization settings use `GET/PATCH /organizations/current` for display name, description, timezone, default environment/region, and the supported date/time display format. `GET/PATCH /organizations/current/settings/security` reads or updates the canonical organization password minimum and refresh-session lifetime/concurrency policy. General updates require `organizations:update`; security reads and updates require `security_settings:read` and `security_settings:update`. Both update routes append before/after audit details in the same database transaction. Notification and integration settings remain unavailable until their organization-scoped backend resources exist.

Phase 04 adds asynchronous scan creation, bounded scan/job progress reads, cooperative cancellation, rerun-as-new-job, and tenant-scoped normalized asset list/detail/relationship reads. Scan list supports bounded pagination and status, cloud-account, and text filters; it returns tenant status counts for the management view. A request selects one connected registered cloud account, enabled regions, and supported resource types. It cannot supply an organization as authority. Scan requests return an accepted job identifier; AWS calls run in Celery workers. These endpoints do not evaluate policies or create findings.

Phase 05 adds GET /policies/rules, tenant-scoped GET /findings, finding investigation detail/evidence reads, lifecycle transitions, assignment, and suppression. Suppression requires a reason and expiration; the authenticated approver and action are retained in the finding event stream.

Phase 06 adds /risk/summary, finding/asset/account risk reads, CIS framework summaries, and control details. Finding detail links risk factors, evidence, compliance controls, and lifecycle events. Risk authorization uses the corresponding existing finding, asset, or cloud-account read permission.

Phase 08 adds POST/GET /reports, GET /reports/{id}, and GET /reports/{id}/export?format=pdf|csv|json; POST /findings/{id}/remediation, GET /remediation, and POST /remediation/{id}/decision; signed-in-user GET /notifications and POST /notifications/{id}/read; and GET /audit-events with bounded pagination. Reports are point-in-time snapshots capped at 500 rows. Remediation approval records human intent only and never executes a cloud change. Export requires reports:export; audit reads require audit:read; remediation operations require remediation:read or remediation:execute. The UI downloads exports through the authenticated API client.

## Requests and responses

Validate request shape, types, bounds, and allowed values at the API boundary. Use consistent response representations and stable identifiers. Do not expose secrets, credentials, database internals, sensitive infrastructure details, or unnecessary stack traces. Exact envelope and field naming are **UNRESOLVED** and must be set in explicit API contracts.

## Pagination and filtering

Collection endpoints must define bounded pagination and documented filters. Filtering, sorting, and search must be validated, authorized, and organization-scoped on the backend. Exact cursor/offset strategy, default limits, and response metadata are **UNRESOLVED** per contract; do not silently establish global values here.

## Errors

Errors should be consistent and actionable without disclosing sensitive implementation details. Exact error schema, code taxonomy, and HTTP mapping are **UNRESOLVED** until the API contract phase defines them.

## Security and tenant context

- Authentication establishes caller identity; authorization checks every protected operation on the backend.
- Tenant-owned resource access must be organization-scoped and resistant to manipulated IDs, route/query/body values, filters, exports, search, and direct object references.
- Never treat frontend checks or caller-supplied organization IDs as a security boundary.
- Background work must carry and validate organization and account context.
- Exports and global search results must enforce the same tenant and permission boundaries.

## Idempotency and audit

Use idempotency where repeated requests could create duplicate or unsafe effects, especially for retryable operations. The exact endpoints, key format, and retention are **UNRESOLVED** until contracts require them. Sensitive actions must be auditable as required by the specification.

## Asynchronous work

Long-running scans are asynchronous: `POST /scans` returns an accepted scan resource with its identifier, current status, and progress counters. `GET /scans` and `GET /scans/{id}` expose organization-scoped progress; `POST /scans/{id}/cancel` requests cooperative cancellation. Status values are `queued`, `running`, `cancelling`, `completed`, `partial`, `failed`, and `cancelled`. AWS calls run through Celery workers; never execute a scan in the request lifecycle. Result pagination and filtering follow the bounded scan and asset contracts implemented in Phase 04.
