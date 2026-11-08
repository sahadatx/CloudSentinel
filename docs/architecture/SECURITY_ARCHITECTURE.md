# Security Architecture

**Status:** Phase 00 baseline with Phase 02 identity, Phase 03 organization/AWS access, Phase 04–06 assessment, and Phase 07–08 console/operations controls.
**Authority:** `PROJECT_SPECIFICATION.md`.

## Security principles and trust boundaries

Apply least privilege, defense in depth, secure defaults, credential protection, backend authorization, tenant isolation, auditability, and evidence integrity. Identity authenticates a principal; authorization independently checks current permissions and tenant scope for every protected action. Frontend permission checks are UX controls only.

## Phase 02 authentication controls

- Passwords are hashed with Argon2id; plaintext passwords are never stored or logged.
- Access tokens are short lived (15 minutes by default), signed with HS256 using a configured secret of at least 32 characters, and validated against a fixed algorithm, issuer, audience, and required claims.
- API responses use `Cache-Control: no-store` so browser and intermediary caches do not retain access tokens or tenant data.
- Refresh tokens are cryptographically random, opaque, single use, rotated on refresh, stored only as SHA-256 digests, and associated with an absolute-expiry revocable session.
- Reuse of a consumed refresh token revokes the session. Logout revokes its refresh session; access tokens are checked against current session state.
- Refresh cookies are HttpOnly, SameSite=Strict, scoped to `/auth`, and Secure outside development. Refresh/logout require a double-submit CSRF header matching the CSRF cookie.
- Login errors are generic across invalid password, user, membership, and organization.
- Email/password login resolves the organization only when the identity has exactly one active, unlocked membership in an active organization. Ambiguous identities fail with the same generic credential response; API clients can still supply an explicit organization slug.
- Login attempts are rate limited by keyed email and source IP using Redis; login fails closed when the limiter is unavailable.
- Behind a reverse proxy, configure Uvicorn's forwarded-IP allowlist with only trusted proxy addresses so `request.client.host` identifies the client safely. Until that deployment setting is configured, clients behind one proxy share its IP rate-limit bucket; never trust forwarded headers from untrusted peers.
- Password recovery returns one generic response for known and unknown identities, rate limits using Redis with keyed email/IP identifiers, persists only SHA-256 token digests, and expires single-use tokens after a configured short TTL. Reset and invitation URLs place tokens in fragments so they are not sent in HTTP requests; pages remove the fragments immediately and use a no-referrer policy. Reset consumes the token, changes the password, and revokes all active sessions.
- Forced password changes are persisted on the identity. Backend permission and tenant-session dependencies deny application operations until the user reauthenticates with the current password and completes the change. The current session remains active and other sessions are revoked after completion.
- Token claims are not trusted without database checks for current active user, membership, session, role, and grants.

The HMAC key is supplied through `CLOUDSENTINEL_JWT_SIGNING_KEY`; staging and production require a minimum 32-character key, a configured database, and an HTTPS frontend URL. Use a secrets manager in deployed environments. Never commit actual secrets.

## Tenant and database boundaries

The trusted tenant is selected from a validated active membership. Tenant-owned ORM reads are organization-filtered, and tenant-owned flushes must match the session's organization. Raw SQL/Core access does not receive ORM filtering and therefore requires explicit tenant predicates or must not be used for tenant-owned data. Unscoped sessions are reserved for authentication/bootstrap paths.

## AWS access

Preferred architecture:

```text
CloudSentinel -> AWS STS AssumeRole -> Read-only Security Role -> AWS Account
```

Permanent AWS access keys are not the default. Phase 03 connection validation calls STS AssumeRole with a generated ExternalId, a unique short-lived session name, and a 900-second session. A second STS call confirms the assumed identity account ID. Temporary credentials are held only in memory for that validation request; they are not persisted, returned, or logged. Errors stored with account metadata are bounded identifiers only, never provider messages. The generated ExternalId is returned only in one-time account creation or explicit rotation responses so the customer can configure role trust; later reads omit it. Region settings are metadata only and do not trigger resource collection.

Phase 04 workers retrieve the registered account and ExternalId from tenant-scoped storage, assume the configured read-only role, and use short-lived credentials in memory for AWS SDK calls. Queue arguments contain only a scan-job identifier. The worker derives and revalidates organization/account/initiator context from persisted records. Collection is limited to requested, enabled regions and supported resource types; failures are stored as sanitized codes. Credentials, Lambda environment variables, and unfiltered SDK responses are excluded from inventory and logs.

Account validation uses bounded STS client timeouts/retries and a Redis request limit keyed to the active organization, user, and source IP. If Redis cannot enforce the limit, validation fails closed without calling AWS. External IDs are returned only in one-time create/rotation responses; audit events record rotation without the value.

Local connection-flow work may opt into `CLOUDSENTINEL_AWS_VALIDATION_MODE=mock` only when `CLOUDSENTINEL_APP_ENV` is `development` or `test`. The mock provider simulates role ARN/account matching, ExternalId trust, AssumeRole, caller identity, and baseline permission checks without AWS credentials or network access. Its result is persisted as `validation_mode=mock`, shown as `LOCAL / MOCK`, and audited with the mode. Mock-validated accounts are excluded from real connected-account metrics and cannot queue or execute scans. Production and staging reject mock mode at configuration load; the default mode is real STS.

Phase 05 evaluates versioned JSON rule documents through a bounded interpreter; policy data never becomes executable code. Finding transitions and suppression are backend-authorized and event-recorded. Phase 06 evidence contains only matched fields and selected normalized configuration after sensitive-key filtering. Risk factors are persisted per finding and higher-level aggregates are calculated from tenant-scoped active findings. CIS AWS Foundations 7.1.0 is identified, but the control mapping remains unverified and inactive; results must not imply full benchmark coverage.

## Logs, errors, SSRF, and IDOR

Never log passwords, API keys, AWS secret keys, access/refresh tokens, session secrets, or private credentials. Authentication failures do not reveal account existence. API errors do not expose secrets or infrastructure details. Treat identifiers and filters as untrusted and enforce organization-scoped lookups. Any future feature fetching user-controlled URLs must define destination validation, egress constraints, redirect handling, and metadata/private-address protection before implementation.

## Background work, evidence, and remediation

Workers must carry trusted tenant context, revalidate ownership, prevent cross-job leakage, and publish tenant-scoped results. Evidence must not contain credentials. Audit events are tenant-aware and secret-free. Initial remediation is recommendation-based; destructive automatic changes are prohibited.

Phase 08 remediation requests retain requester, separate approver/rejector, notes, and timestamps. The approval endpoint records a decision only; it does not execute an AWS API, shell command, Terraform plan, or worker job. Reports are bounded tenant snapshots; CSV exports neutralize spreadsheet formulas; export actions are audit recorded. In-app notices are visible only to the target active organization member. The frontend keeps access tokens in memory and uses the established HttpOnly refresh cookie and CSRF header contract.
