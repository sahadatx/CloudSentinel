# Role-Based Access Control

**Status:** Phase 02 authorization foundation; Phase 03 management, Phase 04–06 assessment, and Phase 07–08 operational views are active.
**Authority:** `PROJECT_SPECIFICATION.md`, sections 9–11; role grants below are the locked least-privilege baseline.

## Locked role set

CloudSentinel defines exactly these roles: `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ADMIN`, `SECURITY_ANALYST`, `CLOUD_ENGINEER`, `AUDITOR`, and `VIEWER`. The database constrains role codes to this set.

## Permission catalog

Permissions use `resource:action` codes, with the specification's initial catalog:

- Cloud accounts: `read`, `create`, `update`, `delete`
- Assets: `read`, `export`
- Findings: `read`, `update`, `assign`, `suppress`
- Policies: `read`, `create`, `update`
- Reports: `read`, `create`, `export`
- Remediation: `read`, `execute`
- Audit: `read`
- Organization: `read`, `update`
- Organization security settings: `read`, `update` (separate `security_settings:read` and `security_settings:update` grants)
- Users: `read`, `invite`, `update`, `disable`
- Teams: `read`, `create`, `update`, `delete`
- Scans: `read`, `create`, `cancel`

## Default role grants

The migration seeds the following deny-by-default matrix. Every grant is scoped to the active organization membership. `SUPER_ADMIN` therefore does not bypass tenant boundaries.

| Role | Grants |
|---|---|
| `SUPER_ADMIN` | All catalog permissions, within its explicitly selected organization |
| `ORG_ADMIN` | All catalog permissions for its organization, including organization, user and team administration |
| `SECURITY_ADMIN` | All product catalog permissions except `cloud_accounts:delete` and `remediation:execute`; plus `organizations:read`, `users:read`, `teams:read` |
| `SECURITY_ANALYST` | `assets:read`, `assets:export`, `findings:read`, `findings:update`, `findings:assign`, `policies:read`, `reports:read`, `reports:create`, `reports:export`, `remediation:read`, `audit:read` |
| `CLOUD_ENGINEER` | `cloud_accounts:read`, `assets:read`, `findings:read`, `findings:update`, `policies:read`, `reports:read`, `remediation:read`, `remediation:execute` |
| `AUDITOR` | Read-only catalog (`cloud_accounts:read`, `assets:read`, `findings:read`, `policies:read`, `reports:read`, `remediation:read`, `audit:read`) plus `assets:export` and `reports:export` |
| `VIEWER` | Read-only catalog: `cloud_accounts:read`, `assets:read`, `findings:read`, `policies:read`, `reports:read`, `remediation:read`, `audit:read` |

The Phase 03 organization/user/team permissions are granted to `SUPER_ADMIN` and `ORG_ADMIN`; `SECURITY_ADMIN` receives read-only organization/user/team access. All roles receive `organizations:read` so the active organization context can be displayed. Cloud account grants remain those seeded in Phase 02. This mapping is a conservative product baseline, not a substitute for resource-level authorization. `SUPER_ADMIN` is still bound to the active membership organization and cannot list or administer other tenants. New organizations are provisioned through the trusted operator bootstrap command. Invitation tokens are returned once to the authorized issuer for secure out-of-band delivery; email delivery is deferred. Sensitive actions such as suppression, export, and remediation require their own backend permission checks and any phase-specific approval/audit controls.

Organization password/session policy permissions are granted to `SUPER_ADMIN`, `ORG_ADMIN`, and `SECURITY_ADMIN`; other roles cannot view or modify those policies. General organization configuration continues to use `organizations:read` and `organizations:update`. Backend checks remain authoritative even when the UI disables controls.

Phase 04 adds scan permissions without changing existing grants: `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ADMIN`, `SECURITY_ANALYST`, and `CLOUD_ENGINEER` may read/create/cancel scans; `AUDITOR` and `VIEWER` may read scans only. Every scan permission is organization-scoped.

Phases 05–06 use the existing permission catalog for policy, finding, asset, and account reads/actions. Policy authoring and privilege expansion are not introduced here. A suppression approver must hold findings:suppress; the actor, reason, and expiry are retained with the finding lifecycle event.

## Enforcement

Backend authorization is mandatory. Permission dependencies deny by default. Authenticated tenant context comes from a validated token and active membership; request-supplied organization identifiers do not establish authority. The frontend may hide controls for usability but cannot authorize actions.

Phase 08 report snapshots require `reports:create`, reading snapshots requires `reports:read`, and JSON/CSV downloads require `reports:export`. Remediation request and decision endpoints require `remediation:execute`; a requestor cannot decide their own request. Audit access requires `audit:read`. In-app notifications are scoped to the authenticated user and active organization; the organization context permission is used only to access the signed-in user's notices. Frontend route/action visibility is convenience only.
