# CloudSentinel

CloudSentinel is an enterprise cloud security posture and risk intelligence platform. The product source of truth is [`PROJECT_SPECIFICATION.md`](PROJECT_SPECIFICATION.md); engineering boundaries and the current gate are documented in [`docs/`](docs/README.md).

## Current roadmap status

Phases 01–08 are complete. Phase 09 security QA and Phase 10 production/deployment foundations are in progress. Remaining product scanning and hosting decisions are recorded in [`docs/SECURITY_QA_AND_DEPLOYMENT.md`](docs/SECURITY_QA_AND_DEPLOYMENT.md) and [`docs/architecture/PHASE_GATES.md`](docs/architecture/PHASE_GATES.md).

## Development setup

Copy `.env.example` to `.env` and replace both values with independent random 32-byte secrets, for example using `openssl rand -hex 32`. Start PostgreSQL, Redis, the backend, and the infrastructure-only Celery worker:

```sh
make docker-up-build
```

Use `make docker-up` to start the already-built images without requesting a rebuild. Run `make docker-up-build` for the first startup or after Python/frontend source or dependency changes. The Python development image uses BuildKit's pip cache, so later source-triggered builds can reuse downloaded dependencies.

The development Compose stack exposes the backend at `http://127.0.0.1:8001` and the React console at `http://127.0.0.1:5173`. The frontend proxies authenticated API requests to the backend. To expose the local console through a temporary public Cloudflare tunnel, explicitly start the `public-tunnel` profile with `docker compose --profile public-tunnel up`; anyone who reaches the URL still needs valid CloudSentinel credentials. For local UI development outside Compose, use `make frontend-install` once, then `make frontend-dev`; validate with `make frontend-build` and `make frontend-lint`.

Password recovery emails in the local Compose environment are captured by Mailpit at `http://127.0.0.1:8025`; they are not delivered externally. The development-only SMTP connection uses the private Compose network without TLS or credentials. Non-development environments must use an authenticated SMTP provider with STARTTLS.

The API is published at `http://localhost:8001`; PostgreSQL is bound to localhost port `5433` and Redis to `6380`. Run the migration inside the Compose backend:

```sh
make docker-migrate
```

Provision the first organization and its tenant-scoped administrator through the trusted operator command:

```sh
docker compose exec backend python -m app.bootstrap_org \
  --name "Example Organization" \
  --slug example-organization \
  --email admin@example.com \
  --display-name "Initial Administrator"
```

To populate the console with an explicitly synthetic dataset for local UI exploration, seed the existing organization after provisioning and migrating:

```sh
make docker-seed-demo ORG_SLUG=example-organization ADMIN_EMAIL=admin@example.com
```

This command is restricted to `CLOUDSENTINEL_APP_ENV=development` and is safe to rerun. By default it tops up the main UI collections to 100 rows (50 for demo users, teams, and invitations), so pagination and filters have enough data to explore. Use `--minimum-rows 50` with `app.seed_demo_cli` when a smaller sample is preferred. Synthetic account, inventory, scan, finding, alert, customer assessment, report, remediation, and notification rows are visibly labeled `DEMO ONLY`; demo AWS accounts use mock validation and never call AWS. Demo members are inactive, have non-deliverable `.invalid` email addresses, and cannot sign in. Demo invitations are expired and revoked with random digests; no session or refresh-token records are fabricated. Skip the command when a tenant should contain only collected data.

The command prompts for a password only when the email does not already identify an active CloudSentinel user. Organization and user/team APIs require authentication and remain scoped to the selected organization. AWS accounts use a read-only role ARN and generated ExternalId; the ExternalId appears only in the account creation response for role trust setup. Connection validation calls AWS STS only. It does not collect cloud resources.

When running Alembic outside Docker, set `CLOUDSENTINEL_DATABASE_URL` to the PostgreSQL URL reachable from the host. Never commit `.env` or real credentials.

Install tooling and run checks:

```sh
make install
make test
make lint
make typecheck
```

The process liveness endpoint is `GET /health`. `GET /ready` checks PostgreSQL and Redis. Authentication endpoints are `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, and `GET /auth/me`. Phase 03 adds tenant-scoped organization profile, user invitation/membership, team, and AWS account management endpoints.

### Local AWS connection validation

The default Compose stack intentionally has no AWS identity. To validate account roles locally, first configure and log into a short-lived host profile (prefer AWS IAM Identity Center with `aws configure sso` and `aws sso login`), then run this helper from the CloudSentinel checkout:

```sh
aws configure sso
aws sso login --profile your-sso-profile
./scripts/dev-with-aws-profile.sh your-sso-profile
```

The helper validates the profile without printing account details, mounts it read-only into both services, rebuilds them, and verifies that API and worker can each call STS. The local containers run with the host UID/GID so they can read the host's normally owner-only AWS config and SSO cache. Do not use permanent access keys or commit profile files. In deployed environments, attach a workload identity (for example an ECS task role or EKS web identity role) to both the API and worker; do not use this local profile overlay. Without either a local profile or a deployment workload identity, STS validation returns `NoCredentialsError` by design.

For UI and connection-state work without any AWS account, set `CLOUDSENTINEL_AWS_VALIDATION_MODE=mock` in the local `.env` and restart the backend. Mock validation is visibly labeled `LOCAL / MOCK`, supports `success`, `assume_role_denied`, `external_id_mismatch`, `identity_mismatch`, and `permission_denied` scenarios through `CLOUDSENTINEL_AWS_MOCK_SCENARIO`, and never permits real scans. The setting is rejected in staging and production; keep the default `real` for actual AWS connections.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for phase discipline and engineering workflow.
