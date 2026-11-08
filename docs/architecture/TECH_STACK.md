# Technology Stack

**Status:** Locked stack transcription  
**Authority:** `PROJECT_SPECIFICATION.md`, sections 7, 58, and 59.

| Area | Specified technologies / direction |
|---|---|
| Backend | Python, FastAPI, PostgreSQL, SQLAlchemy, Alembic, Pydantic, Redis, Celery, Boto3 |
| Search | OpenSearch |
| Object storage | S3; MinIO for local/development where appropriate |
| Frontend | React, TypeScript, Vite, Tailwind CSS, TanStack Query, React Router, Recharts |
| Quality/security tooling | Ruff, MyPy, Pytest, Bandit, pip-audit, Semgrep, Trivy |

Docker Compose may support local development with PostgreSQL, Redis, OpenSearch, MinIO where needed, backend, and worker. Production infrastructure is designed separately. Production should support containerized services, secure configuration, scalable workers, managed database where appropriate, secure object storage, observability, health/readiness checks, and horizontal scaling where appropriate. Kubernetes may be introduced in the infrastructure phase.

This list records the locked direction. It does not authorize adding dependencies or creating manifests/configuration during Phase 00. No additional technologies are selected here.

Phase 02 uses PyJWT for signed access tokens, `pwdlib` with Argon2 for password hashes, `psycopg` as the PostgreSQL driver, and `email-validator` for validated login email inputs. These dependencies support Phase 02 contracts; they do not expand the product stack.

Phase 07 frontend dependencies implement the locked frontend stack: React/TypeScript and Vite, Tailwind CSS, TanStack Query, React Router, and Recharts. TypeScript, ESLint, and Prettier provide frontend type/lint/format commands. Exact frontend versions are constrained in the npm lockfile. Phase 08 adds no external service dependency; notifications are in-app and report snapshots are database-backed. PDF uses a dependency-free text renderer over snapshots capped at 500 rows; output-byte limits and production document requirements remain unresolved.
