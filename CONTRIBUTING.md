# Contributing to CloudSentinel

CloudSentinel is developed as a security-first, multi-tenant platform. `PROJECT_SPECIFICATION.md` is the product source of truth. Read it and `docs/AI_ENGINEERING_RULES.md` before work; use [the architecture index](docs/README.md) for supporting conventions.

## Repository structure

The target repository layout is specified in section 6 of `PROJECT_SPECIFICATION.md`. It includes backend, frontend, scanner engine, policy and reporting engines, infrastructure, documentation, tests, and CI workflows. Directories are added in their roadmap phases; do not create placeholder application code.

## Phase-based development

Work on one phase at a time. Before implementation, define scope, expected files, contracts, database changes, tests, security considerations, acceptance criteria, and prohibited future work. Follow [Phase Gates](docs/architecture/PHASE_GATES.md). Stop at the requested phase gate; do not include future-phase features.

## Branches and commits

Use `main` for the integrated line and phase branches such as `phase/00-architecture`, `phase/01-foundation`, and `phase/02-database`, following the specification. A phase should be implemented, tested, reviewed, security-reviewed, committed, and gated before merge. Keep commits focused and describe the phase and purpose. Do not commit secrets or generated artifacts unintentionally.

## Coding and testing

Use the locked stack and tooling in [Technology Stack](docs/architecture/TECH_STACK.md). Keep modules within their documented ownership boundaries; preserve backend-first feature delivery and explicit API contracts. Add meaningful unit, integration, API, authorization, tenant-isolation, and security tests appropriate to the feature. Run relevant checks for implementation work and report results and unresolved issues. The specification targets 90%+ meaningful backend coverage; coverage alone does not replace direct tests of security-critical paths.

## Security requirements

Enforce authorization and tenant isolation on the backend. Never hard-code or commit secrets, expose credentials, or log sensitive tokens. Preserve evidence integrity and auditability. Use AWS AssumeRole with read-only access as the preferred integration, and keep initial remediation human-controlled. Security-sensitive features require direct security tests.

## Architecture changes

Do not silently change locked architecture. If implementation exposes a genuine problem, stop and explain the issue, affected components, alternatives, and security/maintenance impact. Obtain explicit approval before updating architecture documentation or proceeding with the change, as required by specification section 65.
