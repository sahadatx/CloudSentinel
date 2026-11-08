# CloudSentinel Documentation

## Start here

1. Read [`PROJECT_SPECIFICATION.md`](../PROJECT_SPECIFICATION.md), the authoritative product and architecture source.
2. Read [`AI_ENGINEERING_RULES.md`](AI_ENGINEERING_RULES.md) before AI-assisted changes.
3. Read [`CONTRIBUTING.md`](../CONTRIBUTING.md) for repository workflow and [`architecture/PHASE_GATES.md`](architecture/PHASE_GATES.md) for phase scope.
4. Work only on the explicitly requested phase.

## Architecture documentation

- [Architecture](architecture/ARCHITECTURE.md) — system context, subsystem flow, asynchronous scans, provider evolution.
- [Boundaries](architecture/BOUNDARIES.md) — subsystem ownership and handoffs.
- [Database Conventions](architecture/DATABASE_CONVENTIONS.md) — PostgreSQL, ORM/migrations, tenancy, and schema guidance (Phase 02 foundation and Phase 03 management metadata implemented).
- [API Conventions](architecture/API_CONVENTIONS.md) — contracts, validation, errors, pagination, authorization, and isolation.
- [RBAC](architecture/RBAC.md) — locked roles and permission model.
- [Multi-Tenancy](architecture/MULTI_TENANCY.md) — organization ownership and isolation expectations.
- [Security Architecture](architecture/SECURITY_ARCHITECTURE.md) — trust boundaries, AWS access, secrets, evidence, audit, and threat expectations.
- [UI Design System](architecture/UI_DESIGN_SYSTEM.md) — locked console philosophy, colors, navigation, and information patterns.
- [Technology Stack](architecture/TECH_STACK.md) — technologies and tooling from the specification.
- [Decision Register](architecture/DECISIONS.md) — locked decisions and explicitly unresolved implementation choices.
- [Phase Gates](architecture/PHASE_GATES.md) — the superseding 10-phase roadmap and gate expectations.
- [AWS EKS Deployment](../infrastructure/terraform/aws/README.md) — AWS production prerequisites, infrastructure, recovery targets, and release flow.

## Development rules and roadmap

`PROJECT_SPECIFICATION.md` contains the full product requirements and locked roadmap. `docs/AI_ENGINEERING_RULES.md` is the AI-agent rules document; its repository copy currently ends mid-section, so the product specification remains the complete authoritative source for the rules it defines. Architecture docs summarize that source and do not silently amend it.

Phases 01–08 are complete, covering the runtime, identity and tenant foundations, AWS discovery/inventory, policy/findings, risk/compliance/evidence, the frontend console, and the operational workflows. Phases 09–10 now include enterprise SAML/SCIM, isolated customer IaC/container scans, retention/offboarding, distributed tracing, and optional AWS cross-region recovery foundations. Production deployment, customer IdP configuration, CIS control-map verification, and measured recovery drills remain unverified. See [Enterprise Readiness](ENTERPRISE_READINESS.md) for the implementation status and prerequisites.
