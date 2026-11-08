# UI Design System

**Status:** Locked Phase 00 product and visual baseline; Phase 07 console implemented against backend contracts.
**Authority:** `PROJECT_SPECIFICATION.md`, sections 29–44.

## Product philosophy

Dark-first, clean enterprise, high information density, security-focused, and minimally decorative. CloudSentinel is an Enterprise Security Operations Console. Prioritize investigation, evidence, risk, and actionable security intelligence over decoration.

## Color tokens

| Role | Locked value |
|---|---|
| Background | `#0B0F14` |
| Surface | `#111820` |
| Card | `#151D26` |
| Border | `#26313D` |
| Primary text | `#F3F4F6` |
| Secondary text | `#9CA3AF` |
| Muted text | `#667085` |

Severity colors are semantic: Critical red, High orange, Medium yellow, Low blue/neutral, Success green. Color communicates meaning rather than decoration; pair color with readable labels or other cues.

## Navigation and global context

Locked primary navigation:

```text
CLOUDSENTINEL
OVERVIEW: Dashboard
CLOUD: Cloud Accounts, Assets
SECURITY: Findings, Policies, Risk, Compliance
OPERATIONS: Remediation, Reports, Alerts
GOVERNANCE: Audit Logs
ADMINISTRATION: Administration
```

Keep Organization, Environment, and Region visible in the global header (for example: Acme Corp / Production / Global) so operators know the context in which they are acting.

## Information patterns

- **Dashboard:** answer security posture, what needs attention, and highest risk. Use score/accounts/assets/open findings, posture trend/risk distribution, and critical findings/top risky assets/recent activity. Metrics must come from real backend data in production.
- **Findings:** dense SOC-style table with search, severity/status/account/region/category/assignee filters, pagination, and appropriate saved views, column customization, and safe bulk actions.
- **Finding investigation:** finding identity and status, asset/account/region, why it matters, evidence, risk, compliance, remediation, and activity; preserve Finding → Evidence → Risk → Impact → Remediation → Verification.
- **Assets:** overview, configuration, security, relationships where useful, findings, activity, and evidence.
- **Cloud accounts:** connection health/status, score/counts, regions, scan action, and account metadata.
- **Compliance:** framework score and passed/failed/not-assessed controls, with failed controls traceable to resources, findings, and evidence.
- **Remediation:** recommended action, risk, change preview, execution method, approvals and execution/verification state when those workflows exist. Initial behavior is recommendation-based.

## Responsive behavior

Desktop uses a persistent sidebar and dense main content. Tablet collapses the sidebar. Mobile uses top navigation and slide navigation, stacked content, and horizontally scrollable dense tables or responsive card representations. Preserve security context and usability at every size.

## Avoid

Excessive gradients, giant rounded cards, excessive animation, ubiquitous glass effects, unnecessary charts, rainbow colors, oversized headings, decorative graphics, and whitespace that hides security data. Prefer dense tables, clear hierarchy, semantic indicators, evidence, actions, and readable data.

Frontend permission checks may tailor UX but never replace backend authorization. This document does not authorize React implementation in Phase 00.

Phase 07 implements the locked token palette, navigation groups, global organization context, dense tables, loading/error/empty states, and desktop/tablet/mobile layouts in `frontend/cloudsentinel-ui/`. Screens fetch tenant-scoped APIs and do not ship seeded production metrics.
