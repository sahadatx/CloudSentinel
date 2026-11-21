import { FilterField } from "../shared/FilterField";
import { DataTable } from "../shared/DataTable";
import { FilterFooter } from "../shared/FilterFooter";
import { RiskProgress } from "../shared/RiskProgress";
import { Icon } from "../shared/Icon";
import { ViewAction } from "../shared/ViewAction";
import { lazy, Suspense, useEffect, useLayoutEffect } from "react";
import { useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { createPortal } from "react-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import {
  api,
  type Account,
  type Asset,
  type Finding,
  type Notification,
  type Page,
} from "../shared/api";
import { useAuth } from "../shared/useAuth";
import { KpiIcon } from "../shared/kpi";
import { kpiTone } from "../shared/kpi-utils";
import { DrawerFact, RightDrawer } from "../shared/RightDrawer";
import {
  formatOrganizationDateTime,
  organizationDateToUtcIso,
} from "../shared/date-time";
import { Pagination } from "../shared/Pagination";

const RiskDistributionChart = lazy(
  () => import("../components/RiskDistributionChart"),
);

function DismissibleActionMenu({
  className,
  label,
  children,
}: {
  className: string;
  label: string;
  children: ReactNode;
}) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });

  useEffect(() => {
    if (!open) return;
    const closeOutside = (event: PointerEvent) => {
      if (
        event.target instanceof Node &&
        !menuRef.current?.contains(event.target) &&
        !triggerRef.current?.contains(event.target)
      ) {
        setOpen(false);
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener("pointerdown", closeOutside);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOutside);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [open]);

  useLayoutEffect(() => {
    if (!open) return;
    const updatePosition = () => {
      const trigger = triggerRef.current?.getBoundingClientRect();
      const menu = menuRef.current;
      if (!trigger || !menu) return;
      const margin = 8;
      const width = menu.offsetWidth;
      const height = menu.offsetHeight;
      const left = Math.max(
        margin,
        Math.min(trigger.right - width, window.innerWidth - width - margin),
      );
      const below = window.innerHeight - trigger.bottom;
      const top = below >= height + margin
        ? trigger.bottom + 6
        : Math.max(margin, trigger.top - height - 6);
      setPosition({ top, left });
    };
    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
    };
  }, [open, children]);

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className={`${className}-trigger`}
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        title="More actions"
        onClick={() => setOpen((value) => !value)}
      >
        <span aria-hidden="true">⋮</span>
      </button>
      {open && createPortal(
        <div
          ref={menuRef}
          className={`${className}-popover`}
          style={{ top: position.top, left: position.left }}
          onClick={(event) => {
            if (event.target instanceof Element && event.target.closest('[role="menuitem"]')) {
              setOpen(false);
            }
          }}
        >
          {children}
        </div>,
        document.body,
      )}
    </>
  );
}

type RiskSummary = {
  organization_score: number | null;
  organization_level: string | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  at_risk_assets: number;
  open_critical_findings: number;
};
type RiskFindingItem = {
  id: string;
  title: string;
  severity: string;
  status: string;
  asset_id: string;
  asset_name: string | null;
  account_name: string | null;
  score: number;
  level: string;
};
type DashboardOverview = {
  organization_id: string;
  organization_name: string;
  environment: string | null;
  region: string | null;
  available_environments: string[];
  available_regions: string[];
  last_updated_at: string | null;
  security_score: number | null;
  security_score_level: string | null;
  security_score_model_version: string;
  cloud_accounts: number | null;
  connected_accounts: number | null;
  local_mock_accounts: number | null;
  assets: number | null;
  open_findings: number | null;
  open_by_severity: Record<string, number> | null;
  critical_findings: number | null;
  high_risk_assets: number | null;
  organization_risk_score: number | null;
  organization_risk_level: string | null;
  risk_distribution: Record<string, number> | null;
  compliance_score: number | null;
  passing_controls: number | null;
  failing_controls: number | null;
  partial_controls: number | null;
  not_assessed_controls: number | null;
  top_risky_assets: {
    id: string;
    name: string;
    resource_type: string;
    account_name: string;
    region: string;
    score: number;
    level: string;
  }[];
  critical_findings_list: {
    id: string;
    title: string;
    severity: string;
    status: string;
    asset_id: string;
    asset_name: string;
    risk_score: number | null;
    risk_level: string | null;
  }[];
  recent_activity: {
    id: string;
    action: string;
    resource_type: string;
    resource_id: string | null;
    details: Record<string, unknown>;
    created_at: string;
    href: string | null;
  }[];
  scan_status_counts: Record<string, number> | null;
  recent_scans: {
    id: string;
    account_name: string;
    status: string;
    progress_percent: number;
    created_at: string;
    finished_at: string | null;
  }[];
  remediation_counts: Record<string, number> | null;
  unread_notifications: number | null;
  active_alerts: number | null;
  trend_available: boolean;
  trend: { date: string; [metric: string]: unknown }[];
};
type Framework = {
  code: string;
  name: string;
  version: string;
  controls_total: number;
  assessed: number;
  passed: number;
  failed: number;
  not_assessed: number;
  partial: number;
  compliance_score: number | null;
};
type ComplianceControl = {
  id: string | null;
  code: string;
  title: string;
  domain: string | null;
  description: string | null;
  category: string | null;
  severity: string;
  version: string;
  framework_code: string | null;
  framework_name: string | null;
  framework_version: string | null;
  status: string;
  assessed_assets: number;
  passed_assets: number;
  failed_assets: number;
  finding_ids: string[];
  compliance_score: number | null;
  last_assessed_at: string | null;
  guidance: Record<string, unknown>;
};
type ComplianceAssessment = {
  id: string;
  asset_id: string;
  asset_name: string;
  resource_type: string;
  account_id: string;
  account_name: string;
  region: string;
  status: string;
  observed: Record<string, unknown> | null;
  expected: Record<string, unknown> | null;
  evidence_id: string | null;
  policy_version: string | null;
  assessed_at: string;
};
type ComplianceAssessmentRecord = {
  assessment_id: string;
  framework_code: string;
  framework_name: string;
  framework_version: string;
  coverage_status: string;
  control_code: string;
  control_title: string;
  status: string;
  asset_name: string;
  resource_type: string;
  account_name: string;
  region: string;
  assessed_at: string;
  synthetic: boolean;
};
type ComplianceAssessmentRecordPage = {
  items: ComplianceAssessmentRecord[];
  total: number;
  offset: number;
  limit: number;
};
type ComplianceEvidence = {
  id: string;
  asset_id: string;
  asset_name: string;
  source: string;
  expected_state: Record<string, unknown>;
  observed_state: Record<string, unknown>;
  configuration: Record<string, unknown>;
  collected_at: string;
};
type Report = {
  id: string;
  name: string;
  report_type: string;
  status: string;
  file_format: string;
  report_version: number;
  generator_version: string;
  created_at: string;
  created_by_user_id: string;
  created_by_name: string | null;
  created_by_role: string | null;
  filters: Record<string, unknown>;
  checksum: string | null;
  snapshot_checksum: string | null;
  data_snapshot_at: string | null;
  generated_at: string | null;
  retention_until: string | null;
  parent_report_id: string | null;
  error_code: string | null;
  error_message: string | null;
  snapshot?: Record<string, unknown> | null;
};
type Remediation = {
  id: string;
  finding_id: string;
  requested_by_user_id: string;
  decided_by_user_id: string | null;
  status: string;
  request_note: string;
  decision_note: string | null;
  action_definition: Record<string, unknown>;
  evidence_id: string | null;
  verification_status: string;
  requested_at: string;
  decided_at: string | null;
};
type RemediationDetail = {
  request: Remediation;
  finding: {
    id: string;
    title: string;
    severity: string;
    status: string;
    asset_id: string;
    asset_name: string;
    resource_id: string;
    account_id: string;
    account_name: string;
    aws_account_id: string;
    region_code: string;
    risk_score: number | null;
  };
  evidence: {
    id: string;
    source: string;
    expected_state: Record<string, unknown>;
    detected_condition: Record<string, unknown>;
    collected_at: string;
  } | null;
};
type AlertRow = {
  id: string;
  alert_rule_id: string | null;
  alert_type: string;
  source_type: string;
  source_id: string;
  source_href: string | null;
  account_name: string | null;
  region_code: string | null;
  title: string;
  description: string;
  severity: string;
  status: string;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  acknowledged_by_user_id: string | null;
  acknowledged_at: string | null;
  resolved_by_user_id: string | null;
  resolved_at: string | null;
  dismissed_by_user_id: string | null;
  dismissed_at: string | null;
  created_at: string;
};
type AlertRule = {
  id: string;
  code: string;
  name: string;
  description: string;
  event_type: string;
  severity: string;
  enabled: boolean;
  threshold_score: number | null;
  updated_at: string;
};
type UserRow = {
  user_id: string;
  email: string;
  display_name: string;
  role_code: string;
  is_active: boolean;
};
type Team = {
  id: string;
  name: string;
  description: string | null;
  member_count: number;
};
type Org = { id: string; name: string; slug: string; is_active: boolean };

function useLoad<T>(key: string, path: string, enabled = true) {
  return useQuery({
    queryKey: [key, path],
    queryFn: () => api.get<T>(path),
    enabled,
  });
}

function PageHeader({
  className,
  eyebrow,
  title,
  description,
  action,
}: {
  className?: string;
  eyebrow?: string;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className={`page-header${className ? ` ${className}` : ""}`}>
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  );
}

function LoadState({
  error,
  loading,
  empty,
  emptyTitle,
  emptyMessage,
  emptyAction,
  children,
}: {
  error: Error | null;
  loading: boolean;
  empty?: boolean;
  emptyTitle?: string;
  emptyMessage?: string;
  emptyAction?: React.ReactNode;
  children: React.ReactNode;
}) {
  if (loading)
    return (
      <div className="state-panel">
        <span className="spinner" />
        Loading current organization data…
      </div>
    );
  if (error)
    return (
      <div className="state-panel error-state">
        <strong>Data could not be loaded</strong>
        <span>{error.message}</span>
      </div>
    );
  if (empty)
    return (
      <div className="state-panel">
        <strong>{emptyTitle ?? "No data yet"}</strong>
        <span>{emptyMessage ?? "Connect an AWS account and run a scan to populate this view."}</span>
        {emptyAction}
      </div>
    );
  return <>{children}</>;
}

function severityClass(value: string) {
  return `severity severity-${value.toLowerCase()}`;
}
function date(value: string) {
  return formatOrganizationDateTime(value);
}

function complianceStatusLabel(value: Asset["compliance_status"]): string {
  switch (value) {
    case "PASS":
      return "Compliant";
    case "FAIL":
      return "Issues found";
    case "PARTIAL":
      return "Partial";
    case "NOT_APPLICABLE":
      return "Not applicable";
    default:
      return "Not assessed";
  }
}

export function DashboardPage() {
  const queryClient = useQueryClient();
  const [environment, setEnvironment] = useState("");
  const [region, setRegion] = useState("");
  const params = new URLSearchParams();
  if (environment) params.set("environment", environment);
  if (region) params.set("region", region);
  const path = `/dashboard/overview${params.size ? `?${params}` : ""}`;
  const overview = useLoad<DashboardOverview>("dashboard-overview", path);
  const data = overview.data;
  const hasAccounts = (data?.cloud_accounts ?? 0) > 0;
  const hasScans =
    (data?.scan_status_counts &&
      Object.values(data.scan_status_counts).some((value) => value > 0)) ??
    false;
  return (
    <>
      <PageHeader
        eyebrow="SECURITY OPERATIONS"
        title="Security overview"
        description={
          data
            ? `${data.organization_name} · ${environment || "All environments"} · ${region || "All regions"}`
            : "Current organization security posture"
        }
        action={
          <button
            className="secondary-button"
            onClick={() =>
              void queryClient.invalidateQueries({
                queryKey: ["dashboard-overview"],
              })
            }
          >
            Refresh
          </button>
        }
      />
      <LoadState
        loading={overview.isLoading}
        error={overview.error}
        empty={!overview.isLoading && !overview.error && !data}
      >
        {data && (
          <>
            <div className="dashboard-context-filters">
              <div className="dashboard-context">
                <span>Organization</span>
                <strong>{data.organization_name}</strong>
              </div>
              <label>
                Environment
                <select
                  value={environment}
                  onChange={(event) => {
                    setEnvironment(event.target.value);
                    setRegion("");
                  }}
                >
                  <option value="">All environments</option>
                  {(data.available_environments ?? []).map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </label>
              <label>
                Region
                <select
                  value={region}
                  onChange={(event) => setRegion(event.target.value)}
                >
                  <option value="">All regions</option>
                  {(data.available_regions ?? []).map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </label>
              <span className="dashboard-updated">
                Last updated
                <br />
                <strong>
                  {data.last_updated_at
                    ? date(data.last_updated_at)
                    : "No security data yet"}
                </strong>
              </span>
            </div>
            {(data.local_mock_accounts ?? 0) > 0 ? (
              <div className="notice-banner">
                <strong>Local demo data</strong>
                <span>
                  Dashboard metrics include synthetic results from{" "}
                  {data.local_mock_accounts?.toLocaleString()} local mock cloud
                  {data.local_mock_accounts === 1 ? " account." : " accounts."}
                </span>
              </div>
            ) : !hasAccounts ? (
              <div className="notice-banner">
                <strong>No cloud accounts connected yet.</strong>
                <Link to="/cloud-accounts/connect">Add Cloud Account</Link>
              </div>
            ) : !hasScans ? (
              <div className="notice-banner">
                <strong>No security assessment has been completed yet.</strong>
                <Link to="/cloud-accounts">Start a scan</Link>
              </div>
            ) : data.open_findings === 0 ? (
              <div className="notice-banner">
                <strong>No security findings detected.</strong>
                <span>
                  Latest scan data contains no active findings in this context.
                </span>
              </div>
            ) : null}
            <div className="metric-grid dashboard-kpis">
              <Metric
                label="Security score"
                className="dashboard-score-card"
                value={data.security_score ?? "—"}
                suffix={
                  data.security_score == null
                    ? "Requires risk and compliance assessments"
                    : `/100 · ${data.security_score_level} · model v${data.security_score_model_version}`
                }
                tone={data.security_score_level
                  ?.toLowerCase()
                  .replaceAll(" ", "-")}
              />
              <Metric
                label="Cloud accounts"
                value={data.cloud_accounts ?? "—"}
                suffix={
                  data.connected_accounts == null
                    ? "Connection status unavailable"
                    : data.local_mock_accounts
                      ? `${data.connected_accounts.toLocaleString()} connected · includes ${data.local_mock_accounts.toLocaleString()} local mock`
                      : `${data.connected_accounts.toLocaleString()} connected`
                }
              />
              <Metric
                label="Assets"
                value={data.assets ?? "—"}
                suffix="In selected context"
              />
              <Metric
                label="Open findings"
                value={data.open_findings ?? "—"}
                suffix="Open, triaged, assigned, or in progress"
                tone="high"
              />
              <Metric
                label="Critical findings"
                value={data.critical_findings ?? "—"}
                suffix="Active critical severity"
                tone="critical"
              />
              <Metric
                label="High-risk assets"
                value={data.high_risk_assets ?? "—"}
                suffix="Aggregated asset risk ≥ 60"
                tone="high"
              />
              <Metric
                label="Compliance"
                value={
                  data.compliance_score == null
                    ? "—"
                    : `${data.compliance_score}%`
                }
                suffix={
                  data.compliance_score == null
                    ? "No assessed controls"
                    : `${data.passing_controls} passing · ${data.failing_controls} failing`
                }
              />
              <Metric
                label="Active alerts"
                value={data.active_alerts ?? "—"}
                suffix="Open or acknowledged security events"
                tone={data.active_alerts ? "high" : undefined}
              />
              <Metric
                label="Unread notifications"
                value={data.unread_notifications ?? "—"}
                suffix="For your user account"
              />
            </div>
            <div className="dashboard-grid dashboard-grid-insights">
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Findings overview</h2>
                    <p>Open findings by policy severity</p>
                  </div>
                  <Link to="/findings">View all findings</Link>
                </div>
                <div className="dashboard-severity-list">
                  {Object.entries(data.open_by_severity ?? {}).map(
                    ([name, count]) => (
                      <Link
                        key={name}
                        to={`/findings?severity=${name}&status=OPEN`}
                      >
                        <span className={severityClass(name)}>{name}</span>
                        <strong>{count}</strong>
                      </Link>
                    ),
                  )}
                </div>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Risk distribution</h2>
                    <p>Finding risk bands from persisted assessments</p>
                  </div>
                  <Link to="/risk">View risk</Link>
                </div>
                {data.risk_distribution ? (
                  <Suspense
                    fallback={
                      <div className="empty-inline">Loading chart…</div>
                    }
                  >
                    <RiskDistributionChart
                      critical={data.risk_distribution.CRITICAL ?? 0}
                      high={data.risk_distribution.HIGH ?? 0}
                      medium={data.risk_distribution.MEDIUM ?? 0}
                      low={data.risk_distribution.LOW ?? 0}
                      informational={data.risk_distribution.INFORMATIONAL ?? 0}
                    />
                  </Suspense>
                ) : (
                  <div className="empty-inline">
                    Risk assessments are not available for this context.
                  </div>
                )}
              </section>
            </div>
            <div className="dashboard-grid dashboard-grid-assets">
              <section className="panel table-panel">
                <div className="panel-heading">
                  <div>
                    <h2>Top risky assets</h2>
                    <p>Cumulative risk from active finding assessments</p>
                  </div>
                  <Link to="/assets">All assets</Link>
                </div>
                {(data.top_risky_assets ?? []).length ? (
                  <div className="table-scroll">
                    <DataTable caption="Highest risk cloud assets">
                      <thead>
                        <tr>
                          <th scope="col">Asset</th>
                          <th scope="col">Type</th>
                          <th scope="col">Account</th>
                          <th scope="col">Region</th>
                          <th scope="col">Risk</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(data.top_risky_assets ?? []).map((item) => (
                          <tr key={item.id}>
                            <td>
                              <Link to={`/assets/${item.id}`}>{item.name}</Link>
                            </td>
                            <td>{item.resource_type.replaceAll("_", " ")}</td>
                            <td>{item.account_name}</td>
                            <td>{item.region}</td>
                            <td>
                              {item.score} · {item.level}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </DataTable>
                  </div>
                ) : (
                  <div className="empty-inline">
                    No assessed risky assets in this context.
                  </div>
                )}
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Compliance</h2>
                    <p>Latest control assessments</p>
                  </div>
                  <Link to="/compliance">View compliance</Link>
                </div>
                <div className="compliance-counts">
                  <div>
                    <strong>
                      {data.compliance_score == null
                        ? "—"
                        : `${data.compliance_score}%`}
                    </strong>
                    <span>Score</span>
                  </div>
                  <div>
                    <strong className="text-success">
                      {data.passing_controls ?? "—"}
                    </strong>
                    <span>Passing</span>
                  </div>
                  <div>
                    <strong className="text-critical">
                      {data.failing_controls ?? "—"}
                    </strong>
                    <span>Failing</span>
                  </div>
                  <div>
                    <strong>{data.not_assessed_controls ?? "—"}</strong>
                    <span>Not assessed</span>
                  </div>
                </div>
              </section>
            </div>
            <div className="dashboard-grid dashboard-grid-response">
              <section className="panel table-panel">
                <div className="panel-heading">
                  <div>
                    <h2>Critical findings</h2>
                    <p>Highest-risk active critical findings</p>
                  </div>
                  <Link to="/findings?severity=CRITICAL&status=OPEN">
                    All critical findings
                  </Link>
                </div>
                {(data.critical_findings_list ?? []).length ? (
                  <div className="dashboard-critical-list">
                    {(data.critical_findings_list ?? []).map((item) => (
                      <Link key={item.id} to={`/findings/${item.id}`}>
                        <span>
                          <strong>{item.title}</strong>
                          <small>
                            {item.asset_name} ·{" "}
                            {item.status.replaceAll("_", " ")}
                          </small>
                        </span>
                        <b>
                          {item.risk_score == null
                            ? "Risk not assessed"
                            : `${item.risk_score} · ${item.risk_level}`}
                        </b>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="empty-inline">
                    No active critical findings.
                  </div>
                )}
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Scan activity</h2>
                    <p>Canonical scan job state</p>
                  </div>
                  <Link to="/scans">View scans</Link>
                </div>
                <div className="dashboard-status-counts">
                  {Object.entries(data.scan_status_counts ?? {}).map(
                    ([name, count]) => (
                      <div key={name}>
                        <span>{name}</span>
                        <strong>{count}</strong>
                      </div>
                    ),
                  )}
                </div>
                {(data.recent_scans ?? []).length ? (
                  <div className="scan-list">
                    {(data.recent_scans ?? []).map((scan) => (
                      <Link
                        className="scan-row"
                        key={scan.id}
                        to={`/scans/${scan.id}`}
                      >
                        <span className={`scan-indicator ${scan.status}`} />
                        <div>
                          <strong>
                            {scan.status} · {scan.account_name}
                          </strong>
                          <small>{date(scan.created_at)}</small>
                        </div>
                        <b>{scan.progress_percent}%</b>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="empty-inline">
                    No scans are available yet.
                  </div>
                )}
              </section>
            </div>
            <div className="dashboard-grid dashboard-grid-operations">
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Remediation</h2>
                    <p>Recorded approval request lifecycle</p>
                  </div>
                  <Link to="/remediation">View queue</Link>
                </div>
                {data.remediation_counts ? (
                  <div className="dashboard-status-counts">
                    {[
                      "PENDING_APPROVAL",
                      "APPROVED",
                      "VERIFYING",
                      "COMPLETED",
                      "FAILED",
                    ].map((name) => (
                      <div key={name}>
                        <span>{name.replaceAll("_", " ")}</span>
                        <strong>{data.remediation_counts?.[name] ?? 0}</strong>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-inline">
                    Remediation data is not available for your role.
                  </div>
                )}
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Recent activity</h2>
                    <p>Audit events, with sensitive details omitted</p>
                  </div>
                  <Link to="/audit">Audit log</Link>
                </div>
                {(data.recent_activity ?? []).length ? (
                  <div className="dashboard-activity-list">
                    {(data.recent_activity ?? []).map((item) => (
                      <div key={item.id}>
                        <span />
                        <strong>
                          {item.action
                            .replaceAll(".", " ")
                            .replaceAll("_", " ")}
                        </strong>
                        <small>
                          {item.resource_type.replaceAll("_", " ")} ·{" "}
                          {date(item.created_at)}
                        </small>
                        {item.href && <Link to={item.href}>Open</Link>}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-inline">
                    No recent activity is available to your role.
                  </div>
                )}
              </section>
            </div>
            <div className="dashboard-grid dashboard-grid-footer">
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Security alerts</h2>
                    <p>Open and acknowledged findings, risk, and scan events</p>
                  </div>
                  <Link to="/alerts">View alerts</Link>
                </div>
                <strong className="dashboard-alert-count">
                  {data.active_alerts ?? "—"}
                </strong>
                <Link to="/notifications">
                  Unread notifications: {data.unread_notifications ?? "—"} →
                </Link>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Security trends</h2>
                    <p>Historical posture snapshots</p>
                  </div>
                </div>
                {data.trend_available && (data.trend ?? []).length ? (
                  <div className="empty-inline">
                    Trend data is available from stored snapshots.
                  </div>
                ) : (
                  <div className="empty-inline">
                    Historical security score snapshots are not available yet.
                    No trend is inferred from current data.
                  </div>
                )}
              </section>
            </div>
          </>
        )}
      </LoadState>
    </>
  );
}

function Metric({
  label,
  value,
  suffix,
  tone,
  className,
}: {
  label: string;
  value: string | number;
  suffix: string;
  tone?: string;
  className?: string;
}) {
  return (
    <section className={`metric-card kpi-tone-${tone ?? kpiTone(label)} ${className ?? ""}`}>
      <div className="metric-main-row">
        <span>{label}</span>
        <div className={tone ? `metric-value tone-${tone}` : "metric-value"}>
          {typeof value === "number" ? value.toLocaleString() : value}
        </div>
        <KpiIcon label={label} />
      </div>
      <small>{suffix}</small>
    </section>
  );
}

export function AssetsPage() {
  const [searchParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const accountId = searchParams.get("cloud_account_id") ?? "";
  const [region, setRegion] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [provider, setProvider] = useState("");
  const [environment, setEnvironment] = useState("");
  const [offset, setOffset] = useState(0);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const summary = useLoad<{
    total: number;
    new: number;
    active: number;
    stale: number;
    removed: number;
    critical: number | null;
    high_risk: number | null;
  }>("asset-summary", "/assets/summary");
  const filterOptions = useLoad<{
    regions: string[];
    resource_types: string[];
    environments: string[];
    providers: string[];
    accounts: { id: string; name: string }[];
  }>("asset-filter-options", "/assets/filter-options");
  const filters = new URLSearchParams({ limit: "30", offset: String(offset) });
  if (search) filters.set("search", search);
  if (accountId) filters.set("cloud_account_id", accountId);
  if (region) filters.set("region", region);
  if (resourceType) filters.set("resource_type", resourceType);
  if (provider) filters.set("provider", provider);
  if (environment) filters.set("environment", environment);
  const query = useLoad<Page<Asset>>(
    "asset-list",
    `/assets?${filters.toString()}`,
  );
  const exportAssets = useMutation({
    mutationFn: () => api.get<Blob>(`/assets/export?${filters.toString()}`),
    onSuccess: (blob) => {
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "cloudsentinel-assets.csv";
      anchor.click();
      URL.revokeObjectURL(url);
    },
  });
  return (
    <>
      <PageHeader
        eyebrow="CLOUD / INVENTORY"
        title="Assets"
        description="Discover and investigate cloud resources across your connected environments."
        action={
          <div className="header-actions">
            <button
              className="secondary-button"
              disabled={exportAssets.isPending || !query.data?.total}
              onClick={() => exportAssets.mutate()}
            >
              {exportAssets.isPending ? "Exporting…" : "Export CSV"}
            </button>
            <button
              className="quiet-button"
              disabled={query.isFetching}
              onClick={() => {
                void query.refetch();
                void summary.refetch();
              }}
            >
              {query.isFetching ? "Refreshing…" : "↻ Refresh"}
            </button>
          </div>
        }
      />
      {summary.error && (
        <div className="banner-error">
          Asset summary could not be loaded: {summary.error.message}
        </div>
      )}
      <div className="metric-grid">
        <Metric
          label="Total assets"
          value={summary.data?.total ?? "—"}
          suffix="Persisted inventory"
        />
        <Metric
          label="Active"
          value={summary.data?.active ?? "—"}
          suffix="Seen in a successful scan"
          tone="good"
        />
        <Metric
          label="Critical"
          value={summary.data?.critical ?? "—"}
          suffix={
            summary.data?.critical == null
              ? "Not available"
              : "Open critical findings"
          }
          tone="critical"
        />
        <Metric
          label="High risk"
          value={summary.data?.high_risk ?? "—"}
          suffix={
            summary.data?.high_risk == null
              ? "Not available"
              : "Risk score 60 or higher"
          }
          tone="high"
        />
      </div>
      <div className="asset-filter-toolbar">
      <div className="filter-row asset-filter-row">
        <FilterField label="Search" className="filter-field-search"><input
          aria-label="Search assets"
          placeholder="Search asset ID, name, or ARN"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
        /></FilterField>
        <FilterField label="Provider"><select
          aria-label="Filter provider"
          value={provider}
          onChange={(event) => {
            setProvider(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All providers</option>
          {filterOptions.data?.providers.map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select></FilterField>
        <FilterField label="Region"><select
          aria-label="Filter region"
          value={region}
          onChange={(event) => {
            setRegion(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All regions</option>
          {filterOptions.data?.regions.map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select></FilterField>
        <FilterField label="Environment"><select
          aria-label="Filter environment"
          value={environment}
          onChange={(event) => {
            setEnvironment(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All environments</option>
          {filterOptions.data?.environments.map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select></FilterField>
        <FilterField label="Resource type"><select
          aria-label="Filter resource type"
          value={resourceType}
          onChange={(event) => {
            setResourceType(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All resource types</option>
          {filterOptions.data?.resource_types.map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select></FilterField>
        <span>
          {query.data?.total ?? 0} assets
          {accountId && <> · scoped to {filterOptions.data?.accounts.find((item) => item.id === accountId)?.name ?? "selected account"}</>}
        </span>
      </div>
      <FilterFooter className="asset-filter-footer" active={Boolean(search || provider || region || environment || resourceType)} onReset={() => {
              setSearch("");
              setProvider("");
              setRegion("");
              setEnvironment("");
              setResourceType("");
              setOffset(0);
            }} />
      </div>
      {exportAssets.error && (
        <div className="error-state" role="alert">
          Could not export assets: {exportAssets.error.message}
        </div>
      )}
      <section className="panel table-panel">
        <LoadState
          loading={query.isLoading}
          error={query.error}
          empty={!query.data?.items.length}
        >
          <DataTable caption="Cloud asset inventory" actions>
            <thead>
              <tr>
                <th scope="col">Resource</th>
                <th scope="col">Type</th>
                <th scope="col">Account</th>
                <th scope="col">Environment</th>
                <th scope="col">Region</th>
                <th scope="col">Risk</th>
                <th scope="col">Compliance</th>
                <th scope="col">Last observed</th>
                <th scope="col">Status</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {query.data?.items.map((asset) => (
                <tr key={asset.id}>
                  <td>
                    <button
                      className="text-button row-primary"
                      onClick={() => setSelectedAsset(asset)}
                    >
                      {asset.name || asset.resource_id}
                    </button>
                    <small>{asset.resource_id}</small>
                    {asset.attributes.cloudsentinel_data_origin ===
                      "local_mock" && (
                      <small className="asset-sample-label">
                        Local sample inventory
                      </small>
                    )}
                  </td>
                  <td>{asset.resource_type}</td>
                  <td>
                    {asset.cloud_account_name ||
                      asset.cloud_account_id.slice(0, 8) + "…"}
                  </td>
                  <td>{asset.environment || "—"}</td>
                  <td>{asset.region_code}</td>
                  <td>
                    {asset.risk_score == null
                      ? "Not assessed"
                      : `${asset.risk_score} / 100`}
                  </td>
                  <td>
                    <span
                      className={`compliance-status status-${(asset.compliance_status ?? "NOT_ASSESSED").toLowerCase()}`}
                    >
                      {complianceStatusLabel(asset.compliance_status)}
                    </span>
                  </td>
                  <td>{date(asset.last_seen_at)}</td>
                  <td>
                    <span
                      className={`asset-lifecycle asset-lifecycle-${asset.status}`}
                    >
                      {asset.status}
                    </span>
                  </td>
                  <td>
                    <button
                      type="button"
                      className="scan-view-action"
                      aria-label={`View asset ${asset.name || asset.resource_id}`}
                      onClick={() => setSelectedAsset(asset)}
                    >
                      <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M2.2 12s3.5-6 9.8-6 9.8 6 9.8 6-3.5 6-9.8 6-9.8-6-9.8-6Z" />
                        <circle cx="12" cy="12" r="2.8" />
                      </svg>
                      <span>View</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </DataTable>
        </LoadState>
      </section>
      <PageControls page={query.data} onOffsetChange={setOffset} />
      {selectedAsset && (
        <RightDrawer
          className="asset-preview-drawer"
          title={selectedAsset.name || selectedAsset.resource_id}
          description={`${selectedAsset.resource_type} · ${selectedAsset.region_code}`}
          onClose={() => setSelectedAsset(null)}
        >
          <section className="asset-preview-hero">
            <div>
              <span className="eyebrow">{selectedAsset.provider} RESOURCE</span>
              <strong>{selectedAsset.resource_type.replaceAll("_", " ")}</strong>
              <small>{selectedAsset.cloud_account_name || "Cloud account"} · {selectedAsset.region_code}</small>
            </div>
            <span className={`asset-lifecycle asset-lifecycle-${selectedAsset.status}`}>
              {selectedAsset.status}
            </span>
          </section>
          <div className="asset-preview-risk">
            <div><span>Asset risk</span><strong>{selectedAsset.risk_score == null ? "Not assessed" : `${selectedAsset.risk_score} / 100`}</strong></div>
            {selectedAsset.risk_score != null && <RiskProgress value={selectedAsset.risk_score} label={`Asset risk score ${selectedAsset.risk_score} out of 100`} />}
          </div>
          <section className="asset-preview-section">
            <h3>Resource context</h3>
            <div className="drawer-facts">
            <DrawerFact label="Provider" value={selectedAsset.provider} />
            <DrawerFact label="Resource ID" value={selectedAsset.resource_id} />
            <DrawerFact
              label="Cloud account"
              value={
                selectedAsset.cloud_account_name ||
                selectedAsset.cloud_account_id
              }
            />
            <DrawerFact
              label="Environment"
              value={selectedAsset.environment || "Not specified"}
            />
            <DrawerFact label="Region" value={selectedAsset.region_code} />
            <DrawerFact label="Status" value={selectedAsset.status} />
            <DrawerFact
              label="First seen"
              value={date(selectedAsset.first_seen_at)}
            />
            <DrawerFact
              label="Last seen"
              value={date(selectedAsset.last_seen_at)}
            />
            <DrawerFact
              label="ARN"
              value={selectedAsset.resource_arn ?? "Not available"}
            />
            <DrawerFact label="Owner" value={selectedAsset.owner_metadata?.owner || "Unassigned"} />
            <DrawerFact label="Tags" value={String(Object.keys(selectedAsset.tags).length)} />
            {selectedAsset.last_scan_job_id && <DrawerFact label="Last scan" value={selectedAsset.last_scan_job_id} />}
            </div>
          </section>
          <div className="drawer-actions asset-preview-actions">
            <Link
              className="primary-button"
              to={`/assets/${selectedAsset.id}`}
              onClick={() => setSelectedAsset(null)}
            >
              Full details
            </Link>
            <Link className="secondary-button" to={`/findings?asset_id=${selectedAsset.id}`} onClick={() => setSelectedAsset(null)}>View findings</Link>
          </div>
        </RightDrawer>
      )}
    </>
  );
}

export function AssetDetailPage() {
  const { assetId = "" } = useParams();
  const { user } = useAuth();
  const [detailParams, setDetailParams] = useSearchParams();
  const [tab, setTab] = useState(detailParams.get("tab") || "overview");
  const asset = useLoad<Asset>(`asset-${assetId}`, `/assets/${assetId}`);
  const risk = useLoad<{
    score: number | null;
    level: string | null;
    factors: Record<string, unknown>;
  }>(
    `asset-risk-${assetId}`,
    `/risk/assets/${assetId}`,
    tab === "overview" || tab === "security",
  );
  const relationships = useLoad<{ relationship_type: string; target: Asset }[]>(
    `asset-relationships-${assetId}`,
    `/assets/${assetId}/relationships`,
    tab === "relationships",
  );
  const findings = useLoad<Page<Finding>>(
    `asset-findings-${assetId}`,
    `/findings?limit=50&asset_id=${assetId}`,
    tab === "findings" && Boolean(user?.permissions.includes("findings:read")),
  );
  const evidence = useLoad<
    {
      id: string;
      finding_id: string;
      scan_job_id: string;
      rule_version: string;
      scanner_version: string;
      source: string;
      expected_state: Record<string, unknown>;
      detected_condition: Record<string, unknown>;
      configuration: Record<string, unknown>;
      collected_at: string;
    }[]
  >(
    `asset-evidence-${assetId}`,
    `/assets/${assetId}/evidence`,
    tab === "evidence" && Boolean(user?.permissions.includes("findings:read")),
  );
  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "configuration", label: "Configuration" },
    { id: "security", label: "Security" },
    { id: "relationships", label: "Relationships" },
    ...(user?.permissions.includes("findings:read")
      ? [
          { id: "findings", label: "Findings" },
          { id: "evidence", label: "Evidence" },
        ]
      : []),
    { id: "activity", label: "Activity" },
  ];
  const securityAttributes = asset.data
    ? Object.entries(asset.data.attributes).filter(([key]) =>
        /encrypt|public|access|security|logging|tls|policy|kms|version/i.test(
          key,
        ),
      )
    : [];
  return (
    <>
      <div className="account-detail-back">
        <Link to="/assets">← Assets</Link>
      </div>
      <PageHeader
        eyebrow="CLOUD / ASSET"
        title={asset.data?.name || asset.data?.resource_id || "Asset details"}
        description={
          asset.data
            ? `${asset.data.resource_type.replaceAll("_", " ")} · ${asset.data.provider} · ${asset.data.cloud_account_name || "Cloud account"} · ${asset.data.region_code}`
            : "Investigate collected cloud resource identity and configuration."
        }
        action={
          <div className="header-actions">
            <button
              className="quiet-button"
              disabled={asset.isLoading}
              onClick={() => void asset.refetch()}
            >
              ↻ Refresh
            </button>
            {user?.permissions.includes("findings:read") && (
              <Link
                to={`/findings?asset_id=${assetId}`}
                className="secondary-button"
              >
                View findings
              </Link>
            )}
          </div>
        }
      />
      <LoadState loading={asset.isLoading} error={asset.error}>
        {asset.data && (
          <>
            <div className="asset-detail-title-row asset-detail-identity">
              <div>
                <span
                  className={`asset-lifecycle asset-lifecycle-${asset.data.status}`}
                >
                  {asset.data.status}
                </span>
                <span className="asset-environment-label">
                  {asset.data.environment || "Environment not specified"}
                </span>
                {asset.data.attributes.cloudsentinel_data_origin ===
                  "local_mock" && (
                  <span className="status-pill">Local sample inventory</span>
                )}
              </div>
              <code>{asset.data.id}</code>
            </div>
            <div className="asset-detail-highlights">
              <div className={asset.data.risk_score != null && asset.data.risk_score >= 80 ? "asset-highlight-risk" : ""}>
                <span>Risk score</span>
                <strong>{asset.data.risk_score == null ? "Not assessed" : `${asset.data.risk_score} / 100`}</strong>
                <small>{risk.data?.level || (risk.data?.score == null ? "No risk assessment available" : "Calculated asset risk")}</small>
              </div>
              <div><span>Lifecycle</span><strong>{asset.data.status}</strong><small>{asset.data.missed_scan_count} consecutive scans missed</small></div>
              <div><span>Last observed</span><strong>{date(asset.data.last_seen_at)}</strong><small>{asset.data.last_scan_job_id ? `Scan ${asset.data.last_scan_job_id.slice(0, 8).toUpperCase()}` : "Scan reference unavailable"}</small></div>
              <div><span>Tags</span><strong>{Object.keys(asset.data.tags).length}</strong><small>{asset.data.owner_metadata?.owner || "Owner not assigned"}</small></div>
            </div>
            <nav className="account-detail-tabs" aria-label="Asset details">
              {tabs.map((item) => (
                <button
                  key={item.id}
                  className={tab === item.id ? "active" : ""}
                  onClick={() => {
                    setTab(item.id);
                    setDetailParams({ tab: item.id });
                  }}
                >
                  {item.label}
                </button>
              ))}
            </nav>
            {tab === "overview" && (
              <div className="account-detail-grid">
                <section className="panel asset-detail-panel">
                  <h2>Asset identity</h2>
                  <div className="account-facts-list">
                    <Info
                      label="Resource type"
                      value={asset.data.resource_type.replaceAll("_", " ")}
                    />
                    <Info label="Provider" value={asset.data.provider} />
                    <Info
                      label="Cloud account"
                      value={
                        asset.data.cloud_account_name ||
                        asset.data.cloud_account_id
                      }
                    />
                    <Info
                      label="Account ID"
                      value={asset.data.cloud_account_id}
                    />
                    <Info label="Region" value={asset.data.region_code} />
                    <Info
                      label="Environment"
                      value={asset.data.environment || "Not specified"}
                    />
                    <Info
                      label="Owner"
                      value={asset.data.owner_metadata?.owner || "Unassigned"}
                    />
                    <Info label="Resource ID" value={asset.data.resource_id} />
                    <Info
                      label="ARN"
                      value={asset.data.resource_arn || "Not available"}
                    />
                  </div>
                </section>
                <section className="panel asset-detail-panel">
                  <h2>Lifecycle & security summary</h2>
                  <div className="account-facts-list">
                    <Info label="Status" value={asset.data.status} />
                    <Info
                      label="First seen"
                      value={date(asset.data.first_seen_at)}
                    />
                    <Info
                      label="Last seen"
                      value={date(asset.data.last_seen_at)}
                    />
                    <Info
                      label="Updated"
                      value={date(
                        asset.data.updated_at ?? asset.data.last_seen_at,
                      )}
                    />
                    <Info
                      label="Risk"
                      value={
                        risk.data && Object.keys(risk.data.factors).length
                          ? `${risk.data.score} · ${risk.data.level}`
                          : "Not assessed"
                      }
                    />
                    <Info
                      label="Compliance"
                      value={complianceStatusLabel(asset.data.compliance_status)}
                    />
                    <Info
                      label="Last compliance assessment"
                      value={asset.data.compliance_last_assessed_at ? date(asset.data.compliance_last_assessed_at) : "Not available"}
                    />
                    <Info
                      label="Tags"
                      value={
                        Object.keys(asset.data.tags).length
                          ? String(Object.keys(asset.data.tags).length)
                          : "None"
                      }
                    />
                  </div>
                </section>
                <section className="panel asset-detail-panel">
                  <h2>Tags</h2>
                  {Object.entries(asset.data.tags).length ? (
                    <div className="asset-tags">
                      {Object.entries(asset.data.tags).map(([key, value]) => (
                        <span key={key}>
                          <b>{key}</b>
                          {value}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="empty-inline">No tags were collected.</div>
                  )}
                </section>
              </div>
            )}
            {tab === "configuration" && (
              <section className="panel account-tab-panel">
                <div className="panel-heading">
                  <div>
                    <h2>Collected configuration</h2>
                    <p>
                      Sanitized normalized attributes captured by the latest
                      scan.
                    </p>
                  </div>
                </div>
                {Object.keys(asset.data.attributes).length ? (
                  <pre className="json-view">
                    {JSON.stringify(asset.data.attributes, null, 2)}
                  </pre>
                ) : (
                  <div className="empty-inline">
                    Configuration data is not currently available.
                  </div>
                )}
              </section>
            )}
            {tab === "security" && (
              <div className="account-detail-grid">
                <section className="panel">
                  <h2>Security metadata</h2>
                  {securityAttributes.length ? (
                    <div className="account-facts-list">
                      {securityAttributes.map(([key, value]) => (
                        <Info
                          key={key}
                          label={key.replaceAll("_", " ")}
                          value={
                            typeof value === "string"
                              ? value
                              : JSON.stringify(value)
                          }
                        />
                      ))}
                    </div>
                  ) : (
                    <div className="empty-inline">
                      No security-specific configuration attributes were
                      collected.
                    </div>
                  )}
                </section>
                <section className="panel">
                  <h2>Security assessment</h2>
                  <div className="account-facts-list">
                    <Info
                      label="Risk"
                      value={
                        risk.data && Object.keys(risk.data.factors).length
                          ? `${risk.data.score} · ${risk.data.level}`
                          : "Not assessed"
                      }
                    />
                    <Info
                      label="Compliance"
                      value={complianceStatusLabel(asset.data.compliance_status)}
                    />
                    <Info
                      label="Last assessment"
                      value={asset.data.compliance_last_assessed_at ? date(asset.data.compliance_last_assessed_at) : "Not available"}
                    />
                  </div>
                </section>
              </div>
            )}
            {tab === "relationships" && (
              <section className="panel account-tab-panel">
                <h2>Known relationships</h2>
                {relationships.isLoading ? (
                  <div className="state-panel">Loading relationships…</div>
                ) : relationships.error ? (
                  <div className="error-state">
                    Relationships could not be loaded:{" "}
                    {relationships.error.message}
                  </div>
                ) : relationships.data?.length ? (
                  <ul className="relationship-list">
                    {relationships.data.map((edge) => (
                      <li key={`${edge.target.id}-${edge.relationship_type}`}>
                        <span>
                          {edge.relationship_type.replaceAll("_", " ")}
                        </span>
                        <Link to={`/assets/${edge.target.id}`}>
                          {edge.target.name || edge.target.resource_id}
                        </Link>
                        <small>
                          {edge.target.resource_type.replaceAll("_", " ")} ·{" "}
                          {edge.target.region_code}
                        </small>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="empty-inline">
                    No relationships have been discovered yet.
                  </div>
                )}
              </section>
            )}
            {tab === "findings" && (
              <section className="panel account-tab-panel">
                <h2>Findings</h2>
                {findings.isLoading ? (
                  <div className="state-panel">Loading findings…</div>
                ) : findings.error ? (
                  <div className="error-state">
                    Findings could not be loaded: {findings.error.message}
                  </div>
                ) : (
                  <FindingTable rows={findings.data?.items ?? []} />
                )}
              </section>
            )}
            {tab === "evidence" && (
              <section className="panel account-tab-panel">
                <h2>Evidence</h2>
                {evidence.isLoading ? (
                  <div className="state-panel">Loading evidence…</div>
                ) : evidence.error ? (
                  <div className="error-state">
                    Evidence could not be loaded: {evidence.error.message}
                  </div>
                ) : evidence.data?.length ? (
                  <div className="table-scroll">
                    <DataTable caption="Asset finding evidence">
                      <thead>
                        <tr>
                          <th scope="col">Finding</th>
                          <th scope="col">Rule version</th>
                          <th scope="col">Scanner</th>
                          <th scope="col">Collected</th>
                          <th scope="col">Observed condition</th>
                        </tr>
                      </thead>
                      <tbody>
                        {evidence.data.map((item) => (
                          <tr key={item.id}>
                            <td>
                              <Link to={`/findings/${item.finding_id}`}>
                                {item.finding_id.slice(0, 8)}
                              </Link>
                            </td>
                            <td>{item.rule_version}</td>
                            <td>{item.scanner_version}</td>
                            <td>{date(item.collected_at)}</td>
                            <td>
                              <code>
                                {JSON.stringify(item.detected_condition)}
                              </code>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </DataTable>
                  </div>
                ) : (
                  <div className="empty-inline">
                    No evidence is available for this asset yet.
                  </div>
                )}
              </section>
            )}
            {tab === "activity" && (
              <section className="panel account-tab-panel">
                <h2>Inventory activity</h2>
                <div className="activity-list">
                  <div>
                    <span className="activity-dot" />
                    <div>
                      <strong>First discovered</strong>
                      <small>{date(asset.data.first_seen_at)}</small>
                    </div>
                  </div>
                  <div>
                    <span className="activity-dot" />
                    <div>
                      <strong>Last observed</strong>
                      <small>
                        {date(asset.data.last_seen_at)} ·{" "}
                        {asset.data.last_scan_job_id
                          ? `Scan ${asset.data.last_scan_job_id.slice(0, 8).toUpperCase()}`
                          : "Scan record unavailable"}
                      </small>
                    </div>
                  </div>
                  <div>
                    <span className="activity-dot" />
                    <div>
                      <strong>
                        Current inventory status: {asset.data.status}
                      </strong>
                      <small>
                        {asset.data.missed_scan_count} consecutive successful
                        scans missed
                      </small>
                    </div>
                  </div>
                </div>
              </section>
            )}
          </>
        )}
      </LoadState>
    </>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="detail-fact">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function PageControls({
  page,
  onOffsetChange,
}: {
  page: Page<unknown> | undefined;
  onOffsetChange: (offset: number) => void;
}) {
  if (!page || page.total === 0) return null;
  return <Pagination total={page.total} offset={page.offset} limit={page.limit} onOffsetChange={onOffsetChange} label="Table pages" />;
}

function FindingTable({
  rows,
  onView,
}: {
  rows: Finding[];
  onView?: (finding: Finding) => void;
}) {
  if (!rows.length)
    return <div className="empty-inline">No findings match this view.</div>;
  return (
    <div className="table-scroll">
      <DataTable caption="Security findings" actions={Boolean(onView)}>
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Finding</th>
            <th scope="col">Asset</th>
            <th scope="col">Account</th>
            <th scope="col">Region</th>
            <th scope="col">Risk</th>
            <th scope="col">Status</th>
            <th scope="col">Assignee</th>
            <th scope="col">Updated</th>
            {onView && <th scope="col">Action</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((finding) => (
            <tr key={finding.id}>
              <td>
                <span className={severityClass(finding.severity)}>
                  {finding.severity}
                </span>
              </td>
              <td>
                <Link to={`/findings/${finding.id}`} className="row-primary">
                  {finding.title}
                </Link>
                <small>{finding.rule_id}</small>
                {finding.data_origin === "local_mock" && (
                  <small className="asset-sample-label">
                    Simulated policy assessment
                  </small>
                )}
              </td>
              <td>
                <Link to={`/assets/${finding.asset_id}`}>
                  {finding.asset_name || finding.asset_id.slice(0, 12)}
                </Link>
                <small>{finding.asset_type || "Asset"}</small>
              </td>
              <td>
                {finding.account_name || finding.cloud_account_id.slice(0, 12)}
              </td>
              <td>{finding.region_code}</td>
              <td>
                {finding.risk_score == null
                  ? "Not assessed"
                  : finding.risk_score}
              </td>
              <td>
                <span className={`status-pill status-${finding.status.toLowerCase()}`}>
                  {finding.status.replaceAll("_", " ")}
                </span>
              </td>
              <td>
                {finding.assignee_name ? (
                  <span className="finding-assignee-cell">
                    <strong>{finding.assignee_name}</strong>
                    {finding.assignee_role && (
                      <small>{finding.assignee_role.replaceAll("_", " ").toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase())}</small>
                    )}
                  </span>
                ) : "—"}
              </td>
              <td>{date(finding.last_seen_at)}</td>
              {onView && (
                <td>
                  <div className="scan-row-actions">
                    <button
                      type="button"
                      className="scan-view-action"
                      aria-label={`View finding ${finding.id.slice(0, 8)}`}
                      onClick={() => onView(finding)}
                    >
                      <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M2.2 12s3.5-6 9.8-6 9.8 6 9.8 6-3.5 6-9.8 6-9.8-6-9.8-6Z" />
                        <circle cx="12" cy="12" r="2.8" />
                      </svg>
                      <span>View</span>
                    </button>
                  </div>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </DataTable>
    </div>
  );
}

export function FindingsPage() {
  const { user } = useAuth();
  const [searchParams] = useSearchParams();
  const [search, setSearch] = useState(searchParams.get("asset_id") ?? "");
  const [severity, setSeverity] = useState(
    searchParams.get("severity")?.toUpperCase() ?? "",
  );
  const [status, setStatus] = useState(
    searchParams.get("status")?.toUpperCase() ?? "",
  );
  const [accountId, setAccountId] = useState("");
  const [region, setRegion] = useState("");
  const [category, setCategory] = useState("");
  const [assetType, setAssetType] = useState("");
  const [framework, setFramework] = useState("");
  const [complianceControl, setComplianceControl] = useState(
    searchParams.get("compliance_control") ?? "",
  );
  const [detectedFrom, setDetectedFrom] = useState("");
  const [detectedTo, setDetectedTo] = useState("");
  const [overdue, setOverdue] = useState("");
  const [assignedToMe, setAssignedToMe] = useState(false);
  const [offset, setOffset] = useState(0);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const accounts = useLoad<Account[]>(
    "accounts",
    "/cloud-accounts",
    Boolean(user?.permissions.includes("cloud_accounts:read")),
  );
  const kpis = useLoad<{
    open: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    overdue: number;
    suppressed: number;
    resolved: number;
  }>("finding-kpis", "/findings/kpis");
  const filterOptions = useLoad<{
    categories: string[];
    regions: string[];
    asset_types: string[];
    frameworks: string[];
  }>("finding-filter-options", "/findings/filter-options");
  const filters = new URLSearchParams({
    page_size: "30",
    offset: String(offset),
  });
  if (search) filters.set("search", search);
  if (severity) filters.set("severity", severity);
  if (status) filters.set("status", status);
  if (accountId) filters.set("cloud_account_id", accountId);
  if (region) filters.set("region", region);
  if (category) filters.set("category", category);
  if (assetType) filters.set("asset_type", assetType);
  if (framework) filters.set("framework", framework);
  if (complianceControl) filters.set("compliance_control", complianceControl);
  const detectedFromUtc = detectedFrom
    ? organizationDateToUtcIso(detectedFrom, "start")
    : null;
  const detectedToUtc = detectedTo
    ? organizationDateToUtcIso(detectedTo, "end")
    : null;
  if (detectedFromUtc) filters.set("detected_from", detectedFromUtc);
  if (detectedToUtc) filters.set("detected_to", detectedToUtc);
  if (overdue) filters.set("overdue", overdue);
  if (assignedToMe && user) filters.set("assigned_to_user_id", user.id);
  const query = useLoad<Page<Finding>>(
    "findings-list",
    `/findings?${filters.toString()}`,
  );
  const exportFindings = useMutation({
    mutationFn: () => api.get<Blob>(`/findings/export?${filters.toString()}`),
    onSuccess: (blob) => {
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "cloudsentinel-findings.csv";
      anchor.click();
      URL.revokeObjectURL(url);
    },
  });
  const rows = query.data?.items ?? [];
  return (
    <>
      <PageHeader
        eyebrow="SECURITY"
        title="Findings"
        description="Investigate evidence-backed security conditions across the organization."
        action={
          <button
            className="secondary-button"
            disabled={exportFindings.isPending || !query.data?.total}
            onClick={() => exportFindings.mutate()}
          >
            {exportFindings.isPending ? "Exporting…" : "Export CSV"}
          </button>
        }
      />
      {exportFindings.error && (
        <div className="error-state" role="alert">
          Could not export findings: {exportFindings.error.message}
        </div>
      )}
      <div className="metric-grid">
        <Metric
          label="Open"
          value={kpis.data?.open ?? "—"}
          suffix="Active findings"
        />
        <Metric
          label="Critical"
          value={kpis.data?.critical ?? "—"}
          suffix="Critical severity"
          tone="critical"
        />
        <Metric
          label="High"
          value={kpis.data?.high ?? "—"}
          suffix="High severity"
        />
        <Metric
          label="Medium"
          value={kpis.data?.medium ?? "—"}
          suffix="Medium severity"
        />
        <Metric
          label="Low"
          value={kpis.data?.low ?? "—"}
          suffix="Low severity"
        />
        <Metric
          label="Overdue"
          value={kpis.data?.overdue ?? "—"}
          suffix="Past due date"
          tone="critical"
        />
        <Metric
          label="Suppressed"
          value={kpis.data?.suppressed ?? "—"}
          suffix="Approved suppressions"
        />
        <Metric
          label="Resolved"
          value={kpis.data?.resolved ?? "—"}
          suffix="Resolved or verified"
        />
      </div>
      <div className="findings-filter-toolbar">
        <div className="findings-filter-line">
        <div className="findings-search-field">
          <FilterField label="Search" className="filter-field-search"><input
            aria-label="Search findings"
            placeholder="Search finding, policy ID, description, or asset ID"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setOffset(0);
            }}
          /></FilterField>
          {complianceControl && (
            <button
              className="status-pill"
              onClick={() => {
                setComplianceControl("");
                setOffset(0);
              }}
            >
              Control {complianceControl} ×
            </button>
          )}
        </div>
        <FilterField label="Severity"><select
          aria-label="Filter severity"
          value={severity}
          onChange={(event) => {
            setSeverity(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All severity</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map(
            (item) => (
              <option key={item}>{item}</option>
            ),
          )}
        </select></FilterField>
        <FilterField label="Status"><select
          aria-label="Filter status"
          value={status}
          onChange={(event) => {
            setStatus(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All status</option>
          {[
            "OPEN",
            "TRIAGED",
            "ASSIGNED",
            "IN_PROGRESS",
            "RESOLVED",
            "VERIFIED",
            "CLOSED",
            "SUPPRESSED",
          ].map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select></FilterField>
        <FilterField label="Cloud account"><select
          aria-label="Filter cloud account"
          value={accountId}
          onChange={(event) => {
            setAccountId(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All accounts</option>
          {accounts.data?.map((account) => (
            <option key={account.id} value={account.id}>
              {account.name}
            </option>
          ))}
        </select></FilterField>
        <FilterField label="Region"><select
          aria-label="Filter region"
          value={region}
          onChange={(event) => {
            setRegion(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All regions</option>
          {filterOptions.data?.regions.map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select></FilterField>
        </div>
        <div className="findings-filter-line findings-filter-line-secondary">
        <FilterField label="Category"><select
          aria-label="Filter category"
          value={category}
          onChange={(event) => {
            setCategory(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All categories</option>
          {filterOptions.data?.categories.map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select></FilterField>
        <FilterField label="Asset type"><select
          aria-label="Filter asset type"
          value={assetType}
          onChange={(event) => {
            setAssetType(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All asset types</option>
          {filterOptions.data?.asset_types.map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select></FilterField>
        <FilterField label="Framework"><select
          aria-label="Filter framework"
          value={framework}
          onChange={(event) => {
            setFramework(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All frameworks</option>
          {filterOptions.data?.frameworks.map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select></FilterField>
        <label className="finding-date-filter scan-date-filter">
          From
          <input
            aria-label="Detected from"
            type="date"
            max={detectedTo || undefined}
            value={detectedFrom}
            onClick={(event) => { try { event.currentTarget.showPicker?.(); } catch { /* Browser picker already open or unsupported. */ } }}
            onChange={(event) => {
              setDetectedFrom(event.target.value);
              setOffset(0);
            }}
          />
        </label>
        <label className="finding-date-filter scan-date-filter">
          To
          <input
            aria-label="Detected to"
            type="date"
            min={detectedFrom || undefined}
            value={detectedTo}
            onClick={(event) => { try { event.currentTarget.showPicker?.(); } catch { /* Browser picker already open or unsupported. */ } }}
            onChange={(event) => {
              setDetectedTo(event.target.value);
              setOffset(0);
            }}
          />
        </label>
        <FilterField label="Due date"><select
          aria-label="Overdue filter"
          value={overdue}
          onChange={(event) => {
            setOverdue(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All due dates</option>
          <option value="true">Overdue</option>
          <option value="false">Not overdue</option>
        </select></FilterField>
        <label className="inline-filter">
          <input
            type="checkbox"
            checked={assignedToMe}
            onChange={(event) => {
              setAssignedToMe(event.target.checked);
              setOffset(0);
            }}
          />{" "}
          Assigned to me
        </label>
        <span>{query.data?.total ?? 0} findings</span>
        </div>
        <FilterFooter className="scan-filter-footer" active={Boolean(search || severity || status || accountId || region || category || assetType || framework || complianceControl || detectedFrom || detectedTo || overdue || assignedToMe)} onReset={() => {
              setSearch(""); setSeverity(""); setStatus(""); setAccountId("");
              setRegion(""); setCategory(""); setAssetType(""); setFramework("");
              setComplianceControl(""); setDetectedFrom(""); setDetectedTo("");
              setOverdue(""); setAssignedToMe(false); setOffset(0);
            }} />
      </div>
      <section className="panel table-panel">
        <LoadState
          loading={query.isLoading}
          error={query.error}
          empty={!rows.length}
        >
          <FindingTable rows={rows} onView={setSelectedFinding} />
        </LoadState>
      </section>
      <PageControls page={query.data} onOffsetChange={setOffset} />
      {selectedFinding && (
        <RightDrawer
          className="finding-preview-drawer"
          title="Finding details"
          description={`${selectedFinding.rule_id} · ${selectedFinding.category} · ${selectedFinding.region_code}`}
          onClose={() => setSelectedFinding(null)}
        >
          <section className="scan-preview-hero finding-preview-hero">
            <div>
              <span className="eyebrow">FINDING · {selectedFinding.id.slice(0, 8).toUpperCase()}</span>
              <strong>{selectedFinding.title}</strong>
              <small>{selectedFinding.rule_id} · {selectedFinding.category}</small>
            </div>
            <div className="finding-preview-badges">
              <span className={severityClass(selectedFinding.severity)}>{selectedFinding.severity}</span>
              <span className={`status-pill status-${selectedFinding.status.toLowerCase()}`}>{selectedFinding.status.replaceAll("_", " ")}</span>
            </div>
          </section>
          <div className="scan-preview-stats finding-preview-stats">
            <div className="finding-preview-risk-score">
              <span>Calculated risk</span>
              <strong>{selectedFinding.risk_score == null ? "Not assessed" : `${selectedFinding.risk_score} / 100`}</strong>
              {selectedFinding.risk_score != null && <RiskProgress value={selectedFinding.risk_score} label={`Risk score ${selectedFinding.risk_score} out of 100`} />}
            </div>
            <div><span>First detected</span><strong>{date(selectedFinding.first_seen_at)}</strong></div>
          </div>
          <section className="scan-preview-section">
            <h3>Investigation context</h3>
            <div className="scan-preview-facts">
              <DrawerFact label="Finding ID" value={selectedFinding.id} />
              <DrawerFact label="Asset" value={selectedFinding.asset_name || selectedFinding.asset_id} />
              <DrawerFact label="Account" value={selectedFinding.account_name || selectedFinding.cloud_account_id} />
              <DrawerFact label="Region" value={selectedFinding.region_code} />
              <DrawerFact label="Last detected" value={date(selectedFinding.last_seen_at)} />
              <DrawerFact label="Assignee" value={selectedFinding.assignee_name || "Unassigned"} />
              <DrawerFact label="Due date" value={selectedFinding.due_at ? date(selectedFinding.due_at) : "Not set"} />
            </div>
          </section>
          <section className="scan-preview-section finding-preview-copy">
            <h3>What was detected</h3>
            <p>{selectedFinding.description}</p>
            <h3>Recommended remediation</h3>
            <p>{selectedFinding.remediation}</p>
          </section>
          <div className="drawer-actions scan-preview-actions">
            <Link
              className="primary-button"
              to={`/findings/${selectedFinding.id}`}
              onClick={() => setSelectedFinding(null)}
            >
              Open full details
            </Link>
            <Link className="secondary-button" to={`/assets/${selectedFinding.asset_id}`} onClick={() => setSelectedFinding(null)}>View asset</Link>
            <Link className="secondary-button" to={`/policies?search=${encodeURIComponent(selectedFinding.rule_id)}`} onClick={() => setSelectedFinding(null)}>View policy</Link>
          </div>
        </RightDrawer>
      )}
    </>
  );
}

type FindingDetail = Finding & {
  risk_score: number | null;
  risk_level: string | null;
  risk_factors: Record<string, unknown>;
  risk_model: string | null;
  risk_model_version: string | null;
  risk_calculated_at: string | null;
  evidence: {
    id: string;
    scan_job_id: string;
    rule_version: string;
    scanner_version: string;
    source: string;
    expected_state: Record<string, unknown>;
    detected_condition: Record<string, unknown>;
    configuration: Record<string, unknown>;
    collected_at: string;
  }[];
  compliance_controls: {
    framework_code: string;
    framework_name: string;
    framework_version: string;
    control_code: string;
    title: string;
  }[];
  events: {
    id: string;
    actor_user_id: string;
    action: string;
    from_status: string | null;
    to_status: string | null;
    reason: string | null;
    created_at: string;
  }[];
};

export function FindingDetailPage() {
  const { findingId = "" } = useParams();
  const query = useLoad<FindingDetail>(
    `finding-${findingId}`,
    `/findings/${findingId}`,
  );
  const { user } = useAuth();
  const client = useQueryClient();
  const [statusComment, setStatusComment] = useState("");
  const [suppressionReason, setSuppressionReason] = useState("");
  const [remediationNote, setRemediationNote] = useState("");
  const [workflowFeedback, setWorkflowFeedback] = useState<{
    action: "assignment" | "status" | "suppression" | "remediation";
    message: string;
    kind: "success" | "error";
  } | null>(null);
  const [suppressionExpiration, setSuppressionExpiration] = useState(() =>
    new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10),
  );
  const [assigneeId, setAssigneeId] = useState("");
  const [assignmentDue, setAssignmentDue] = useState("");
  const assignmentDueRef = useRef<HTMLInputElement>(null);
  const suppressionExpirationRef = useRef<HTMLInputElement>(null);
  const assignees = useLoad<{ id: string; display_name: string }[]>(
    "finding-assignees",
    "/findings/assignees",
    Boolean(user?.permissions.includes("findings:assign")),
  );
  const transition = useMutation({
    mutationFn: (body: { status: string; reason?: string }) =>
      api.post(`/findings/${findingId}/transition`, body),
    onSuccess: (_result, body) => {
      setWorkflowFeedback({
        action: "status",
        message: `Finding status updated to ${body.status.replaceAll("_", " ").toLowerCase()}.`,
        kind: "success",
      });
      client.invalidateQueries({ queryKey: [`finding-${findingId}`] });
    },
  });
  const suppress = useMutation({
    mutationFn: () => {
      const expiresAt = organizationDateToUtcIso(suppressionExpiration, "end");
      if (!expiresAt) throw new Error("Choose a valid suppression expiry date.");
      return api.post(`/findings/${findingId}/suppress`, {
        reason: suppressionReason,
        expires_at: expiresAt,
      });
    },
    onSuccess: () => {
      setSuppressionReason("");
      setWorkflowFeedback({
        action: "suppression",
        message: "Suppression request submitted and recorded in activity.",
        kind: "success",
      });
      client.invalidateQueries({ queryKey: [`finding-${findingId}`] });
    },
  });
  const assign = useMutation({
    mutationFn: () => {
      const dueAt = assignmentDue
        ? organizationDateToUtcIso(assignmentDue, "end")
        : query.data?.due_at ?? null;
      if (assignmentDue && !dueAt) throw new Error("Choose a valid due date.");
      return api.post(`/findings/${findingId}/assign`, {
        assignee_user_id: assigneeId,
        due_at: dueAt,
      });
    },
    onSuccess: () => {
      setWorkflowFeedback({
        action: "assignment",
        message: "Finding assigned successfully. The activity log has been updated.",
        kind: "success",
      });
      client.invalidateQueries({ queryKey: [`finding-${findingId}`] });
    },
  });
  const remediate = useMutation({
    mutationFn: () =>
      api.post("/findings/" + findingId + "/remediation", {
        request_note: remediationNote,
      }),
    onSuccess: () => {
      setRemediationNote("");
      setWorkflowFeedback({
        action: "remediation",
        message: "Approval request submitted. No cloud changes were executed.",
        kind: "success",
      });
    },
  });
  const finding = query.data;
  async function run(
    action: () => Promise<unknown>,
    actionType: "assignment" | "status" | "suppression" | "remediation",
  ) {
    setWorkflowFeedback((current) => current?.action === actionType ? null : current);
    try {
      await action();
    } catch (error) {
      setWorkflowFeedback({
        action: actionType,
        message: error instanceof Error ? error.message : "Action failed. Please try again.",
        kind: "error",
      });
    }
  }
  function actionFeedback(
    action: "assignment" | "status" | "suppression" | "remediation",
  ) {
    if (workflowFeedback?.action !== action) return null;
    return (
      <div className={`finding-workflow-feedback finding-workflow-feedback-${workflowFeedback.kind}`} role="status">
        <span aria-hidden="true">{workflowFeedback.kind === "success" ? "✓" : "!"}</span>
        {workflowFeedback.message}
      </div>
    );
  }
  return (
    <>
      <PageHeader
        eyebrow="SECURITY / INVESTIGATION"
        title={finding?.title ?? "Finding details"}
        description={
          finding
            ? `${finding.id} · ${finding.rule_id} · ${finding.category} · ${finding.region_code}`
            : "Evidence, risk, and action history for this finding."
        }
        action={
          <Link to="/findings" className="quiet-button">
            ← Findings
          </Link>
        }
      />
      <LoadState loading={query.isLoading} error={query.error}>
        {finding && (
          <>
            <div className="finding-summary finding-detail-hero panel">
              <div>
                <div className="finding-detail-hero-meta">
                  <span className="finding-detail-id">FINDING · {finding.id}</span>
                  <div className="finding-preview-badges">
                    <span className={severityClass(finding.severity)}>{finding.severity}</span>
                    <span className={`status-pill status-${finding.status.toLowerCase()}`}>{finding.status.replaceAll("_", " ")}</span>
                  </div>
                </div>
                {finding.data_origin === "local_mock" && (
                  <p className="asset-sample-label finding-sample-note">
                    Simulated policy assessment on local sample inventory.
                  </p>
                )}
                <p className="finding-detail-description">{finding.description}</p>
              </div>
              <div className="risk-score">
                <span>RISK SCORE</span>
                <strong>{finding.risk_score ?? "—"}</strong>
                <small>{finding.risk_level ?? "Not assessed"}</small>
                {finding.risk_score != null && <RiskProgress value={finding.risk_score} label={`Risk score ${finding.risk_score} out of 100`} />}
              </div>
            </div>
            <section className="panel risk-assessment-panel finding-detail-section">
              <div className="panel-heading">
                <div>
                  <h2>Risk assessment</h2>
                  <p>Policy severity remains separate from calculated risk.</p>
                </div>
                <span>
                  {finding.risk_model
                    ? `${finding.risk_model} v${finding.risk_model_version}`
                    : "Model unavailable"}
                </span>
              </div>
              {finding.risk_score == null ? (
                <div className="empty-inline">
                  Risk has not been assessed for this finding.
                </div>
              ) : (
                <div className="risk-factor-grid">
                  {Object.entries(finding.risk_factors).map(([name, value]) => (
                    <div className="finding-risk-factor" key={name}>
                      <span>{name.replaceAll("_", " ")}</span>
                      <strong>{String(value)}</strong>
                      {typeof value === "number" && <progress max="100" value={Math.min(100, Math.max(0, value))} aria-label={`${name.replaceAll("_", " ")} ${value} out of 100`} />}
                    </div>
                  ))}
                </div>
              )}
              {finding.risk_calculated_at && finding.risk_score != null && (
                <p className="finding-risk-calculated">Calculated {date(finding.risk_calculated_at)}</p>
              )}
            </section>
            <section className="panel finding-context-strip finding-detail-context">
              <div>
                <span>Rule</span>
                <strong>
                  {finding.rule_id} · v{finding.rule_version}
                </strong>
              </div>
              <div>
                <span>Asset</span>
                <strong>{finding.asset_name}</strong>
              </div>
              <div>
                <span>Account</span>
                <strong>{finding.account_name}</strong>
              </div>
              <div>
                <span>Region</span>
                <strong>{finding.region_code}</strong>
              </div>
              <div>
                <span>Detected</span>
                <strong>{date(finding.first_seen_at)}</strong>
              </div>
              <div>
                <span>Last observed</span>
                <strong>{date(finding.last_seen_at)}</strong>
              </div>
              <div>
                <span>Assignee</span>
                <strong>{finding.assignee_name || "Unassigned"}</strong>
              </div>
              <div>
                <span>Due</span>
                <strong>
                  {finding.due_at ? date(finding.due_at) : "Not set"}
                </strong>
              </div>
            </section>
            <section className="panel finding-workflow-panel">
              <div className="panel-heading"><div><h2>Workflow actions</h2><p>Manage ownership and status, suppress the finding, or request reviewed remediation.</p></div></div>
              <div className="finding-workflow-grid">
                {user?.permissions.includes("findings:assign") && ["TRIAGED", "ASSIGNED"].includes(finding.status) && (
                  <div className="finding-action-card finding-assignment-card">
                    <div className="finding-action-heading"><span className="finding-action-step" aria-hidden="true">01</span><div><h3>Assignment</h3><p>Choose a member to own this finding. A due date is optional.</p></div></div>
                    <div className="finding-action-fields">
                      <label><span className="finding-field-label">Assignee <span className="field-required">Required</span></span><select aria-label="Finding assignee" value={assigneeId || finding.assigned_to_user_id || ""} onChange={(event) => setAssigneeId(event.target.value)}><option value="">Select a team member</option>{assignees.data?.map((member) => <option key={member.id} value={member.id}>{member.display_name}</option>)}</select></label>
                      <label><span className="finding-field-label">Due date <span className="field-optional">Optional</span></span><div className="finding-date-control"><input ref={assignmentDueRef} aria-label="Finding due date" type="date" value={assignmentDue || query.data?.due_at?.slice(0, 10) || ""} onChange={(event) => setAssignmentDue(event.target.value)} /><button type="button" aria-label="Open due date calendar" onClick={() => { const input = assignmentDueRef.current; if (!input) return; if (typeof input.showPicker === "function") input.showPicker(); else { input.focus(); input.click(); } }}><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5" width="18" height="16" rx="2" /><path d="M16 3v4M8 3v4M3 10h18" /></svg></button></div></label>
                    </div>
                    <div className="finding-action-footer"><span>Assignment is recorded in the finding activity.</span><button className="primary-button" disabled={(!assigneeId && !finding.assigned_to_user_id) || assign.isPending} onClick={() => run(() => assign.mutateAsync(), "assignment")}>{assign.isPending ? "Saving assignment…" : "Save assignment"}</button></div>
                    {actionFeedback("assignment")}
                  </div>
                )}
                {user?.permissions.includes("findings:update") && (
                  <div className="finding-action-card finding-status-card">
                    <div className="finding-action-heading"><span className="finding-action-step">02</span><div><h3>Investigation status</h3><p>Move this finding through the review workflow.</p></div></div>
                    <label className="finding-action-field"><span className="finding-field-label">Status comment <span className="field-optional">Optional</span></span><textarea aria-label="Finding status comment" placeholder="Add context for the status change" value={statusComment} onChange={(event) => setStatusComment(event.target.value)} rows={3} /></label>
                    <div className="finding-action-buttons">
                      {finding.status === "OPEN" && <button className="secondary-button" onClick={() => run(() => transition.mutateAsync({ status: "TRIAGED", reason: statusComment.trim() || undefined }), "status")}>Triage finding</button>}
                      {["TRIAGED", "ASSIGNED"].includes(finding.status) && <button className="secondary-button" onClick={() => run(() => transition.mutateAsync({ status: "IN_PROGRESS", reason: statusComment.trim() || undefined }), "status")}>Start investigation</button>}
                      {finding.status === "IN_PROGRESS" && <button className="secondary-button" onClick={() => run(() => transition.mutateAsync({ status: "RESOLVED", reason: statusComment.trim() || undefined }), "status")}>Mark resolved</button>}
                      {finding.status === "RESOLVED" && <button className="secondary-button" onClick={() => { if (statusComment.trim().length < 3) { setWorkflowFeedback({ action: "status", message: "Add at least three characters of verification evidence in the status comment.", kind: "error" }); return; } void run(() => transition.mutateAsync({ status: "VERIFIED", reason: statusComment }), "status"); }}>Verify resolution</button>}
                      {!(["OPEN", "TRIAGED", "ASSIGNED", "IN_PROGRESS", "RESOLVED"].includes(finding.status)) && <span className="finding-action-state">No status action is available for this finding.</span>}
                    </div>
                    {actionFeedback("status")}
                  </div>
                )}
                {user?.permissions.includes("findings:suppress") && !["VERIFIED", "CLOSED", "SUPPRESSED"].includes(finding.status) && (
                  <div className="finding-action-card finding-suppression-card">
                    <div className="finding-action-heading"><span className="finding-action-step finding-action-step-alt">ALT</span><div><h3>Alternative: suppress</h3><p>Temporarily pause this finding with a recorded reason. This is an alternative to remediation.</p></div></div>
                    <label className="finding-action-field"><span className="finding-field-label">Suppression reason <span className="field-required">Required</span></span><textarea aria-label="Suppression reason" placeholder="Explain why this finding should be suppressed" value={suppressionReason} onChange={(event) => setSuppressionReason(event.target.value)} rows={3} /></label>
                    <div className="finding-action-fields">
                      <label>Expires on<div className="finding-date-control"><input ref={suppressionExpirationRef} aria-label="Suppression expiration" type="date" value={suppressionExpiration} onChange={(event) => setSuppressionExpiration(event.target.value)} /><button type="button" aria-label="Open suppression expiration calendar" onClick={() => { const input = suppressionExpirationRef.current; if (!input) return; if (typeof input.showPicker === "function") input.showPicker(); else { input.focus(); input.click(); } }}><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5" width="18" height="16" rx="2" /><path d="M16 3v4M8 3v4M3 10h18" /></svg></button></div></label>
                      <div className="finding-approver"><span>Approver</span><strong>{user.display_name}</strong></div>
                    </div>
                    <button className="secondary-button" disabled={suppressionReason.trim().length < 3 || suppress.isPending} onClick={() => run(() => suppress.mutateAsync(), "suppression")}>{suppress.isPending ? "Submitting…" : "Request suppression"}</button>
                    {actionFeedback("suppression")}
                  </div>
                )}
                {user?.permissions.includes("remediation:execute") && !["RESOLVED", "VERIFIED", "CLOSED", "SUPPRESSED"].includes(finding.status) && (
                  <div className="finding-action-card finding-remediation-card">
                    <div className="finding-action-heading"><span className="finding-action-step">03</span><div><h3>Reviewed remediation</h3><p>Submit a recommended fix for approval. No cloud changes happen until an approver authorizes it.</p></div></div>
                    <label className="finding-action-field"><span className="finding-field-label">Request context <span className="field-required">Required</span></span><textarea aria-label="Remediation approval request note" placeholder="Describe the recommended action and approval context" value={remediationNote} onChange={(event) => setRemediationNote(event.target.value)} rows={3} /></label>
                    <button className="primary-button" disabled={remediationNote.trim().length < 3 || remediate.isPending} onClick={() => run(() => remediate.mutateAsync(), "remediation")}>{remediate.isPending ? "Submitting request…" : "Request approval"}</button>
                    {actionFeedback("remediation")}
                  </div>
                )}
              </div>
            </section>
            <div className="two-column">
              <section className="panel finding-detail-section finding-evidence-panel">
                <div className="panel-heading">
                  <div>
                    <h2>Evidence</h2>
                    <p>Collected configuration and matched condition</p>
                  </div>
                </div>
                {finding.evidence.length ? (
                  finding.evidence.map((item) => (
                    <div className="evidence-block" key={item.id}>
                      <div className="evidence-meta">
                        Evidence {item.id} · {item.source} · Rule{" "}
                        {item.rule_version} · Scanner {item.scanner_version} ·{" "}
                        {date(item.collected_at)}
                      </div>
                      <details className="finding-evidence-details">
                        <summary>Expected state <span>View JSON</span></summary>
                        <pre className="json-view">{JSON.stringify(item.expected_state, null, 2)}</pre>
                      </details>
                      <details className="finding-evidence-details">
                        <summary>Detected condition <span>View JSON</span></summary>
                        <pre className="json-view">{JSON.stringify(item.detected_condition, null, 2)}</pre>
                      </details>
                      <details className="finding-evidence-details">
                        <summary>Collected configuration <span>View JSON</span></summary>
                        <pre className="json-view">{JSON.stringify(item.configuration, null, 2)}</pre>
                      </details>
                    </div>
                  ))
                ) : (
                  <div className="empty-inline">
                    No evidence snapshot is available.
                  </div>
                )}
              </section>
              <div className="stack">
                <section className="panel finding-detail-section">
                  <h2>Asset context</h2>
                  <dl className="compact-list">
                    <dt>Asset</dt>
                    <dd>
                      <Link to={`/assets/${finding.asset_id}`}>
                        {finding.asset_name} · {finding.asset_type}
                      </Link>
                    </dd>
                    <dt>Account</dt>
                    <dd>{finding.account_name}</dd>
                    <dt>Region</dt>
                    <dd>{finding.region_code}</dd>
                    <dt>Rule</dt>
                    <dd>{finding.rule_id}</dd>
                  </dl>
                  <h3>Recommended remediation</h3>
                  <p>{finding.remediation}</p>
                  <Link
                    to={`/policies?search=${encodeURIComponent(finding.rule_id)}`}
                  >
                    View policy {finding.rule_id}
                  </Link>
                </section>
                <section className="panel finding-detail-section">
                  <h2>Compliance mapping</h2>
                  {finding.compliance_controls.length ? (
                    finding.compliance_controls.map((control) => (
                      <div
                        className="mapping-row"
                        key={`${control.framework_code}-${control.control_code}`}
                      >
                        <b>{control.control_code}</b>
                        <span>
                          {control.title}
                          <small>
                            {control.framework_name} ·{" "}
                            {control.framework_version}
                          </small>
                        </span>
                      </div>
                    ))
                  ) : (
                    <div className="empty-inline">
                      No verified control mapping.
                    </div>
                  )}
                </section>
                <section className="panel finding-detail-section">
                  <h2>Activity</h2>
                  <div className="timeline">
                    {finding.events.map((event) => (
                      <div key={event.id}>
                        <i />
                        <strong>{event.action.replaceAll("_", " ")}</strong>
                        <small>{date(event.created_at)}</small>
                        {event.reason && <p>{event.reason}</p>}
                      </div>
                    ))}
                  </div>
                </section>
              </div>
            </div>
          </>
        )}
      </LoadState>
    </>
  );
}

export function RiskPage() {
  const [riskMin, setRiskMin] = useState("0");
  const [riskBand, setRiskBand] = useState("");
  const [severity, setSeverity] = useState("");
  const [findingStatus, setFindingStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const query = useLoad<RiskSummary>("risk-summary", "/risk/summary");
  const params = new URLSearchParams({ risk_min: riskMin, limit: "30", offset: String(offset) });
  if (riskBand) params.set("risk_band", riskBand);
  if (severity) params.set("severity", severity);
  if (findingStatus) params.set("status", findingStatus);
  const findings = useLoad<Page<RiskFindingItem>>(
    `risk-findings-${params.toString()}`,
    `/risk/findings?${params.toString()}`,
  );
  const data = query.data;
  return (
    <>
      <PageHeader
        eyebrow="SECURITY / RISK"
        title="Risk intelligence"
        description="Prioritize organization exposure using persisted finding assessments and cumulative asset risk."
      />
      <LoadState loading={query.isLoading} error={query.error}>
        {data && (
          <>
            <div className="risk-overview panel">
              <div>
                <span>ORGANIZATION RISK</span>
                <strong>{data.organization_score ?? "—"}{data.organization_score != null && <small>/100</small>}</strong>
                <b className={data.organization_level ? severityClass(data.organization_level) : ""}>{data.organization_level ?? "Not assessed"}</b>
              </div>
              <p>Scores use CloudSentinel Default v1.0. Asset, account, and organization risk aggregate active finding assessments; verified and closed findings are inactive.</p>
            </div>
            <div className="metric-grid risk-metric-grid">
              {[
                ["Total", data.critical + data.high + data.medium + data.low + data.informational, "risk"],
                ["Critical", data.critical, "critical"],
                ["High", data.high, "high"],
                ["Medium", data.medium, "medium"],
                ["Low", data.low, "low"],
                ["Informational", data.informational, "info"],
              ].map(([name, count, tone]) => (
                <Metric key={String(name)} label={String(name)} value={count} suffix="Current count" tone={String(tone)} />
              ))}
            </div>
            <section className="panel table-panel">
              <div className="panel-heading"><div><h2>Highest risk findings</h2><p>Persisted risk assessments ranked by score</p></div></div>
              <div className="action-strip risk-filters">
                <FilterField label="Minimum risk"><input aria-label="Minimum risk score" type="number" min="0" max="100" value={riskMin} onChange={(event) => { setRiskMin(event.target.value); setOffset(0); }} /></FilterField>
                <FilterField label="Risk band"><select aria-label="Filter by risk band" value={riskBand} onChange={(event) => { setRiskBand(event.target.value); setOffset(0); }}><option value="">All bands</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((item) => <option key={item} value={item}>{item}</option>)}</select></FilterField>
                <FilterField label="Severity"><select aria-label="Filter by severity" value={severity} onChange={(event) => { setSeverity(event.target.value); setOffset(0); }}><option value="">All severities</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((item) => <option key={item} value={item}>{item}</option>)}</select></FilterField>
                <FilterField label="Finding status"><select aria-label="Filter by finding status" value={findingStatus} onChange={(event) => { setFindingStatus(event.target.value); setOffset(0); }}><option value="">All active</option>{["OPEN", "TRIAGED", "ASSIGNED", "IN_PROGRESS", "RESOLVED", "SUPPRESSED"].map((item) => <option key={item} value={item}>{item.replaceAll("_", " ")}</option>)}</select></FilterField>
              </div>
              <FilterFooter className="scan-filter-footer" active={Boolean(riskMin !== "0" || riskBand || severity || findingStatus)} onReset={() => { setRiskMin("0"); setRiskBand(""); setSeverity(""); setFindingStatus(""); setOffset(0); }} />
              <LoadState loading={findings.isLoading} error={findings.error} empty={!findings.data?.items.length}>
                <div className="table-scroll"><DataTable caption="Risk findings" actions>
                  <thead><tr><th scope="col">Finding</th><th scope="col">Severity</th><th scope="col">Asset</th><th scope="col">Account</th><th scope="col">Status</th><th scope="col">Risk</th><th scope="col">Actions</th></tr></thead>
                  <tbody>{(findings.data?.items ?? []).map((item) => <tr key={item.id}>
                    <td>{item.title}</td>
                    <td><span className={`status-pill ${severityClass(item.severity)}`}>{item.severity}</span></td>
                    <td><Link to={`/assets/${item.asset_id}`}>{item.asset_name ?? "Asset"}</Link></td>
                    <td>{item.account_name ?? "—"}</td>
                    <td>{item.status.replaceAll("_", " ")}</td>
                    <td><b className={severityClass(item.level)}>{item.score} · {item.level}</b></td>
                    <td><Link className="scan-view-action" aria-label={`View finding ${item.title}`} to={`/findings/${item.id}`}><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.2 12s3.5-6 9.8-6 9.8 6 9.8 6-3.5 6-9.8 6-9.8-6-9.8-6Z" /><circle cx="12" cy="12" r="2.8" /></svg><span>View</span></Link></td>
                  </tr>)}</tbody>
                </DataTable></div>
                {findings.data && <Pagination total={findings.data.total} offset={offset} limit={30} onOffsetChange={setOffset} label="Risk finding pages" />}
              </LoadState>
            </section>
          </>
        )}
      </LoadState>
    </>
  );
}

export function CompliancePage() {
  const query = useLoad<Framework[]>(
    "compliance-frameworks",
    "/compliance/frameworks",
  );
  const [selectedFramework, setSelectedFramework] = useState("");
  const framework = selectedFramework || query.data?.[0]?.code || "";
  const [status, setStatus] = useState("");
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [provider, setProvider] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [assessedAfter, setAssessedAfter] = useState("");
  const [assessedBefore, setAssessedBefore] = useState("");
  const [controlOffset, setControlOffset] = useState(0);
  const [recordOffset, setRecordOffset] = useState(0);
  const [recordStatus, setRecordStatus] = useState("");
  const [selected, setSelected] = useState<ComplianceControl | null>(null);
  const summary = useLoad<{
    frameworks: number;
    compliance_score: number | null;
    passing_controls: number;
    failing_controls: number;
    partial_controls: number;
    not_assessed_controls: number;
    not_applicable_controls: number;
    critical_failures: number;
  }>("compliance-summary", "/compliance/summary");
  const recordParams = new URLSearchParams({
    offset: String(recordOffset),
    limit: "50",
  });
  if (recordStatus) recordParams.set("status", recordStatus);
  const assessmentRecordsEnabled =
    !query.isLoading && !query.error && query.data?.length === 0;
  const assessmentRecords = useLoad<ComplianceAssessmentRecordPage>(
    `compliance-assessment-records-${recordStatus}-${recordOffset}`,
    `/compliance/assessment-records?${recordParams.toString()}`,
    assessmentRecordsEnabled,
  );
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (category) params.set("category", category);
  if (severity) params.set("severity", severity);
  if (provider) params.set("provider", provider);
  const assessedAfterUtc = assessedAfter
    ? organizationDateToUtcIso(assessedAfter, "start")
    : null;
  const assessedBeforeUtc = assessedBefore
    ? organizationDateToUtcIso(assessedBefore, "end")
    : null;
  if (assessedAfterUtc) params.set("assessed_after", assessedAfterUtc);
  if (assessedBeforeUtc) params.set("assessed_before", assessedBeforeUtc);
  const controls = useLoad<ComplianceControl[]>(
    `compliance-controls-${framework}-${params.toString()}`,
    framework ? `/compliance/frameworks/${framework}/controls?${params}` : "",
    Boolean(framework),
  );
  const filteredControls = (controls.data ?? []).filter((item) => {
    const term = searchTerm.trim().toLowerCase();
    return !term || [item.code, item.title, item.category, item.severity, item.status]
      .some((value) => (value ?? "").toLowerCase().includes(term));
  });
  const maxControlOffset = Math.max(0, Math.ceil(filteredControls.length / 30) - 1) * 30;
  const visibleControlOffset = Math.min(controlOffset, maxControlOffset);
  const visibleControls = filteredControls.slice(visibleControlOffset, visibleControlOffset + 30);
  const categories = useLoad<
    {
      category: string;
      total: number;
      passed: number;
      failed: number;
      partial: number;
      not_assessed: number;
      compliance_score: number | null;
    }[]
  >(
    `compliance-categories-${framework}`,
    framework ? `/compliance/frameworks/${framework}/categories` : "",
    Boolean(framework),
  );
  return (
    <>
      <PageHeader
        eyebrow="SECURITY / COMPLIANCE"
        title="Compliance"
        description="Framework compliance posture and control assessments from policy evaluations. Compliance status and security risk are assessed separately."
      />
      <div className="panel settings-policy-note compliance-benchmark-note" role="note">
        <strong>CIS AWS Foundations · 7.1.0 · Mapping unverified</strong>
        <p>The benchmark version is recorded, but CloudSentinel's control mapping is being reviewed. CIS coverage is disabled until that review is complete.</p>
        <a href="https://www.cisecurity.org/benchmark/amazon-web-services" target="_blank" rel="noreferrer">View CIS AWS Foundations benchmark</a>
      </div>
      <LoadState
        loading={
          query.isLoading ||
          summary.isLoading ||
          (assessmentRecordsEnabled && assessmentRecords.isLoading)
        }
        error={
          query.error ??
          summary.error ??
          (assessmentRecordsEnabled ? assessmentRecords.error : null)
        }
        empty={!query.data?.length && !assessmentRecords.data?.total}
        emptyTitle="No control evaluation records yet"
        emptyMessage="No verified framework is enabled and no scan evaluation records are available for this organization."
      >
        {query.data && query.data.length > 0 && summary.data && (
          <>
            <div className="action-strip compliance-toolbar compliance-framework-picker">
              <label>
                Framework
                <select
                  value={framework}
                  onChange={(event) => { setSelectedFramework(event.target.value); setControlOffset(0); }}
                >
                  {query.data.map((item) => (
                    <option key={item.code} value={item.code}>
                      {item.name} · {item.version}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="metric-grid five compliance-metrics">
              <Metric
                label="Frameworks"
                value={summary.data.frameworks}
                suffix="Available frameworks"
              />
              <Metric
                label="Overall compliance"
                className="compliance-overall-metric"
                value={
                  summary.data.compliance_score == null
                    ? "—"
                    : `${summary.data.compliance_score}%`
                }
                suffix="Assessed control coverage"
                tone="high"
              />
              <Metric
                label="Passing controls"
                value={summary.data.passing_controls}
                suffix="Latest status PASS"
                tone="low"
              />
              <Metric
                label="Failing controls"
                value={summary.data.failing_controls}
                suffix="Latest status FAIL"
                tone="critical"
              />
              <Metric
                label="Partial controls"
                value={summary.data.partial_controls}
                suffix="Mixed assessment outcomes"
              />
            </div>
            <section className="panel table-panel">
              <div className="panel-heading">
                <div>
                  <h2>Controls</h2>
                  <p>Assessment status, coverage, and linked findings</p>
                </div>
              </div>
              <div className="action-strip compliance-toolbar compliance-control-filters">
                <FilterField label="Search controls" className="filter-field-search"><input
                    aria-label="Search controls"
                    type="search"
                    value={searchTerm}
                    onChange={(event) => { setSearchTerm(event.target.value); setControlOffset(0); }}
                    placeholder="ID, control, category"
                  /></FilterField>
                <FilterField label="Status"><select
                    value={status}
                    onChange={(event) => { setStatus(event.target.value); setControlOffset(0); }}
                  >
                    <option value="">All statuses</option>
                    {[
                      "PASS",
                      "FAIL",
                      "PARTIAL",
                      "NOT_ASSESSED",
                      "NOT_APPLICABLE",
                    ].map((item) => (
                      <option key={item}>{item}</option>
                    ))}
                  </select></FilterField>
                <FilterField label="Category"><select
                    value={category}
                    onChange={(event) => { setCategory(event.target.value); setControlOffset(0); }}
                  >
                    <option value="">All categories</option>
                    {categories.data?.map((item) => (
                      <option key={item.category}>{item.category}</option>
                    ))}
                  </select></FilterField>
                <FilterField label="Severity"><select
                    value={severity}
                    onChange={(event) => { setSeverity(event.target.value); setControlOffset(0); }}
                  >
                    <option value="">All severities</option>
                    {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map(
                      (item) => (
                        <option key={item}>{item}</option>
                      ),
                    )}
                  </select></FilterField>
                <FilterField label="Provider"><select
                    value={provider}
                    onChange={(event) => { setProvider(event.target.value); setControlOffset(0); }}
                  >
                    <option value="">All providers</option>
                    <option>AWS</option>
                  </select></FilterField>
                <label>
                  From
                  <input type="date" value={assessedAfter} onChange={(event) => { setAssessedAfter(event.target.value); setControlOffset(0); }} />
                </label>
                <label>
                  To
                  <input type="date" value={assessedBefore} onChange={(event) => { setAssessedBefore(event.target.value); setControlOffset(0); }} />
                </label>
              </div>
              <FilterFooter className="scan-filter-footer" active={Boolean(selectedFramework || status || category || severity || provider || searchTerm || assessedAfter || assessedBefore)} onReset={() => { setSelectedFramework(""); setStatus(""); setCategory(""); setSeverity(""); setProvider(""); setSearchTerm(""); setAssessedAfter(""); setAssessedBefore(""); setControlOffset(0); }} />
              <LoadState
                loading={controls.isLoading}
                error={controls.error}
                empty={!filteredControls.length}
              >
                <div className="table-scroll">
                  <DataTable caption="Compliance controls" actions>
                    <thead>
                      <tr>
                        <th scope="col">Control ID</th>
                        <th scope="col">Control</th>
                        <th scope="col">Framework</th>
                        <th scope="col">Category</th>
                        <th scope="col">Status</th>
                        <th scope="col">Compliance</th>
                        <th scope="col">Findings</th>
                        <th scope="col">Last assessed</th>
                        <th scope="col">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visibleControls.map((item) => (
                        <tr
                          key={item.code}
                          onClick={() => setSelected(item)}
                          className="clickable-row"
                        >
                          <td>
                            <button
                              className="quiet-button"
                              onClick={() => setSelected(item)}
                            >
                              {item.code}
                            </button>
                          </td>
                          <td>{item.title}</td>
                          <td>
                            {query.data.find((f) => f.code === framework)?.name}
                          </td>
                          <td>{item.category ?? "—"}</td>
                          <td>
                            <span
                              className={`compliance-status status-${item.status.toLowerCase()}`}
                            >
                              {item.status.replaceAll("_", " ")}
                            </span>
                          </td>
                          <td>
                            {item.compliance_score == null
                              ? "—"
                              : `${item.compliance_score}%`}
                          </td>
                          <td>{item.finding_ids.length}</td>
                          <td>
                            {item.last_assessed_at
                              ? date(item.last_assessed_at)
                              : "Not assessed"}
                          </td>
                          <td>
                            <button
                              type="button"
                              className="scan-view-action"
                              aria-label={`View compliance control ${item.code}`}
                              onClick={(event) => {
                                event.stopPropagation();
                                setSelected(item);
                              }}
                            >
                              <svg viewBox="0 0 24 24" aria-hidden="true">
                                <path d="M2.2 12s3.5-6 9.8-6 9.8 6 9.8 6-3.5 6-9.8 6-9.8-6-9.8-6Z" />
                                <circle cx="12" cy="12" r="2.8" />
                              </svg>
                              <span>View</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </DataTable>
                </div>
                <Pagination total={filteredControls.length} offset={visibleControlOffset} limit={30} onOffsetChange={setControlOffset} label="Compliance control pages" />
              </LoadState>
            </section>
          </>
        )}
        {!query.data?.length && assessmentRecords.data && (
          <section className="panel table-panel">
            <div className="panel-heading">
              <div>
                <h2>Recorded control evaluations</h2>
                <p>Stored scan results for review, separate from verified framework coverage</p>
              </div>
            </div>
            <div className="panel settings-policy-note compliance-record-note" role="note">
              <strong>CIS mapping is unverified · Compliance score unavailable</strong>
              <p>These records show the results stored by scans. The framework mapping is inactive pending review, so these rows do not represent a CIS compliance attestation. Synthetic demo rows are labeled in the data source column.</p>
            </div>
            <div className="scan-filter-toolbar">
              <FilterField label="Assessment status">
                <select
                  value={recordStatus}
                  onChange={(event) => {
                    setRecordStatus(event.target.value);
                    setRecordOffset(0);
                  }}
                >
                  <option value="">All statuses</option>
                  {[
                    "PASS",
                    "FAIL",
                    "PARTIAL",
                    "NOT_ASSESSED",
                    "NOT_APPLICABLE",
                  ].map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </FilterField>
              <button
                type="button"
                className="text-button"
                disabled={!recordStatus}
                onClick={() => {
                  setRecordStatus("");
                  setRecordOffset(0);
                }}
              >
                Reset filters
              </button>
            </div>
            {assessmentRecords.data.items.length ? (
              <div className="table-scroll">
                <DataTable caption="Recorded compliance evaluation evidence">
                  <thead>
                    <tr>
                      <th scope="col">Framework</th>
                      <th scope="col">Control</th>
                      <th scope="col">Outcome</th>
                      <th scope="col">Account</th>
                      <th scope="col">Asset</th>
                      <th scope="col">Resource type</th>
                      <th scope="col">Region</th>
                      <th scope="col">Assessed</th>
                      <th scope="col">Data source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assessmentRecords.data.items.map((item) => (
                      <tr key={item.assessment_id}>
                        <td>
                          {item.framework_name} · {item.framework_version}
                        </td>
                        <td>
                          <strong>{item.control_code}</strong>
                          <small>{item.control_title}</small>
                        </td>
                        <td>
                          <span
                            className={`compliance-status status-${item.status.toLowerCase()}`}
                          >
                            {item.status.replaceAll("_", " ")}
                          </span>
                        </td>
                        <td>{item.account_name}</td>
                        <td>{item.asset_name}</td>
                        <td>{item.resource_type.replaceAll("_", " ")}</td>
                        <td>{item.region}</td>
                        <td>{date(item.assessed_at)}</td>
                        <td>{item.synthetic ? "Synthetic demo" : "Recorded scan"}</td>
                      </tr>
                    ))}
                  </tbody>
                </DataTable>
              </div>
            ) : (
              <div className="state-panel">No evaluation records match this status.</div>
            )}
            <Pagination
              total={assessmentRecords.data.total}
              offset={recordOffset}
              limit={50}
              onOffsetChange={setRecordOffset}
              disabled={assessmentRecords.isFetching}
              label="Compliance evaluation pages"
            />
          </section>
        )}
      </LoadState>
      {selected && (
        <RightDrawer
          title={`${selected.code} · ${selected.title}`}
          description={`${selected.status} · ${selected.framework_name ?? "Framework"}`}
          onClose={() => setSelected(null)}
        >
          <div className="drawer-facts">
            <DrawerFact
              label="Category"
              value={selected.category ?? "Not classified"}
            />
            <DrawerFact label="Severity" value={selected.severity} />
            <DrawerFact
              label="Compliance"
              value={
                selected.compliance_score == null
                  ? "Not assessed"
                  : `${selected.compliance_score}%`
              }
            />
            <DrawerFact
              label="Affected resources"
              value={String(selected.assessed_assets)}
            />
            <DrawerFact
              label="Open findings"
              value={String(selected.finding_ids.length)}
            />
          </div>
          <p>
            {selected.description ?? "No control description is available."}
          </p>
          <div className="drawer-actions">
            <Link className="primary-button" to={`/compliance/${selected.id}`}>
              View control details
            </Link>
            <Link
              className="secondary-button"
              to={`/findings?compliance_control=${selected.code}`}
            >
              View findings
            </Link>
          </div>
        </RightDrawer>
      )}
    </>
  );
}

export function ComplianceControlDetailsPage() {
  const { controlId = "" } = useParams();
  const control = useLoad<ComplianceControl>(
    `compliance-control-${controlId}`,
    `/compliance/controls/${controlId}`,
    Boolean(controlId),
  );
  const base =
    control.data?.framework_code && control.data.code
      ? `/compliance/frameworks/${control.data.framework_code}/controls/${control.data.code}`
      : "";
  const assessments = useLoad<ComplianceAssessment[]>(
    `compliance-assessments-${controlId}`,
    base ? `${base}/assessments` : "",
    Boolean(base),
  );
  const findings = useLoad<
    {
      id: string;
      title: string;
      remediation: string;
      severity: string;
      status: string;
      asset_id: string;
      asset_name: string;
      risk_score: number | null;
    }[]
  >(
    `compliance-related-findings-${controlId}`,
    base ? `${base}/findings` : "",
    Boolean(base),
  );
  const evidence = useLoad<ComplianceEvidence[]>(
    `compliance-evidence-${controlId}`,
    base ? `${base}/evidence` : "",
    Boolean(base),
  );
  const activity = useLoad<
    { action: string; detail: string; created_at: string }[]
  >(
    `compliance-activity-${controlId}`,
    base ? `${base}/activity` : "",
    Boolean(base),
  );
  return (
    <>
      <PageHeader
        className="compliance-control-page-header"
        eyebrow="COMPLIANCE / CONTROL"
        title={control.data?.title ?? "Control details"}
        description={
          control.data
            ? `${control.data.framework_name} · ${control.data.code} · Version ${control.data.framework_version ?? control.data.version}`
            : "Control assessment and evidence"
        }
        action={
          control.data?.framework_code ? (
            <Link
              className="quiet-button"
              to={`/compliance?framework=${control.data.framework_code}`}
            >
              ← Compliance
            </Link>
          ) : undefined
        }
      />
      <LoadState loading={control.isLoading} error={control.error}>
        {control.data && (
          <>
            <section className="panel control-detail-header control-detail-hero">
              <div>
                <div className="eyebrow">CONTROL REFERENCE</div>
                <strong>{control.data.framework_code} · {control.data.code}</strong>
                <div className="control-detail-tags"><span>{control.data.category ?? control.data.domain ?? "Uncategorized"}</span><span className={`severity severity-${control.data.severity.toLowerCase()}`}>{control.data.severity}</span><span>Version {control.data.version}</span></div>
              </div>
              <span
                className={`compliance-status status-${control.data.status.toLowerCase()}`}
              >
                {control.data.status.replaceAll("_", " ")}
              </span>
            </section>
            <div className="metric-grid five control-detail-metrics">
              <Metric
                label="Assessment"
                value={control.data.status.replaceAll("_", " ")}
                suffix="Latest aggregate status"
              />
              <Metric
                label="Passed"
                value={control.data.passed_assets}
                suffix="Resources passed"
                tone="low"
              />
              <Metric
                label="Failed"
                value={control.data.failed_assets}
                suffix="Resources failed"
                tone="critical"
              />
              <Metric
                label="Not assessed"
                value={Math.max(
                  0,
                  control.data.assessed_assets -
                    control.data.passed_assets -
                    control.data.failed_assets,
                )}
                suffix="No current assessment"
              />
              <Metric
                label="Last assessed"
                value={
                  control.data.last_assessed_at
                    ? date(control.data.last_assessed_at)
                    : "—"
                }
                suffix="Latest evaluation time"
              />
            </div>
            <section className="panel control-description-panel">
              <div className="panel-heading">
                <div>
                  <h2>Control description</h2>
                  <p>
                    {control.data.category ??
                      control.data.domain ??
                      "Uncategorized"}{" "}
                    · {control.data.severity}
                  </p>
                </div>
              </div>
              <p>
                {control.data.description ??
                  "The control registry has no additional description."}
              </p>
            </section>
            <section className="panel table-panel control-resource-panel">
              <div className="panel-heading">
                <div>
                  <h2>Affected resources</h2>
                  <p>Latest tenant assessment for each resource</p>
                </div>
              </div>
              <LoadState
                loading={assessments.isLoading}
                error={assessments.error}
                empty={!assessments.data?.length}
              >
                <div className="table-scroll">
                  <DataTable caption="Resources assessed for this compliance control" className="control-resource-table">
                    <thead>
                      <tr>
                        <th scope="col">Resource</th>
                        <th scope="col">Account</th>
                        <th scope="col">Region</th>
                        <th scope="col">Status</th>
                        <th scope="col">Policy</th>
                        <th scope="col">Assessed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {assessments.data?.map((item) => (
                        <tr key={item.id}>
                          <td>
                            <Link to={`/assets/${item.asset_id}`}>
                              {item.asset_name}
                            </Link>
                            <small className="table-subtext">
                              {item.resource_type}
                            </small>
                          </td>
                          <td>{item.account_name}</td>
                          <td>{item.region}</td>
                          <td><span className={`status-pill status-${item.status.toLowerCase()}`}>{item.status.replaceAll("_", " ")}</span></td>
                          <td>{item.policy_version ?? "—"}</td>
                          <td>{date(item.assessed_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </DataTable>
                </div>
              </LoadState>
            </section>
            <section className="panel table-panel control-findings-panel">
              <div className="panel-heading">
                <div>
                  <h2>Related findings</h2>
                  <p>Policy findings mapped to this control</p>
                </div>
                <Link to={`/findings?compliance_control=${control.data.code}`}>
                  View findings
                </Link>
              </div>
              <LoadState
                loading={findings.isLoading}
                error={findings.error}
                empty={!findings.data?.length}
              >
                <div className="table-scroll">
                  <DataTable caption="Findings linked to this compliance control" className="control-findings-table">
                    <thead>
                      <tr>
                        <th scope="col">Finding</th>
                        <th scope="col">Severity</th>
                        <th scope="col">Status</th>
                        <th scope="col">Asset</th>
                        <th scope="col">Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.data?.map((item) => (
                        <tr key={item.id}>
                          <td>
                            <Link to={`/findings/${item.id}`}>
                              {item.title}
                            </Link>
                          </td>
                          <td><span className={severityClass(item.severity)}>{item.severity}</span></td>
                          <td><span className={`status-pill status-${item.status.toLowerCase()}`}>{item.status.replaceAll("_", " ")}</span></td>
                          <td>
                            <Link to={`/assets/${item.asset_id}`}>
                              {item.asset_name}
                            </Link>
                          </td>
                          <td>{item.risk_score ?? "Not assessed"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </DataTable>
                </div>
              </LoadState>
            </section>
            <section className="panel compliance-control-detail-section">
              <div className="panel-heading">
                <div>
                  <h2>Evidence</h2>
                  <p>Sanitized source evidence linked to this control</p>
                </div>
              </div>
              <LoadState
                loading={evidence.isLoading}
                error={evidence.error}
                empty={!evidence.data?.length}
              >
                <div className="compliance-evidence-list">
                  {evidence.data?.map((item) => (
                    <article key={item.id}>
                      <h3>{item.asset_name}</h3>
                      <small>
                        Source: {item.source} · Evidence {item.id} ·{" "}
                        {date(item.collected_at)}
                      </small>
                      <div>
                        <span>Expected</span>
                        <pre>
                          {JSON.stringify(item.expected_state, null, 2)}
                        </pre>
                      </div>
                      <div>
                        <span>Observed</span>
                        <pre>
                          {JSON.stringify(item.observed_state, null, 2)}
                        </pre>
                      </div>
                      <div>
                        <span>Configuration</span>
                        <pre>{JSON.stringify(item.configuration, null, 2)}</pre>
                      </div>
                    </article>
                  ))}
                </div>
              </LoadState>
            </section>
            <section className="panel compliance-control-detail-section">
              <div className="panel-heading">
                <div>
                  <h2>Remediation guidance</h2>
                  <p>Policy guidance only. No changes are executed.</p>
                </div>
              </div>
              {Object.keys(control.data.guidance).length ? (
                <pre>{JSON.stringify(control.data.guidance, null, 2)}</pre>
              ) : findings.data?.length ? (
                <ul className="control-remediation-list">
                  {[
                    ...new Set(findings.data.map((item) => item.remediation)),
                  ].map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              ) : (
                <div className="empty-inline">
                  No remediation guidance is registered for this control.
                </div>
              )}
            </section>
            <section className="panel compliance-control-detail-section compliance-control-activity">
              <h2>Control activity</h2>
              <LoadState
                loading={activity.isLoading}
                error={activity.error}
                empty={!activity.data?.length}
              >
                <div className="timeline">
                  {activity.data?.map((item, index) => (
                    <div key={`${item.created_at}-${index}`}>
                      <i />
                      <strong>{item.action.replaceAll("_", " ")}</strong>
                      <small>{date(item.created_at)}</small>
                      <p>{item.detail}</p>
                    </div>
                  ))}
                </div>
              </LoadState>
            </section>
          </>
        )}
      </LoadState>
    </>
  );
}

export function RemediationPage() {
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const params = new URLSearchParams({ limit: "30", offset: String(offset) });
  if (status) params.set("status", status);
  const query = useLoad<Page<Remediation>>(
    "remediation-list",
    `/remediation?${params}`,
  );
  const summary = useLoad<{
    pending_approval: number;
    approved: number;
    verification_pending: number;
    completed: number;
    failed: number;
    rejected: number;
    cancelled: number;
  }>("remediation-summary", "/remediation/summary");
  const { user } = useAuth();
  const client = useQueryClient();
  const canRequest = Boolean(
    user?.permissions.includes("remediation:execute") &&
      user.permissions.includes("findings:read"),
  );
  const findings = useLoad<Page<Finding>>(
    "remediation-eligible-findings",
    "/findings?limit=100",
    canRequest,
  );
  const [requestError, setRequestError] = useState("");
  const [requestSuccess, setRequestSuccess] = useState("");
  const requestApproval = useMutation({
    mutationFn: (findingId: string) =>
      api.post(`/findings/${findingId}/remediation`, {
        request_note:
          "Approval requested from the remediation queue using the finding's registered recommendation.",
      }),
    onSuccess: async () => {
      setRequestError("");
      setRequestSuccess(
        "Approval request created. It is waiting for a separate reviewer.",
      );
      await Promise.all([
        client.invalidateQueries({ queryKey: ["remediation-list"] }),
        client.invalidateQueries({ queryKey: ["remediation-summary"] }),
        client.invalidateQueries({
          queryKey: ["remediation-eligible-findings"],
        }),
      ]);
    },
    onError: (error) => {
      setRequestSuccess("");
      setRequestError(
        error instanceof Error ? error.message : "Approval request failed.",
      );
    },
  });
  const existingRequests = query.data?.items ?? [];
  const pendingFindingIds = new Set(
    existingRequests
      .filter((item) =>
        ["PENDING_APPROVAL", "APPROVED", "VERIFYING"].includes(item.status),
      )
      .map((item) => item.finding_id),
  );
  const activeFindings = (findings.data?.items ?? []).filter(
    (finding) =>
      ["OPEN", "TRIAGED", "ASSIGNED", "IN_PROGRESS"].includes(
        finding.status,
      ) &&
      finding.remediation.trim().length > 0 &&
      !pendingFindingIds.has(finding.id),
  );
  const ownPendingRequests = existingRequests.filter(
    (item) =>
      item.status === "PENDING_APPROVAL" &&
      item.requested_by_user_id === user?.id,
  ).length;
  const decision = useMutation({
    mutationFn: ({
      id,
      decision,
    }: {
      id: string;
      decision: "APPROVED" | "REJECTED";
    }) =>
      api.post(`/remediation/${id}/decision`, {
        decision,
        decision_note: `Reviewed by ${user?.display_name ?? "authorized operator"}.`,
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["remediation-list"] });
      await client.invalidateQueries({ queryKey: ["remediation-summary"] });
    },
  });
  return (
    <div className="remediation-page">
      <PageHeader
        eyebrow="OPERATIONS"
        title="Remediation"
        description="Review recommended fixes, record approval, and verify manual changes with a clean scan."
      />
      {ownPendingRequests > 0 && (
        <div className="notice-banner remediation-review-notice" role="status">
          <span className="remediation-notice-icon" aria-hidden="true">!</span>
          <div className="remediation-notice-copy">
            <strong>Independent review required</strong>
            <span>
              {ownPendingRequests} pending {ownPendingRequests === 1 ? "request is" : "requests are"} waiting for another organization member with remediation permission to review.
            </span>
          </div>
        </div>
      )}
      <div className="notice-banner remediation-manual-notice" role="note">
        <span className="remediation-notice-icon" aria-hidden="true">i</span>
        <div className="remediation-notice-copy">
          <strong>Manual execution</strong>
          <span>
            Approval records authorization; it does not change AWS. Apply the approved fix manually, then verify it with a fresh scan.
          </span>
        </div>
      </div>
      <section className="remediation-workflow-guide panel">
        <h2>How to move a request forward</h2>
        <ol>
          <li>A different authorized reviewer approves or rejects it.</li>
          <li>After approval, apply the recommended fix manually in AWS.</li>
          <li>Run a clean scan, mark the finding resolved, then verify it in request details.</li>
        </ol>
      </section>
      <div className="metric-grid five remediation-kpis">
        <Metric
          label="Pending approval"
          value={summary.data?.pending_approval ?? "—"}
          suffix="Awaiting a separate reviewer"
        />
        <Metric
          label="Approved"
          value={summary.data?.approved ?? "—"}
          suffix="Manual fix authorized"
        />
        <Metric
          label="Verification pending"
          value={summary.data?.verification_pending ?? "—"}
          suffix="Awaiting verification after a fresh scan"
        />
        <Metric
          label="Completed"
          value={summary.data?.completed ?? "—"}
          suffix="Verified after a clean scan"
        />
        <Metric
          label="Failed"
          value={summary.data?.failed ?? "—"}
          suffix="Verification or workflow failed"
          tone="critical"
        />
      </div>
      {canRequest && (
        <section className="panel table-panel remediation-candidates-panel">
          <div className="panel-heading">
            <div>
              <h2>Findings ready for remediation</h2>
              <p>
                Create a human-reviewed approval request from a finding’s registered fix.
                No cloud change runs from this page.
              </p>
            </div>
            <span className="status-pill">{activeFindings.length} eligible</span>
          </div>
          {requestSuccess && (
            <p className="inline-notice remediation-feedback" role="status">{requestSuccess}</p>
          )}
          {requestError && <p className="error-state remediation-feedback" role="alert">{requestError}</p>}
          <LoadState
            loading={findings.isLoading}
            error={findings.error}
            empty={!activeFindings.length}
            emptyTitle="No findings need a new remediation request"
            emptyMessage="Active findings with registered remediation guidance will appear here. Existing pending requests are omitted."
          >
            <div className="table-scroll">
              <DataTable caption="Remediation recommendations" actions>
                <thead>
                  <tr>
                    <th scope="col">Finding</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Status</th>
                    <th scope="col">Recommendation</th>
                    <th scope="col">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {activeFindings.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <Link
                          className="row-primary"
                          to={`/findings/${finding.id}`}
                        >
                          {finding.title}
                        </Link>
                        <small>{finding.account_name ?? finding.id}</small>
                      </td>
                      <td>
                        <span className={severityClass(finding.severity)}>
                          {finding.severity}
                        </span>
                      </td>
                      <td>
                        <span className={`status-pill status-${finding.status.toLowerCase()}`}>{finding.status.replaceAll("_", " ")}</span>
                      </td>
                      <td>{finding.remediation}</td>
                      <td>
                        <button
                          className="primary-button"
                          disabled={requestApproval.isPending}
                          onClick={() => requestApproval.mutate(finding.id)}
                        >
                          Request approval
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
          </LoadState>
        </section>
      )}
      <div className="remediation-list-toolbar">
        <div>
          <h2>Approval requests</h2>
          <p>Track review decisions and verification progress.</p>
        </div>
        <label className="remediation-status-filter">
          <span>Status</span>
          <select
            aria-label="Filter remediation status"
            value={status}
            onChange={(event) => { setStatus(event.target.value); setOffset(0); }}
          >
          <option value="">All statuses</option>
          {[
            "PENDING_APPROVAL",
            "APPROVED",
            "VERIFYING",
            "COMPLETED",
            "FAILED",
            "REJECTED",
            "CANCELLED",
          ].map((item) => (
            <option key={item} value={item}>
              {item.replaceAll("_", " ")}
            </option>
          ))}
          </select>
        </label>
      </div>
      <FilterFooter className="remediation-filter-footer" active={Boolean(status)} onReset={() => { setStatus(""); setOffset(0); }} />
      <section className="panel table-panel remediation-requests-panel">
        <LoadState
          loading={query.isLoading}
          error={query.error}
          empty={!query.data?.items.length}
          emptyTitle={status ? "No requests match this status" : "No remediation requests yet"}
          emptyMessage={
            status ? "Reset the status filter to view all approval requests." : canRequest
              ? "Choose an active finding above to create a human-reviewed approval request."
              : "Requests will appear here after an authorized analyst submits a finding’s remediation recommendation."
          }
        >
          <div className="table-scroll">
          <DataTable caption="Remediation requests and decisions" actions>
            <thead>
              <tr>
                <th scope="col">Finding</th>
                <th scope="col">Recommendation</th>
                <th scope="col">Requested</th>
                <th scope="col">Requester</th>
                <th scope="col">Status</th>
                <th scope="col">Decision</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {query.data?.items.map((row) => (
                <tr key={row.id}>
                  <td>
                    <Link to={`/remediation/${row.id}`} className="row-primary">
                      {row.finding_id.slice(0, 12)}…
                    </Link>
                    <small>{row.request_note}</small>
                  </td>
                  <td>
                    {String(
                      row.action_definition.recommendation ??
                        "Manual remediation guidance",
                    )}
                  </td>
                  <td>{date(row.requested_at)}</td>
                  <td>
                    {row.requested_by_user_id === user?.id
                      ? `${user.display_name} (you)`
                      : `${row.requested_by_user_id.slice(0, 8)}…`}
                  </td>
                  <td>
                    <span className={`status-pill status-${row.status.toLowerCase()}`}>{row.status.replaceAll("_", " ")}</span>
                  </td>
                  <td>
                    {row.status === "PENDING_APPROVAL" &&
                    user?.permissions.includes("remediation:execute") ? (
                      row.requested_by_user_id === user.id ? (
                        <span className="remediation-review-hint">
                          Waiting for another reviewer
                        </span>
                      ) : (
                        <div className="button-pair">
                          <button
                            className="small-button"
                            disabled={decision.isPending}
                            onClick={() =>
                              decision.mutate({
                                id: row.id,
                                decision: "APPROVED",
                              })
                            }
                          >
                            Approve
                          </button>
                          <button
                            className="small-button danger-button"
                            disabled={decision.isPending}
                            onClick={() =>
                              decision.mutate({
                                id: row.id,
                                decision: "REJECTED",
                              })
                            }
                          >
                            Reject
                          </button>
                        </div>
                      )
                    ) : (
                      row.decision_note || "—"
                    )}
                  </td>
                  <td>
                    <Link className="scan-view-action" to={`/remediation/${row.id}`} aria-label={`View remediation request ${row.id.slice(0, 8)}`}>
                      <Icon name="eye" /><span>View</span>
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </DataTable>
          </div>
        </LoadState>
        {query.data && <Pagination total={query.data.total} offset={offset} limit={30} onOffsetChange={setOffset} label="Remediation request pages" />}
      </section>
    </div>
  );
}

export function RemediationDetailPage() {
  const { remediationId } = useParams();
  const { user } = useAuth();
  const client = useQueryClient();
  const detail = useLoad<RemediationDetail>(
    `remediation-${remediationId}`,
    `/remediation/${remediationId}`,
    Boolean(remediationId),
  );
  const item = detail.data;
  const canReview = Boolean(user?.permissions.includes("remediation:execute"));
  const [scanId, setScanId] = useState("");
  const [verificationNote, setVerificationNote] = useState("");
  const [fixConfirmed, setFixConfirmed] = useState(false);
  const scans = useLoad<
    Page<{
      id: string;
      status: string;
      created_at: string;
      errors_count: number;
    }>
  >(
    `remediation-verification-scans-${item?.finding.account_id}`,
    item
      ? `/scans?limit=20&status=completed&cloud_account_id=${item.finding.account_id}`
      : "",
    Boolean(item && user?.permissions.includes("scans:read")),
  );
  const invalidate = async () => {
    await client.invalidateQueries({ queryKey: ["remediation-list"] });
    await client.invalidateQueries({ queryKey: ["remediation-summary"] });
    await client.invalidateQueries({
      queryKey: [`remediation-${remediationId}`],
    });
  };
  const decision = useMutation({
    mutationFn: (value: "APPROVED" | "REJECTED") =>
      api.post(`/remediation/${remediationId}/decision`, {
        decision: value,
        decision_note: `Reviewed by ${user?.display_name ?? "authorized operator"}.`,
      }),
    onSuccess: invalidate,
  });
  const cancel = useMutation({
    mutationFn: () =>
      api.post(`/remediation/${remediationId}/cancel`, {
        decision_note: "Cancelled by authorized operator.",
      }),
    onSuccess: invalidate,
  });
  const verify = useMutation({
    mutationFn: (result: "PASSED" | "FAILED") =>
      api.post(`/remediation/${remediationId}/verify`, {
        scan_job_id: scanId,
        result,
        note: verificationNote,
      }),
    onSuccess: invalidate,
  });
  const findingTransition = useMutation({
    mutationFn: (status: "TRIAGED" | "IN_PROGRESS" | "RESOLVED") =>
      api.post(`/findings/${item?.finding.id}/transition`, {
        status,
        reason:
          status === "RESOLVED"
            ? `Manual fix confirmed after clean scan ${scanId.slice(0, 8)}. ${verificationNote.trim()}`
            : "Manual remediation approved; investigation is progressing.",
      }),
    onSuccess: async () => {
      await invalidate();
      await client.invalidateQueries({
        queryKey: [`finding-${item?.finding.id}`],
      });
    },
  });
  const canUpdateFinding = Boolean(
    user?.permissions.includes("findings:update"),
  );
  const eligibleScans = (scans.data?.items ?? []).filter(
    (scan) =>
      scan.errors_count === 0 &&
      new Date(scan.created_at) >= new Date(item?.request.requested_at ?? 0),
  );
  const selectedScan = eligibleScans.find((scan) => scan.id === scanId);
  const findingResolved = Boolean(
    item && ["RESOLVED", "VERIFIED", "CLOSED"].includes(item.finding.status),
  );
  const nextFindingStep =
    item?.finding.status === "OPEN"
      ? { status: "TRIAGED" as const, label: "Triage finding" }
      : item?.finding.status === "TRIAGED"
        ? { status: "IN_PROGRESS" as const, label: "Start investigation" }
        : item?.finding.status === "IN_PROGRESS"
          ? { status: "RESOLVED" as const, label: "Mark finding resolved" }
          : null;
  const canVerifyPassed = Boolean(
    selectedScan &&
      verificationNote.trim().length >= 3 &&
      findingResolved,
  );
  return (
    <>
      <PageHeader
        eyebrow="OPERATIONS / REMEDIATION"
        title="Remediation request"
        description={remediationId ?? "Manual remediation workflow"}
        action={
          <Link className="quiet-button" to="/remediation">
            Back to queue
          </Link>
        }
      />
      <LoadState loading={detail.isLoading} error={detail.error}>
        {item && (
          <>
            <div className="notice-banner">
              <strong>{item.request.status.replaceAll("_", " ")}</strong>
              <span>
                Manual action only. CloudSentinel does not execute this AWS
                change.
              </span>
            </div>
            <div className="dashboard-grid">
              <section className="panel">
                <h2>Overview</h2>
                <div className="drawer-facts">
                  <DrawerFact
                    label="Finding"
                    value={
                      <Link to={`/findings/${item.finding.id}`}>
                        {item.finding.title}
                      </Link>
                    }
                  />
                  <DrawerFact label="Severity" value={item.finding.severity} />
                  <DrawerFact
                    label="Finding status"
                    value={item.finding.status}
                  />
                  <DrawerFact
                    label="Asset"
                    value={
                      <Link to={`/assets/${item.finding.asset_id}`}>
                        {item.finding.asset_name}
                      </Link>
                    }
                  />
                  <DrawerFact
                    label="Account"
                    value={item.finding.account_name}
                  />
                  <DrawerFact
                    label="Account ID"
                    value={item.finding.aws_account_id}
                  />
                  <DrawerFact label="Region" value={item.finding.region_code} />
                  <DrawerFact
                    label="Risk"
                    value={
                      item.finding.risk_score == null
                        ? "Not assessed"
                        : `${item.finding.risk_score}/100`
                    }
                  />
                </div>
              </section>
              <section className="panel">
                <h2>Recommended action</h2>
                <p>
                  {String(
                    item.request.action_definition.recommendation ??
                      "No remediation guidance was recorded.",
                  )}
                </p>
                <p>
                  <strong>Target:</strong>{" "}
                  {String(item.request.action_definition.resource_type)} ·{" "}
                  {String(item.request.action_definition.resource_id)}
                </p>
                <p>
                  <strong>Available method:</strong> Manual change only
                </p>
                <div className="notice-banner">
                  <span>
                    Console, CLI, and Terraform templates are not available for
                    this policy definition.
                  </span>
                </div>
              </section>
            </div>
            <div className="dashboard-grid">
              <section className="panel">
                <h2>Evidence</h2>
                {item.evidence ? (
                  <>
                    <DrawerFact label="Source" value={item.evidence.source} />
                    <DrawerFact
                      label="Observed at"
                      value={date(item.evidence.collected_at)}
                    />
                    <h3>Expected</h3>
                    <pre className="json-view">
                      {JSON.stringify(item.evidence.expected_state, null, 2)}
                    </pre>
                    <h3>Observed</h3>
                    <pre className="json-view">
                      {JSON.stringify(
                        item.evidence.detected_condition,
                        null,
                        2,
                      )}
                    </pre>
                  </>
                ) : (
                  <div className="empty-inline">
                    No finding evidence was attached when this request was
                    created.
                  </div>
                )}
              </section>
              <section className="panel">
                <h2>Approval and verification</h2>
                <DrawerFact
                  label="Requester"
                  value={
                    item.request.requested_by_user_id === user?.id
                      ? `${user.display_name} (you)`
                      : item.request.requested_by_user_id
                  }
                />
                <DrawerFact
                  label="Requested"
                  value={date(item.request.requested_at)}
                />
                <DrawerFact
                  label="Decision"
                  value={item.request.decision_note ?? "Pending"}
                />
                <DrawerFact
                  label="Verification"
                  value={item.request.verification_status}
                />
                {item.request.status === "APPROVED" && (
                  <div className="remediation-verification-notice">
                    <strong>Verification checklist</strong>
                    <ol>
                      <li>Apply the approved fix manually in AWS.</li>
                      <li>Select a clean completed scan from after this request.</li>
                      <li>Confirm the finding is resolved, then verify the result.</li>
                    </ol>
                    <span>CloudSentinel does not execute the AWS change.</span>
                  </div>
                )}
                {item.request.status === "PENDING_APPROVAL" && canReview && (
                  <>
                    {item.request.requested_by_user_id === user?.id ? (
                      <div className="notice-banner remediation-review-notice">
                        <strong>Separate reviewer required</strong>
                        <span>
                          You submitted this request. Ask another authorized
                          remediation reviewer in this organization to approve
                          or reject it.
                        </span>
                      </div>
                    ) : (
                      <div className="button-pair">
                        <button
                          className="primary-button"
                          disabled={decision.isPending}
                          onClick={() => decision.mutate("APPROVED")}
                        >
                          Approve manual change
                        </button>
                        <button
                          className="danger-button"
                          disabled={decision.isPending}
                          onClick={() => decision.mutate("REJECTED")}
                        >
                          Reject
                        </button>
                      </div>
                    )}
                  </>
                )}
                {["PENDING_APPROVAL", "APPROVED"].includes(
                  item.request.status,
                ) &&
                  canReview && (
                    <button
                      className="quiet-button"
                      disabled={cancel.isPending}
                      onClick={() => cancel.mutate()}
                    >
                      Cancel request
                    </button>
                  )}
                {item.request.status === "APPROVED" && canReview && (
                  <div className="remediation-verify-form">
                    <div className="remediation-step-card">
                      <div className="remediation-step-heading">
                        <span className="remediation-step-number">1</span>
                        <div>
                          <strong>Choose a clean scan</strong>
                          <small>
                            Same account · completed · no errors · after request
                          </small>
                        </div>
                      </div>
                      {scans.isLoading ? (
                        <div className="remediation-scan-state">
                          <span className="spinner" /> Loading completed scans…
                        </div>
                      ) : scans.error ? (
                        <div className="remediation-scan-empty error-state">
                          <strong>Scan history could not be loaded</strong>
                          <span>{scans.error.message}</span>
                        </div>
                      ) : eligibleScans.length === 0 ? (
                        <div className="remediation-scan-empty">
                          <strong>No eligible scan yet</strong>
                          <span>
                            Run a new scan for {item.finding.account_name} after
                            applying the fix. It must complete with zero errors.
                          </span>
                          {user?.permissions.includes("scans:create") && (
                            <Link
                              className="secondary-button"
                              to={`/scans?create=${item.finding.account_id}`}
                            >
                              Start scan for this account
                            </Link>
                          )}
                        </div>
                      ) : (
                        <>
                          <label>
                            Clean completed scan
                            <select
                              value={scanId}
                              onChange={(event) => {
                                setScanId(event.target.value);
                                setFixConfirmed(false);
                              }}
                            >
                              <option value="">Select scan</option>
                              {eligibleScans.map((scan) => (
                                <option key={scan.id} value={scan.id}>
                                  {date(scan.created_at)} · {scan.id.slice(0, 8)} · 0 errors
                                </option>
                              ))}
                            </select>
                          </label>
                          {selectedScan && (
                            <div className="remediation-scan-selected" role="status">
                              <strong>Clean scan selected</strong>
                              <span>
                                {date(selectedScan.created_at)} · {selectedScan.id}
                              </span>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                    <div className="remediation-step-card">
                      <div className="remediation-step-heading">
                        <span className="remediation-step-number">2</span>
                        <div>
                          <strong>Resolve the finding</strong>
                          <small>Current status: {item.finding.status}</small>
                        </div>
                      </div>
                      {findingResolved ? (
                        <div className="remediation-scan-selected" role="status">
                          <strong>Finding resolved</strong>
                          <span>The finding is ready for verification.</span>
                        </div>
                      ) : canUpdateFinding && nextFindingStep ? (
                        <>
                          <p className="remediation-step-help">
                            Move through OPEN → TRIAGED → IN PROGRESS → RESOLVED.
                            Only mark it resolved after the selected scan confirms
                            the AWS fix.
                          </p>
                          {nextFindingStep.status === "RESOLVED" && (
                            <label className="remediation-confirm-fix">
                              <input
                                type="checkbox"
                                checked={fixConfirmed}
                                disabled={!selectedScan}
                                onChange={(event) =>
                                  setFixConfirmed(event.target.checked)
                                }
                              />
                              I checked the selected scan and confirmed the fix.
                            </label>
                          )}
                          <button
                            className="secondary-button remediation-transition-button"
                            disabled={
                              findingTransition.isPending ||
                              (nextFindingStep.status === "RESOLVED" &&
                                (!selectedScan ||
                                  !fixConfirmed ||
                                  verificationNote.trim().length < 3))
                            }
                            onClick={() =>
                              findingTransition.mutate(nextFindingStep.status)
                            }
                          >
                            {findingTransition.isPending
                              ? "Updating finding…"
                              : nextFindingStep.label}
                          </button>
                          {nextFindingStep.status === "RESOLVED" &&
                            (!selectedScan ||
                              !fixConfirmed ||
                              verificationNote.trim().length < 3) && (
                              <small className="remediation-disabled-reason">
                                {!selectedScan
                                  ? "Select an eligible clean scan first."
                                  : !fixConfirmed
                                    ? "Confirm that you reviewed the scan and the fix is present."
                                    : "Add a verification note of at least 3 characters."}
                              </small>
                            )}
                        </>
                      ) : (
                        <div className="remediation-scan-empty">
                          <strong>Finding needs attention</strong>
                          <span>
                            Open the finding details to update its status, or ask
                            a member with finding update permission.
                          </span>
                          <Link
                            className="secondary-button"
                            to={`/findings/${item.finding.id}`}
                          >
                            Open finding
                          </Link>
                        </div>
                      )}
                    </div>
                    <label>
                      Verification note <span className="field-hint">At least 3 characters</span>
                      <textarea
                        rows={2}
                        value={verificationNote}
                        onChange={(event) =>
                          setVerificationNote(event.target.value)
                        }
                      />
                    </label>
                    <div className="button-pair">
                      <button
                        className="primary-button remediation-verify-button"
                        disabled={!canVerifyPassed || verify.isPending}
                        onClick={() => verify.mutate("PASSED")}
                      >
                        Verify passed
                      </button>
                      <button
                        className="quiet-button"
                        disabled={
                          !scanId ||
                          verificationNote.trim().length < 3 ||
                          verify.isPending
                        }
                        onClick={() => verify.mutate("FAILED")}
                      >
                        Verification failed
                      </button>
                    </div>
                    {!canVerifyPassed && (
                      <p className="remediation-disabled-reason">
                        {!selectedScan
                          ? "Verify passed is unavailable until you select an eligible clean scan."
                          : !findingResolved
                            ? "Verify passed is unavailable until the finding is marked resolved after reviewing the scan."
                            : "Add a verification note of at least 3 characters to finish."}
                      </p>
                    )}
                    {findingTransition.error && (
                      <p className="error-state" role="alert">
                        {findingTransition.error.message}
                      </p>
                    )}
                  </div>
                )}
                {decision.error && (
                  <p className="error-state">{decision.error.message}</p>
                )}
                {cancel.error && (
                  <p className="error-state">{cancel.error.message}</p>
                )}
                {verify.error && (
                  <p className="error-state">{verify.error.message}</p>
                )}
              </section>
            </div>
          </>
        )}
      </LoadState>
    </>
  );
}

export function ReportsPage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const [builderOpen, setBuilderOpen] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState("security_assessment");
  const [format, setFormat] = useState("PDF");
  const [environment, setEnvironment] = useState("");
  const [accountId, setAccountId] = useState("");
  const [region, setRegion] = useState("");
  const [severity, setSeverity] = useState("");
  const [findingStatus, setFindingStatus] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [reportSearch, setReportSearch] = useState("");
  const [reportStatus, setReportStatus] = useState("");
  const [reportTypeFilter, setReportTypeFilter] = useState("");
  const [reportFormatFilter, setReportFormatFilter] = useState("");
  const [reportEnvironmentFilter, setReportEnvironmentFilter] = useState("");
  const [reportDateFrom, setReportDateFrom] = useState("");
  const [reportDateTo, setReportDateTo] = useState("");
  const [feedback, setFeedback] = useState("");
  const [offset, setOffset] = useState(0);
  const reportParams = new URLSearchParams({ limit: "30", offset: String(offset) });
  if (reportSearch.trim()) reportParams.set("search", reportSearch.trim());
  if (reportStatus) reportParams.set("status", reportStatus);
  if (reportTypeFilter) reportParams.set("report_type", reportTypeFilter);
  if (reportFormatFilter) reportParams.set("file_format", reportFormatFilter);
  if (reportEnvironmentFilter) reportParams.set("environment", reportEnvironmentFilter);
  if (reportDateFrom) reportParams.set("date_from", reportDateFrom);
  if (reportDateTo) reportParams.set("date_to", reportDateTo);
  const path = `/reports?${reportParams.toString()}`;
  const query = useQuery({
    queryKey: ["reports-list", path],
    queryFn: () => api.get<Page<Report>>(path),
    refetchInterval: (activeQuery) =>
      activeQuery.state.data?.items.some((item) =>
        ["QUEUED", "GENERATING"].includes(item.status),
      )
        ? 3000
        : false,
  });
  const summary = useLoad<{
    total: number;
    queued: number;
    completed: number;
    failed: number;
    expired: number;
  }>("reports-summary", "/reports/summary");
  const accountOptions = useLoad<Account[] | Page<Account>>(
    "report-account-options",
    "/cloud-accounts?limit=100",
    Boolean(user?.permissions.includes("cloud_accounts:read")),
  );
  const accountOptionRows = Array.isArray(accountOptions.data)
    ? accountOptions.data
    : (accountOptions.data?.items ?? []);
  const reportEnvironments = [...new Set(
    accountOptionRows.map((account) => account.environment?.trim()).filter((value): value is string => Boolean(value)),
  )].sort((a, b) => a.localeCompare(b));
  const scopedAccounts = accountId
    ? accountOptionRows.filter((account) => account.id === accountId)
    : accountOptionRows;
  const reportRegions = [...new Set(
    scopedAccounts.flatMap((account) => [
      ...(account.primary_region ? [account.primary_region] : []),
      ...account.regions.filter((item) => item.is_enabled).map((item) => item.region_code),
    ]),
  )].sort((a, b) => a.localeCompare(b));
  const canCreate = Boolean(user?.permissions.includes("reports:create"));
  const canExport = Boolean(user?.permissions.includes("reports:export"));
  const refreshReports = async () => {
    await Promise.all([
      client.invalidateQueries({ queryKey: ["reports-list"] }),
      client.invalidateQueries({ queryKey: ["reports-summary"] }),
    ]);
  };
  const create = useMutation({
    mutationFn: () =>
      api.post<Report>("/reports", {
        name: name.trim(),
        report_type: kind,
        file_format: format,
        filters: {
          environment: environment || null,
          cloud_account_id: accountId || null,
          region: region || null,
          severities: severity ? [severity] : [],
          finding_statuses: findingStatus ? [findingStatus] : [],
          date_from: dateFrom || null,
          date_to: dateTo || null,
        },
      }),
    onSuccess: async (report) => {
      setFeedback(`Report queued. Generation status: ${report.status}.`);
      setBuilderOpen(false);
      await refreshReports();
    },
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "Report could not be queued.",
      ),
  });
  const lifecycle = useMutation({
    mutationFn: ({
      id,
      action,
    }: {
      id: string;
      action: "cancel" | "regenerate";
    }) =>
      action === "cancel"
        ? api.post(`/reports/${id}/cancel`)
        : api.post(`/reports/${id}/regenerate`),
    onSuccess: async () => {
      setFeedback("Report lifecycle updated.");
      await refreshReports();
    },
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "Report action failed.",
      ),
  });
  const download = useMutation({
    mutationFn: ({
      id,
      fileFormat,
    }: {
      id: string;
      fileFormat: "json" | "csv" | "pdf";
    }) => api.exportReport(id, fileFormat),
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "Report download failed.",
      ),
  });
  const types = [
    ["executive_security", "Executive security"],
    ["security_assessment", "Security assessment"],
    ["findings", "Findings"],
    ["compliance", "Compliance"],
    ["risk", "Risk"],
    ["assets", "Asset inventory"],
    ["scans", "Scan activity"],
    ["remediation", "Remediation"],
  ];
  return (
    <>
      <PageHeader
        eyebrow="OPERATIONS"
        title="Reports"
        description="Generate reproducible snapshots from canonical security data and download authorized PDF, CSV, or JSON exports."
        action={
          canCreate ? (
            <button
              className="primary-button"
              onClick={() => {
                setFeedback("");
                setBuilderOpen(true);
              }}
            >
              Create report
            </button>
          ) : undefined
        }
      />
      {feedback && <div className="inline-notice">{feedback}</div>}
      <div className="metric-grid report-metrics">
        <Metric
          label="Total reports"
          value={summary.data?.total ?? "—"}
          suffix="Organization report history"
        />
        <Metric
          label="Queued"
          value={summary.data?.queued ?? "—"}
          suffix="Waiting to generate"
        />
        <Metric
          label="Generated"
          value={summary.data?.completed ?? "—"}
          suffix="Completed snapshots"
        />
        <Metric
          label="Failed"
          value={summary.data?.failed ?? "—"}
          suffix="Generation needs attention"
          tone="critical"
        />
        <Metric
          label="Expired"
          value={summary.data?.expired ?? "—"}
          suffix="Removed by retention policy"
        />
      </div>
      <div className="findings-filter-toolbar report-filter-toolbar">
        <div className="findings-filter-line report-filter-line">
          <FilterField label="Search" className="filter-field-search"><input
            aria-label="Search reports"
            placeholder="Search report names"
            value={reportSearch}
            onChange={(event) => { setReportSearch(event.target.value); setOffset(0); }}
          /></FilterField>
          <FilterField label="Status"><select aria-label="Filter report status" value={reportStatus} onChange={(event) => { setReportStatus(event.target.value); setOffset(0); }}>
            <option value="">All statuses</option>
            {["QUEUED", "GENERATING", "COMPLETED", "FAILED", "CANCELLED", "EXPIRED"].map((value) => <option key={value}>{value}</option>)}
          </select></FilterField>
          <FilterField label="Type"><select aria-label="Filter report type" value={reportTypeFilter} onChange={(event) => { setReportTypeFilter(event.target.value); setOffset(0); }}>
            <option value="">All report types</option>
            {types.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select></FilterField>
          <FilterField label="Format"><select aria-label="Filter report format" value={reportFormatFilter} onChange={(event) => { setReportFormatFilter(event.target.value); setOffset(0); }}>
            <option value="">All formats</option>
            {["PDF", "CSV", "JSON"].map((value) => <option key={value}>{value}</option>)}
          </select></FilterField>
        </div>
        <div className="findings-filter-line report-filter-line report-filter-line-secondary">
          <FilterField label="Environment"><select aria-label="Filter report environment" value={reportEnvironmentFilter} onChange={(event) => { setReportEnvironmentFilter(event.target.value); setOffset(0); }}>
            <option value="">All environments</option>
            {reportEnvironments.map((value) => <option key={value}>{value}</option>)}
          </select></FilterField>
          <label className="finding-date-filter scan-date-filter">
            From
            <input aria-label="Reports created from" type="date" max={reportDateTo || undefined} value={reportDateFrom} onClick={(event) => { try { event.currentTarget.showPicker?.(); } catch { /* Native picker may already be open. */ } }} onChange={(event) => { setReportDateFrom(event.target.value); setOffset(0); }} />
          </label>
          <label className="finding-date-filter scan-date-filter">
            To
            <input aria-label="Reports created to" type="date" min={reportDateFrom || undefined} value={reportDateTo} onClick={(event) => { try { event.currentTarget.showPicker?.(); } catch { /* Native picker may already be open. */ } }} onChange={(event) => { setReportDateTo(event.target.value); setOffset(0); }} />
          </label>
          <span>{query.data ? query.data.total.toLocaleString() : "—"} reports</span>
        </div>
        <FilterFooter className="scan-filter-footer" active={Boolean(reportSearch || reportStatus || reportTypeFilter || reportFormatFilter || reportEnvironmentFilter || reportDateFrom || reportDateTo)} onReset={() => {
              setReportSearch(""); setReportStatus(""); setReportTypeFilter("");
              setReportFormatFilter(""); setReportEnvironmentFilter("");
              setReportDateFrom(""); setReportDateTo(""); setOffset(0);
            }} />
      </div>
      <section className="panel table-panel report-table-panel">
        <LoadState
          loading={query.isLoading}
          error={query.error}
          empty={!query.data?.items.length}
        >
          <DataTable caption="Generated reports" actions>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Type / Scope</th>
                <th scope="col">Status</th>
                <th scope="col">Format</th>
                <th scope="col">Version</th>
                <th scope="col">Created by</th>
                <th scope="col">Generated</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {query.data?.items.map((report) => (
                <tr key={report.id}>
                  <td>
                    <Link className="row-primary" to={`/reports/${report.id}`}>
                      {report.name}
                    </Link>
                    <small>
                      {report.id.slice(0, 12)} · v{report.report_version}
                    </small>
                  </td>
                  <td>
                    {report.report_type.replaceAll("_", " ")}
                    <small>
                      {String(report.filters.environment ?? "All environments")}
                    </small>
                  </td>
                  <td>
                    <span
                      className={`status-pill status-${report.status.toLowerCase()}`}
                    >
                      {report.status}
                    </span>
                    {report.error_message && (
                      <small className="text-critical">
                        {report.error_message}
                      </small>
                    )}
                  </td>
                  <td>{report.file_format}</td>
                  <td>v{report.report_version}</td>
                  <td>
                    <strong className="row-primary">
                      {report.created_by_name ?? report.created_by_user_id.slice(0, 8)}
                    </strong>
                    <small>
                      {report.created_by_role
                        ? report.created_by_role.split("_").map((part) => part[0] + part.slice(1).toLowerCase()).join(" ")
                        : "Role unavailable"}
                    </small>
                  </td>
                  <td>
                    {report.generated_at ? date(report.generated_at) : "—"}
                  </td>
                  <td>
                    <div className="table-row-actions">
                    <Link className="scan-view-action" to={`/reports/${report.id}`} aria-label={`View report ${report.name}`}>
                      <Icon name="eye" /><span>View</span>
                    </Link>
                    <DismissibleActionMenu
                      className="report-actions-menu"
                      label={`Actions for ${report.name}`}
                    >
                      <div className="report-actions-menu-items" role="menu">
                        <div className="report-actions-menu-heading">Report actions</div>
                        <Link role="menuitem" className="report-menu-item" to={`/reports/${report.id}`}>
                          <span className="report-menu-icon" aria-hidden="true">↗</span>
                          <span className="report-menu-copy"><strong>View details</strong><small>Open the snapshot, filters, and report contents</small></span>
                        </Link>
                        {canExport && report.status === "COMPLETED" && (
                          <button
                            role="menuitem"
                            className="report-menu-item"
                            disabled={download.isPending}
                            onClick={() => download.mutate({
                              id: report.id,
                              fileFormat: report.file_format.toLowerCase() as "json" | "csv" | "pdf",
                            })}
                          >
                            <span className="report-menu-icon" aria-hidden="true">↓</span>
                            <span className="report-menu-copy"><strong>Download {report.file_format}</strong><small>Export this completed report</small></span>
                          </button>
                        )}
                        {canCreate && report.status === "QUEUED" && (
                          <button
                            role="menuitem"
                            className="report-menu-item report-menu-danger"
                            disabled={lifecycle.isPending}
                            onClick={() => lifecycle.mutate({ id: report.id, action: "cancel" })}
                          >
                            <span className="report-menu-icon" aria-hidden="true">×</span>
                            <span className="report-menu-copy"><strong>Cancel report</strong><small>Stop this report before generation</small></span>
                          </button>
                        )}
                        {canCreate && ["COMPLETED", "FAILED", "EXPIRED"].includes(report.status) && (
                          <button
                            role="menuitem"
                            className="report-menu-item"
                            disabled={lifecycle.isPending}
                            onClick={() => lifecycle.mutate({ id: report.id, action: "regenerate" })}
                          >
                            <span className="report-menu-icon" aria-hidden="true">↻</span>
                            <span className="report-menu-copy"><strong>Regenerate report</strong><small>Create a fresh snapshot from current data</small></span>
                          </button>
                        )}
                      </div>
                    </DismissibleActionMenu>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </DataTable>
        </LoadState>
      </section>
      {query.data && <Pagination total={query.data.total} offset={offset} limit={30} onOffsetChange={setOffset} label="Report pages" />}
      {builderOpen && (
        <RightDrawer
          title="Create report"
          description="Choose what to include and generate a point-in-time snapshot."
          className="report-create-drawer"
          onClose={() => setBuilderOpen(false)}
        >
          <form
            className="report-builder"
            onSubmit={(event) => {
              event.preventDefault();
              create.mutate();
            }}
          >
            <section className="report-form-section">
              <div className="report-form-section-heading">
                <span>01</span>
                <div><h3>Report details</h3><p>Name the snapshot and choose its output.</p></div>
              </div>
              <label className="report-name-field">
                Report name
                <input
                  required
                  minLength={3}
                  maxLength={160}
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="Production security assessment"
                />
              </label>
              <div className="report-form-grid">
                <label>
                  Report type
                  <select value={kind} onChange={(event) => setKind(event.target.value)}>
                    {types.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                  </select>
                </label>
                <label>
                  Format
                  <select value={format} onChange={(event) => setFormat(event.target.value)}>
                    <option>PDF</option><option>CSV</option><option>JSON</option>
                  </select>
                </label>
              </div>
            </section>
            <section className="report-form-section">
              <div className="report-form-section-heading">
                <span>02</span>
                <div><h3>Report scope</h3><p>Limit the snapshot to a specific environment or cloud resource.</p></div>
              </div>
              <div className="report-form-grid">
                <label>
                  Environment
                  <select value={environment} onChange={(event) => setEnvironment(event.target.value)}>
                    <option value="">All environments</option>
                    {reportEnvironments.map((value) => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
            {user?.permissions.includes("cloud_accounts:read") && (
              <label>
                Cloud account
                <select
                  value={accountId}
                  onChange={(event) => setAccountId(event.target.value)}
                >
                  <option value="">All accounts</option>
                  {accountOptionRows.map((account) => (
                    <option key={account.id} value={account.id}>
                      {account.name} · {account.account_id}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label>
              Region
              <select value={region} onChange={(event) => setRegion(event.target.value)}>
                <option value="">All regions</option>
                {reportRegions.map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
              </div>
            {kind === "findings" && (
              <div className="report-form-grid">
                <label>
                  Severity
                  <select
                    value={severity}
                    onChange={(event) => setSeverity(event.target.value)}
                  >
                    <option value="">All severities</option>
                    {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map(
                      (value) => (
                        <option key={value}>{value}</option>
                      ),
                    )}
                  </select>
                </label>
                <label>
                  Finding status
                  <select
                    value={findingStatus}
                    onChange={(event) => setFindingStatus(event.target.value)}
                  >
                    <option value="">All statuses</option>
                    {[
                      "OPEN",
                      "TRIAGED",
                      "ASSIGNED",
                      "IN_PROGRESS",
                      "RESOLVED",
                      "VERIFIED",
                      "CLOSED",
                      "SUPPRESSED",
                    ].map((value) => (
                      <option key={value}>{value}</option>
                    ))}
                  </select>
                </label>
              </div>
            )}
            </section>
            <section className="report-form-section report-date-section">
              <div className="report-form-section-heading">
                <span>03</span>
                <div><h3>Date range <small>Optional</small></h3><p>Include records created within this time window.</p></div>
              </div>
            <div className="report-date-range">
              <label>
                From
                <input
                  type="date"
                  value={dateFrom}
                  max={dateTo || undefined}
                  onChange={(event) => setDateFrom(event.target.value)}
                  onClick={(event) => event.currentTarget.showPicker?.()}
                />
              </label>
              <label>
                To
                <input
                  type="date"
                  value={dateTo}
                  min={dateFrom || undefined}
                  onChange={(event) => setDateTo(event.target.value)}
                  onClick={(event) => event.currentTarget.showPicker?.()}
                />
              </label>
            </div>
            </section>
            {create.error && (
              <p className="error-state">{create.error.message}</p>
            )}
            <button
              className="primary-button"
              disabled={create.isPending || name.trim().length < 3}
            >
              {create.isPending ? "Queueing report…" : "Generate report"}
            </button>
          </form>
        </RightDrawer>
      )}
    </>
  );
}

export function ReportDetailPage() {
  const { reportId = "" } = useParams();
  const [fullDetails, setFullDetails] = useState<"technical" | "snapshot" | null>(null);
  const reportPath = `/reports/${reportId}`;
  const report = useQuery({
    queryKey: [`report-${reportId}`, reportPath],
    queryFn: () =>
      api.get<{
        id: string;
        report_type: string;
        name: string;
        status: string;
        file_format: string;
        report_version: number;
        generator_version: string;
        created_by_user_id: string;
        created_by_name: string | null;
        created_by_role: string | null;
        filters: Record<string, unknown>;
        checksum: string | null;
        snapshot_checksum: string | null;
        file_size: number | null;
        data_snapshot_at: string | null;
        generated_at: string | null;
        retention_until: string | null;
        parent_report_id: string | null;
        error_code: string | null;
        error_message: string | null;
        created_at: string;
        snapshot: Record<string, unknown> | null;
      }>(reportPath),
    refetchInterval: (activeQuery) =>
      activeQuery.state.data &&
      ["QUEUED", "GENERATING"].includes(activeQuery.state.data.status)
        ? 3000
        : false,
  });
  const snapshotItems = report.data?.snapshot?.items;
  const snapshotItemCount = Array.isArray(snapshotItems) ? snapshotItems.length : null;
  const { user } = useAuth();
  const client = useQueryClient();
  const navigate = useNavigate();
  const activity = useLoad<
    Page<{
      id: string;
      action: string;
      actor_user_id: string | null;
      actor_name: string;
      actor_role: string | null;
      created_at: string;
    }>
  >(
    `report-activity-${reportId}`,
    `/audit-events?resource_type=report&resource_id=${reportId}&limit=100`,
    Boolean(user?.permissions.includes("audit:read")),
  );
  const action = useMutation({
    mutationFn: (kind: "regenerate" | "cancel") =>
      api.post<{ id: string }>(`/reports/${reportId}/${kind}`),
    onSuccess: async (nextReport) => {
      await client.invalidateQueries({ queryKey: [`report-${reportId}`] });
      await client.invalidateQueries({ queryKey: ["reports-list"] });
      navigate(`/reports/${nextReport.id}`);
    },
  });
  const download = useMutation({
    mutationFn: (fileFormat: "pdf" | "csv" | "json") =>
      api.exportReport(reportId, fileFormat),
  });
  return (
    <>
      <PageHeader
        eyebrow="OPERATIONS / REPORT"
        title={report.data?.name ?? "Report"}
        description={
          report.data
            ? `${report.data.report_type.replaceAll("_", " ")} report · ${report.data.status.toLowerCase()}`
            : "Tenant-scoped report snapshot."
        }
        action={
          <div className="button-pair">
            <Link to="/reports" className="quiet-button">
              ← Reports
            </Link>
            {report.data?.status === "COMPLETED" &&
              user?.permissions.includes("reports:export") && (
                <>
                  <button
                    className="small-button"
                    disabled={download.isPending}
                    onClick={() => download.mutate("pdf")}
                  >
                    PDF
                  </button>
                  <button
                    className="small-button"
                    disabled={download.isPending}
                    onClick={() => download.mutate("csv")}
                  >
                    CSV
                  </button>
                  <button
                    className="small-button"
                    disabled={download.isPending}
                    onClick={() => download.mutate("json")}
                  >
                    JSON
                  </button>
                </>
              )}
            {user?.permissions.includes("reports:create") &&
              report.data &&
              ["COMPLETED", "FAILED", "EXPIRED"].includes(report.data.status) && (
                <button
                  className="primary-button"
                  disabled={action.isPending}
                  onClick={() => action.mutate("regenerate")}
                >
                  Regenerate
                </button>
              )}
            {user?.permissions.includes("reports:create") &&
              report.data?.status === "QUEUED" && (
                <button
                  className="danger-button"
                  disabled={action.isPending}
                  onClick={() => action.mutate("cancel")}
                >
                  Cancel
                </button>
              )}
          </div>
        }
      />
      <section className="panel report-detail-shell">
        <LoadState loading={report.isLoading} error={report.error}>
          {report.data && (
            <>
              <div className="report-detail-identity">
                <div>
                  <span className="eyebrow">REPORT SNAPSHOT</span>
                  <p>{report.data.id}</p>
                </div>
                <span className={`status-pill status-${report.data.status.toLowerCase()}`}>
                  {report.data.status}
                </span>
              </div>
              <div className="report-detail-facts">
                <div className="drawer-fact report-creator-fact">
                  <span>Created by</span>
                  <strong>{report.data.created_by_name ?? report.data.created_by_user_id.slice(0, 8)}</strong>
                  <small>{report.data.created_by_role?.split("_").map((part) => part[0] + part.slice(1).toLowerCase()).join(" ") ?? "Role unavailable"}</small>
                </div>
                <DrawerFact label="Format" value={report.data.file_format} />
                <DrawerFact
                  label="Version"
                  value={`v${report.data.report_version} · generator ${report.data.generator_version}`}
                />
                <DrawerFact
                  label="Created"
                  value={date(report.data.created_at)}
                />
                <DrawerFact
                  label="Generated"
                  value={
                    report.data.generated_at
                      ? date(report.data.generated_at)
                      : "Pending"
                  }
                />
                <DrawerFact
                  label="Data snapshot"
                  value={
                    report.data.data_snapshot_at
                      ? date(report.data.data_snapshot_at)
                      : "—"
                  }
                />
                <div className="drawer-fact report-scope-card">
                  <span>Scope</span>
                  <div className="report-scope-tags">
                    {Object.entries(report.data.filters).filter(([, value]) => value != null && value !== "" && (!Array.isArray(value) || value.length > 0)).length ? (
                      Object.entries(report.data.filters)
                        .filter(([, value]) => value != null && value !== "" && (!Array.isArray(value) || value.length > 0))
                        .map(([key, value]) => (
                          <span key={key}>
                            {key.replaceAll("_", " ")}: {Array.isArray(value) ? value.join(", ") : String(value)}
                          </span>
                        ))
                    ) : (
                      <span>Organization-wide</span>
                    )}
                  </div>
                </div>
              </div>
              <div className="report-detail-blocks">
                <button
                  type="button"
                  className="report-detail-block"
                  onClick={() => setFullDetails("technical")}
                  aria-haspopup="dialog"
                >
                  <span className="report-detail-block-icon" aria-hidden="true">⌘</span>
                  <span className="report-detail-block-copy">
                    <strong>Technical details</strong>
                    <small>Checksums, size, retention, and version history</small>
                    <span className="report-detail-block-preview">
                      {report.data.checksum ? `SHA-256 · ${report.data.checksum.slice(0, 12)}…` : "Checksum unavailable"}
                    </span>
                  </span>
                  <span className="report-detail-block-link">View full details <b aria-hidden="true">→</b></span>
                </button>
                <button
                  type="button"
                  className="report-detail-block"
                  onClick={() => setFullDetails("snapshot")}
                  disabled={!report.data.snapshot}
                  aria-haspopup="dialog"
                >
                  <span className="report-detail-block-icon report-disclosure-json" aria-hidden="true">&#123;&#125;</span>
                  <span className="report-detail-block-copy">
                    <strong>Report data</strong>
                    <small>Generated snapshot and full JSON content</small>
                    <span className="report-detail-block-preview">
                      {report.data.snapshot ? snapshotItemCount === null ? "Snapshot available" : `${snapshotItemCount.toLocaleString()} records in snapshot` : "Snapshot not available yet"}
                    </span>
                  </span>
                  <span className="report-detail-block-link">View full details <b aria-hidden="true">→</b></span>
                </button>
              </div>
              {report.data.error_message && (
                <div className="error-state">
                  {report.data.error_message} · {report.data.error_code}
                </div>
              )}
              {action.error && (
                <p className="error-state">{action.error.message}</p>
              )}
              {download.error && (
                <p className="error-state">{download.error.message}</p>
              )}
              {user?.permissions.includes("audit:read") && (
                <section className="panel report-activity-panel">
                  <div className="report-activity-heading">
                    <div>
                      <h2>Report activity</h2>
                      <p>Audited actions and the organization members who performed them.</p>
                    </div>
                    <span>{activity.data?.total ?? 0} events</span>
                  </div>
                  <LoadState
                    loading={activity.isLoading}
                    error={activity.error}
                    empty={!activity.data?.items.length}
                  >
                    <div className="report-activity-list">
                      {activity.data?.items.map((event) => (
                        <article className="report-activity-item" key={event.id}>
                          <span className="report-activity-marker" aria-hidden="true">✓</span>
                          <div className="report-activity-action">
                            <strong>
                            {event.action
                              .replaceAll(".", " ")
                              .replaceAll("_", " ")}
                            </strong>
                            <small>{event.actor_user_id ? event.actor_name : "System"}</small>
                          </div>
                          <div className="report-activity-meta">
                            <span>{event.actor_role?.split("_").map((part) => part[0] + part.slice(1).toLowerCase()).join(" ") ?? "System action"}</span>
                            <time dateTime={event.created_at}>{date(event.created_at)}</time>
                          </div>
                        </article>
                      ))}
                    </div>
                  </LoadState>
                </section>
              )}
              {action.error && (
                <p className="error-state">{action.error.message}</p>
              )}
            </>
          )}
        </LoadState>
      </section>
      {fullDetails && report.data && (
        <RightDrawer
          className="report-full-detail-drawer"
          title={fullDetails === "technical" ? "Technical details" : "Full report data"}
          description={report.data.name}
          onClose={() => setFullDetails(null)}
        >
          {fullDetails === "technical" ? (
            <div className="report-detail-facts report-technical-facts">
              <DrawerFact label="Artifact checksum" value={report.data.checksum ?? "Unavailable for legacy report"} />
              <DrawerFact label="Snapshot checksum" value={report.data.snapshot_checksum ?? "Unavailable for legacy report"} />
              <DrawerFact label="File size" value={report.data.file_size == null ? "—" : `${report.data.file_size.toLocaleString()} bytes`} />
              <DrawerFact label="Retention until" value={report.data.retention_until ? date(report.data.retention_until) : "Not set"} />
              <DrawerFact label="Report version" value={`v${report.data.report_version} · generator ${report.data.generator_version}`} />
              {report.data.parent_report_id && <DrawerFact label="Version of" value={report.data.parent_report_id} />}
            </div>
          ) : report.data.snapshot ? (
            <pre className="json-view report-full-json">{JSON.stringify(report.data.snapshot, null, 2)}</pre>
          ) : (
            <div className="empty-inline">The report worker has not produced a snapshot yet.</div>
          )}
        </RightDrawer>
      )}
    </>
  );
}

export function NotificationsPage() {
  const [offset, setOffset] = useState(0);
  const params = new URLSearchParams({ limit: "30", offset: String(offset) });
  const query = useLoad<Page<Notification> & { unread: number }>(
    "notification-list",
    `/notifications?${params.toString()}`,
  );
  const client = useQueryClient();
  const mark = useMutation({
    mutationFn: (id: string) => api.post(`/notifications/${id}/read`),
    onSuccess: () =>
      client.invalidateQueries({ queryKey: ["notification-list"] }),
  });
  return (
    <>
      <PageHeader
        eyebrow="OPERATIONS"
        title="Notifications"
        description="Review important updates from findings, scans, reports, and remediation activity."
      />
      <section className="panel notification-list">
        <div className="panel-heading notification-list-heading">
          <div>
            <h2>Recent notifications</h2>
            <p>Personal updates for your organization workspace.</p>
          </div>
          <span className="notification-unread-count">
            <i aria-hidden="true" />
            {query.data ? query.data.unread.toLocaleString() : "—"} unread
          </span>
        </div>
        <LoadState
          loading={query.isLoading}
          error={query.error}
          empty={!query.data?.items.length}
        >
          {query.data?.items.map((row) => {
            const category = row.category.toLowerCase();
            return (
              <article
                className={`notification-row${row.read_at ? " is-read" : " unread"}`}
                key={row.id}
              >
                <div className={`notification-mark notification-mark-${category}`} aria-hidden="true">
                  <Icon name={category === "scan" ? "scan" : category === "finding" ? "warning" : category === "report" ? "report" : category === "remediation" ? "remediation" : "bell"} />
                </div>
                <div className="notification-content">
                  <div className="notification-title-line">
                    <strong>{row.title}</strong>
                    {!row.read_at && <span className="notification-new-badge">New</span>}
                  </div>
                  <p>{row.message}</p>
                  <div className="notification-meta">
                    <span>{category.replaceAll("_", " ")}</span>
                    <i aria-hidden="true">·</i>
                    <time dateTime={row.created_at}>{date(row.created_at)}</time>
                  </div>
                </div>
                {!row.read_at && (
                  <button
                    className="notification-mark-read"
                    disabled={mark.isPending}
                    aria-label={`Mark ${row.title} as read`}
                    onClick={() => mark.mutate(row.id)}
                  >
                    <Icon name="check" />
                    <span>{mark.isPending ? "Saving…" : "Mark as read"}</span>
                  </button>
                )}
              </article>
            );
          })}
        </LoadState>
        {query.data && <Pagination total={query.data.total} offset={offset} limit={30} onOffsetChange={setOffset} label="Notification pages" />}
      </section>
    </>
  );
}

export function AlertsPage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<AlertRow | null>(null);
  const [rulesOpen, setRulesOpen] = useState(false);
  const params = new URLSearchParams({ limit: "30", offset: String(offset) });
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);
  if (source) params.set("source_type", source);
  if (search.trim()) params.set("search", search.trim());
  const alerts = useLoad<Page<AlertRow>>("alerts-list", `/alerts?${params}`);
  const alertItems = alerts.data?.items ?? [];
  const summary = useLoad<{
    active: number;
    critical: number;
    high: number;
    acknowledged: number;
    resolved: number;
    dismissed: number;
  }>("alerts-summary", "/alerts/summary");
  const rules = useLoad<AlertRule[] | { items?: AlertRule[] }>(
    "alert-rules",
    "/alert-rules",
    rulesOpen,
  );
  const alertRules = Array.isArray(rules.data)
    ? rules.data
    : (rules.data?.items ?? []);
  const invalidate = async () => {
    await client.invalidateQueries({ queryKey: ["alerts-list"] });
    await client.invalidateQueries({ queryKey: ["alerts-summary"] });
  };
  const action = useMutation({
    mutationFn: ({
      id,
      kind,
    }: {
      id: string;
      kind: "acknowledge" | "resolve" | "dismiss";
    }) => api.post(`/alerts/${id}/${kind}`),
    onSuccess: invalidate,
  });
  const ruleUpdate = useMutation({
    mutationFn: ({
      id,
      enabled,
      threshold_score,
    }: {
      id: string;
      enabled?: boolean;
      threshold_score?: number;
    }) => api.patch(`/alert-rules/${id}`, { enabled, threshold_score }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["alert-rules"] });
      await invalidate();
    },
  });
  const reconcile = useMutation({
    mutationFn: () =>
      api.post<{
        evaluated_findings: number;
        evaluated_scans: number;
        created_alerts: number;
      }>("/alerts/reconcile"),
    onSuccess: invalidate,
  });
  const canManage = Boolean(user?.permissions.includes("alerts:manage"));
  const hasAlertFilters = Boolean(status || severity || source || search.trim());
  return (
    <>
      <PageHeader
        eyebrow="OPERATIONS / RESPONSE"
        title="Alerts"
        description="Security events from findings, risk assessments, and scan outcomes."
        action={
          canManage ? (
            <button
              className="secondary-button"
              onClick={() => setRulesOpen((open) => !open)}
            >
              {rulesOpen ? "Hide rules" : "Configure rules"}
            </button>
          ) : undefined
        }
      />
      <div className="metric-grid alert-kpi-grid">
        <Metric
          label="Active"
          value={summary.data?.active ?? "—"}
          suffix="Open or acknowledged"
          tone="high"
        />
        <Metric
          label="Critical"
          value={summary.data?.critical ?? "—"}
          suffix="Active critical alerts"
          tone="critical"
        />
        <Metric
          label="High"
          value={summary.data?.high ?? "—"}
          suffix="Active high alerts"
          tone="high"
        />
        <Metric
          label="Acknowledged"
          value={summary.data?.acknowledged ?? "—"}
          suffix="Awaiting resolution"
        />
        <Metric
          label="Resolved"
          value={summary.data?.resolved ?? "—"}
          suffix="Resolved alerts"
        />
      </div>
      {summary.error && (
        <div className="state-panel error-state" role="alert">
          <strong>Alert summary could not be loaded</strong>
          <span>{summary.error.message}</span>
        </div>
      )}
      {rulesOpen && (
        <section className="panel alert-rules-panel">
          <div className="panel-heading">
            <div>
              <h2>Alert rules</h2>
              <p>Organization defaults; threshold changes are audited.</p>
            </div>
          </div>
          <LoadState
            loading={rules.isLoading}
            error={rules.error}
            empty={!alertRules.length}
          >
            <div className="table-scroll">
              <DataTable caption="Alert rules">
                <thead>
                  <tr>
                    <th scope="col">Rule</th>
                    <th scope="col">Event</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Risk threshold</th>
                    <th scope="col">Enabled</th>
                  </tr>
                </thead>
                <tbody>
                  {alertRules.map((rule) => (
                    <tr key={rule.id}>
                      <td>
                        <strong>{rule.name}</strong>
                        <small>{rule.description}</small>
                      </td>
                      <td>{rule.event_type.replaceAll("_", " ")}</td>
                      <td>{rule.severity}</td>
                      <td>
                        {rule.event_type === "HIGH_RISK_FINDING" &&
                        canManage ? (
                          <input
                            key={`${rule.id}-${rule.threshold_score}`}
                            aria-label={`${rule.name} risk score threshold`}
                            className="alert-threshold-input"
                            type="number"
                            min={0}
                            max={100}
                            defaultValue={rule.threshold_score ?? ""}
                            disabled={ruleUpdate.isPending}
                            onBlur={(event) => {
                              const value = event.currentTarget.value;
                              const threshold_score =
                                value === "" ? null : Number(value);
                              if (
                                threshold_score !== rule.threshold_score &&
                                threshold_score !== null &&
                                threshold_score >= 0 &&
                                threshold_score <= 100
                              )
                                ruleUpdate.mutate({
                                  id: rule.id,
                                  threshold_score,
                                });
                            }}
                          />
                        ) : rule.threshold_score == null ? (
                          "—"
                        ) : (
                          `${rule.threshold_score}+`
                        )}
                      </td>
                      <td>
                        <label className="toggle-label">
                          <input
                            type="checkbox"
                            checked={rule.enabled}
                            disabled={ruleUpdate.isPending || !canManage}
                            onChange={(event) =>
                              ruleUpdate.mutate({
                                id: rule.id,
                                enabled: event.target.checked,
                              })
                            }
                          />{" "}
                          {rule.enabled ? "On" : "Off"}
                        </label>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
          </LoadState>
          {ruleUpdate.error && (
            <p className="error-state">{ruleUpdate.error.message}</p>
          )}
        </section>
      )}
      <div className="scan-filter-toolbar alerts-filter-toolbar">
        <div className="scan-filters">
          <FilterField label="Search" className="filter-field-search"><input
            aria-label="Search alerts"
            placeholder="Search alert title"
            value={search}
            onChange={(event) => { setSearch(event.target.value); setOffset(0); }}
          /></FilterField>
          <FilterField label="Severity"><select
            aria-label="Filter alert severity"
            value={severity}
            onChange={(event) => { setSeverity(event.target.value); setOffset(0); }}
          >
            <option value="">All severities</option>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select></FilterField>
          <FilterField label="Status"><select
            aria-label="Filter alert status"
            value={status}
            onChange={(event) => { setStatus(event.target.value); setOffset(0); }}
          >
            <option value="">All statuses</option>
            {["OPEN", "ACKNOWLEDGED", "RESOLVED", "DISMISSED"].map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select></FilterField>
          <FilterField label="Source"><select
            aria-label="Filter alert source"
            value={source}
            onChange={(event) => { setSource(event.target.value); setOffset(0); }}
          >
            <option value="">All sources</option>
            <option value="FINDING">Finding</option>
            <option value="SCAN">Scan</option>
          </select></FilterField>
        </div>
        <FilterFooter className="scan-filter-footer" active={hasAlertFilters} onReset={() => {
          setSearch(""); setSeverity(""); setStatus(""); setSource(""); setOffset(0);
        }} />
      </div>
      <section className="panel table-panel alert-table-panel">
        <LoadState
          loading={alerts.isLoading}
          error={alerts.error}
          empty={!alertItems.length}
          emptyTitle={hasAlertFilters ? "No matching alerts" : "No alert events yet"}
          emptyMessage={
            hasAlertFilters
              ? "Change or clear the filters to see other alerts."
              : "Alerts are created from active findings and failed or partial scans. You can evaluate existing records for this organization."
          }
          emptyAction={
            !hasAlertFilters && canManage ? (
              <button
                className="secondary-button"
                disabled={reconcile.isPending}
                onClick={() => reconcile.mutate()}
              >
                {reconcile.isPending ? "Evaluating…" : "Evaluate existing events"}
              </button>
            ) : undefined
          }
        >
          <div className="table-scroll">
            <DataTable caption="Security alerts" actions>
              <thead>
                <tr>
                  <th scope="col">Severity</th>
                  <th scope="col">Alert</th>
                  <th scope="col">Source</th>
                  <th scope="col">Account</th>
                  <th scope="col">Region</th>
                  <th scope="col">Status</th>
                  <th scope="col">Occurrences</th>
                  <th scope="col">Created</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {alertItems.map((item) => (
                  <tr key={item.id} onDoubleClick={() => setSelected(item)}>
                    <td>
                      <span className={severityClass(item.severity)}>
                        {item.severity}
                      </span>
                    </td>
                    <td>
                      <button
                        className="text-button row-primary"
                        onClick={() => setSelected(item)}
                      >
                        {item.title}
                      </button>
                      <small>{item.description}</small>
                    </td>
                    <td>
                      {item.source_type}
                      {item.source_href && (
                        <small>
                          <Link to={item.source_href}>
                            {item.source_id.slice(0, 12)}…
                          </Link>
                        </small>
                      )}
                    </td>
                    <td>{item.account_name ?? "—"}</td>
                    <td>{item.region_code ?? "—"}</td>
                    <td>
                      <span className={`status-pill status-${item.status.toLowerCase()}`}>{item.status.replaceAll("_", " ")}</span>
                    </td>
                    <td>{item.occurrence_count}</td>
                      <td>{date(item.created_at)}</td>
                    <td>
                      <div className="table-row-actions">
                      <ViewAction label={`View alert ${item.title}`} onClick={() => setSelected(item)} />
                      <DismissibleActionMenu
                        className="alert-row-actions"
                        label={`Actions for ${item.title}`}
                      >
                        <div className="alert-row-action-menu" role="menu">
                          <div className="alert-row-action-heading">Alert actions</div>
                          <button
                            role="menuitem"
                            className="alert-menu-item"
                            onClick={() => setSelected(item)}
                          >
                            <span className="alert-menu-icon alert-menu-icon-details" aria-hidden="true">
                              <svg viewBox="0 0 24 24"><path d="M2.5 12s3.4-6 9.5-6 9.5 6 9.5 6-3.4 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg>
                            </span>
                            <span className="alert-menu-copy"><strong>View details</strong><small>Inspect the event and its source</small></span>
                          </button>
                          {canManage && ["OPEN", "ACKNOWLEDGED"].includes(item.status) && (
                            <div className="alert-row-action-separator" />
                          )}
                          {canManage && item.status === "OPEN" && (
                            <button
                              role="menuitem"
                              className="alert-menu-item"
                              disabled={action.isPending}
                              onClick={() => action.mutate({ id: item.id, kind: "acknowledge" })}
                            >
                              <span className="alert-menu-icon alert-menu-icon-ack" aria-hidden="true">
                                <svg viewBox="0 0 24 24"><path d="m5 12.5 4.2 4.2L19 7"/></svg>
                              </span>
                              <span className="alert-menu-copy"><strong>Acknowledge</strong><small>Mark as reviewed and being handled</small></span>
                            </button>
                          )}
                          {canManage && ["OPEN", "ACKNOWLEDGED"].includes(item.status) && (
                            <button
                              role="menuitem"
                              className="alert-menu-item"
                              disabled={action.isPending}
                              onClick={() => action.mutate({ id: item.id, kind: "resolve" })}
                            >
                              <span className="alert-menu-icon alert-menu-icon-resolve" aria-hidden="true">
                                <svg viewBox="0 0 24 24"><path d="m5 12.5 4.2 4.2L19 7"/><circle cx="12" cy="12" r="9"/></svg>
                              </span>
                              <span className="alert-menu-copy"><strong>Resolve alert</strong><small>Close after the issue is addressed</small></span>
                            </button>
                          )}
                          {canManage && ["OPEN", "ACKNOWLEDGED"].includes(item.status) && (
                            <button
                              role="menuitem"
                              className="alert-menu-item alert-menu-dismiss"
                              disabled={action.isPending}
                              onClick={() => action.mutate({ id: item.id, kind: "dismiss" })}
                            >
                              <span className="alert-menu-icon alert-menu-icon-dismiss" aria-hidden="true">
                                <svg viewBox="0 0 24 24"><path d="m7 7 10 10M17 7 7 17"/></svg>
                              </span>
                              <span className="alert-menu-copy"><strong>Dismiss alert</strong><small>Close when no action is required</small></span>
                            </button>
                          )}
                          {(!canManage || !["OPEN", "ACKNOWLEDGED"].includes(item.status)) && (
                            <span className="alert-row-action-note">
                              {!canManage
                                ? "Your role can view alerts but cannot change their status."
                                : item.status === "RESOLVED"
                                  ? "This alert is resolved. No further actions are available."
                                  : item.status === "DISMISSED"
                                    ? "This alert is dismissed. No further actions are available."
                                    : "There are no more actions for this alert."}
                            </span>
                          )}
                        </div>
                      </DismissibleActionMenu>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </DataTable>
          </div>
        </LoadState>
        {alerts.data && <Pagination total={alerts.data.total} offset={offset} limit={30} onOffsetChange={setOffset} label="Alert pages" />}
        {reconcile.data && (
          <p className="success-state" role="status">
            Evaluated {reconcile.data.evaluated_findings} active findings and{" "}
            {reconcile.data.evaluated_scans} scan outcomes; created{" "}
            {` ${reconcile.data.created_alerts}`} alerts.
          </p>
        )}
        {reconcile.error && (
          <p className="error-state" role="alert">{reconcile.error.message}</p>
        )}
        {action.error && <p className="error-state">{action.error.message}</p>}
      </section>
      {selected && (
        <RightDrawer
          title={selected.title}
          description={`${selected.id} · ${selected.severity} · ${selected.status}`}
          onClose={() => setSelected(null)}
        >
          <div className="drawer-facts">
            <DrawerFact label="Source" value={selected.source_type} />
            <DrawerFact label="Account" value={selected.account_name ?? "—"} />
            <DrawerFact label="Region" value={selected.region_code ?? "—"} />
            <DrawerFact
              label="Occurrences"
              value={String(selected.occurrence_count)}
            />
            <DrawerFact
              label="First seen"
              value={date(selected.first_seen_at)}
            />
            <DrawerFact label="Last seen" value={date(selected.last_seen_at)} />
          </div>
          <p>{selected.description}</p>
          {selected.source_href && (
            <Link className="primary-button" to={selected.source_href}>
              View source record
            </Link>
          )}
          {canManage && selected.status === "OPEN" && (
            <button
              className="secondary-button"
              onClick={() => {
                action.mutate({ id: selected.id, kind: "acknowledge" });
                setSelected(null);
              }}
            >
              Acknowledge
            </button>
          )}
          {canManage && ["OPEN", "ACKNOWLEDGED"].includes(selected.status) && (
            <button
              className="secondary-button"
              onClick={() => {
                action.mutate({ id: selected.id, kind: "resolve" });
                setSelected(null);
              }}
            >
              Resolve
            </button>
          )}
        </RightDrawer>
      )}
    </>
  );
}

export function AuditPage() {
  const { user } = useAuth();
  const [search, setSearch] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [status, setStatus] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [actorRole, setActorRole] = useState("");
  const [actorId, setActorId] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<AuditRow | null>(null);
  const [exportError, setExportError] = useState("");
  const params = new URLSearchParams({ limit: "30", offset: String(offset) });
  if (search.trim()) params.set("search", search.trim());
  if (resourceType) params.set("resource_type", resourceType);
  if (actorRole) params.set("actor_role", actorRole);
  if (actorId) params.set("actor_id", actorId);
  if (status) params.set("status", status);
  const dateFromUtc = dateFrom ? organizationDateToUtcIso(dateFrom, "start") : null;
  const dateToUtc = dateTo ? organizationDateToUtcIso(dateTo, "end") : null;
  if (dateFromUtc) params.set("date_from", dateFromUtc);
  if (dateToUtc) params.set("date_to", dateToUtc);
  const query = useLoad<Page<AuditRow>>(
    `audit-events-${params}`,
    `/audit-events?${params}`,
  );
  const summary = useLoad<AuditSummary>(
    "audit-summary",
    "/audit-events/summary",
  );
  const users = useLoad<Page<UserRow>>("audit-organization-users", "/users?limit=100");
  const actorUsers = (users.data?.items ?? []).filter((member) => !actorRole || member.role_code === actorRole);
  const actorRoles = [...new Set((users.data?.items ?? []).map((member) => member.role_code))].sort();
  const exportAllowed = Boolean(user?.permissions.includes("audit:export"));
  const exportLogs = async (format: "CSV" | "JSON") => {
    setExportError("");
    try {
      const exportParams = new URLSearchParams(params);
      exportParams.delete("limit");
      exportParams.delete("offset");
      exportParams.set("format", format);
      const blob = await api.get<Blob>(`/audit-export?${exportParams}`);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `cloudsentinel-audit.${format.toLowerCase()}`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      setExportError(
        error instanceof Error ? error.message : "Audit export failed.",
      );
    }
  };
  return (
    <>
      <PageHeader
        eyebrow="GOVERNANCE"
        title="Audit Logs"
        description="Security activity and accountability trail for this organization."
        action={
          exportAllowed ? (
            <div className="button-pair">
              <button
                className="secondary-button"
                onClick={() => void exportLogs("CSV")}
              >
                Export CSV
              </button>
              <button
                className="secondary-button"
                onClick={() => void exportLogs("JSON")}
              >
                Export JSON
              </button>
            </div>
          ) : undefined
        }
      />
      {exportError && <p className="error-state">{exportError}</p>}
      <div className="kpi-grid four-up audit-kpis">
        <KpiCard label="Events Today" value={summary.data?.events_today} />
        <KpiCard
          label="Security Events"
          value={summary.data?.security_events}
        />
        <KpiCard label="Failed Actions" value={summary.data?.failed_actions} />
        <KpiCard
          label="Administrative Actions"
          value={summary.data?.administrative_actions}
        />
      </div>
      <div className="action-strip compliance-toolbar compliance-control-filters audit-filter-row">
        <FilterField label="Search" className="filter-field-search"><input
          aria-label="Search audit logs"
          placeholder="Search actor, action, target, request ID"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
        /></FilterField>
        <FilterField label="Resource type"><select
          aria-label="Filter resource type"
          value={resourceType}
          onChange={(event) => {
            setResourceType(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All resource types</option>
          {[
            "user",
            "team",
            "organization",
            "cloud_account",
            "asset",
            "finding",
            "policy",
            "scan_job",
            "remediation_request",
            "alert",
            "report",
            "audit",
          ].map((value) => (
            <option key={value} value={value}>
              {value.replaceAll("_", " ")}
            </option>
          ))}
        </select></FilterField>
        <FilterField label="Status"><select
          aria-label="Filter audit status"
          value={status}
          onChange={(event) => {
            setStatus(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All statuses</option>
          <option value="SUCCESS">Success</option>
          <option value="FAILURE">Failure</option>
        </select></FilterField>
        <FilterField label="Actor role"><select
          aria-label="Filter actor role"
          value={actorRole}
          onChange={(event) => {
            setActorRole(event.target.value);
            setActorId("");
            setOffset(0);
          }}
        >
          <option value="">All roles</option>
          {actorRoles.map((role) => <option key={role} value={role}>{role.replaceAll("_", " ")}</option>)}
        </select></FilterField>
        <FilterField label="Actor"><select
          aria-label="Filter actor name"
          value={actorId}
          onChange={(event) => {
            setActorId(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">All actors</option>
          {actorUsers.map((member) => <option key={member.user_id} value={member.user_id}>{member.display_name}</option>)}
        </select></FilterField>
        <label>
          From{" "}
          <input
            type="date"
            value={dateFrom}
            onChange={(event) => {
              setDateFrom(event.target.value);
              setOffset(0);
            }}
          />
        </label>
        <label>
          To{" "}
          <input
            type="date"
            value={dateTo}
            onChange={(event) => {
              setDateTo(event.target.value);
              setOffset(0);
            }}
          />
        </label>
      </div>
      <FilterFooter className="scan-filter-footer audit-filter-reset-row" active={Boolean(search.trim() || resourceType || status || dateFrom || dateTo || actorRole || actorId)} onReset={() => {
          setSearch(""); setResourceType(""); setStatus(""); setDateFrom(""); setDateTo("");
          setActorRole(""); setActorId(""); setOffset(0);
        }} />
      <section className="panel table-panel">
        <LoadState
          loading={query.isLoading}
          error={query.error}
          empty={!query.data?.items.length}
        >
          <div className="table-scroll audit-table-scroll">
          <DataTable caption="Audit event history" actions>
            <thead>
              <tr>
                <th scope="col">Actor</th>
                <th scope="col">Action</th>
                <th scope="col">Target</th>
                <th scope="col">Resource Type</th>
                <th scope="col">Status</th>
                <th scope="col">IP Address</th>
                <th scope="col">Request ID</th>
                <th scope="col">Timestamp</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {query.data?.items.map((event) => (
                <tr key={event.id}>
                  <td>
                    {event.actor_name}
                    <small>{event.actor_role ?? event.actor_type}</small>
                  </td>
                  <td className="row-primary">{event.action}</td>
                  <td>
                    {event.target_type ?? event.resource_type}
                    <small>{event.target_id ?? event.resource_id ?? "—"}</small>
                  </td>
                  <td>{event.resource_type.replaceAll("_", " ")}</td>
                  <td>
                    <span
                      className={`status-pill ${event.status === "FAILURE" ? "status-danger" : ""}`}
                    >
                      {event.status}
                    </span>
                  </td>
                  <td>{event.ip_address ?? "—"}</td>
                  <td>
                    <code
                      className="audit-request-id"
                      title={event.request_id ?? undefined}
                    >{event.request_id ?? "—"}</code>
                  </td>
                  <td>{date(event.created_at)}</td>
                  <td>
                    <button
                      className="scan-view-action"
                      aria-label={`View audit event ${event.id.slice(0, 8)}`}
                      onClick={() => setSelected(event)}
                    >
                      <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.2 12s3.5-6 9.8-6 9.8 6 9.8 6-3.5 6-9.8 6-9.8-6-9.8-6Z" /><circle cx="12" cy="12" r="2.8" /></svg>
                      <span>View</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </DataTable>
          </div>
        </LoadState>
        {query.data && <Pagination total={query.data.total} offset={offset} limit={30} onOffsetChange={setOffset} label="Audit event pages" />}
      </section>
      {selected && (
        <RightDrawer
          className="audit-event-drawer"
          title="Audit Event"
          description="Organization security activity record"
          onClose={() => setSelected(null)}
        >
          <section className="audit-event-hero">
            <div className="audit-event-hero-icon" aria-hidden="true">≡</div>
            <div className="audit-event-hero-copy">
              <span className="eyebrow">{selected.resource_type.replaceAll("_", " ")}</span>
              <h3>{selected.action.replaceAll("_", " ")}</h3>
              <p>{date(selected.created_at)}</p>
            </div>
            <span className={`status-pill ${selected.status === "FAILURE" ? "status-danger" : "status-connected"}`}>
              {selected.status}
            </span>
          </section>
          <div className="drawer-facts">
            <DrawerFact
              label="Actor"
              value={`${selected.actor_name} · ${selected.actor_role ?? selected.actor_type}`}
            />
            <DrawerFact
              label="Target"
              value={`${selected.target_type ?? selected.resource_type} · ${selected.target_id ?? selected.resource_id ?? "—"}`}
            />
            <DrawerFact label="Resource type" value={selected.resource_type} />
            <DrawerFact label="Timestamp" value={date(selected.created_at)} />
            <DrawerFact label="IP address" value={selected.ip_address ?? "—"} />
            <DrawerFact label="User agent" value={selected.user_agent ?? "—"} />
            <DrawerFact label="Request ID" value={selected.request_id ?? "—"} />
            <DrawerFact label="Event ID" value={selected.id} />
            <DrawerFact
              label="Retention until"
              value={
                selected.retention_until
                  ? date(selected.retention_until)
                  : "Organization policy"
              }
            />
          </div>
          <AuditJson label="Before" value={selected.before} />
          <AuditJson label="After" value={selected.after} />
          <AuditJson label="Additional metadata" value={selected.details} />
        </RightDrawer>
      )}
    </>
  );
}

type AuditRow = {
  id: string;
  actor_user_id: string | null;
  actor_type: string;
  actor_name: string;
  actor_role: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  target_type: string | null;
  target_id: string | null;
  status: "SUCCESS" | "FAILURE";
  ip_address: string | null;
  user_agent: string | null;
  request_id: string | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  details: Record<string, unknown>;
  retention_until: string | null;
  created_at: string;
};
type AuditSummary = {
  events_today: number;
  security_events: number;
  failed_actions: number;
  administrative_actions: number;
};
function KpiCard({
  label,
  value,
}: {
  label: string;
  value: number | undefined;
}) {
  return (
    <article className={`kpi-card kpi-tone-${kpiTone(label)}`}>
      <span>{label}</span>
      <strong>{value === undefined ? "—" : value.toLocaleString()}</strong>
      <KpiIcon label={label} />
    </article>
  );
}
function AuditJson({
  label,
  value,
}: {
  label: string;
  value: Record<string, unknown> | null;
}) {
  return (
    <section className="audit-json-section">
      <h3>{label}</h3>
      {value ? (
        <pre>{JSON.stringify(value, null, 2)}</pre>
      ) : (
        <p>Not recorded for this event.</p>
      )}
    </section>
  );
}

export function AdminPage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const org = useLoad<Org>("organization-profile", "/organizations/current");
  const users = useLoad<Page<UserRow>>(
    "organization-users",
    "/users?limit=100",
  );
  const teams = useLoad<Team[]>("organization-teams", "/teams");
  const [name, setName] = useState("");
  const [feedback, setFeedback] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteName, setInviteName] = useState("");
  const [inviteRole, setInviteRole] = useState("VIEWER");
  const [invitationLink, setInvitationLink] = useState("");
  const [teamName, setTeamName] = useState("");
  const [organizationEditOpen, setOrganizationEditOpen] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [teamOpen, setTeamOpen] = useState(false);
  const [selectedMember, setSelectedMember] = useState<UserRow | null>(null);
  const [roleDrafts, setRoleDrafts] = useState<Record<string, string>>({});
  const update = useMutation({
    mutationFn: () => api.patch("/organizations/current", { name }),
    onSuccess: () => {
      setFeedback("Organization profile updated.");
      setOrganizationEditOpen(false);
      client.invalidateQueries({ queryKey: ["organization-profile"] });
      client.invalidateQueries({ queryKey: ["organization"] });
    },
    onError: (error) =>
      setFeedback(error instanceof Error ? error.message : "Update failed."),
  });
  const invite = useMutation({
    mutationFn: () =>
      api.post<{
        email: string;
        invitation_url: string;
        email_delivery: "sent" | "failed";
      }>("/users/invitations", {
        email: inviteEmail,
        display_name: inviteName,
        role_code: inviteRole,
      }),
    onSuccess: (result) => {
      setInvitationLink(result.invitation_url);
      setInviteEmail("");
      setInviteName("");
      setFeedback(
        result.email_delivery === "sent"
          ? `Invitation email sent to ${result.email}. Ask them to check spam or promotions if it is not in the inbox.`
          : `Invitation created, but email delivery failed for ${result.email}. Copy the invitation link below and share it securely.`,
      );
      client.invalidateQueries({ queryKey: ["organization-users"] });
    },
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "Invitation failed.",
      ),
  });
  const changeRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: string }) =>
      api.patch(`/users/${id}/role`, { role_code: role }),
    onSuccess: () =>
      client.invalidateQueries({ queryKey: ["organization-users"] }),
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "Role update failed.",
      ),
  });
  const changeActive = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      active
        ? api.post(`/users/${id}/enable`)
        : api.post(`/users/${id}/disable`),
    onSuccess: () =>
      client.invalidateQueries({ queryKey: ["organization-users"] }),
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "Membership update failed.",
      ),
  });
  const createTeam = useMutation({
    mutationFn: () => api.post("/teams", { name: teamName }),
    onSuccess: () => {
      setTeamName("");
      setTeamOpen(false);
      client.invalidateQueries({ queryKey: ["organization-teams"] });
    },
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "Team creation failed.",
      ),
  });
  const deleteTeam = useMutation({
    mutationFn: (id: string) => api.delete(`/teams/${id}`),
    onSuccess: () =>
      client.invalidateQueries({ queryKey: ["organization-teams"] }),
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "Team deletion failed.",
      ),
  });
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    update.mutate();
  }
  function submitInvitation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setInvitationLink("");
    invite.mutate();
  }
  function submitTeam(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    createTeam.mutate();
  }
  return (
    <>
      <PageHeader
        eyebrow="ADMINISTRATION"
        title="Administration"
        description="Organization context, users, teams, and role visibility."
        action={
          user?.permissions.includes("users:invite") ? (
            <button
              className="primary-button"
              onClick={() => {
                setInvitationLink("");
                setInviteOpen(true);
              }}
            >
              Invite member
            </button>
          ) : undefined
        }
      />
      <section className="panel admin-profile">
        <div className="panel-heading">
          <div>
            <h2>Organization</h2>
            <p>{org.data?.slug}</p>
          </div>
          <span className="status-pill">{user?.role.replaceAll("_", " ")}</span>
        </div>
        <div className="drawer-facts">
          <DrawerFact
            label="Organization"
            value={org.data?.name ?? "Loading"}
          />
          <DrawerFact label="Tenant slug" value={org.data?.slug ?? "—"} />
          <DrawerFact
            label="Status"
            value={org.data?.is_active ? "Active" : "Inactive"}
          />
        </div>
        {user?.permissions.includes("organizations:update") && (
          <div className="drawer-actions">
            <button
              className="secondary-button"
              onClick={() => setOrganizationEditOpen(true)}
            >
              Edit organization
            </button>
          </div>
        )}
        {feedback && <p className="inline-feedback">{feedback}</p>}
      </section>
      {user?.permissions.includes("users:invite") && (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Invite organization member</h2>
              <p>Send a one-time invitation link to the new member by email.</p>
            </div>
          </div>
          <button
            className="secondary-button"
            onClick={() => {
              setInvitationLink("");
              setInviteOpen(true);
            }}
          >
            Open invitation form
          </button>
          {invitationLink && (
            <div className="token-reveal">
              <code>{invitationLink}</code>
              <button
                className="small-button"
                onClick={() =>
                  void navigator.clipboard
                    .writeText(invitationLink)
                    .then(() => setFeedback("Invitation link copied."))
                }
              >
                Copy link
              </button>
            </div>
          )}
        </section>
      )}
      <div className="two-column">
        <section className="panel table-panel">
          <div className="panel-heading">
            <div>
              <h2>Organization members</h2>
              <p>Role assignments in this organization</p>
            </div>
          </div>
          <LoadState
            loading={users.isLoading}
            error={users.error}
            empty={!users.data?.items.length}
          >
            <DataTable caption="Organization members" actions>
              <thead>
                <tr>
                  <th scope="col">Member</th>
                  <th scope="col">Role</th>
                  <th scope="col">Status</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.data?.items.map((row) => (
                  <tr key={row.user_id}>
                    <td>
                      <button
                        className="text-button row-primary"
                        onClick={() => setSelectedMember(row)}
                      >
                        {row.display_name}
                      </button>
                      <small>{row.email}</small>
                    </td>
                    <td>
                      {user?.permissions.includes("users:update") ? (
                        <select
                          aria-label={`Role for ${row.email}`}
                          value={roleDrafts[row.user_id] ?? row.role_code}
                          onChange={(event) =>
                            setRoleDrafts({
                              ...roleDrafts,
                              [row.user_id]: event.target.value,
                            })
                          }
                        >
                          {[
                            "SUPER_ADMIN",
                            "ORG_ADMIN",
                            "SECURITY_ADMIN",
                            "SECURITY_ANALYST",
                            "CLOUD_ENGINEER",
                            "AUDITOR",
                            "VIEWER",
                          ].map((role) => (
                            <option key={role}>{role}</option>
                          ))}
                        </select>
                      ) : (
                        row.role_code.replaceAll("_", " ")
                      )}
                    </td>
                    <td>
                      <span className="status-pill">
                        {row.is_active ? "ACTIVE" : "DISABLED"}
                      </span>
                    </td>
                    <td>
                      <div className="button-pair">
                        {user?.permissions.includes("users:update") &&
                          row.role_code !==
                            (roleDrafts[row.user_id] ?? row.role_code) && (
                            <button
                              className="small-button"
                              disabled={changeRole.isPending}
                              onClick={() =>
                                changeRole.mutate({
                                  id: row.user_id,
                                  role: roleDrafts[row.user_id],
                                })
                              }
                            >
                              Save role
                            </button>
                          )}
                        {row.user_id !== user?.id &&
                          row.is_active &&
                          user?.permissions.includes("users:disable") && (
                            <button
                              className="small-button"
                              disabled={changeActive.isPending}
                              onClick={() =>
                                changeActive.mutate({
                                  id: row.user_id,
                                  active: false,
                                })
                              }
                            >
                              Disable
                            </button>
                          )}
                        {!row.is_active &&
                          user?.permissions.includes("users:update") && (
                            <button
                              className="small-button"
                              disabled={changeActive.isPending}
                              onClick={() =>
                                changeActive.mutate({
                                  id: row.user_id,
                                  active: true,
                                })
                              }
                            >
                              Enable
                            </button>
                          )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </DataTable>
          </LoadState>
        </section>
        <section className="panel table-panel">
          <div className="panel-heading">
            <div>
              <h2>Teams</h2>
              <p>Organization work groups</p>
            </div>
            {user?.permissions.includes("teams:create") && (
              <button
                className="secondary-button"
                onClick={() => setTeamOpen(true)}
              >
                Create team
              </button>
            )}
          </div>
          <LoadState
            loading={teams.isLoading}
            error={teams.error}
            empty={!teams.data?.length}
          >
            <DataTable caption="Organization teams" actions>
              <thead>
                <tr>
                  <th scope="col">Team</th>
                  <th scope="col">Members</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {teams.data?.map((team) => (
                  <tr key={team.id}>
                    <td>
                      {team.name}
                      <small>{team.description}</small>
                    </td>
                    <td>{team.member_count}</td>
                    <td>
                      {user?.permissions.includes("teams:delete") && (
                        <button
                          className="small-button danger-button"
                          disabled={deleteTeam.isPending}
                          onClick={() => deleteTeam.mutate(team.id)}
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </DataTable>
          </LoadState>
        </section>
      </div>
      {inviteOpen && (
        <RightDrawer
          title="Invite organization member"
          description="Send a one-time, 72-hour invitation link to the member's email. Creating a replacement link invalidates any older pending link."
          onClose={() => setInviteOpen(false)}
        >
          <form className="drawer-form" onSubmit={submitInvitation}>
            <label>
              Full name
              <input
                required
                minLength={2}
                maxLength={200}
                value={inviteName}
                onChange={(event) => setInviteName(event.target.value)}
              />
            </label>
            <label>
              Email
              <input
                required
                type="email"
                value={inviteEmail}
                onChange={(event) => setInviteEmail(event.target.value)}
              />
            </label>
            <label>
              Role
              <select
                value={inviteRole}
                onChange={(event) => setInviteRole(event.target.value)}
              >
                {[
                  "SUPER_ADMIN",
                  "ORG_ADMIN",
                  "SECURITY_ADMIN",
                  "SECURITY_ANALYST",
                  "CLOUD_ENGINEER",
                  "AUDITOR",
                  "VIEWER",
                ].map((role) => (
                  <option key={role}>{role}</option>
                ))}
              </select>
            </label>
            <button className="primary-button" disabled={invite.isPending}>
              {invite.isPending ? "Sending…" : "Send invitation"}
            </button>
            {invitationLink && (
              <div className="token-reveal">
                <code>{invitationLink}</code>
                <button
                  type="button"
                  className="small-button"
                  onClick={() =>
                    void navigator.clipboard
                      .writeText(invitationLink)
                      .then(() => setFeedback("Invitation link copied."))
                  }
                >
                  Copy link
                </button>
              </div>
            )}
            {invite.error && (
              <div className="error-state">{invite.error.message}</div>
            )}
          </form>
        </RightDrawer>
      )}
      {organizationEditOpen && (
        <RightDrawer
          title="Edit organization"
          description="Change the display name for this organization."
          onClose={() => setOrganizationEditOpen(false)}
        >
          <form className="drawer-form" onSubmit={save}>
            <label>
              Organization name
              <input
                required
                minLength={2}
                maxLength={200}
                value={name || org.data?.name || ""}
                onChange={(event) => setName(event.target.value)}
              />
            </label>
            <button className="primary-button" disabled={update.isPending}>
              {update.isPending ? "Saving…" : "Save organization"}
            </button>
            {update.error && (
              <div className="error-state">{update.error.message}</div>
            )}
          </form>
        </RightDrawer>
      )}
      {teamOpen && (
        <RightDrawer
          title="Create team"
          description="Add an organization-scoped team."
          onClose={() => setTeamOpen(false)}
        >
          <form className="drawer-form" onSubmit={submitTeam}>
            <label>
              Team name
              <input
                required
                minLength={1}
                maxLength={120}
                value={teamName}
                onChange={(event) => setTeamName(event.target.value)}
              />
            </label>
            <button className="primary-button" disabled={createTeam.isPending}>
              {createTeam.isPending ? "Creating…" : "Create team"}
            </button>
            {createTeam.error && (
              <div className="error-state">{createTeam.error.message}</div>
            )}
          </form>
        </RightDrawer>
      )}
      {selectedMember && (
        <RightDrawer
          title={selectedMember.display_name}
          description="Organization membership details"
          onClose={() => setSelectedMember(null)}
        >
          <div className="drawer-facts">
            <DrawerFact label="Email" value={selectedMember.email} />
            <DrawerFact
              label="Role"
              value={selectedMember.role_code.replaceAll("_", " ")}
            />
            <DrawerFact
              label="Membership status"
              value={selectedMember.is_active ? "Active" : "Disabled"}
            />
          </div>
        </RightDrawer>
      )}
    </>
  );
}

export function ProfilePage() {
  type Profile = {
    user_id: string;
    email: string;
    display_name: string;
    role_code: string;
    organization_name: string;
    is_active: boolean;
    created_at: string;
    last_login_at: string | null;
    team_names: string[];
  };
  type MfaStatus = { enabled: boolean; pending_enrollment: boolean };
  type MfaSetup = { secret: string; otpauth_url: string; recovery_codes: string[] };
  const { updateDisplayName } = useAuth();
  const profile = useLoad<Profile>("my-profile", "/users/me");
  const mfa = useLoad<MfaStatus>("my-mfa-status", "/auth/mfa");
  const [displayNameDraft, setDisplayNameDraft] = useState<string | null>(null);
  const [mfaSetupResult, setMfaSetupResult] = useState<MfaSetup | null>(null);
  const [mfaMessage, setMfaMessage] = useState("");
  const displayName = displayNameDraft ?? profile.data?.display_name ?? "";
  const [saved, setSaved] = useState(false);
  const saveProfile = useMutation({
    mutationFn: () => updateDisplayName(displayName.trim()),
    onSuccess: async () => {
      setSaved(true);
      await profile.refetch();
      setDisplayNameDraft(null);
    },
  });
  const startMfaSetup = useMutation({
    mutationFn: (currentPassword: string) =>
      api.post<MfaSetup>("/auth/mfa/setup", { current_password: currentPassword }),
    onSuccess: (result) => {
      setMfaSetupResult(result);
      setMfaMessage("Scan the authenticator setup value, save the recovery codes, then verify a code.");
    },
  });
  const confirmMfaSetup = useMutation({
    mutationFn: (code: string) => api.post<MfaStatus>("/auth/mfa/verify", { code }),
    onSuccess: async () => {
      setMfaSetupResult(null);
      setMfaMessage("Multi-factor authentication is enabled for your account.");
      await mfa.refetch();
    },
  });
  const disableMfa = useMutation({
    mutationFn: (values: { currentPassword: string; code: string }) =>
      api.post<MfaStatus>("/auth/mfa/disable", {
        current_password: values.currentPassword,
        code: values.code,
      }),
    onSuccess: async () => {
      setMfaMessage("Multi-factor authentication has been disabled.");
      await mfa.refetch();
    },
  });
  return (
    <>
      <PageHeader eyebrow="PROFILE / ACCOUNT" title="Profile details" description="View and update your personal account details." />
      {saveProfile.error && <div className="banner-error">{saveProfile.error.message}</div>}
      {saved && <div className="banner-success">Profile updated.</div>}
      <section className="panel" style={{ maxWidth: 760, padding: 24 }}>
        <LoadState loading={profile.isLoading} error={profile.error} empty={!profile.data}>
          {profile.data && (
            <form className="form-stack" onSubmit={(event) => { event.preventDefault(); setSaved(false); saveProfile.mutate(); }}>
              <label className="profile-field">Full name
                <input required minLength={2} maxLength={200} value={displayName} onChange={(event) => setDisplayNameDraft(event.target.value)} />
              </label>
              <label className="profile-field">Email address
                <input value={profile.data.email} readOnly />
              </label>
              <div className="drawer-facts">
                <DrawerFact label="Role" value={profile.data.role_code.replaceAll("_", " ")} />
                <DrawerFact label="Organization" value={profile.data.organization_name} />
                <DrawerFact label="Status" value={profile.data.is_active ? "Active" : "Inactive"} />
                <DrawerFact label="Teams" value={profile.data.team_names.join(", ") || "No teams assigned"} />
              </div>
              <div><button className="primary-button" type="submit" disabled={saveProfile.isPending || displayName.trim().length < 2}>{saveProfile.isPending ? "Saving…" : "Save changes"}</button></div>
            </form>
          )}
        </LoadState>
      </section>
      <section className="panel" style={{ maxWidth: 760, padding: 24, marginTop: 18 }}>
        <div className="panel-heading">
          <div><h2>Multi-factor authentication</h2><p>Protect sign-in with an authenticator app and single-use recovery codes.</p></div>
          <span className={`status-badge ${mfa.data?.enabled ? "status-active" : ""}`}>
            {mfa.isLoading ? "Checking" : mfa.data?.enabled ? "Enabled" : mfa.data?.pending_enrollment ? "Setup pending" : "Not enabled"}
          </span>
        </div>
        {mfa.error && <div className="banner-error" role="alert">{mfa.error.message}</div>}
        {mfaMessage && <div className="banner-success" role="status">{mfaMessage}</div>}
        {(startMfaSetup.error || confirmMfaSetup.error || disableMfa.error) && (
          <div className="banner-error" role="alert">{(startMfaSetup.error ?? confirmMfaSetup.error ?? disableMfa.error)?.message}</div>
        )}
        {!mfa.data?.enabled && !mfaSetupResult && (
          <form className="form-stack" onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            startMfaSetup.mutate(String(form.get("mfa-current-password")));
          }}>
            <label className="profile-field">Confirm your password
              <input name="mfa-current-password" type="password" autoComplete="current-password" required maxLength={128} />
            </label>
            <div><button className="primary-button" disabled={startMfaSetup.isPending || mfa.isLoading}>
              {startMfaSetup.isPending ? "Preparing setup…" : mfa.data?.pending_enrollment ? "Restart setup" : "Set up authenticator"}
            </button></div>
          </form>
        )}
        {mfaSetupResult && (
          <div className="form-stack">
            <div className="settings-policy-note"><strong>Authenticator setup value</strong><p>Enter this value in your authenticator app. Keep recovery codes somewhere secure; each code works once.</p><code>{mfaSetupResult.secret}</code><p><small>Setup URI: {mfaSetupResult.otpauth_url}</small></p></div>
            <div className="settings-policy-note"><strong>Recovery codes</strong><div className="mfa-recovery-codes">{mfaSetupResult.recovery_codes.map((code) => <code key={code}>{code}</code>)}</div></div>
            <form className="form-stack" onSubmit={(event) => {
              event.preventDefault();
              const form = new FormData(event.currentTarget);
              confirmMfaSetup.mutate(String(form.get("mfa-verify-code")));
            }}>
              <label className="profile-field">Authenticator code
                <input name="mfa-verify-code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" minLength={6} maxLength={6} required />
              </label>
              <div><button className="primary-button" disabled={confirmMfaSetup.isPending}>{confirmMfaSetup.isPending ? "Verifying…" : "Verify and enable MFA"}</button></div>
            </form>
          </div>
        )}
        {mfa.data?.enabled && (
          <form className="form-stack" onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            disableMfa.mutate({
              currentPassword: String(form.get("mfa-disable-password")),
              code: String(form.get("mfa-disable-code")),
            });
          }}>
            <div className="settings-policy-note"><strong>Authenticator is active</strong><p>Sign-ins now require a current authenticator code or an unused recovery code after your password.</p></div>
            <label className="profile-field">Confirm your password
              <input name="mfa-disable-password" type="password" autoComplete="current-password" required maxLength={128} />
            </label>
            <label className="profile-field">Authenticator or recovery code
              <input name="mfa-disable-code" autoComplete="one-time-code" required maxLength={20} />
            </label>
            <div><button className="secondary-button" disabled={disableMfa.isPending}>{disableMfa.isPending ? "Disabling…" : "Disable MFA"}</button></div>
          </form>
        )}
      </section>
    </>
  );
}

export function SessionsPage() {
  type AuthSession = {
    id: string;
    created_at: string;
    last_used_at: string | null;
    expires_at: string;
    current: boolean;
  };
  const client = useQueryClient();
  const sessions = useLoad<AuthSession[]>("auth-sessions", "/auth/sessions");
  const revokeOthers = useMutation({
    mutationFn: () => api.post("/auth/sessions/revoke-others"),
    onSuccess: () => client.invalidateQueries({ queryKey: ["auth-sessions"] }),
  });
  const revokeOne = useMutation({
    mutationFn: (id: string) => api.delete(`/auth/sessions/${id}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["auth-sessions"] }),
  });
  return (
    <>
      <PageHeader
        eyebrow="PROFILE / SECURITY"
        title="Active sessions"
        description="Review and revoke sessions belonging to your account. Device and location details are not collected."
        action={
          <button
            className="secondary-button"
            disabled={
              revokeOthers.isPending ||
              !sessions.data?.some((item) => !item.current)
            }
            onClick={() => revokeOthers.mutate()}
          >
            Revoke other sessions
          </button>
        }
      />
      {(revokeOthers.error || revokeOne.error) && (
        <div className="banner-error">
          {(revokeOthers.error ?? revokeOne.error)?.message}
        </div>
      )}
      <section className="panel table-panel">
        <LoadState
          loading={sessions.isLoading}
          error={sessions.error}
          empty={!sessions.data?.length}
        >
          <DataTable caption="Active account sessions" actions>
            <thead>
              <tr>
                <th scope="col">Session</th>
                <th scope="col">Created</th>
                <th scope="col">Last active</th>
                <th scope="col">Expires</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {sessions.data?.map((item) => (
                <tr key={item.id}>
                  <td className="row-primary">
                    {item.current ? "Current session" : item.id.slice(0, 12)}
                  </td>
                  <td>{date(item.created_at)}</td>
                  <td>
                    {item.last_used_at
                      ? date(item.last_used_at)
                      : "Not recorded"}
                  </td>
                  <td>{date(item.expires_at)}</td>
                  <td>
                    {item.current ? (
                      "Sign out to end"
                    ) : (
                      <button
                        className="text-button"
                        disabled={revokeOne.isPending}
                        onClick={() => revokeOne.mutate(item.id)}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </DataTable>
        </LoadState>
      </section>
    </>
  );
}
