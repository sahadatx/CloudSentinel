import { FilterField } from "../shared/FilterField";
import { DataTable } from "../shared/DataTable";
import { FilterFooter } from "../shared/FilterFooter";
import { ViewAction } from "../shared/ViewAction";
import { useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type Page, type Policy } from "../shared/api";
import { useAuth } from "../shared/useAuth";
import { KpiIcon } from "../shared/kpi";
import { kpiTone } from "../shared/kpi-utils";
import { DrawerFact, RightDrawer } from "../shared/RightDrawer";
import { Pagination } from "../shared/Pagination";
import { formatOrganizationDateTime } from "../shared/date-time";

type PolicySummary = {
  total: number;
  enabled: number;
  disabled: number;
  critical: number;
  compliance_mapped: number;
};
type PolicyAssessment = {
  assessment_id: string;
  asset_id: string;
  asset_name: string | null;
  resource_id: string;
  resource_type: string;
  account_name: string;
  region_code: string;
  result: "PASS" | "FAIL" | "NOT_APPLICABLE" | "ERROR";
  error_code: string | null;
  policy_version: number;
  scan_job_id: string;
  evaluated_at: string;
};
type AssessmentPage = Page<PolicyAssessment> & {
  assessed: number;
  passed: number;
  failed: number;
  not_applicable: number;
  errors: number;
};
type PolicyVersion = {
  version: number;
  snapshot: Record<string, unknown>;
  changed_by_user_id: string | null;
  created_at: string;
};

const severityClass = (severity: string) => `severity severity-${severity.toLowerCase()}`;
const dateText = (value?: string) => value ? formatOrganizationDateTime(value) : "—";
const jsonText = (value: unknown) => JSON.stringify(value, null, 2);

function PolicyHeader({ title, description, action, className = "" }: { title: string; description?: string; action?: ReactNode; className?: string }) {
  return <div className={`page-header ${className}`}><div><div className="eyebrow">SECURITY / POLICY</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>;
}

function PolicyMetric({ label, value }: { label: string; value: number | string }) {
  return <section className={`metric-card kpi-tone-${kpiTone(label)}`}><div className="metric-main-row"><span>{label}</span><div className="metric-value">{value}</div><KpiIcon label={label} /></div><small>Current organization policy registry</small></section>;
}

export function PoliciesPage() {
  const [searchParams] = useSearchParams();
  const initialSearch = searchParams.get("search") ?? "";
  return <PoliciesPageContent key={initialSearch} initialSearch={initialSearch} />;
}

function PoliciesPageContent({ initialSearch }: { initialSearch: string }) {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState(initialSearch);
  const [provider, setProvider] = useState("");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [status, setStatus] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [framework, setFramework] = useState("");
  const [sortBy, setSortBy] = useState("rule_id");
  const [sortDirection, setSortDirection] = useState("asc");
  const [offset, setOffset] = useState(0);
  const [preview, setPreview] = useState<Policy | null>(null);
  const [editor, setEditor] = useState<Policy | "create" | null>(null);
  const [message, setMessage] = useState("");
  const filters = new URLSearchParams({ limit: "30", offset: String(offset), sort_by: sortBy, sort_direction: sortDirection });
  if (search) filters.set("search", search);
  if (provider) filters.set("provider", provider);
  if (severity) filters.set("severity", severity);
  if (category) filters.set("category", category);
  if (status) filters.set("status", status);
  if (resourceType) filters.set("resource_type", resourceType);
  if (framework) filters.set("framework", framework);
  const listPath = `/policies?${filters.toString()}`;
  const policies = useQuery({ queryKey: ["policies", listPath], queryFn: () => api.get<Page<Policy>>(listPath) });
  const summary = useQuery({ queryKey: ["policy-summary"], queryFn: () => api.get<PolicySummary>("/policies/summary") });
  const options = useQuery({ queryKey: ["policy-filter-options"], queryFn: () => api.get<{ providers: string[]; severities: string[]; categories: string[]; statuses: string[]; resource_types: string[]; frameworks: string[] }>("/policies/filter-options") });
  const save = useMutation({
    mutationFn: async (body: { id?: string; payload: Record<string, unknown> }) => body.id ? api.patch<Policy>(`/policies/${body.id}`, body.payload) : api.post<Policy>("/policies", body.payload),
    onSuccess: async (policy) => {
      setEditor(null);
      setMessage(`${policy.rule_id} saved. Future scans will use the current policy version.`);
      await invalidatePolicies(queryClient);
      if (policy.id) queryClient.setQueryData(["policy", policy.id], policy);
    },
  });
  const canCreate = Boolean(user?.permissions.includes("policies:create"));
  return <>
    <PolicyHeader title="Policies" description="Manage versioned security rules and review asset assessment coverage." action={canCreate ? <button className="primary-button" onClick={() => setEditor("create")}>＋ Create policy</button> : undefined} />
    {message && <div className="banner-success" role="status">{message}</div>}
    {summary.error && <div className="banner-error">Policy summary could not be loaded: {summary.error.message}</div>}
    <div className="metric-grid five">
      <PolicyMetric label="Total policies" value={summary.data?.total ?? "—"} />
      <PolicyMetric label="Enabled" value={summary.data?.enabled ?? "—"} />
      <PolicyMetric label="Disabled" value={summary.data?.disabled ?? "—"} />
      <PolicyMetric label="Critical" value={summary.data?.critical ?? "—"} />
      <PolicyMetric label="Compliance mapped" value={summary.data?.compliance_mapped ?? "—"} />
    </div>
    <div className="policy-filter-toolbar">
    <div className="filter-row policy-filters">
      <FilterField label="Search" className="filter-field-search"><input aria-label="Search policies" placeholder="Search rule ID or name" value={search} onChange={(event) => { setSearch(event.target.value); setOffset(0); }} /></FilterField>
      <FilterField label="Provider"><select aria-label="Provider" value={provider} onChange={(event) => { setProvider(event.target.value); setOffset(0); }}><option value="">All providers</option>{options.data?.providers.map((value) => <option key={value}>{value}</option>)}</select></FilterField>
      <FilterField label="Severity"><select aria-label="Severity" value={severity} onChange={(event) => { setSeverity(event.target.value); setOffset(0); }}><option value="">All severities</option>{options.data?.severities.map((value) => <option key={value}>{value}</option>)}</select></FilterField>
      <FilterField label="Category"><select aria-label="Category" value={category} onChange={(event) => { setCategory(event.target.value); setOffset(0); }}><option value="">All categories</option>{options.data?.categories.map((value) => <option key={value}>{value}</option>)}</select></FilterField>
      <FilterField label="Status"><select aria-label="Status" value={status} onChange={(event) => { setStatus(event.target.value); setOffset(0); }}><option value="">All statuses</option>{options.data?.statuses.map((value) => <option key={value}>{value}</option>)}</select></FilterField>
      <FilterField label="Resource type"><select aria-label="Resource type" value={resourceType} onChange={(event) => { setResourceType(event.target.value); setOffset(0); }}><option value="">All resource types</option>{options.data?.resource_types.map((value) => <option key={value}>{value}</option>)}</select></FilterField>
      <FilterField label="Framework"><select aria-label="Framework" value={framework} onChange={(event) => { setFramework(event.target.value); setOffset(0); }}><option value="">All frameworks</option>{options.data?.frameworks.map((value) => <option key={value}>{value}</option>)}</select></FilterField>
      <FilterField label="Sort by"><select aria-label="Sort policies" value={`${sortBy}:${sortDirection}`} onChange={(event) => { const [field, direction] = event.target.value.split(":"); setSortBy(field); setSortDirection(direction); setOffset(0); }}><option value="rule_id:asc">Rule ID A–Z</option><option value="name:asc">Name A–Z</option><option value="severity:desc">Severity</option><option value="category:asc">Category</option><option value="version:desc">Version newest</option></select></FilterField>
    </div>
    <FilterFooter className="policy-filter-reset" active={Boolean(search || provider || severity || category || status || resourceType || framework || sortBy !== "rule_id" || sortDirection !== "asc")} onReset={() => { setSearch(""); setProvider(""); setSeverity(""); setCategory(""); setStatus(""); setResourceType(""); setFramework(""); setSortBy("rule_id"); setSortDirection("asc"); setOffset(0); }} />
    </div>
    <section className="panel table-panel">
      {policies.isLoading ? <div className="state-panel">Loading organization policies…</div> : policies.error ? <div className="error-state">Policies could not be loaded: {policies.error.message}</div> : !policies.data?.items.length ? <div className="empty-inline">No policies match these filters.</div> : <div className="table-scroll"><DataTable caption="Security policy registry" actions><thead><tr><th scope="col">Rule ID</th><th scope="col">Name</th><th scope="col">Severity</th><th scope="col">Category</th><th scope="col">Provider</th><th scope="col">Resource type</th><th scope="col">Status</th><th scope="col">Version</th><th scope="col">Compliance</th><th scope="col">Actions</th></tr></thead><tbody>{policies.data.items.map((policy) => <tr key={policy.id} onDoubleClick={() => setPreview(policy)}><td><button className="text-button row-primary" onClick={() => setPreview(policy)}>{policy.rule_id}</button></td><td><button className="text-button" onClick={() => setPreview(policy)}>{policy.name}</button><small>{policy.description}</small></td><td><span className={`severity severity-${policy.severity.toLowerCase()}`}>{policy.severity}</span></td><td>{policy.category}</td><td>{policy.provider}</td><td>{policy.resource_types.join(", ")}</td><td><span className={`status-pill ${policy.status}`}>{policy.status}</span></td><td>v{policy.version}</td><td>{policy.compliance_controls.length ? `${policy.compliance_controls.length} mapped` : "Not mapped"}</td><td><ViewAction label={`View policy ${policy.rule_id}`} onClick={() => setPreview(policy)} /></td></tr>)}</tbody></DataTable></div>}
    </section>
    {policies.data && policies.data.total > 0 && <Pagination total={policies.data.total} offset={policies.data.offset} limit={policies.data.limit} onOffsetChange={setOffset} disabled={policies.isFetching} label="Policy pages" />}
    {preview && <RightDrawer className="policy-preview-drawer" title="Policy overview" description={`${preview.rule_id} · ${preview.provider} · v${preview.version}`} onClose={() => setPreview(null)}>
      <section className="policy-preview-hero"><div><span className="eyebrow">VERSIONED SECURITY RULE</span><strong>{preview.name}</strong><small>{preview.rule_id}</small></div><div><span className={severityClass(preview.severity)}>{preview.severity}</span><span className={`status-pill ${preview.status}`}>{preview.status}</span></div></section>
      <div className="policy-preview-stats"><div><span>Resource types</span><strong>{preview.resource_types.length}</strong></div><div><span>Compliance mappings</span><strong>{preview.compliance_controls.length}</strong></div><div><span>Policy version</span><strong>v{preview.version}</strong></div></div>
      <section className="policy-preview-section"><h3>Policy details</h3><div className="drawer-facts"><DrawerFact label="Provider" value={preview.provider} /><DrawerFact label="Category" value={preview.category} /><DrawerFact label="Severity" value={preview.severity} /><DrawerFact label="Status" value={preview.status} /><DrawerFact label="Rule ID" value={preview.rule_id} /><DrawerFact label="Registry" value={preview.is_builtin ? "AWS built-in" : "Organization policy"} /></div></section>
      <section className="policy-preview-section"><h3>Purpose</h3><p>{preview.description}</p><h3>Recommended remediation</h3><p>{preview.remediation}</p></section>
      <section className="policy-preview-section"><h3>Applies to</h3><div className="scan-preview-tags">{preview.resource_types.map((resource) => <span key={resource}>{resource.replaceAll("_", " ")}</span>)}</div>{preview.compliance_controls.length > 0 && <><h3>Compliance mappings</h3><div className="policy-preview-mappings">{preview.compliance_controls.map((item) => <span key={`${item.framework}-${item.control}`}><b>{item.control}</b>{item.framework} · {item.title}</span>)}</div></>}</section>
      <div className="drawer-actions scan-preview-actions"><Link className="primary-button" to={`/policies/${preview.id}`} onClick={() => setPreview(null)}>Open full details</Link></div>
    </RightDrawer>}
    {editor && <PolicyEditor policy={editor === "create" ? null : editor} busy={save.isPending} error={save.error?.message ?? null} onClose={() => setEditor(null)} onSave={(payload) => save.mutate({ id: editor === "create" ? undefined : editor.id, payload })} />}
  </>;
}

export function PolicyDetailsPage() {
  const { policyId = "" } = useParams();
  return <PolicyDetailsPageContent key={policyId} policyId={policyId} />;
}

function PolicyDetailsPageContent({ policyId }: { policyId: string }) {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useState(params.get("tab") ?? "overview");
  const [result, setResult] = useState("");
  const [assessmentOffset, setAssessmentOffset] = useState(0);
  const [editorOpen, setEditorOpen] = useState(false);
  const [confirmStatus, setConfirmStatus] = useState<"enabled" | "disabled" | null>(null);
  const [assessment, setAssessment] = useState<PolicyAssessment | null>(null);
  const [message, setMessage] = useState("");
  const path = `/policies/${policyId}`;
  const policy = useQuery({ queryKey: ["policy", policyId], queryFn: () => api.get<Policy>(path) });
  const versions = useQuery({ queryKey: ["policy-versions", policyId], queryFn: () => api.get<PolicyVersion[]>(`${path}/versions`) });
  const assessmentParams = new URLSearchParams({ limit: "50", offset: String(assessmentOffset) });
  if (result) assessmentParams.set("result", result);
  const assessments = useQuery({ queryKey: ["policy-assessments", policyId, result, assessmentOffset], queryFn: () => api.get<AssessmentPage>(`${path}/assessments?${assessmentParams}`), enabled: tab === "affected" });
  const evidence = useQuery({ queryKey: ["policy-assessment-evidence", policyId, assessment?.assessment_id], queryFn: () => api.get<Record<string, unknown>>(`${path}/assessments/${assessment?.assessment_id}/evidence`), enabled: Boolean(assessment) });
  const update = useMutation({ mutationFn: (payload: Record<string, unknown>) => api.patch<Policy>(path, payload), onSuccess: async (row) => { queryClient.setQueryData(["policy", policyId], row); setEditorOpen(false); setMessage("Policy definition saved as a new version. Past assessments keep their original version."); await invalidatePolicies(queryClient); await queryClient.invalidateQueries({ queryKey: ["policy-versions", policyId] }); } });
  const statusChange = useMutation({ mutationFn: (next: "enabled" | "disabled") => api.post<Policy>(`${path}/${next === "enabled" ? "enable" : "disable"}`, {}), onSuccess: async (row) => { queryClient.setQueryData(["policy", policyId], row); setConfirmStatus(null); setMessage(`Policy ${row.status}. New scans will ${row.status === "enabled" ? "evaluate" : "skip"} this rule.`); await invalidatePolicies(queryClient); } });
  const duplicate = useMutation({ mutationFn: () => api.post<Policy>(`${path}/duplicate`, {}), onSuccess: async (row) => { await invalidatePolicies(queryClient); window.location.assign(`/policies/${row.id}`); } });
  const tabs = useMemo(() => [
    ["overview", "Overview"], ["detection", "Detection Logic"], ["evidence", "Evidence Logic"], ["remediation", "Remediation"], ["compliance", "Compliance"], ["affected", "Affected Resources"], ["versions", "Version History"],
  ], []);
  const canUpdate = Boolean(user?.permissions.includes("policies:update"));
  const canCreate = Boolean(user?.permissions.includes("policies:create"));
  const data = policy.data;
  return <>
    <div className="account-detail-back"><Link to="/policies">← Policies</Link></div>
    <PolicyHeader className="policy-detail-page-header" title={data?.name ?? "Policy details"} description={data ? `${data.rule_id} · ${data.provider} · ${data.category}` : "Rule definition, assessment evidence, and affected resources."} action={<div className="header-actions">{canUpdate && <button className="secondary-button" onClick={() => setEditorOpen(true)}>Edit</button>}{data && canUpdate && <button className="secondary-button" onClick={() => setConfirmStatus(data.status === "enabled" ? "disabled" : "enabled")}>{data.status === "enabled" ? "Disable" : "Enable"}</button>}{canCreate && <button className="quiet-button" disabled={duplicate.isPending} onClick={() => duplicate.mutate()}>Duplicate</button>}</div>} />
    {message && <div className="banner-success" role="status">{message}</div>}
    {policy.isLoading ? <div className="state-panel">Loading policy definition…</div> : policy.error ? <div className="error-state">Policy could not be loaded: {policy.error.message}</div> : data && <>
      <section className="panel policy-detail-heading policy-detail-hero"><div><span className={severityClass(data.severity)}>{data.severity}</span><span className={`status-pill ${data.status}`}>{data.status}</span><span className="status-pill">Version {data.version}</span>{data.is_builtin && <span className="status-pill">AWS built-in</span>}</div><p>{data.description}</p><div className="policy-detail-reference"><span>Rule ID <strong>{data.rule_id}</strong></span><span>Provider <strong>{data.provider}</strong></span><span>Category <strong>{data.category}</strong></span></div></section>
      <div className="policy-detail-highlights"><div><span>Policy status</span><strong>{data.status}</strong><small>{data.status === "enabled" ? "Evaluated by future scans" : "Skipped by future scans"}</small></div><div><span>Current version</span><strong>v{data.version}</strong><small>Versioned policy definition</small></div><div><span>Resource types</span><strong>{data.resource_types.length}</strong><small>{data.resource_types.join(", ")}</small></div><div><span>Compliance mappings</span><strong>{data.compliance_controls.length}</strong><small>{data.compliance_controls.length ? "Mapped controls" : "No controls mapped"}</small></div></div>
      <nav className="account-detail-tabs policy-tabs" aria-label="Policy details">{tabs.map(([id, label]) => <button key={id} className={tab === id ? "active" : ""} onClick={() => { setTab(id); setParams({ tab: id }); }}>{label}</button>)}</nav>
      {tab === "overview" && <div className="account-detail-grid"><section className="panel"><h2>Policy overview</h2><div className="account-facts-list"><PolicyFact label="Rule ID" value={data.rule_id} /><PolicyFact label="Provider" value={data.provider} /><PolicyFact label="Resource types" value={data.resource_types.join(", ")} /><PolicyFact label="Category" value={data.category} /><PolicyFact label="Severity" value={data.severity} /><PolicyFact label="Status" value={data.status} /><PolicyFact label="Version" value={String(data.version)} /></div></section><section className="panel"><h2>Detection summary</h2><p>Validated rule logic runs only against normalized asset configuration. No dynamic code execution is used.</p><pre className="policy-code">{jsonText(data.detection_logic)}</pre></section></div>}
      {tab === "detection" && <section className="panel account-tab-panel"><h2>Detection Logic</h2><p>The rule condition is evaluated against canonical asset fields.</p><pre className="policy-code">{jsonText(data.detection_logic)}</pre><div className="policy-result-legend"><span>PASS · Condition did not match</span><span>FAIL · Condition matched</span><span>NOT_APPLICABLE · Resource type does not match</span><span>ERROR · Safe evaluation failure</span></div></section>}
      {tab === "evidence" && <section className="panel account-tab-panel"><h2>Evidence Logic</h2><p>For PASS and FAIL assessments, CloudSentinel stores the rule condition and observed canonical fields.</p><pre className="policy-code">{jsonText(data.evidence_logic)}</pre></section>}
      {tab === "remediation" && <section className="panel account-tab-panel"><h2>Recommended remediation</h2><p>{data.remediation}</p><div className="settings-policy-note"><strong>Guidance only</strong><p>This page does not execute AWS commands or make cloud changes.</p></div></section>}
      {tab === "compliance" && <section className="panel account-tab-panel"><h2>Compliance mapping</h2>{data.compliance_controls.length ? <div className="table-scroll"><DataTable caption="Policy compliance mappings"><thead><tr><th scope="col">Framework</th><th scope="col">Control</th><th scope="col">Mapping</th></tr></thead><tbody>{data.compliance_controls.map((control, index) => <tr key={`${control.framework}-${control.control}-${index}`}><td>{control.framework}</td><td>{control.control}</td><td>{control.title}</td></tr>)}</tbody></DataTable></div> : <div className="empty-inline">This rule has no compliance mapping. No compliance score is calculated here.</div>}</section>}
      {tab === "affected" && (
        <section className="panel account-tab-panel">
          <div className="policy-tab-header">
            <div><h2>Affected resources</h2><p>Latest assessment per asset, derived from scan results.</p></div>
            <FilterField label="Result">
              <select aria-label="Filter assessment result" value={result} onChange={(event) => { setResult(event.target.value); setAssessmentOffset(0); }}>
                <option value="">All results</option>
                {["FAIL", "PASS", "NOT_APPLICABLE", "ERROR"].map((value) => <option key={value}>{value}</option>)}
              </select>
            </FilterField>
          </div>
          <FilterFooter className="policy-filter-reset" active={Boolean(result)} onReset={() => { setResult(""); setAssessmentOffset(0); }} />
          {assessments.isLoading ? <div className="state-panel">Loading assessments…</div> : assessments.error ? <div className="error-state" role="alert">Assessment results could not be loaded: {assessments.error.message}</div> : assessments.data && <>
            <div className="policy-assessment-counts"><span>Assessed <b>{assessments.data.assessed}</b></span><span>Passed <b>{assessments.data.passed}</b></span><span>Failed <b>{assessments.data.failed}</b></span><span>Not applicable <b>{assessments.data.not_applicable}</b></span><span>Errors <b>{assessments.data.errors}</b></span></div>
            {assessments.data.items.length ? <div className="table-scroll">
              <DataTable caption="Policy resource assessments" actions>
                <thead><tr><th scope="col">Asset</th><th scope="col">Account</th><th scope="col">Region</th><th scope="col">Result</th><th scope="col">Policy version</th><th scope="col">Last evaluated</th><th scope="col">Action</th></tr></thead>
                <tbody>{assessments.data.items.map((item) => <tr key={item.assessment_id}>
                  <td><Link to={`/assets/${item.asset_id}`}>{item.asset_name || item.resource_id}</Link><small>{item.resource_type} · {item.resource_id}</small></td>
                  <td>{item.account_name}</td><td>{item.region_code}</td>
                  <td><span className={`assessment-result assessment-${item.result.toLowerCase()}`}>{item.result}</span></td>
                  <td>v{item.policy_version}</td><td>{dateText(item.evaluated_at)}</td>
                  <td>{item.result === "PASS" || item.result === "FAIL" ? <ViewAction label={`View assessment evidence for ${item.asset_name || item.resource_id}`} onClick={() => setAssessment(item)} /> : "—"}</td>
                </tr>)}</tbody>
              </DataTable>
            </div> : <div className="empty-inline">{result ? "No assessment results match this filter. Reset the result filter to see other assessments." : "No assessment results are available. Run a scan after enabling this policy."}</div>}
            {assessments.data.total > 0 && <Pagination total={assessments.data.total} offset={assessments.data.offset} limit={assessments.data.limit} onOffsetChange={setAssessmentOffset} disabled={assessments.isFetching} label="Policy assessment pages" />}
          </>}
        </section>
      )}
      {tab === "versions" && <section className="panel account-tab-panel"><h2>Version history</h2>{versions.isLoading ? <div className="state-panel">Loading policy history…</div> : versions.error ? <div className="error-state">Version history could not be loaded.</div> : versions.data?.length ? <div className="policy-version-list">{versions.data.map((version) => <article key={version.version}><div><strong>Version {version.version}{version.version === data.version && <span className="status-pill">Current</span>}</strong><small>{dateText(version.created_at)} · {version.changed_by_user_id ? `Actor ${version.changed_by_user_id.slice(0, 8)}` : "Bundled policy"}</small></div><details><summary>View saved definition</summary><pre className="policy-code">{jsonText(version.snapshot)}</pre></details></article>)}</div> : <div className="empty-inline">No version history is available.</div>}</section>}
    </>}
    {editorOpen && data && <PolicyEditor policy={data} busy={update.isPending} error={update.error?.message ?? null} onClose={() => setEditorOpen(false)} onSave={(payload) => update.mutate(payload)} />}
    {confirmStatus && data && <RightDrawer title={`${confirmStatus === "disabled" ? "Disable" : "Enable"} policy?`} description={`${data.rule_id} · ${data.name}`} onClose={() => setConfirmStatus(null)}><p>{confirmStatus === "disabled" ? "Future scans will skip this rule. Existing assessments and version history remain available." : "Future scans will evaluate this rule against matching assets."}</p><div className="drawer-actions"><button className="quiet-button" onClick={() => setConfirmStatus(null)}>Cancel</button><button className="primary-button" disabled={statusChange.isPending} onClick={() => statusChange.mutate(confirmStatus)}>{statusChange.isPending ? "Saving…" : `Confirm ${confirmStatus}`}</button></div>{statusChange.error && <p className="error-state">{statusChange.error.message}</p>}</RightDrawer>}
    {assessment && <RightDrawer title="Assessment evidence" description={`${assessment.result} · ${assessment.asset_name || assessment.resource_id}`} onClose={() => setAssessment(null)}>{evidence.isLoading ? <div className="state-panel">Loading evidence…</div> : evidence.error ? <div className="error-state">Evidence could not be loaded.</div> : evidence.data && <><PolicyFact label="Expected state" value={jsonText(evidence.data.expected_state)} /><PolicyFact label="Observed state" value={jsonText(evidence.data.observed_state)} /><PolicyFact label="Assessment" value={String(evidence.data.assessment_id)} /></>}</RightDrawer>}
  </>;
}

function PolicyFact({ label, value }: { label: string; value: string }) {
  return <div className="detail-fact"><span>{label}</span><strong>{value}</strong></div>;
}

function PolicyEditor({ policy, busy, error, onClose, onSave }: { policy: Policy | null; busy: boolean; error: string | null; onClose: () => void; onSave: (payload: Record<string, unknown>) => void }) {
  const [name, setName] = useState(policy?.name ?? "");
  const [ruleId, setRuleId] = useState("");
  const [description, setDescription] = useState(policy?.description ?? "");
  const [category, setCategory] = useState(policy?.category ?? "STORAGE");
  const [severity, setSeverity] = useState(policy?.severity ?? "HIGH");
  const [resourceTypes, setResourceTypes] = useState(policy?.resource_types.join(", ") ?? "s3_bucket");
  const [detection, setDetection] = useState(jsonText(policy?.detection_logic ?? { path: "attributes.example", op: "equals", value: true }));
  const [evidence, setEvidence] = useState(jsonText(policy?.evidence_logic ?? {}));
  const [remediation, setRemediation] = useState(policy?.remediation ?? "");
  const [compliance, setCompliance] = useState(jsonText(policy?.compliance_controls ?? []));
  const [parseError, setParseError] = useState("");
  const { user } = useAuth();
  function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setParseError("");
    try {
      const detectionLogic = JSON.parse(detection) as Record<string, unknown>;
      const evidenceLogic = JSON.parse(evidence) as Record<string, unknown>;
      const complianceControls = JSON.parse(compliance) as { framework: string; control: string; title: string }[];
      const types = resourceTypes.split(",").map((value) => value.trim()).filter(Boolean);
      if (policy) onSave({ name, description, category, severity, resource_types: types, detection_logic: detectionLogic, evidence_logic: evidenceLogic, remediation, compliance_controls: complianceControls });
      else onSave({ ...(ruleId.trim() ? { rule_id: ruleId.trim() } : {}), name, description, provider: "AWS", category, severity, resource_types: types, status: "enabled", detection_logic: detectionLogic, evidence_logic: evidenceLogic, remediation, compliance_controls: complianceControls });
    } catch {
      setParseError("Detection, evidence, and compliance fields must contain valid JSON.");
    }
  }
  return <RightDrawer title={policy ? `Edit ${policy.rule_id}` : "Create policy"} description="Define a versioned AWS security rule using CloudSentinel’s safe policy DSL." onClose={onClose} className="policy-editor-drawer">
    <form className="policy-editor-form" onSubmit={submit} aria-busy={busy}>
      <section className="policy-editor-section">
        <div className="policy-editor-section-heading"><span>01</span><div><h3>Policy details</h3><p>Set the rule identity and the AWS resources it evaluates.</p></div></div>
        <div className="policy-editor-fields">
          {!policy && <label><span className="policy-field-label">Rule ID <span className="field-optional">Optional</span></span><input disabled={busy} name="rule_id" value={ruleId} maxLength={100} placeholder="Generated automatically" onChange={(event) => setRuleId(event.target.value)} /><small>Leave blank to generate an ID from the policy name.</small></label>}
          <label className={policy ? "policy-editor-field-wide" : ""}><span className="policy-field-label">Name <span className="field-required">Required</span></span><input disabled={busy} required maxLength={300} value={name} onChange={(event) => setName(event.target.value)} placeholder="Describe the security condition" /></label>
          <label className="policy-editor-field-wide"><span className="policy-field-label">Description <span className="field-required">Required</span></span><textarea disabled={busy} required maxLength={2000} rows={3} value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Explain what the rule detects and why it matters." /></label>
          <div className="policy-editor-two-col">
            <label><span className="policy-field-label">Category <span className="field-required">Required</span></span><input disabled={busy} required maxLength={100} value={category} onChange={(event) => setCategory(event.target.value)} placeholder="For example: STORAGE" /></label>
            <label>Severity<select disabled={busy} value={severity} onChange={(event) => setSeverity(event.target.value)}>{["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((value) => <option key={value}>{value}</option>)}</select></label>
          </div>
          <label className="policy-editor-field-wide"><span className="policy-field-label">Resource types <span className="field-required">Required</span></span><input disabled={busy} required value={resourceTypes} onChange={(event) => setResourceTypes(event.target.value)} placeholder="s3_bucket, ec2_instance" /><small>Separate supported AWS resource types with commas.</small></label>
        </div>
      </section>
      <section className="policy-editor-section">
        <div className="policy-editor-section-heading"><span>02</span><div><h3>Detection and evidence</h3><p>Use JSON conditions supported by the safe DSL. Executable code is not accepted.</p></div></div>
        <div className="policy-editor-fields">
          <label className="policy-editor-field-wide"><span className="policy-field-label">Detection logic <span className="field-required">Required</span></span><textarea disabled={busy} required rows={9} className="policy-json-input" spellCheck={false} value={detection} onChange={(event) => setDetection(event.target.value)} /><small>Evaluated against normalized asset attributes.</small></label>
          <label className="policy-editor-field-wide">Evidence logic<textarea disabled={busy} rows={5} className="policy-json-input" spellCheck={false} value={evidence} onChange={(event) => setEvidence(event.target.value)} /><small>JSON describing which observed fields support the result.</small></label>
        </div>
      </section>
      <section className="policy-editor-section">
        <div className="policy-editor-section-heading"><span>03</span><div><h3>Remediation and compliance</h3><p>Provide clear operator guidance and optional framework mappings.</p></div></div>
        <div className="policy-editor-fields">
          <label className="policy-editor-field-wide"><span className="policy-field-label">Remediation guidance <span className="field-required">Required</span></span><textarea disabled={busy} required maxLength={2000} rows={3} value={remediation} onChange={(event) => setRemediation(event.target.value)} placeholder="Describe the recommended steps to resolve the finding." /></label>
          <label className="policy-editor-field-wide">Compliance mappings<textarea disabled={busy} rows={4} className="policy-json-input" spellCheck={false} value={compliance} onChange={(event) => setCompliance(event.target.value)} /><small>JSON array of framework, control, and title objects.</small></label>
        </div>
      </section>
      {parseError && <div className="error-state" role="alert">{parseError}</div>}
      {error && <div className="error-state" role="alert">{error}</div>}
      {!user?.permissions.includes(policy ? "policies:update" : "policies:create") && <div className="empty-inline">Read only: policy update permission is required.</div>}
      <div className="drawer-actions"><button type="button" className="quiet-button" onClick={onClose}>Cancel</button><button className="primary-button" disabled={busy || !user?.permissions.includes(policy ? "policies:update" : "policies:create")}>{busy ? "Saving…" : policy ? "Save new version" : "Create policy"}</button></div>
    </form>
  </RightDrawer>;
}

async function invalidatePolicies(client: ReturnType<typeof useQueryClient>) {
  await Promise.all([
    client.invalidateQueries({ queryKey: ["policies"] }),
    client.invalidateQueries({ queryKey: ["policy-summary"] }),
    client.invalidateQueries({ queryKey: ["policy-filter-options"] }),
  ]);
}
