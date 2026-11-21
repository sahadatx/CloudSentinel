import { FilterField } from "../shared/FilterField";
import { DataTable } from "../shared/DataTable";
import { FilterFooter } from "../shared/FilterFooter";
import { ViewAction } from "../shared/ViewAction";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type Account, type Page } from "../shared/api";
import { useAuth } from "../shared/useAuth";
import { RightDrawer } from "../shared/RightDrawer";
import {
  formatOrganizationDateTime,
  organizationDateToUtcIso,
} from "../shared/date-time";
import { KpiIcon } from "../shared/kpi";
import { kpiTone } from "../shared/kpi-utils";
import { Pagination } from "../shared/Pagination";

type Scan = {
  id: string;
  cloud_account_id: string;
  status: string;
  requested_regions: string[];
  requested_resource_types: string[];
  progress_total: number;
  progress_completed: number;
  resources_discovered: number;
  errors_count: number;
  error_codes: Record<string, string>[];
  progress_percent: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};
type ScanPageData = Page<Scan> & { status_counts: Record<string, number> };
type AuditEvent = { id: string; actor_user_id: string | null; action: string; created_at: string; details: Record<string, unknown> };

const readable = (value: string) => value.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
const date = (value: string | null) => value ? formatOrganizationDateTime(value) : "—";

export function ScansPage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const initialAccountId = params.get("create") ?? "";
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [status, setStatus] = useState("");
  const [accountFilter, setAccountFilter] = useState("");
  const [search, setSearch] = useState("");
  const [createdAfter, setCreatedAfter] = useState("");
  const [createdBefore, setCreatedBefore] = useState("");
  const [offset, setOffset] = useState(0);
  const [cancelScan, setCancelScan] = useState<Scan | null>(null);
  const page = useQuery({
    queryKey: ["scans", offset, status, accountFilter, search, createdAfter, createdBefore],
    queryFn: () => {
      const query = new URLSearchParams({ offset: String(offset), limit: "30" });
      if (status) query.set("status", status);
      if (accountFilter) query.set("cloud_account_id", accountFilter);
      if (search.trim()) query.set("search", search.trim());
      const createdAfterUtc = createdAfter ? organizationDateToUtcIso(createdAfter, "start") : null;
      const createdBeforeUtc = createdBefore ? organizationDateToUtcIso(createdBefore, "end") : null;
      if (createdAfterUtc) query.set("created_after", createdAfterUtc);
      if (createdBeforeUtc) query.set("created_before", createdBeforeUtc);
      return api.get<ScanPageData>(`/scans?${query.toString()}`);
    },
    refetchInterval: (query) => query.state.data?.items.some((scan) => ["queued", "running", "cancelling"].includes(scan.status)) ? 5000 : false,
  });
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => api.get<Account[]>("/cloud-accounts"), enabled: Boolean(user?.permissions.includes("cloud_accounts:read")) });
  const filtered = page.data?.items ?? [];
  const hasScanFilters = Boolean(search.trim() || status || accountFilter || createdAfter || createdBefore);
  const selectedAccount = accounts.data?.find((item) => item.id === selectedScan?.cloud_account_id);
  const cancel = useMutation({
    mutationFn: (scanId: string) => api.post<Scan>(`/scans/${scanId}/cancel`),
    onSuccess: async () => { setCancelScan(null); await client.invalidateQueries({ queryKey: ["scans"] }); },
  });

  return <>
    <div className="page-header"><div><div className="eyebrow">CLOUD OPERATIONS</div><h1>Scan Management</h1><p>Queue and monitor organization cloud inventory scans.</p></div>{user?.permissions.includes("scans:create") && <button className="primary-button" onClick={() => setParams({ create: initialAccountId || "1" })}>＋ Start scan</button>}</div>
    <div className="account-summary-grid scan-summary-grid"><Metric label="Total scans" value={page.data?.total ?? "—"} /><Metric label="Queued" value={page.data ? page.data.status_counts.queued ?? 0 : "—"} tone="pending" /><Metric label="Running" value={page.data ? (page.data.status_counts.running ?? 0) + (page.data.status_counts.cancelling ?? 0) : "—"} tone="connected" /><Metric label="Completed" value={page.data ? page.data.status_counts.completed ?? 0 : "—"} /><Metric label="Failed" value={page.data ? (page.data.status_counts.failed ?? 0) + (page.data.status_counts.partial ?? 0) : "—"} tone="error" /></div>
    <section className="panel table-panel scan-table-panel">
      <div className="scan-filter-toolbar">
        <div className="scan-filters">
          <FilterField label="Search" className="filter-field-search"><input aria-label="Search scans" placeholder="Search scan ID, account name, or account ID" value={search} onChange={(event) => { setSearch(event.target.value); setOffset(0); }} /></FilterField>
          <FilterField label="Status"><select aria-label="Filter status" value={status} onChange={(event) => { setStatus(event.target.value); setOffset(0); }}><option value="">All statuses</option>{["queued", "running", "cancelling", "completed", "partial", "failed", "cancelled"].map((value) => <option key={value} value={value}>{readable(value)}</option>)}</select></FilterField>
          <FilterField label="Cloud account"><select aria-label="Filter account" value={accountFilter} onChange={(event) => { setAccountFilter(event.target.value); setOffset(0); }}><option value="">All accounts</option>{accounts.data?.map((account) => <option key={account.id} value={account.id}>{account.name}</option>)}</select></FilterField>
          <label className="scan-date-filter scan-date-from">From<input type="date" aria-label="From date" max={createdBefore || undefined} value={createdAfter} onClick={(event) => { try { event.currentTarget.showPicker?.(); } catch { /* Browser picker already open or unsupported. */ } }} onChange={(event) => { setCreatedAfter(event.target.value); setOffset(0); }} /></label>
          <label className="scan-date-filter scan-date-to">To<input type="date" aria-label="To date" min={createdAfter || undefined} value={createdBefore} onClick={(event) => { try { event.currentTarget.showPicker?.(); } catch { /* Browser picker already open or unsupported. */ } }} onChange={(event) => { setCreatedBefore(event.target.value); setOffset(0); }} /></label>
        </div>
        <FilterFooter className="scan-filter-footer" active={hasScanFilters} onReset={() => { setSearch(""); setStatus(""); setAccountFilter(""); setCreatedAfter(""); setCreatedBefore(""); setOffset(0); }} />
      </div>
      {page.isLoading ? <div className="state-panel">Loading scan jobs…</div> : page.error ? <div className="state-panel error-state">Scan jobs could not be loaded: {page.error.message}</div> : filtered.length ? <div className="table-scroll"><DataTable caption="Cloud inventory scan jobs" actions><thead><tr><th scope="col">Scan ID</th><th scope="col">Cloud account</th><th scope="col">Status</th><th scope="col">Started</th><th scope="col">Finished</th><th scope="col">Resources</th><th scope="col">Errors</th><th scope="col">Actions</th></tr></thead><tbody>{filtered.map((scan) => { const account = accounts.data?.find((item) => item.id === scan.cloud_account_id); return <tr key={scan.id}><td><button className="text-button row-primary" onClick={() => setSelectedScan(scan)}>{scan.id.slice(0, 8).toUpperCase()}</button></td><td>{account?.name ?? "Cloud account"}</td><td><ScanStatus status={scan.status} /></td><td>{date(scan.started_at ?? scan.created_at)}</td><td>{date(scan.finished_at)}</td><td>{scan.resources_discovered}</td><td>{scan.errors_count}</td><td><div className="scan-row-actions"><ViewAction label={`View scan ${scan.id.slice(0, 8)}`} onClick={() => setSelectedScan(scan)} />{user?.permissions.includes("scans:cancel") && ["queued", "running"].includes(scan.status) && <button className="text-button" onClick={() => setCancelScan(scan)}>Cancel</button>}</div></td></tr>; })}</tbody></DataTable></div> : <div className="state-panel"><strong>{hasScanFilters ? "No scans match these filters" : "No scans yet"}</strong><span>{hasScanFilters ? "Change or reset the selected filters to see other scans." : "Start a scan for a connected AWS account to create a scan record."}</span></div>}
      {page.data && page.data.total > 0 && <Pagination total={page.data.total} offset={offset} limit={30} onOffsetChange={setOffset} disabled={page.isFetching} label="Scan pages" />}
    </section>
    {params.has("create") && <StartScanDrawer initialAccountId={params.get("create") === "1" ? "" : params.get("create") ?? ""} accounts={accounts.data ?? []} accountsLoading={accounts.isLoading} accountsError={accounts.error} onClose={() => setParams({})} onCreated={(scan) => { void client.invalidateQueries({ queryKey: ["scans"] }); navigate(`/scans/${scan.id}`); }} />}
    {selectedScan && <RightDrawer className="scan-preview-drawer" title="Scan overview" description={`${selectedScan.id.slice(0, 8).toUpperCase()} · ${selectedAccount?.name ?? "Cloud account"}`} onClose={() => setSelectedScan(null)}>
      <section className="scan-preview-hero">
        <div><span className="eyebrow">SCAN JOB</span><strong>{readable(selectedScan.status)}</strong></div>
        <ScanStatus status={selectedScan.status} />
      </section>
      <section className="scan-preview-progress">
        <div className="scan-preview-progress-heading"><strong>Collection progress</strong><b>{selectedScan.progress_percent}%</b></div>
        <progress max="100" value={selectedScan.progress_percent} />
        <span>{selectedScan.progress_completed} of {selectedScan.progress_total} collection units complete</span>
      </section>
      <div className="scan-preview-stats">
        <div><span>Resources found</span><strong>{selectedScan.resources_discovered.toLocaleString()}</strong></div>
        <div className={selectedScan.errors_count ? "has-errors" : ""}><span>Collection errors</span><strong>{selectedScan.errors_count.toLocaleString()}</strong></div>
      </div>
      <section className="scan-preview-section">
        <h3>Run details</h3>
        <div className="scan-preview-facts">
          <Fact label="Scan ID" value={selectedScan.id} />
          <Fact label="Cloud account" value={selectedAccount?.name ?? "Cloud account"} />
          <Fact label="Account ID" value={selectedAccount?.account_id ?? selectedScan.cloud_account_id} />
          <Fact label="Requested" value={date(selectedScan.created_at)} />
          <Fact label="Started" value={date(selectedScan.started_at)} />
          <Fact label="Finished" value={date(selectedScan.finished_at)} />
        </div>
      </section>
      <section className="scan-preview-section">
        <h3>Scope</h3>
        <span className="scan-preview-label">Regions</span>
        <div className="scan-preview-tags">{selectedScan.requested_regions.length ? selectedScan.requested_regions.map((region) => <span key={region}>{region}</span>) : <span>Default regions</span>}</div>
        <span className="scan-preview-label">Resource types</span>
        <div className="scan-preview-tags">{selectedScan.requested_resource_types.length ? selectedScan.requested_resource_types.map((resource) => <span key={resource}>{readable(resource)}</span>) : <span>All supported types</span>}</div>
      </section>
      {selectedScan.errors_count > 0 && <div className="scan-preview-warning"><strong>Scan completed with collection errors</strong><span>Open the full scan to review sanitized error details and affected regions.</span></div>}
      <div className="drawer-actions scan-preview-actions">
        <Link className="primary-button" to={`/scans/${selectedScan.id}`} onClick={() => setSelectedScan(null)}>View full scan</Link>
        {user?.permissions.includes("scans:cancel") && ["queued", "running"].includes(selectedScan.status) && <button className="danger-button" onClick={() => { setCancelScan(selectedScan); setSelectedScan(null); }}>Cancel scan</button>}
      </div>
    </RightDrawer>}
    {cancelScan && <RightDrawer title="Cancel scan?" description="The worker will stop between collection units. Completed work remains recorded." onClose={() => setCancelScan(null)}><p>Cancel scan {cancelScan.id.slice(0, 8).toUpperCase()} for {accounts.data?.find((item) => item.id === cancelScan.cloud_account_id)?.name ?? "this cloud account"}?</p><div className="drawer-actions"><button className="secondary-button" onClick={() => setCancelScan(null)}>Keep running</button><button className="danger-button" disabled={cancel.isPending} onClick={() => cancel.mutate(cancelScan.id)}>{cancel.isPending ? "Requesting…" : "Cancel scan"}</button></div>{cancel.error && <p className="error-state" role="alert">{cancel.error.message}</p>}</RightDrawer>}
  </>;
}

function StartScanDrawer({ initialAccountId, accounts, accountsLoading, accountsError, onClose, onCreated }: { initialAccountId: string; accounts: Account[]; accountsLoading: boolean; accountsError: Error | null; onClose: () => void; onCreated: (scan: Scan) => void }) {
  const [accountId, setAccountId] = useState(initialAccountId);
  const [regions, setRegions] = useState<string[] | null>(null);
  const account = accounts.find((item) => item.id === accountId);
  const enabledRegions = account?.regions.filter((region) => region.is_enabled).map((region) => region.region_code) ?? [];
  const create = useMutation({ mutationFn: () => api.post<Scan>("/scans", { cloud_account_id: accountId, regions: regions === null ? undefined : regions }), onSuccess: onCreated });
  const connectedAccounts = accounts.filter((item) => item.connection_status === "connected");
  return (
    <RightDrawer
      className="scan-start-drawer"
      title="Start a cloud scan"
      description="Choose an AWS account and define the scan scope."
      onClose={onClose}
    >
      <form
        className="scan-start-form"
        aria-busy={create.isPending}
        onSubmit={(event) => {
          event.preventDefault();
          if (create.isPending) return;
          create.mutate();
        }}
      >
        <div className="scan-start-intro">
          <span className="scan-start-step">1</span>
          <div>
            <strong>Select a connected account</strong>
            <small>Only validated AWS accounts can run scans.</small>
          </div>
        </div>
        <label className="scan-start-account-field">
          <span>AWS cloud account <span className="field-required">Required</span></span>
          <select
            required
            value={accountId}
            onChange={(event) => {
              setAccountId(event.target.value);
              setRegions(null);
            }}
            disabled={accountsLoading || create.isPending}
          >
            <option value="">Select an account</option>
            {connectedAccounts.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} · {item.account_id}
              </option>
            ))}
          </select>
        </label>
        {accountsLoading && <div className="state-panel">Loading connected accounts…</div>}
        {accountsError && <p className="error-state" role="alert">Accounts could not be loaded: {accountsError.message}</p>}
        {!accountsLoading && !accountsError && connectedAccounts.length === 0 && (
          <div className="scan-start-empty">
            <strong>No connected AWS accounts</strong>
            <span>Connect and validate an AWS account before starting a scan.</span>
            <Link to="/cloud-accounts">Open Cloud Accounts</Link>
          </div>
        )}
        {account && (
          <div className="scan-start-account-card">
            <span className="aws-badge">AWS</span>
            <div>
              <strong>{account.name}</strong>
              <small>{account.account_id}{account.environment ? ` · ${account.environment}` : ""}</small>
            </div>
            <span className="scan-start-connected"><i /> Connected</span>
          </div>
        )}

        <div className="scan-start-intro scan-start-scope-heading">
          <span className="scan-start-step">2</span>
          <div>
            <strong>Choose scan regions</strong>
            <small>Select which enabled regions to include.</small>
          </div>
        </div>
        {account && enabledRegions.length > 0 && (
          <fieldset className="scan-region-picker scan-region-picker-cards" disabled={create.isPending}>
            <legend>Enabled regions <span>{(regions ?? enabledRegions).length} selected</span></legend>
            <div className="scan-region-options">
              {enabledRegions.map((region) => (
                <label key={region}>
                  <input
                    type="checkbox"
                    checked={regions === null || regions.includes(region)}
                    onChange={(event) => setRegions((current) => {
                      const selected = current ?? enabledRegions;
                      return event.target.checked
                        ? [...new Set([...selected, region])]
                        : selected.filter((item) => item !== region);
                    })}
                  />
                  <span>{region}</span>
                </label>
              ))}
            </div>
            <small>All enabled regions are selected by default. Scan resources include all resource types supported by the backend.</small>
          </fieldset>
        )}
        {account && enabledRegions.length === 0 && (
          <div className="scan-start-empty"><strong>No scan regions enabled</strong><span>Enable at least one region in the cloud account settings before scanning.</span></div>
        )}
        {!account && <div className="scan-start-scope-placeholder">Select an account to review its available regions.</div>}

        <div className="scan-start-notice">
          <span aria-hidden="true">ⓘ</span>
          <p>Starting a scan queues an asynchronous inventory collection. It does not make changes in AWS or create findings by itself.</p>
        </div>
        {create.error && <p className="error-state" role="alert">Scan could not be queued: {create.error.message}</p>}
        <div className="drawer-actions scan-start-actions">
          <button type="button" className="secondary-button" onClick={onClose}>Cancel</button>
          <button
            type="submit"
            className="primary-button"
            disabled={!accountId || !account || account.connection_status !== "connected" || create.isPending || (regions !== null && regions.length === 0) || enabledRegions.length === 0}
          >
            {create.isPending ? "Queueing scan…" : "Queue scan"}
          </button>
        </div>
      </form>
    </RightDrawer>
  );
}

export function ScanDetailPage() {
  const { scanId = "" } = useParams();
  const { user } = useAuth();
  const client = useQueryClient();
  const navigate = useNavigate();
  const [tab, setTab] = useState("overview");
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [confirmRerun, setConfirmRerun] = useState(false);
  const scan = useQuery({ queryKey: ["scan", scanId], queryFn: () => api.get<Scan>(`/scans/${scanId}`), refetchInterval: (query) => ["queued", "running", "cancelling"].includes(query.state.data?.status ?? "") ? 3000 : false });
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => api.get<Account[]>("/cloud-accounts") });
  const activity = useQuery({ queryKey: ["scan-activity", scanId], queryFn: () => api.get<Page<AuditEvent>>(`/audit-events?limit=50&resource_type=scan_job&resource_id=${scanId}`), enabled: tab === "activity" && Boolean(user?.permissions.includes("audit:read")) });
  const cancel = useMutation({ mutationFn: () => api.post<Scan>(`/scans/${scanId}/cancel`), onSuccess: async () => { setConfirmCancel(false); await client.invalidateQueries({ queryKey: ["scan", scanId] }); } });
  const rerun = useMutation({ mutationFn: () => api.post<Scan>(`/scans/${scanId}/rerun`), onSuccess: (job) => navigate(`/scans/${job.id}`) });
  if (scan.isLoading) return <div className="state-panel">Loading scan…</div>;
  if (scan.error || !scan.data) return <div className="state-panel error-state"><strong>Scan not found</strong><span>{scan.error?.message ?? "This scan does not exist or is not accessible."}</span><Link to="/scans">Return to Scan Management</Link></div>;
  const job = scan.data;
  const account = accounts.data?.find((item) => item.id === job.cloud_account_id);
  const tabs = ["overview", "execution", "resources", "errors", ...(user?.permissions.includes("audit:read") ? ["activity"] : [])];
  return <div className="scan-detail-page">
    <div className="account-detail-back"><Link to="/scans">← Scan Management</Link></div><div className="account-detail-header scan-detail-header"><div><div className="eyebrow">CLOUD OPERATIONS / SCAN JOB</div><h1>Scan {job.id.slice(0, 8).toUpperCase()}</h1><p>{account?.name ?? "Cloud account"} · Requested {date(job.created_at)} · <code>{job.id}</code></p><ScanStatus status={job.status} /></div><div className="detail-header-actions">{user?.permissions.includes("scans:create") && ["completed", "partial", "failed", "cancelled"].includes(job.status) && <button className="secondary-button" disabled={rerun.isPending} onClick={() => setConfirmRerun(true)}>Re-run scan</button>}{user?.permissions.includes("scans:cancel") && ["queued", "running"].includes(job.status) && <button className="danger-button" onClick={() => setConfirmCancel(true)}>Cancel scan</button>}<Link className="quiet-button" to="/scans">All scans</Link></div></div>
    {(cancel.error || rerun.error) && <p className="error-state" role="alert">{(cancel.error ?? rerun.error)?.message}</p>}
    <div className="scan-detail-highlights">
      <div><span>Resources discovered</span><strong>{job.resources_discovered.toLocaleString()}</strong><small>Inventory records from this run</small></div>
      <div className={job.errors_count ? "has-errors" : ""}><span>Collection errors</span><strong>{job.errors_count.toLocaleString()}</strong><small>{job.errors_count ? "Review the Errors tab" : "No collection errors"}</small></div>
      <div><span>Progress</span><strong>{job.progress_percent}%</strong><small>{job.progress_completed} of {job.progress_total} units complete</small></div>
      <div><span>Requested regions</span><strong>{job.requested_regions.length}</strong><small>{job.requested_regions.length ? job.requested_regions.join(", ") : "Default region scope"}</small></div>
    </div>
    <nav className="account-detail-tabs" aria-label="Scan details">{tabs.map((name) => <button key={name} className={tab === name ? "active" : ""} onClick={() => setTab(name)}>{readable(name)}</button>)}</nav>
    {tab === "overview" && <div className="account-detail-grid"><section className="panel"><h2>Scan summary</h2><div className="account-facts-list"><Fact label="Cloud account" value={account?.name ?? job.cloud_account_id} /><Fact label="Status" value={readable(job.status)} /><Fact label="Started" value={date(job.started_at)} /><Fact label="Finished" value={date(job.finished_at)} /><Fact label="Regions" value={job.requested_regions.join(", ")} /><Fact label="Resource types requested" value={String(job.requested_resource_types.length)} /><Fact label="Resources discovered" value={String(job.resources_discovered)} /><Fact label="Errors" value={String(job.errors_count)} /></div></section><section className="panel"><h2>Progress</h2><div className="scan-progress-value">{job.progress_percent}%</div><progress max="100" value={job.progress_percent} /><p>{job.progress_completed} of {job.progress_total} collection units completed.</p>{job.status === "queued" && <p>The scan is queued for a worker.</p>}{job.status === "cancelling" && <p>Cancellation requested. The worker will stop safely.</p>}</section></div>}
    {tab === "execution" && <section className="panel account-tab-panel"><h2>Execution</h2><ol className="scan-timeline"><li className={job.created_at ? "complete" : ""}><strong>Queued</strong><span>{date(job.created_at)}</span></li><li className={job.started_at ? "complete" : "pending"}><strong>Worker started</strong><span>{date(job.started_at)}</span></li><li className={["completed", "partial"].includes(job.status) ? "complete" : job.status === "running" || job.status === "cancelling" ? "current" : "pending"}><strong>AWS inventory collection</strong><span>{job.progress_completed} / {job.progress_total} units</span></li><li className={job.finished_at ? "complete" : "pending"}><strong>{readable(job.status)}</strong><span>{date(job.finished_at)}</span></li></ol></section>}
    {tab === "resources" && <section className="panel account-tab-panel"><h2>Resources</h2><div className="account-facts-list"><Fact label="Resources discovered by this job" value={String(job.resources_discovered)} /><Fact label="Requested resource types" value={job.requested_resource_types.map(readable).join(", ") || "All supported types"} /><Fact label="Regions" value={job.requested_regions.join(", ")} /></div><p className="drawer-help">This scan records normalized inventory. Browse the current inventory in Assets; the scanner does not create findings.</p>{user?.permissions.includes("assets:read") && <Link className="secondary-button" to={`/assets?cloud_account_id=${job.cloud_account_id}`}>Open Assets</Link>}</section>}
    {tab === "errors" && <section className="panel account-tab-panel"><h2>Errors and warnings</h2>{job.errors_count === 0 ? <div className="empty-inline">No scan errors were recorded.</div> : <><p>{job.errors_count} collection errors were recorded. Details are sanitized.</p><ul className="scan-error-list">{job.error_codes.map((item, index) => <li key={`${item.code}-${index}`}><strong>{readable(item.resource_type ?? "collection")}</strong><span>{item.region ?? "Global"}</span><code>{item.code ?? "scan_error"}</code></li>)}</ul></>}</section>}
    {tab === "activity" && <section className="panel account-tab-panel"><h2>Activity</h2>{activity.isLoading ? <p>Loading audit activity…</p> : activity.error ? <p className="error-state">Could not load scan activity.</p> : activity.data?.items.length ? <div className="activity-list">{activity.data.items.map((event) => <div key={event.id}><span className="activity-dot" /><div><strong>{readable(event.action)}</strong><small>{date(event.created_at)} · {event.actor_user_id ? `User ${event.actor_user_id.slice(0, 8)}` : "System"}</small></div></div>)}</div> : <div className="empty-inline">No audit activity is recorded for this scan.</div>}</section>}
    {confirmCancel && <RightDrawer title="Cancel scan?" description="The worker will stop between collection units; completed work remains recorded." onClose={() => setConfirmCancel(false)}><p>Cancel scan {job.id.slice(0, 8).toUpperCase()} for {account?.name ?? "this account"}?</p><div className="drawer-actions"><button className="secondary-button" onClick={() => setConfirmCancel(false)}>Keep running</button><button className="danger-button" disabled={cancel.isPending} onClick={() => cancel.mutate()}>{cancel.isPending ? "Requesting…" : "Cancel scan"}</button></div></RightDrawer>}
    {confirmRerun && <RightDrawer title="Queue a new scan?" description="This creates a new scan job and keeps the original scan history unchanged." onClose={() => setConfirmRerun(false)}><div className="drawer-facts"><Fact label="Cloud account" value={account?.name ?? job.cloud_account_id} /><Fact label="Regions" value={job.requested_regions.join(", ")} /><Fact label="Resource types" value={String(job.requested_resource_types.length)} /></div><div className="drawer-actions"><button className="secondary-button" onClick={() => setConfirmRerun(false)}>Cancel</button><button className="primary-button" disabled={rerun.isPending} onClick={() => rerun.mutate()}>{rerun.isPending ? "Queueing…" : "Confirm re-run"}</button></div></RightDrawer>}
  </div>;
}

function Metric({ label, value, tone }: { label: string; value: number | string; tone?: string }) { return <div className={`account-summary-card summary-${tone ?? kpiTone(label)}`}><span>{label}</span><strong>{value}</strong><KpiIcon label={label} /></div>; }
function ScanStatus({ status }: { status: string }) { return <span className={`account-status account-status-${status === "partial" ? "error" : status === "queued" || status === "cancelling" ? "pending" : status === "running" ? "connected" : status === "completed" ? "connected" : "error"}`}><i />{readable(status)}</span>; }
function Fact({ label, value }: { label: string; value: string }) { return <div className="account-fact"><dt>{label}</dt><dd>{value}</dd></div>; }
