import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Page } from "../shared/api";
import { useAuth } from "../shared/useAuth";
import { FilterField } from "../shared/FilterField";
import { DataTable } from "../shared/DataTable";
import { Icon } from "../shared/Icon";
import { Pagination } from "../shared/Pagination";
import { formatOrganizationDateTime } from "../shared/date-time";

type CustomerScan = {
  id: string;
  scan_type: "iac" | "container";
  source_filename: string;
  status: string;
  finding_count: number;
  scanner_version: string | null;
  error_code: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  expires_at: string;
};
type CustomerScanStatus = { enabled: boolean; max_upload_bytes: number; timeout_seconds: number };
type CustomerFinding = {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  category: string;
  resource: string | null;
  details: Record<string, unknown>;
};
type CustomerFindingPage = Page<CustomerFinding>;

const readable = (value: string) => value.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
const date = (value: string | null) => value ? formatOrganizationDateTime(value) : "—";

export function CustomerScansPage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const navigate = useNavigate();
  const [scanType, setScanType] = useState<"iac" | "container">("iac");
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [offset, setOffset] = useState(0);
  const canCreate = Boolean(user?.permissions.includes("scans:create"));
  const capabilities = useQuery({
    queryKey: ["customer-scan-status"],
    queryFn: () => api.get<CustomerScanStatus>("/customer-scans/status"),
  });
  const page = useQuery({
    queryKey: ["customer-scans", offset, status, typeFilter],
    queryFn: () => {
      const query = new URLSearchParams({ offset: String(offset), limit: "20" });
      if (status) query.set("status", status);
      if (typeFilter) query.set("scan_type", typeFilter);
      return api.get<Page<CustomerScan>>(`/customer-scans?${query.toString()}`);
    },
    refetchInterval: (query) => query.state.data?.items.some((job) => ["queued", "running", "cancelling"].includes(job.status)) ? 5000 : false,
  });
  const maxUploadMiB = capabilities.data
    ? Math.round(capabilities.data.max_upload_bytes / (1024 * 1024))
    : null;
  const create = useMutation({
    mutationFn: () => {
      if (!file) throw new Error("Choose an artifact first.");
      const form = new FormData();
      form.append("scan_type", scanType);
      form.append("file", file);
      return api.upload<CustomerScan>("/customer-scans", form);
    },
    onSuccess: async (job) => {
      setFile(null);
      const input = document.getElementById("customer-scan-file") as HTMLInputElement | null;
      if (input) input.value = "";
      await client.invalidateQueries({ queryKey: ["customer-scans"] });
      navigate(`/customer-scans/${job.id}`);
    },
  });
  const hasFilters = Boolean(status || typeFilter);

  return <div className="customer-scan-page">
    <div className="page-header"><div><div className="eyebrow">SECURITY ASSESSMENTS</div><h1>IaC &amp; Container Scans</h1><p>Assess infrastructure templates and container images in a short lived, isolated scanner task.</p></div></div>
    {capabilities.isLoading ? <div className="panel state-panel">Checking assessment service…</div> : capabilities.error ? <div className="panel state-panel error-state">Assessment service availability could not be checked: {capabilities.error.message}</div> : capabilities.data?.enabled ? <section className="panel customer-scan-upload">
      <div className="customer-scan-upload-copy"><h2>Submit an assessment</h2><p>Uploaded archives are scanned offline in an isolated environment. Findings and source artifacts expire automatically within 24 hours.</p><div className="settings-policy-note"><strong>Accepted inputs</strong><p>IaC: Terraform and supported YAML, JSON, HCL, ZIP or TAR source archives. Container: OCI image TAR only. Maximum upload size is {maxUploadMiB ?? "—"} MiB.</p></div></div>
      <form className="settings-form" aria-busy={create.isPending} onSubmit={(event) => { event.preventDefault(); create.mutate(); }}>
        <label>Assessment type<select value={scanType} onChange={(event) => setScanType(event.target.value as "iac" | "container")} disabled={!canCreate || create.isPending}><option value="iac">Infrastructure as Code</option><option value="container">Container image</option></select></label>
        <label>Source artifact<input id="customer-scan-file" type="file" accept={scanType === "container" ? ".tar,application/x-tar" : ".tf,.tfvars,.tf.json,.tfvars.json,.hcl,.yaml,.yml,.json,.template,.zip,.tar,.tgz,.tar.gz"} onChange={(event) => setFile(event.target.files?.[0] ?? null)} required disabled={!canCreate || create.isPending} /><small>{scanType === "container" ? "Export an OCI image as an archive before uploading." : "Remove credentials and secrets from source files before submitting."}</small></label>
        <div className="settings-form-footer">{!canCreate ? <span>Read only: scan creation permission is required.</span> : <button className="primary-button" disabled={!file || create.isPending}>{create.isPending ? "Uploading and queueing…" : "Queue assessment"}</button>}</div>
        {create.error && <p className="inline-feedback error-state" role="alert">Assessment could not be queued: {create.error.message}</p>}
      </form>
    </section> : <div className="panel state-panel"><strong>Assessments are not enabled for this deployment</strong><span>The platform administrator must configure the isolated scanner service before new IaC or container assessments can be submitted.</span></div>}
    <section className="panel table-panel customer-scan-table-panel">
      <div className="scan-filter-toolbar"><div className="scan-filters">
        <FilterField label="Assessment type"><select value={typeFilter} onChange={(event) => { setTypeFilter(event.target.value); setOffset(0); }}><option value="">All types</option><option value="iac">Infrastructure as Code</option><option value="container">Container</option></select></FilterField>
        <FilterField label="Status"><select value={status} onChange={(event) => { setStatus(event.target.value); setOffset(0); }}><option value="">All statuses</option>{["queued", "running", "cancelling", "completed", "failed", "cancelled"].map((item) => <option key={item} value={item}>{readable(item)}</option>)}</select></FilterField>
      </div><button type="button" className="text-button" disabled={!hasFilters} onClick={() => { setTypeFilter(""); setStatus(""); setOffset(0); }}>Reset filters</button></div>
      {page.isLoading ? <div className="state-panel">Loading assessments…</div> : page.error ? <div className="state-panel error-state">Assessments could not be loaded: {page.error.message}</div> : page.data?.items.length ? <div className="table-scroll"><DataTable caption="Customer IaC and container assessments" actions><thead><tr><th>Assessment</th><th>Type</th><th>Source</th><th>Status</th><th>Findings</th><th>Submitted</th><th>Expires</th><th>Actions</th></tr></thead><tbody>{page.data.items.map((job) => <tr key={job.id}><td><Link className="row-primary" to={`/customer-scans/${job.id}`}>{job.id.slice(0, 8).toUpperCase()}</Link></td><td>{job.scan_type === "iac" ? "IaC" : "Container"}</td><td>{job.source_filename}</td><td><ScanStatus status={job.status} /></td><td>{job.finding_count.toLocaleString()}</td><td>{date(job.created_at)}</td><td>{date(job.expires_at)}</td><td><Link className="scan-view-action" aria-label={`View assessment ${job.id.slice(0, 8).toUpperCase()}`} to={`/customer-scans/${job.id}`}><Icon name="eye" /><span>View</span></Link></td></tr>)}</tbody></DataTable></div> : <div className="state-panel"><strong>{hasFilters ? "No assessments match these filters" : "No assessments yet"}</strong><span>{hasFilters ? "Reset filters to see other assessment runs." : "Upload a sanitized IaC source archive or OCI image TAR to get started."}</span></div>}
      {page.data && page.data.total > 0 && <Pagination total={page.data.total} offset={offset} limit={20} onOffsetChange={setOffset} disabled={page.isFetching} label="Assessment pages" />}
    </section>
  </div>;
}

export function CustomerScanDetailPage() {
  const { scanId = "" } = useParams();
  const { user } = useAuth();
  const client = useQueryClient();
  const [offset, setOffset] = useState(0);
  const [severity, setSeverity] = useState("");
  const [message, setMessage] = useState("");
  const job = useQuery({
    queryKey: ["customer-scan", scanId],
    queryFn: () => api.get<CustomerScan>(`/customer-scans/${scanId}`),
    refetchInterval: (query) => ["queued", "running", "cancelling"].includes(query.state.data?.status ?? "") ? 5000 : false,
  });
  const findings = useQuery({
    queryKey: ["customer-scan-findings", scanId, offset, severity],
    queryFn: () => {
      const query = new URLSearchParams({ offset: String(offset), limit: "25" });
      if (severity) query.set("severity", severity);
      return api.get<CustomerFindingPage>(`/customer-scans/${scanId}/findings?${query.toString()}`);
    },
    enabled: job.data?.status === "completed",
  });
  const cancel = useMutation({
    mutationFn: () => api.post<CustomerScan>(`/customer-scans/${scanId}/cancel`),
    onSuccess: async () => { setMessage("Cancellation requested."); await client.invalidateQueries({ queryKey: ["customer-scan", scanId] }); await client.invalidateQueries({ queryKey: ["customer-scans"] }); },
  });
  if (job.isLoading) return <div className="state-panel">Loading assessment…</div>;
  if (job.error || !job.data) return <div className="state-panel error-state"><strong>Assessment not found</strong><span>{job.error?.message ?? "This assessment is unavailable."}</span><Link to="/customer-scans">Return to assessments</Link></div>;
  const item = job.data;
  return <div className="customer-scan-page">
    <div className="account-detail-back"><Link to="/customer-scans">← IaC &amp; Container Scans</Link></div>
    <div className="account-detail-header"><div><div className="eyebrow">SECURITY ASSESSMENT / {item.scan_type.toUpperCase()}</div><h1>Assessment {item.id.slice(0, 8).toUpperCase()}</h1><p>{item.source_filename} · Submitted {date(item.created_at)} · <code>{item.id}</code></p><ScanStatus status={item.status} /></div>{user?.permissions.includes("scans:cancel") && ["queued", "running"].includes(item.status) && <button className="danger-button" disabled={cancel.isPending} onClick={() => cancel.mutate()}>{cancel.isPending ? "Requesting…" : "Cancel assessment"}</button>}</div>
    <div className="scan-detail-highlights customer-scan-highlights"><div><span>Status</span><strong>{readable(item.status)}</strong><small>{item.error_code ? readable(item.error_code) : "Scanner task state"}</small></div><div><span>Findings</span><strong>{item.finding_count.toLocaleString()}</strong><small>{item.status === "completed" ? "Stored assessment results" : "Available when complete"}</small></div><div><span>Scanner version</span><strong>{item.scanner_version ?? "—"}</strong><small>Pinned release image</small></div><div><span>Data expires</span><strong>{date(item.expires_at)}</strong><small>Source archive and findings are deleted on expiry</small></div></div>
    {(message || cancel.error) && <p className={`inline-feedback ${cancel.error ? "error-state" : ""}`} role="status">{cancel.error?.message ?? message}</p>}
    {item.status === "completed" && <section className="panel table-panel customer-scan-findings-panel"><div className="scan-filter-toolbar"><div><h2>Assessment findings</h2><p>Finding detail fields are filtered and secrets are redacted before they are stored.</p></div><FilterField label="Severity"><select value={severity} onChange={(event) => { setSeverity(event.target.value); setOffset(0); }}><option value="">All severities</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].map((value) => <option key={value}>{value}</option>)}</select></FilterField></div>
      {findings.isLoading ? <div className="state-panel">Loading findings…</div> : findings.error ? <div className="state-panel error-state">Findings could not be loaded: {findings.error.message}</div> : findings.data?.items.length ? <div className="table-scroll"><DataTable caption="Assessment findings"><thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Resource</th><th>Rule</th></tr></thead><tbody>{findings.data.items.map((finding) => <tr key={finding.id}><td><span className={`account-status account-status-${["CRITICAL", "HIGH"].includes(finding.severity) ? "error" : finding.severity === "MEDIUM" ? "pending" : "connected"}`}><i />{finding.severity}</span></td><td><strong>{finding.title}</strong>{Object.entries(finding.details).filter(([, value]) => typeof value === "string" && value).map(([key, value]) => <small className="customer-finding-detail" key={key}>{readable(key)}: {String(value)}</small>)}</td><td>{readable(finding.category)}</td><td>{finding.resource ?? "—"}</td><td><code>{finding.rule_id}</code></td></tr>)}</tbody></DataTable></div> : <div className="state-panel">No findings in this result.</div>}
      {findings.data && findings.data.total > 0 && <Pagination total={findings.data.total} offset={offset} limit={25} onOffsetChange={setOffset} disabled={findings.isFetching} label="Finding pages" />}
    </section>}
    {item.status === "failed" && <div className="panel state-panel error-state"><strong>Assessment failed</strong><span>{readable(item.error_code ?? "scanner_error")}. Retry with a supported input archive after confirming the sandbox is available.</span></div>}
  </div>;
}

function ScanStatus({ status }: { status: string }) {
  const tone = status === "completed" ? "connected" : ["queued", "running", "cancelling"].includes(status) ? "pending" : "error";
  return <span className={`account-status account-status-${tone}`}><i />{readable(status)}</span>;
}
