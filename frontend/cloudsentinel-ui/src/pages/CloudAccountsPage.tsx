import { FilterField } from "../shared/FilterField";
import { ViewAction } from "../shared/ViewAction";
import { DataTable } from "../shared/DataTable";
import { FilterFooter } from "../shared/FilterFooter";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useLayoutEffect, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { createPortal } from "react-dom";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { api, type Account, type Finding, type Page } from "../shared/api";
import { useAuth } from "../shared/useAuth";
import { KpiIcon } from "../shared/kpi";
import { kpiTone } from "../shared/kpi-utils";
import { DrawerFact, RightDrawer } from "../shared/RightDrawer";
import { formatOrganizationDateTime } from "../shared/date-time";
import { Pagination } from "../shared/Pagination";

type AccountCreate = Account & { external_id: string };
type RegionInventory = {
  region_code: string;
  is_enabled: boolean;
  asset_count: number;
};
type AuditEvent = {
  id: string;
  actor_user_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  created_at: string;
};
type Tab =
  | "overview"
  | "connection"
  | "regions"
  | "security"
  | "scans"
  | "activity"
  | "findings";

const statusLabels: Record<string, string> = {
  connected: "Connected",
  pending: "Pending",
  error: "Validation failed",
  disabled: "Disabled",
};

function formatDate(value: string | null | undefined): string {
  if (!value) return "Never";
  return formatOrganizationDateTime(value);
}

function relativeTime(value: string | null | undefined): string {
  if (!value) return "Never";
  const delta = Date.now() - new Date(value).getTime();
  const minutes = Math.max(0, Math.floor(delta / 60_000));
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function maskAccountId(value: string): string {
  return `${value.slice(0, 4)}••••${value.slice(-4)}`;
}

function roleArnValidationMessage(roleArn: string, accountId: string): string {
  if (!roleArn.trim()) return "";
  const match = /^arn:(?:aws|aws-us-gov|aws-cn):iam::(\d{12}):role\/[A-Za-z0-9+=,.@_/-]{1,480}$/.exec(roleArn.trim());
  if (!match) return "Enter a valid AWS IAM role ARN.";
  if (match[1] !== accountId) return "Role ARN belongs to another AWS account.";
  return "";
}

function ValidationChecklist({ status, validationMode = "real" }: { status: "waiting" | "running" | "connected" | "error"; validationMode?: "real" | "mock" }) {
  const checks = [
    ["Role ARN format and account match", status === "connected"],
    ["AWS STS AssumeRole", status === "connected"],
    ["GetCallerIdentity", status === "connected"],
    ["AWS account identity match", status === "connected"],
  ] as const;
  return <div className="aws-validation-checklist" aria-live="polite">
    <strong>{status === "connected" ? "Connection checks passed" : status === "error" ? "Connection validation failed" : "Validation checks"}</strong>
    {checks.map(([label, passed]) => <div className="aws-validation-check" key={label}><span className={passed ? "passed" : status === "error" ? "failed" : "waiting"}>{passed ? "✓" : status === "error" ? "!" : "○"}</span>{label}<b>{passed ? "Passed" : status === "error" ? "Not confirmed" : status === "running" ? "Running" : "Waiting"}</b></div>)}
    <div className="aws-validation-check"><span className={validationMode === "mock" && status === "connected" ? "passed" : "waiting"}>{validationMode === "mock" && status === "connected" ? "✓" : "—"}</span>Baseline IAM permissions<b>{validationMode === "mock" && status === "connected" ? "Passed" : "Not checked"}</b></div>
  </div>;
}

function awsValidationHelp(code: string | null | undefined): string {
  switch (code) {
    case "AccessDenied":
    case "AccessDeniedException":
      return "AWS denied sts:AssumeRole. Check that the role trust policy allows the CloudSentinel AWS principal and the exact External ID shown in this wizard.";
    case "ExternalIdMismatch":
      return "The External ID in the AWS role trust policy does not match this account. Generate a new External ID here and update the trust policy.";
    case "NoCredentialsError":
    case "PartialCredentialsError":
      return "CloudSentinel has no AWS workload identity configured to call STS. Configure the API and worker AWS identities before connecting customer accounts.";
    case "InvalidClientTokenId":
    case "SignatureDoesNotMatch":
      return "The AWS identity configured for the CloudSentinel service is invalid. Ask your CloudSentinel deployment administrator to check its AWS workload credentials.";
    case "account_identity_mismatch":
      return "The role was assumed, but AWS returned an account ID different from the account registered here. Verify the role ARN and account ID.";
    case "EndpointConnectionError":
    case "ConnectTimeoutError":
    case "ReadTimeoutError":
      return "CloudSentinel could not reach the AWS STS endpoint. Check outbound network access and retry.";
    default:
      return "AWS could not validate this role. Confirm the role ARN, trust policy, and External ID, then retry. The underlying AWS message is hidden to protect sensitive details.";
  }
}

function TrustPolicyExample({ externalId }: { externalId: string }) {
  return <details className="trust-policy-example">
    <summary>View trust policy example</summary>
    <p>Replace the principal placeholder with the AWS principal ARN(s) provided by your CloudSentinel deployment administrator.</p>
    <pre>{JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "<CloudSentinel AWS principal ARN>" }, Action: "sts:AssumeRole", Condition: { StringEquals: { "sts:ExternalId": externalId || "<generated External ID>" } } }] }, null, 2)}</pre>
  </details>;
}

function AccountStatus({ status }: { status: string }) {
  return (
    <span className="account-status-group">
      <span className={`account-status account-status-${status}`}>
        <i />
        {statusLabels[status] ?? status}
      </span>
    </span>
  );
}

export function AccountsPage() {
  const { user } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const client = useQueryClient();
  const accounts = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api.get<Account[]>("/cloud-accounts"),
  });
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [region, setRegion] = useState("");
  const [environment, setEnvironment] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 30;
  const [editAccount, setEditAccount] = useState<Account | null>(null);
  const [disableAccount, setDisableAccount] = useState<Account | null>(null);
  const [addAccountOpen, setAddAccountOpen] = useState(
    Boolean((location.state as { openAddAccount?: boolean } | null)?.openAddAccount),
  );
  const [viewAccount, setViewAccount] = useState<Account | null>(null);
  const [removeAccount, setRemoveAccount] = useState<Account | null>(null);
  const [feedback, setFeedback] = useState("");

  const validate = useMutation({
    mutationFn: (accountId: string) =>
      api.post(`/cloud-accounts/${accountId}/validate`),
    onSuccess: () => {
      setFeedback("AWS role validation completed.");
      client.invalidateQueries({ queryKey: ["accounts"] });
    },
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "AWS role validation failed.",
      ),
  });
  const disable = useMutation({
    mutationFn: (accountId: string) =>
      api.post(`/cloud-accounts/${accountId}/disable`),
    onSuccess: () => {
      setDisableAccount(null);
      setFeedback("Account disabled. Existing records were retained.");
      client.invalidateQueries({ queryKey: ["accounts"] });
    },
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "Could not disable account.",
      ),
  });
  const remove = useMutation({
    mutationFn: (accountId: string) =>
      api.delete(`/cloud-accounts/${accountId}`),
    onSuccess: () => {
      setRemoveAccount(null);
      setFeedback("Cloud account removed.");
      client.invalidateQueries({ queryKey: ["accounts"] });
    },
    onError: (error) =>
      setFeedback(
        error instanceof Error ? error.message : "Could not remove account.",
      ),
  });

  const allAccounts = useMemo(() => accounts.data ?? [], [accounts.data]);
  const regionOptions = [
    ...new Set(
      allAccounts.flatMap((account) =>
        account.regions
          .filter((item) => item.is_enabled)
          .map((item) => item.region_code),
      ),
    ),
  ].sort();
  const environmentOptions = [
    ...new Set(
      allAccounts
        .map((account) => account.environment)
        .filter((item): item is string => Boolean(item)),
    ),
  ].sort();
  const filtered = useMemo(
    () =>
      allAccounts.filter((account) => {
        const term = search.trim().toLowerCase();
        return (
          (!term ||
            [account.name, account.account_id, account.role_arn].some((value) =>
              (value ?? "").toLowerCase().includes(term),
            )) &&
          (!status || account.connection_status === status) &&
          (!region ||
            account.regions.some(
              (item) => item.is_enabled && item.region_code === region,
            )) &&
          (!environment || account.environment === environment)
        );
      }),
    [allAccounts, environment, region, search, status],
  );
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageStart = filtered.length ? (currentPage - 1) * pageSize : 0;
  const pageEnd = Math.min(currentPage * pageSize, filtered.length);
  const visibleAccounts = filtered.slice(pageStart, pageEnd);

  const summary = {
    all: allAccounts.length,
    connected: allAccounts.filter(
      (item) => item.connection_status === "connected",
    ).length,
    pending: allAccounts.filter((item) => item.connection_status === "pending")
      .length,
    errors: allAccounts.filter((item) => item.connection_status === "error")
      .length,
    disabled: allAccounts.filter((item) => item.connection_status === "disabled")
      .length,
  };

  return (
    <>
      <div className="account-page-header cloud-accounts-page-header">
        <div>
          <div className="eyebrow">CLOUD ENVIRONMENT</div>
          <h1>Cloud Accounts</h1>
          <p>
            Manage AWS access, connection health, regions, and scan activity.
          </p>
        </div>
        {(user?.permissions.includes("cloud_accounts:create") || user?.permissions.includes("cloud_accounts:update")) && <div className="header-actions">
          {user?.permissions.includes("cloud_accounts:create") && <button className="secondary-button" onClick={() => setAddAccountOpen(true)}>＋ Add Cloud Account</button>}
          <Link className="primary-button" to="/cloud-accounts/connect">Connect AWS</Link>
        </div>}
      </div>
      {feedback && (
        <div className="inline-notice" role="status">
          {feedback}
          <button className="text-button" onClick={() => setFeedback("")}>
            Dismiss
          </button>
        </div>
      )}
      <div
        className="account-summary-grid cloud-account-summary-grid"
        aria-label="Account connection summary"
      >
        <Summary label="All accounts" value={summary.all} />
        <Summary label="Connected" value={summary.connected} tone="connected" />
        <Summary label="Pending" value={summary.pending} tone="pending" />
        <Summary label="Errors" value={summary.errors} tone="error" />
        <Summary label="Disabled" value={summary.disabled} />
      </div>
      <section className="panel accounts-panel">
        <div className="accounts-toolbar">
          <div className="accounts-toolbar-heading">
            <div><h2>Account inventory</h2><p>Review registered AWS accounts and their connection health.</p></div>
            <span className="accounts-result-count">{filtered.length} {filtered.length === 1 ? "account" : "accounts"}</span>
          </div>
          <div className="accounts-filter-controls">
            <FilterField label="Search" className="filter-field-search"><input
              aria-label="Search accounts"
              placeholder="Search name, account ID, or role ARN"
              value={search}
              onChange={(event) => { setSearch(event.target.value); setPage(1); }}
            /></FilterField>
            <FilterField label="Status"><select
              aria-label="Filter status"
              value={status}
              onChange={(event) => { setStatus(event.target.value); setPage(1); }}
            >
              <option value="">All statuses</option>
              {Object.entries(statusLabels).map(([key, label]) => (
                <option key={key} value={key}>
                  {label}
                </option>
              ))}
            </select></FilterField>
            <FilterField label="Region"><select
              aria-label="Filter region"
              value={region}
              onChange={(event) => { setRegion(event.target.value); setPage(1); }}
            >
              <option value="">All regions</option>
              {regionOptions.map((item) => (
                <option key={item}>{item}</option>
              ))}
            </select></FilterField>
            <FilterField label="Environment"><select
              aria-label="Filter environment"
              value={environment}
              onChange={(event) => { setEnvironment(event.target.value); setPage(1); }}
            >
              <option value="">All environments</option>
              {environmentOptions.map((item) => (
                <option key={item}>{item}</option>
              ))}
            </select></FilterField>
          </div>
          <FilterFooter className="accounts-filter-footer" active={Boolean(search || status || region || environment)} onReset={() => {
                  setSearch("");
                  setStatus("");
                  setRegion("");
                  setEnvironment("");
                  setPage(1);
                }} />
        </div>
        {accounts.isLoading ? (
          <div className="state-panel">Loading cloud accounts…</div>
        ) : accounts.error ? (
          <div className="state-panel error-state">
            <strong>Accounts could not be loaded</strong>
            <span>{accounts.error.message}</span>
          </div>
        ) : !filtered.length ? (
          <div className="state-panel">
            <strong>
              {allAccounts.length
                ? "No accounts match these filters"
                : "No AWS accounts connected"}
            </strong>
            <span>
              {allAccounts.length
                ? "Reset filters or search with another value."
                : "Add an AWS account to register its organization-scoped metadata before configuring access."}
            </span>
            {!allAccounts.length &&
              user?.permissions.includes("cloud_accounts:create") && (
                <button className="primary-button" onClick={() => setAddAccountOpen(true)}>Add Cloud Account</button>
              )}
          </div>
        ) : (
          <>
          <div className="table-scroll">
            <DataTable caption="Cloud account inventory" actions className="account-table">
              <thead>
                <tr>
                  <th scope="col">Account</th>
                  <th scope="col">Provider</th>
                  <th scope="col">Account ID</th>
                  <th scope="col">Environment</th>
                  <th scope="col">Status</th>
                  <th scope="col">Regions</th>
                  <th scope="col">IAM role</th>
                  <th scope="col">Last scan</th>
                  <th scope="col">Last validated</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visibleAccounts.map((account) => (
                  <tr key={account.id}>
                    <td>
                      <button
                        className="row-primary text-button"
                        onClick={() => setViewAccount(account)}
                      >
                        {account.name}
                      </button>
                    </td>
                    <td>
                      <span className="aws-badge">AWS</span>
                    </td>
                    <td>
                      <code>{maskAccountId(account.account_id)}</code>
                    </td>
                    <td>{account.environment || "—"}</td>
                    <td>
                      <AccountStatus status={account.connection_status} />
                    </td>
                    <td>
                      {account.regions.filter((item) => item.is_enabled).length}
                    </td>
                    <td>
                      <code title={account.role_arn ?? "Not configured"}>
                        {account.role_arn?.split("/").at(-1) ?? "Not configured"}
                      </code>
                    </td>
                    <td title={formatDate(account.last_scan_at)}>
                      {relativeTime(account.last_scan_at)}
                    </td>
                    <td title={formatDate(account.last_validated_at)}>
                      {relativeTime(account.last_validated_at)}
                    </td>
                    <td>
                      <div className="table-row-actions">
                      <ViewAction label={`View account ${account.name}`} onClick={() => setViewAccount(account)} />
                      <AccountActionsMenu label={`Actions for ${account.name}`}>
                          <button onClick={() => setViewAccount(account)}>
                            <span className="account-action-icon" aria-hidden="true">↗</span>
                            <span className="account-action-copy"><strong>View account</strong><small>Review account status and configuration</small></span>
                          </button>
                          {user?.permissions.includes("cloud_accounts:update") && (
                            <button
                              onClick={() => {
                                setEditAccount(account);
                              }}
                            >
                              <span className="account-action-icon" aria-hidden="true">✎</span>
                              <span className="account-action-copy"><strong>Edit account</strong><small>Update its name or environment</small></span>
                            </button>
                          )}
                          {user?.permissions.includes("cloud_accounts:update") && account.role_arn && (
                            <button
                              onClick={() => validate.mutate(account.id)}
                              disabled={validate.isPending}
                            >
                              <span className="account-action-icon" aria-hidden="true">✓</span>
                              <span className="account-action-copy">
                              <strong>{account.connection_status === "disabled" ? "Validate & enable" : "Validate connection"}</strong>
                              <small>Check that AWS role access is working</small>
                              </span>
                            </button>
                          )}
                          {user?.permissions.includes("scans:create") && account.connection_status === "connected" && (
                            <Link to={`/scans?create=${account.id}`}>
                              <span className="account-action-icon" aria-hidden="true">▶</span>
                              <span className="account-action-copy"><strong>Start scan</strong><small>Scan this account for assets and findings</small></span>
                            </Link>
                          )}
                          {user?.permissions.includes("cloud_accounts:update") &&
                            account.connection_status !== "disabled" && (
                              <button
                                onClick={() => setDisableAccount(account)}
                                disabled={disable.isPending}
                              >
                                <span className="account-action-icon" aria-hidden="true">Ⅱ</span>
                                <span className="account-action-copy"><strong>Disable account</strong><small>Block new scans and retain existing data</small></span>
                              </button>
                            )}
                          {user?.permissions.includes(
                            "cloud_accounts:delete",
                          ) && (
                            <button
                              className="destructive-text"
                              onClick={() => setRemoveAccount(account)}
                            >
                              <span className="account-action-icon account-action-icon-danger" aria-hidden="true">×</span>
                              <span className="account-action-copy"><strong>Remove account</strong><small>Delete its connection configuration</small></span>
                            </button>
                          )}
                          {user?.permissions.includes("cloud_accounts:update") && (account.connection_status === "pending" || account.connection_status === "error" || !account.role_arn) && (
                            <Link to={`/cloud-accounts/connect?account_id=${account.id}`}>
                              <span className="account-action-icon" aria-hidden="true">⚙</span>
                              <span className="account-action-copy"><strong>Configure connection</strong><small>Set up the AWS role and trust relationship</small></span>
                            </Link>
                          )}
                      </AccountActionsMenu>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </DataTable>
          </div>
          <Pagination
            total={filtered.length}
            offset={pageStart}
            limit={pageSize}
            onOffsetChange={(nextOffset) => setPage(Math.floor(nextOffset / pageSize) + 1)}
            label="Cloud account pages"
          />
          </>
        )}
      </section>
      {viewAccount && (
        <RightDrawer
          className="account-preview-drawer"
          title={viewAccount.name}
          description="AWS account overview and connection state"
          onClose={() => setViewAccount(null)}
        >
          <AccountPreview account={viewAccount} />
          <div className="drawer-actions">
            <Link
              className="primary-button"
              to={`/cloud-accounts/${viewAccount.id}`}
              onClick={() => setViewAccount(null)}
            >
              Full details
            </Link>
            {user?.permissions.includes("cloud_accounts:update") && (
              <button
                className="secondary-button"
                onClick={() => {
                  setEditAccount(viewAccount);
                  setViewAccount(null);
                }}
              >
                Edit account
              </button>
            )}
          </div>
        </RightDrawer>
      )}
      {addAccountOpen && <AddAccountDrawer onClose={() => setAddAccountOpen(false)} onContinue={(created) => navigate(`/cloud-accounts/connect?account_id=${created.id}`, { state: { account: created } })} />}
      {editAccount && (
        <EditAccountDialog
          account={editAccount}
          onClose={() => setEditAccount(null)}
          onSaved={() => {
            setEditAccount(null);
            setFeedback("Account details updated.");
            void client.invalidateQueries({ queryKey: ["accounts"] });
          }}
        />
      )}
      {removeAccount && (
        <ConfirmDialog
          title="Remove AWS account?"
          message={`${removeAccount.name} will be disconnected and account configuration will be deleted. Existing scan or asset records may prevent removal.`}
          busy={remove.isPending}
          confirmLabel="Remove account"
          exactConfirmation={removeAccount.name}
          onCancel={() => setRemoveAccount(null)}
          onConfirm={() => remove.mutate(removeAccount.id)}
        />
      )}
      {disableAccount && <ConfirmDialog title="Disable AWS account?" message={`${disableAccount.name} will be blocked from new scans. Existing scan and asset records will be retained.`} busy={disable.isPending} confirmLabel="Disable account" onCancel={() => setDisableAccount(null)} onConfirm={() => disable.mutate(disableAccount.id)} />}
    </>
  );
}

function Summary({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: string;
}) {
  return (
    <div className={`account-summary-card summary-${tone ?? kpiTone(label)}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <KpiIcon label={label} />
    </div>
  );
}

function AccountActionsMenu({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const trigger = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    if (!open) return;
    const update = () => {
      const rect = trigger.current?.getBoundingClientRect();
      if (!rect) return;
      const menuHeight = menu.current?.offsetHeight ?? 240;
      const below = window.innerHeight - rect.bottom;
      const top =
        below >= menuHeight + 12
          ? rect.bottom + 6
          : Math.max(8, rect.top - menuHeight - 6);
      setPosition({
        top,
        left: Math.max(8, Math.min(rect.right - 286, window.innerWidth - 294)),
      });
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <>
      <button
        ref={trigger}
        type="button"
        className="account-actions-trigger"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        ⋮
      </button>
      {open &&
        createPortal(
          <>
            <button
              type="button"
              className="account-actions-backdrop"
              aria-label="Close account actions"
              onClick={() => setOpen(false)}
            />
            <div
              ref={menu}
              className="account-actions-popover"
              role="menu"
              style={{ top: position.top, left: position.left }}
              onClick={() => setOpen(false)}
            >
              <div className="account-actions-heading">Account actions<small>Available for this cloud account</small></div>
              {children}
            </div>
          </>,
          document.body,
        )}
    </>
  );
}

function AddAccountDrawer({
  onClose,
  onContinue,
}: {
  onClose: () => void;
  onContinue: (account: AccountCreate) => void;
}) {
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [accountId, setAccountId] = useState("");
  const [environment, setEnvironment] = useState("");
  const [primaryRegion, setPrimaryRegion] = useState("");
  const [additionalRegions, setAdditionalRegions] = useState<string[]>([]);
  const [regionToAdd, setRegionToAdd] = useState("");
  const [created, setCreated] = useState<AccountCreate | null>(null);
  const awsRegions = useQuery({
    queryKey: ["aws-region-options"],
    queryFn: () => api.get<string[]>("/cloud-accounts/metadata/aws-regions"),
  });
  const create = useMutation({
    mutationFn: () => api.post<AccountCreate>("/cloud-accounts", {
      name,
      account_id: accountId,
      environment: environment || null,
      primary_region: primaryRegion,
      regions: [...new Set([primaryRegion, ...additionalRegions])],
    }),
    onSuccess: (account) => {
      setCreated(account);
      void client.invalidateQueries({ queryKey: ["accounts"] });
    },
  });
  return <RightDrawer className="add-account-drawer" title={created ? "Cloud account added" : "Add cloud account"} description={created ? "This organization-scoped record is pending until AWS role trust is configured." : "Register account details first, then configure AWS access in the connection wizard."} onClose={onClose}>
    {created ? <>
      <AccountStatus status={created.connection_status} />
      <div className="drawer-facts" style={{ marginTop: 16 }}>
        <DrawerFact label="Account name" value={created.name} />
        <DrawerFact label="AWS account ID" value={created.account_id} />
        <DrawerFact label="Primary region" value={created.primary_region || "Not set"} />
      </div>
      <p className="drawer-help">Continue to AWS role setup. The one-time External ID will be available to copy in the connection wizard.</p>
      <div className="drawer-actions"><button className="secondary-button" onClick={onClose}>Finish later</button><button className="primary-button" onClick={() => onContinue(created)}>Configure AWS connection</button></div>
    </> : <form className="drawer-form account-create-form" aria-busy={create.isPending} onSubmit={(event) => { event.preventDefault(); if (!create.isPending) create.mutate(); }}>
      <label>Account name *<input disabled={create.isPending} required minLength={2} maxLength={160} value={name} onChange={(event) => setName(event.target.value)} placeholder="Production AWS" /></label>
      <label>AWS account ID *<input disabled={create.isPending} required inputMode="numeric" pattern="[0-9]{12}" value={accountId} onChange={(event) => setAccountId(event.target.value)} placeholder="123456789012" /></label>
      <label>Environment<input disabled={create.isPending} maxLength={80} value={environment} onChange={(event) => setEnvironment(event.target.value)} placeholder="Production (optional)" /><small>Use your organization’s environment label.</small></label>
      <label>Primary region *
        <select required value={primaryRegion} onChange={(event) => setPrimaryRegion(event.target.value)} disabled={create.isPending || awsRegions.isLoading || Boolean(awsRegions.error)}>
          <option value="">{awsRegions.isLoading ? "Loading AWS regions…" : "Select primary region"}</option>
          {(awsRegions.data ?? []).map((region) => <option key={region} value={region}>{region}</option>)}
        </select>
      </label>
      <label className="form-field-wide">Additional regions
        <div className="region-multiselect">
          {additionalRegions.length > 0 && <div className="region-chips" aria-label="Selected additional regions">
            {additionalRegions.map((region) => <span className="region-chip" key={region}>{region}<button type="button" disabled={create.isPending} aria-label={`Remove ${region}`} onClick={() => setAdditionalRegions((current) => current.filter((item) => item !== region))}>×</button></span>)}
          </div>}
          <select aria-label="Add additional region" value={regionToAdd} onChange={(event) => {
            const selected = event.target.value;
            if (selected) setAdditionalRegions((current) => [...current, selected]);
            setRegionToAdd("");
          }} disabled={create.isPending || awsRegions.isLoading || Boolean(awsRegions.error) || !primaryRegion}>
            <option value="">{primaryRegion ? "Add region…" : "Choose a primary region first"}</option>
            {(awsRegions.data ?? []).filter((region) => region !== primaryRegion && !additionalRegions.includes(region)).map((region) => <option key={region} value={region}>{region}</option>)}
          </select>
        </div>
        <small>Select the regions to include with this account.</small>
      </label>
      {awsRegions.error && <p className="error-state" role="alert">AWS region options could not be loaded. Refresh and try again.</p>}
      <div className="permission-note"><strong>AWS access is configured separately</strong><span>After adding the account, configure its IAM role using STS AssumeRole.</span></div>
      {create.error && <p className="error-state" role="alert">{create.error.message}</p>}
      <div className="drawer-actions"><button type="button" className="secondary-button" onClick={onClose}>Cancel</button><button className="primary-button" disabled={create.isPending || !primaryRegion || !awsRegions.data?.length}>{create.isPending ? "Adding…" : "Add account"}</button></div>
    </form>}
  </RightDrawer>;
}

function AccountPreview({ account }: { account: Account }) {
  return (
    <>
      <section className="account-preview-hero">
        <span className="account-preview-mark" aria-hidden="true">AWS</span>
        <div>
          <span className="eyebrow">CLOUD ACCOUNT</span>
          <strong>{account.environment || "Environment not set"}</strong>
          <span>{maskAccountId(account.account_id)} · {account.primary_region || "Primary region not set"}</span>
        </div>
        <AccountStatus status={account.connection_status} />
      </section>
      <div className="account-preview-stats">
        <div><span>Enabled regions</span><strong>{account.regions.filter((region) => region.is_enabled).length}</strong></div>
        <div><span>Last scan</span><strong>{relativeTime(account.last_scan_at)}</strong></div>
        <div><span>Last validated</span><strong>{relativeTime(account.last_validated_at)}</strong></div>
      </div>
      <section className="account-preview-section">
        <h3>Account configuration</h3>
        <div className="drawer-facts">
          <DrawerFact label="Provider" value="Amazon Web Services" />
        <DrawerFact
          label="Account ID"
          value={maskAccountId(account.account_id)}
        />
        <DrawerFact
          label="Environment"
          value={account.environment || "Not set"}
        />
        <DrawerFact
          label="Primary region"
          value={account.primary_region || "Not set"}
        />
          <DrawerFact label="Created" value={formatDate(account.created_at)} />
          <div className="drawer-fact account-preview-role">
            <span>IAM role</span>
            <strong>{account.role_arn || "Not configured"}</strong>
          </div>
        </div>
      </section>
    </>
  );
}

function EditAccountDialog({
  account,
  onClose,
  onSaved,
}: {
  account: Account;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(account.name);
  const [environment, setEnvironment] = useState(account.environment ?? "");
  const [primaryRegion, setPrimaryRegion] = useState(
    account.primary_region ?? "",
  );
  const [regions, setRegions] = useState(
    account.regions
      .filter((item) => item.is_enabled)
      .map((item) => item.region_code)
      .join(", "),
  );
  const [error, setError] = useState("");
  const save = useMutation({
    mutationFn: () => {
      const payload: Record<string, unknown> = {};
      if (name !== account.name) payload.name = name;
      if (environment !== (account.environment ?? "")) {
        payload.environment = environment || null;
      }
      if (primaryRegion !== (account.primary_region ?? "")) {
        payload.primary_region = primaryRegion;
      }
      const currentRegions = account.regions
        .filter((item) => item.is_enabled)
        .map((item) => item.region_code)
        .sort();
      const nextRegions = regions
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean)
        .sort();
      if (JSON.stringify(currentRegions) !== JSON.stringify(nextRegions)) {
        payload.regions = nextRegions;
      }
      if (!Object.keys(payload).length) {
        throw new Error("No account changes to save.");
      }
      return api.patch(`/cloud-accounts/${account.id}`, payload);
    },
    onSuccess: onSaved,
    onError: (reason) =>
      setError(
        reason instanceof Error ? reason.message : "Could not update account.",
      ),
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    if (save.isPending) return;
    setError("");
    save.mutate();
  }
  return (
    <RightDrawer
      title="Edit AWS account"
      description="Update account labels, environment, and enabled regions. IAM role changes belong in the AWS connection flow."
      onClose={onClose}
    >
      <form className="drawer-form account-edit-form" onSubmit={submit} aria-busy={save.isPending}>
        <label>
          <span>Account name <span className="field-required">Required</span></span>
          <input
            required
            minLength={2}
            maxLength={160}
            value={name}
            disabled={save.isPending}
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <label>
          Environment
          <input
            list="cloud-account-environments"
            maxLength={80}
            value={environment}
            disabled={save.isPending}
            onChange={(event) => setEnvironment(event.target.value)}
            placeholder="e.g. Production"
          />
          <datalist id="cloud-account-environments">
            <option value="Production" />
            <option value="Staging" />
            <option value="Development" />
            <option value="Testing" />
            <option value="Sandbox" />
          </datalist>
        </label>
        <label>
          <span>Primary region <span className="field-required">Required</span></span>
          <input
            required
            value={primaryRegion}
            disabled={save.isPending}
            onChange={(event) => setPrimaryRegion(event.target.value)}
          />
        </label>
        <label>
          <span>Enabled regions <span className="field-required">Required</span></span>
          <input
            required
            value={regions}
            disabled={save.isPending}
            onChange={(event) => setRegions(event.target.value)}
          />
          <small>Comma-separated AWS region codes.</small>
        </label>
        {error && <div className="error-state" role="alert">{error}</div>}
        <div className="drawer-actions">
          <button type="button" className="secondary-button" disabled={save.isPending} onClick={onClose}>Cancel</button>
          <button type="submit" className="primary-button" disabled={save.isPending}>
            {save.isPending ? "Saving…" : "Save changes"}
          </button>
        </div>
      </form>
    </RightDrawer>
  );
}

function ConfirmDialog({
  title,
  message,
  busy,
  confirmLabel,
  exactConfirmation,
  onCancel,
  onConfirm,
}: {
  title: string;
  message: string;
  busy: boolean;
  confirmLabel: string;
  exactConfirmation?: string;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const [typedName, setTypedName] = useState("");
  return (
    <RightDrawer title={title} description={message} onClose={onCancel}>
      {exactConfirmation && <label>Type <strong>{exactConfirmation}</strong> to confirm<input disabled={busy} autoComplete="off" value={typedName} onChange={(event) => setTypedName(event.target.value)} /></label>}
      <div className="drawer-actions"><button className="secondary-button" onClick={onCancel}>Cancel</button><button className="danger-button" disabled={busy || Boolean(exactConfirmation && typedName !== exactConfirmation)} onClick={onConfirm}>{busy ? "Working…" : confirmLabel}</button></div>
    </RightDrawer>
  );
}

export function ConnectAWSPage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const setupAccount = (location.state as { account?: AccountCreate } | null)?.account;
  const pendingAccountId = new URLSearchParams(location.search).get("account_id");
  const connectableAccounts = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api.get<Account[]>("/cloud-accounts"),
    enabled: !setupAccount && !pendingAccountId,
  });
  const [step, setStep] = useState(setupAccount ? 2 : 1);
  const [name, setName] = useState(setupAccount?.name ?? "");
  const [accountId, setAccountId] = useState(setupAccount?.account_id ?? "");
  const [environment, setEnvironment] = useState(setupAccount?.environment ?? "");
  const [primaryRegion, setPrimaryRegion] = useState(setupAccount?.primary_region ?? "");
  const [extraRegions, setExtraRegions] = useState("");
  const [roleArn, setRoleArn] = useState(setupAccount?.role_arn ?? "");
  const [created, setCreated] = useState<AccountCreate | null>(setupAccount ?? null);
  const [validation, setValidation] = useState<{
    connection_status: string;
    validated_at: string;
    validation_mode: "real" | "mock";
    baseline_permissions_status: "not_checked" | "simulated_passed" | "simulated_failed";
  } | null>(null);
  const [error, setError] = useState("");
  const create = useMutation({
    mutationFn: () =>
      api.post<AccountCreate>("/cloud-accounts", {
        name,
        account_id: accountId,
        environment: environment || null,
        primary_region: primaryRegion,
        role_arn: roleArn,
        regions: [
          ...new Set([
            primaryRegion,
            ...extraRegions
              .split(",")
              .map((value) => value.trim())
              .filter(Boolean),
          ]),
        ],
      }),
    onSuccess: (data) => {
      setCreated(data);
      setStep(3);
    },
    onError: (reason) =>
      setError(
        reason instanceof Error
          ? reason.message
          : "Could not register AWS account.",
      ),
  });
  const validate = useMutation({
    mutationFn: () =>
      api.post<{ connection_status: string; validated_at: string; validation_mode: "real" | "mock"; baseline_permissions_status: "not_checked" | "simulated_passed" | "simulated_failed" }>(
        `/cloud-accounts/${created?.id}/validate`,
      ),
    onSuccess: async (data) => {
      setValidation(data);
      setError("");
      await client.invalidateQueries({ queryKey: ["accounts"] });
      if (created) await client.invalidateQueries({ queryKey: ["account", created.id] });
    },
    onError: (reason) =>
      setError(
        reason instanceof Error ? reason.message : "AWS validation failed.",
      ),
  });
  const configureRole = useMutation({
    mutationFn: () => api.patch<Account>(`/cloud-accounts/${created?.id}`, { role_arn: roleArn }),
    onSuccess: (account) => {
      if (!created) return;
      setCreated({ ...account, external_id: created.external_id });
      setStep(3);
      setError("");
    },
    onError: (reason) => setError(reason instanceof Error ? reason.message : "Could not save the IAM role."),
  });
  if (!setupAccount && pendingAccountId) return <ExistingAWSSetupPage accountId={pendingAccountId} />;
  if (!setupAccount) {
    const eligible = (connectableAccounts.data ?? []).filter(
      (account) => account.connection_status === "pending" || account.connection_status === "error" || !account.role_arn,
    );
    return (
      <>
        <div className="account-page-header">
          <div>
            <div className="eyebrow">CLOUD / AWS CONNECTION</div>
            <h1>Connect AWS</h1>
            <p>Select a pending account to configure or repair its AWS role trust.</p>
          </div>
          <Link className="quiet-button" to="/cloud-accounts">Back to accounts</Link>
        </div>
        <section className="panel connection-wizard connection-account-picker">
          {connectableAccounts.isLoading ? <div className="state-panel">Loading cloud accounts…</div> : connectableAccounts.error ? (
            <div className="state-panel error-state"><strong>Accounts could not be loaded</strong><span>{connectableAccounts.error.message}</span></div>
          ) : eligible.length ? (
            <div className="wizard-form">
              <div className="connection-picker-heading">
                <div><h2>Choose an account</h2><p>Choose an account to configure its IAM role and validate access with AWS STS.</p></div>
                <span>{eligible.length} available</span>
              </div>
              <div className="connection-account-options">
                {eligible.map((account) => (
                  <button key={account.id} className="connection-account-option" onClick={() => navigate(`/cloud-accounts/connect?account_id=${account.id}`)}>
                    <span className="connection-account-mark" aria-hidden="true">AWS</span>
                    <span className="connection-account-copy"><strong>{account.name}</strong><small><span>{maskAccountId(account.account_id)}</span><i /> <span>{account.primary_region || "Region not set"}</span></small></span>
                    <span className="connection-account-trailing"><AccountStatus status={account.connection_status} /><span className="connection-account-arrow" aria-hidden="true">→</span></span>
                  </button>
                ))}
              </div>
            </div>
          ) : (
        <div className="state-panel">
                <strong>{connectableAccounts.data?.length ? "No accounts need AWS setup" : "Create a cloud account first"}</strong>
                <span>{connectableAccounts.data?.length ? "All registered accounts are connected or disabled. Add a new account to connect another AWS environment." : "Register the AWS account metadata first. You can then select it here to configure IAM role trust."}</span>
              <div className="drawer-actions">
                {user?.permissions.includes("cloud_accounts:create") && <button className="primary-button" onClick={() => navigate("/cloud-accounts", { state: { openAddAccount: true } })}>Add Cloud Account</button>}
                <Link className="secondary-button" to="/cloud-accounts">Back to Cloud Accounts</Link>
              </div>
            </div>
          )}
        </section>
      </>
    );
  }
  async function copyExternalId() {
    if (created) await navigator.clipboard.writeText(created.external_id);
  }
  return (
    <>
      <div className="account-page-header">
        <div>
          <div className="eyebrow">CLOUD / AWS CONNECTION</div>
          <h1>Connect AWS Account</h1>
          <p>
            Register a read-only cross-account role using AWS STS AssumeRole.
          </p>
        </div>
        <Link className="quiet-button" to="/cloud-accounts">
          Cancel
        </Link>
      </div>
      <section className="panel connection-wizard">
        <ol className="wizard-steps">
          {["Account", "IAM role", "Validate"].map((label, index) => (
            <li
              className={
                step === index + 1
                  ? "current"
                  : step > index + 1
                    ? "complete"
                    : ""
              }
              key={label}
            >
              <span>{index + 1}</span>
              {label}
            </li>
          ))}
        </ol>
        {step === 1 && (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              setStep(2);
            }}
            className="wizard-form"
          >
            <h2>AWS account details</h2>
            <label>
              Account name
              <input disabled={create.isPending || configureRole.isPending}
                required
                minLength={2}
                maxLength={160}
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Production"
              />
            </label>
            <label>
              AWS account ID
              <input disabled={create.isPending || configureRole.isPending}
                required
                inputMode="numeric"
                pattern="[0-9]{12}"
                value={accountId}
                onChange={(event) => setAccountId(event.target.value)}
                placeholder="123456789012"
              />
            </label>
            <label>Environment<input disabled={create.isPending || configureRole.isPending} maxLength={80} value={environment} onChange={(event) => setEnvironment(event.target.value)} placeholder="Production (optional)" /></label>
            <label>
              Primary region
              <input disabled={create.isPending || configureRole.isPending}
                required
                value={primaryRegion}
                onChange={(event) =>
                  setPrimaryRegion(event.target.value.trim())
                }
                placeholder="us-east-1"
              />
            </label>
            <label>
              Additional regions
              <input disabled={create.isPending || configureRole.isPending}
                value={extraRegions}
                onChange={(event) => setExtraRegions(event.target.value)}
                placeholder="us-west-2, eu-west-1"
              />
              <small>
                Comma-separated. Only configured regions are eligible for scans.
              </small>
            </label>
            <button className="primary-button">Next: IAM role</button>
          </form>
        )}
        {step === 2 && (
          <div className="wizard-form">
            <h2>Configure AWS IAM role</h2>
            <p>
              Create or use a read-only IAM role in the target AWS account.
              CloudSentinel does not accept permanent access keys.
            </p>
            <div className="assume-role-diagram">
              <span>CloudSentinel</span>
              <b>→ AWS STS AssumeRole →</b>
              <span>Read-only IAM role</span>
            </div>
            <label>
              Role ARN *
              <input disabled={create.isPending || configureRole.isPending}
                required
                aria-invalid={Boolean(roleArnValidationMessage(roleArn, accountId))}
                value={roleArn}
                onChange={(event) => setRoleArn(event.target.value)}
                placeholder={`arn:aws:iam::${accountId}:role/CloudSentinelReadOnly`}
              />
            </label>
            {roleArnValidationMessage(roleArn, accountId) && <p className="field-error" role="alert">{roleArnValidationMessage(roleArn, accountId)}</p>}
            <div className="external-id-section">
              <label>External ID *</label>
              {created ? <div className="external-id-box"><code>{created.external_id}</code><button type="button" className="quiet-button" onClick={() => void copyExternalId()}>Copy</button></div> : <p className="field-error">Register the cloud account first to generate its External ID.</p>}
              <small>Use this exact value in the role trust policy under <code>sts:ExternalId</code>.</small>
            </div>
            <div className="permission-note">
              <strong>Role trust relationship</strong>
              <span>The target IAM role must trust the CloudSentinel AWS principal or principals used for STS AssumeRole.</span>
              <ul><li><code>sts:AssumeRole</code></li><li><code>sts:ExternalId</code> condition</li></ul>
              <TrustPolicyExample externalId={created?.external_id ?? ""} />
              <span>
                Validation confirms role assumption and AWS account identity. It does not inspect every IAM permission.
              </span>
            </div>
            {error && <div className="error-state">{error}</div>}
            <div className="dialog-actions">
              <button className="quiet-button" onClick={() => created ? navigate("/cloud-accounts") : setStep(1)}>
                Back
              </button>
              <button
                className="primary-button"
                disabled={
                  create.isPending || configureRole.isPending || !roleArn.trim() || Boolean(roleArnValidationMessage(roleArn, accountId)) || !created
                }
                onClick={() => {
                  setError("");
                  if (created) configureRole.mutate();
                  else create.mutate();
                }}
              >
                {create.isPending || configureRole.isPending ? "Saving…" : "Continue to Validation"}
              </button>
            </div>
          </div>
        )}
        {step === 3 && created && (
          <div className="wizard-form">
            <h2>
              {validation ? "Connection validated" : "Complete AWS trust setup"}
            </h2>
            <p>
              Confirm the target role trust policy is saved, then validate the
              STS role assumption and AWS account identity.
            </p>
            <ValidationChecklist validationMode={validation?.validation_mode ?? "real"} status={validation?.connection_status === "connected" ? "connected" : error ? "error" : validate.isPending ? "running" : "waiting"} />
            <div className="validation-state">
              <AccountStatus
                status={
                  validation?.connection_status ?? created.connection_status
                }
              />
              <span>
                {validation
                  ? `Validated ${formatDate(validation.validated_at)}`
                  : "Waiting for AWS STS validation"}
              </span>
            </div>
            {error && <div className="error-state">{error}</div>}
            <div className="dialog-actions">
              <button
                className="quiet-button"
                onClick={() => navigate("/cloud-accounts")}
              >
                Finish later
              </button>
              <button
                className="primary-button"
                disabled={validate.isPending}
                onClick={() => {
                  setError("");
                  validate.mutate();
                }}
              >
                {validate.isPending
                  ? "Validating…"
                  : validation
                    ? "Validate again"
                    : "Validate connection"}
              </button>
              {validation?.connection_status === "connected" && (
                <button
                  className="secondary-button"
                  onClick={() => navigate(`/cloud-accounts/${created.id}`)}
                >
                  View account
                </button>
              )}
            </div>
          </div>
        )}
      </section>
    </>
  );
}

function ExistingAWSSetupPage({ accountId }: { accountId: string }) {
  const navigate = useNavigate();
  const client = useQueryClient();
  const [externalId, setExternalId] = useState("");
  const [roleArnDraft, setRoleArnDraft] = useState<string | null>(null);
  const [roleSaved, setRoleSaved] = useState(false);
  const account = useQuery({
    queryKey: ["account", accountId],
    queryFn: () => api.get<Account>(`/cloud-accounts/${accountId}`),
  });
  const roleArn = roleArnDraft ?? account.data?.role_arn ?? "";
  const issueExternalId = useMutation({
    mutationFn: () => api.post<{ external_id: string }>(`/cloud-accounts/${accountId}/external-id`),
    onSuccess: (result) => {
      setExternalId(result.external_id);
      setRoleSaved(false);
      void client.invalidateQueries({ queryKey: ["accounts"] });
    },
  });
  const saveRole = useMutation({
    mutationFn: () => api.patch(`/cloud-accounts/${accountId}`, { role_arn: roleArn }),
    onSuccess: async () => {
      setRoleSaved(true);
      await client.invalidateQueries({ queryKey: ["account", accountId] });
      await client.invalidateQueries({ queryKey: ["accounts"] });
    },
  });
  const validate = useMutation({
    mutationFn: () => api.post(`/cloud-accounts/${accountId}/validate`),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["account", accountId] });
      await client.invalidateQueries({ queryKey: ["accounts"] });
    },
    onError: async () => {
      await client.invalidateQueries({ queryKey: ["account", accountId] });
      await client.invalidateQueries({ queryKey: ["accounts"] });
    },
  });
  const roleError = account.data ? roleArnValidationMessage(roleArn, account.data.account_id) : "";
  return <>
    <div className="account-page-header"><div><div className="eyebrow">CLOUD / AWS CONNECTION</div><h1>Configure AWS connection</h1><p>Set up a role for {account.data?.name ?? "the selected cloud account"} using temporary STS credentials.</p></div><Link className="quiet-button" to="/cloud-accounts">Cancel</Link></div>
    {account.isLoading ? <div className="state-panel">Loading cloud account…</div> : account.error || !account.data ? <div className="state-panel error-state"><strong>Account setup could not be loaded</strong><span>{account.error?.message ?? "Account not found."}</span></div> : <section className="panel connection-wizard"><ol className="wizard-steps"><li className="complete"><span>1</span>Account</li><li className={!roleSaved ? "current" : "complete"}><span>2</span>IAM role</li><li className={roleSaved ? "current" : ""}><span>3</span>Validate</li></ol><div className="wizard-form"><h2>{account.data.name} · {account.data.account_id}</h2><p>Configure a read-only IAM role and validate it using temporary AWS STS credentials. Permanent access keys are not accepted.</p>{!externalId ? <button className="secondary-button" disabled={issueExternalId.isPending} onClick={() => issueExternalId.mutate()}>{issueExternalId.isPending ? "Generating…" : "Generate one-time External ID"}</button> : <>
      {!roleSaved && <div className="external-id-section"><label>External ID *</label><div className="external-id-box"><code>{externalId}</code><button type="button" className="quiet-button" onClick={() => void navigator.clipboard.writeText(externalId)}>Copy</button></div><small>Use this exact value in the role trust policy under <code>sts:ExternalId</code>.</small></div>}
      {!roleSaved ? <>
        <label>Role ARN *<input disabled={saveRole.isPending || validate.isPending} required aria-invalid={Boolean(roleError)} value={roleArn} onChange={(event) => setRoleArnDraft(event.target.value)} placeholder={`arn:aws:iam::${account.data.account_id}:role/CloudSentinelReadOnly`} /></label>
        {roleError && <p className="field-error" role="alert">{roleError}</p>}
        <div className="permission-note"><strong>Role trust relationship</strong><span>The target IAM role must trust the CloudSentinel AWS principal or principals used for STS AssumeRole.</span><ul><li><code>sts:AssumeRole</code></li><li><code>sts:ExternalId</code> condition</li></ul><TrustPolicyExample externalId={externalId} /><span>Validation confirms role assumption and AWS account identity. It does not inspect every IAM permission.</span></div>
      </> : <>
        <ValidationChecklist validationMode={account.data.validation_mode ?? "real"} status={account.data.connection_status === "connected" ? "connected" : validate.error || account.data.connection_status === "error" ? "error" : validate.isPending ? "running" : "waiting"} />
        {account.data.connection_status === "error" && <div className="aws-validation-error" role="alert"><strong>AWS role validation failed{account.data.last_error_code ? ` (${account.data.last_error_code})` : ""}</strong><p>{awsValidationHelp(account.data.last_error_code)}</p><p>External IDs are case-sensitive. After rotating one, update the AWS role trust policy with the new value before validating again.</p></div>}
      </>}
      {(issueExternalId.error || saveRole.error || validate.error) && <p className="error-state" role="alert">{validate.error ? "AWS role validation failed. See the guidance above and retry after correcting the AWS trust policy." : (issueExternalId.error ?? saveRole.error)?.message}</p>}
      <div className="dialog-actions">{!roleSaved ? <><button className="quiet-button" onClick={() => navigate("/cloud-accounts")}>Back</button><button className="primary-button" disabled={!roleArn.trim() || Boolean(roleError) || saveRole.isPending} onClick={() => saveRole.mutate()}>{saveRole.isPending ? "Saving…" : "Continue to Validation"}</button></> : <><button className="quiet-button" onClick={() => navigate("/cloud-accounts")}>Back</button>{account.data.connection_status === "error" && <button className="secondary-button" disabled={issueExternalId.isPending} onClick={() => issueExternalId.mutate()}>{issueExternalId.isPending ? "Generating…" : "Rotate External ID / Edit Trust"}</button>}<button className="primary-button" disabled={validate.isPending} onClick={() => validate.mutate()}>{validate.isPending ? "Validating…" : "Validate AWS connection"}</button>{account.data.connection_status === "connected" && <button className="secondary-button" onClick={() => navigate(`/cloud-accounts/${accountId}`)}>View account</button>}</>}</div>
    </>}</div></section>}
  </>;
}

export function AccountDetailPage() {
  const { accountId = "" } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const client = useQueryClient();
  const [tab, setTab] = useState<Tab>("overview");
  const [editOpen, setEditOpen] = useState(false);
  const [disableOpen, setDisableOpen] = useState(false);
  const [removeOpen, setRemoveOpen] = useState(false);
  const [feedback, setFeedback] = useState("");
  const account = useQuery({
    queryKey: ["account", accountId],
    queryFn: () => api.get<Account>(`/cloud-accounts/${accountId}`),
  });
  const regions = useQuery({
    queryKey: ["account-regions", accountId],
    queryFn: () =>
      api.get<RegionInventory[]>(`/cloud-accounts/${accountId}/regions`),
    enabled: tab === "regions",
  });
  const findings = useQuery({
    queryKey: ["account-findings", accountId],
    queryFn: () =>
      api.get<Page<Finding>>(
        `/findings?limit=100&cloud_account_id=${accountId}`,
      ),
    enabled:
      tab === "findings" &&
      Boolean(user?.permissions.includes("findings:read")),
  });
  const scans = useQuery({
    queryKey: ["account-scan-history", accountId],
    queryFn: () =>
      api.get<
        Page<{
          id: string;
          cloud_account_id: string;
          status: string;
          created_at: string;
          requested_regions: string[];
          progress_percent: number;
        }>
      >("/scans?limit=100"),
    enabled:
      tab === "scans" && Boolean(user?.permissions.includes("scans:read")),
  });
  const accountScans =
    scans.data?.items.filter((item) => item.cloud_account_id === accountId) ??
    [];
  const activity = useQuery({
    queryKey: ["account-activity", accountId],
    queryFn: () =>
      api.get<Page<AuditEvent>>(
        `/audit-events?limit=50&resource_type=cloud_account&resource_id=${accountId}`,
      ),
    enabled:
      tab === "activity" && Boolean(user?.permissions.includes("audit:read")),
  });
  const validate = useMutation({
    mutationFn: () => api.post(`/cloud-accounts/${accountId}/validate`),
    onSuccess: () => {
      setFeedback("Connection validation succeeded.");
      void client.invalidateQueries({ queryKey: ["account", accountId] });
      void client.invalidateQueries({ queryKey: ["accounts"] });
    },
    onError: (reason) =>
      setFeedback(
        reason instanceof Error
          ? reason.message
          : "Connection validation failed.",
      ),
  });
  const disable = useMutation({
    mutationFn: () => api.post(`/cloud-accounts/${accountId}/disable`),
    onSuccess: async () => { setDisableOpen(false); await client.invalidateQueries({ queryKey: ["account", accountId] }); await client.invalidateQueries({ queryKey: ["accounts"] }); },
  });
  const remove = useMutation({
    mutationFn: () => api.delete(`/cloud-accounts/${accountId}`),
    onSuccess: () => navigate("/cloud-accounts"),
  });
  if (account.isLoading)
    return <div className="state-panel">Loading AWS account…</div>;
  if (account.error || !account.data)
    return (
      <div className="state-panel error-state">
        <strong>Account details could not be loaded</strong>
        <span>{account.error?.message ?? "Account not found."}</span>
        <Link to="/cloud-accounts">Return to Cloud Accounts</Link>
      </div>
    );
  const row = account.data;
  const tabs: { id: Tab; label: string; permission?: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "connection", label: "Connection" },
    { id: "regions", label: "Regions" },
    { id: "security", label: "Security" },
    { id: "scans", label: "Scans", permission: "scans:read" },
    { id: "activity", label: "Activity", permission: "audit:read" },
    { id: "findings", label: "Findings", permission: "findings:read" },
  ];
  return (
    <>
      <div className="account-detail-back">
        <Link to="/cloud-accounts">← Cloud Accounts</Link>
      </div>
      <div className="account-detail-header account-detail-hero">
        <div>
          <div className="eyebrow">AWS CLOUD ACCOUNT</div>
          <h1>{row.name}</h1>
          <p>
            <code>{row.account_id}</code> ·{" "}
            {row.environment || "Environment unspecified"} ·{" "}
            {row.regions.filter((item) => item.is_enabled).length} enabled
            regions
          </p>
          <AccountStatus status={row.connection_status} />
        </div>
        <div className="detail-header-actions">
          {user?.permissions.includes("cloud_accounts:update") && <button className="secondary-button" onClick={() => setEditOpen(true)}>Edit</button>}
          {user?.permissions.includes("cloud_accounts:update") && row.role_arn && (
            <button
              className="secondary-button"
              disabled={validate.isPending}
              onClick={() => validate.mutate()}
            >
              {validate.isPending ? "Validating…" : "Validate connection"}
            </button>
          )}
          {user?.permissions.includes("cloud_accounts:update") && (row.connection_status === "pending" || row.connection_status === "error" || !row.role_arn) && <Link className="primary-button" to={`/cloud-accounts/connect?account_id=${row.id}`}>Configure AWS connection</Link>}
          {user?.permissions.includes("cloud_accounts:update") && row.connection_status !== "disabled" && <button className="secondary-button" onClick={() => setDisableOpen(true)}>Disable</button>}
          {user?.permissions.includes("cloud_accounts:delete") && <button className="danger-button" onClick={() => setRemoveOpen(true)}>Remove</button>}
          {user?.permissions.includes("scans:create") && (row.connection_status === "connected" ? <Link className="primary-button" to={`/scans?create=${row.id}`}>Start scan</Link> : <button className="primary-button" disabled title="Validate the account connection before scanning.">Start scan</button>)}
          <Link className="quiet-button" to="/cloud-accounts">
            All accounts
          </Link>
        </div>
      </div>
      {feedback && (
        <div className="inline-notice" role="status">
          {feedback}
        </div>
      )}
      <div className="account-detail-highlights">
        <div><span>Enabled regions</span><strong>{row.regions.filter((item) => item.is_enabled).length}</strong><small>Configured for scans</small></div>
        <div><span>Last scan</span><strong>{relativeTime(row.last_scan_at)}</strong><small>{formatDate(row.last_scan_at)}</small></div>
        <div><span>Last validation</span><strong>{relativeTime(row.last_validated_at)}</strong><small>{formatDate(row.last_validated_at)}</small></div>
        <div><span>Environment</span><strong>{row.environment || "Unspecified"}</strong><small>Organization account scope</small></div>
      </div>
      <nav className="account-detail-tabs" aria-label="Account details">
        {tabs
          .filter(
            (item) =>
              !item.permission || user?.permissions.includes(item.permission),
          )
          .map((item) => (
            <button
              className={tab === item.id ? "active" : ""}
              key={item.id}
              onClick={() => setTab(item.id)}
            >
              {item.label}
            </button>
          ))}
      </nav>
      {tab === "overview" && (
        <div className="account-detail-grid">
          <section className="panel">
            <h2>Account information</h2>
            <dl className="account-facts-list">
              <Fact label="Account name" value={row.name} />
              <Fact label="Provider" value="AWS" />
              <Fact label="Account ID" value={row.account_id} />
              <Fact
                label="Primary region"
                value={row.primary_region || "Unspecified"}
              />
              <Fact
                label="Environment"
                value={row.environment || "Unspecified"}
              />
              <Fact
                label="Connection"
                value={
                  statusLabels[row.connection_status] ?? row.connection_status
                }
              />
              <Fact label="Created" value={formatDate(row.created_at)} />
              <Fact
                label="Last validated"
                value={formatDate(row.last_validated_at)}
              />
              <Fact label="Last scan" value={formatDate(row.last_scan_at)} />
            </dl>
          </section>
          <section className="panel">
            <h2>Configured regions</h2>
            <div className="region-compact-list">
              {row.regions
                .filter((item) => item.is_enabled)
                .map((item) => (
                  <span className="status-pill" key={item.region_code}>
                    {item.region_code}
                  </span>
                ))}
            </div>
            <button className="text-button" onClick={() => setTab("regions")}>
              View region inventory →
            </button>
          </section>
        </div>
      )}
      {tab === "connection" && (
        <section className="panel account-tab-panel">
          <h2>Connection</h2>
          <dl className="account-facts-list">
            <Fact
              label="Connection status"
              value={
                statusLabels[row.connection_status] ?? row.connection_status
              }
            />
            <Fact label="Authentication method" value="AWS STS AssumeRole" />
            <Fact label="Role ARN" value={row.role_arn || "Not configured"} />
            <Fact label="External ID" value="Hidden after one-time setup" />
            <Fact
              label="Last validation"
              value={formatDate(row.last_validated_at)}
            />
            <Fact
              label="Validation result code"
              value={
                row.last_error_code ||
                (row.connection_status === "connected"
                  ? "Passed"
                  : "Not validated")
              }
            />
          </dl>
          <div className="assume-role-diagram">
            <span>CloudSentinel</span>
            <b>→ STS AssumeRole →</b>
            <span>Configured IAM role</span>
          </div>
          {user?.permissions.includes("cloud_accounts:update") && row.role_arn && (
            <button
              className="primary-button"
              onClick={() => validate.mutate()}
              disabled={validate.isPending}
            >
              Validate connection
            </button>
          )}
        </section>
      )}
      {tab === "regions" && (
        <section className="panel table-panel account-tab-panel account-regions-panel">
          <div className="panel-heading">
            <div>
              <h2>AWS Regions</h2>
              <p>
                Enabled regions are included in account scans. Asset counts reflect the current normalized inventory.
              </p>
            </div>
          </div>
          {regions.isLoading ? (
            <div className="state-panel">Loading region inventory…</div>
          ) : regions.error ? (
            <div className="state-panel error-state">
              Region data could not be loaded.
            </div>
          ) : (
            <>
            <div className="region-inventory-summary">
              <div><span>Configured regions</span><strong>{regions.data?.length ?? 0}</strong></div>
              <div><span>Enabled</span><strong>{regions.data?.filter((item) => item.is_enabled).length ?? 0}</strong></div>
              <div><span>Discovered assets</span><strong>{(regions.data ?? []).reduce((total, item) => total + item.asset_count, 0).toLocaleString()}</strong></div>
            </div>
            <div className="table-scroll">
              <DataTable caption="Cloud account regions" className="region-inventory-table">
                <thead>
                  <tr>
                    <th scope="col">Region</th>
                    <th scope="col">Status</th>
                    <th scope="col">Discovered assets</th>
                  </tr>
                </thead>
                <tbody>
                  {regions.data?.map((item) => (
                    <tr key={item.region_code}>
                      <td><span className="region-code-mark" aria-hidden="true">AWS</span><code>{item.region_code}</code></td>
                      <td><span className={`region-state-pill ${item.is_enabled ? "enabled" : "disabled"}`}><i />{item.is_enabled ? "Enabled" : "Disabled"}</span></td>
                      <td><strong className="region-asset-count">{item.asset_count.toLocaleString()}</strong><span className="region-asset-caption"> assets</span></td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
            </>
          )}
        </section>
      )}
      {tab === "security" && (
        <section className="panel account-tab-panel">
          <h2>Account security</h2>
          <div className="account-security-list">
            <SecurityState
              label="IAM role configured"
              state={row.role_arn ? "configured" : "not-assessed"}
              detail="Role ARN is registered for cross-account access."
            />
            <SecurityState
              label="STS connection validation"
              state={
                row.connection_status === "connected"
                  ? "passed"
                  : row.connection_status === "error"
                    ? "failed"
                    : "not-assessed"
              }
              detail={
                row.last_validated_at
                  ? `Last checked ${formatDate(row.last_validated_at)}`
                  : "Run connection validation to check role trust and AWS identity."
              }
            />
            <SecurityState
              label="Least privilege policy"
              state="not-assessed"
              detail="The configured role policy is not inspected by the account validation endpoint."
            />
            <SecurityState
              label="CloudTrail, public access, encryption, GuardDuty"
              state="not-assessed"
              detail="Security assessment data is not available in this account view."
            />
          </div>
        </section>
      )}
      {tab === "scans" && (
        <section className="panel table-panel account-tab-panel">
          <div className="panel-heading">
            <div>
              <h2>Scan history</h2>
              <p>Recorded scan jobs and their requested regions.</p>
            </div>
          </div>
          {scans.isLoading ? (
            <div className="state-panel">Loading scan history…</div>
          ) : scans.error ? (
            <div className="state-panel error-state">
              Scan history could not be loaded.
            </div>
          ) : accountScans.length ? (
            <div className="table-scroll">
              <DataTable caption="Cloud account scan history">
                <thead>
                  <tr>
                    <th scope="col">Requested</th>
                    <th scope="col">Status</th>
                    <th scope="col">Regions</th>
                    <th scope="col">Progress</th>
                  </tr>
                </thead>
                <tbody>
                  {accountScans.map((item) => (
                    <tr key={item.id}>
                      <td>{formatDate(item.created_at)}</td>
                      <td><Link to={`/scans/${item.id}`}>{item.status}</Link></td>
                      <td>{item.requested_regions.join(", ")}</td>
                      <td>{item.progress_percent}%</td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
          ) : (
            <div className="empty-inline">
              No scan history for this account.
            </div>
          )}
        </section>
      )}
      {tab === "activity" && (
        <section className="panel account-tab-panel">
          <h2>Recent account activity</h2>
          {activity.isLoading ? (
            <div className="state-panel">Loading activity…</div>
          ) : activity.error ? (
            <div className="state-panel error-state">
              Activity could not be loaded.
            </div>
          ) : activity.data?.items.length ? (
            <div className="activity-list">
              {activity.data.items.map((item) => (
                <div key={item.id}>
                  <span className="activity-dot" />
                  <div>
                    <strong>{item.action.replaceAll(".", " ")}</strong>
                    <small>
                      {formatDate(item.created_at)} ·{" "}
                      {item.actor_user_id
                        ? `User ${item.actor_user_id.slice(0, 8)}`
                        : "System"}
                    </small>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-inline">
              No account activity is recorded yet.
            </div>
          )}
        </section>
      )}
      {tab === "findings" && (
        <section className="panel table-panel account-tab-panel">
          <div className="panel-heading">
            <div>
              <h2>Account findings</h2>
              <p>Findings are shown from the active organization scope.</p>
            </div>
          </div>
          {findings.isLoading ? (
            <div className="state-panel">Loading findings…</div>
          ) : findings.error ? (
            <div className="state-panel error-state">
              Findings could not be loaded.
            </div>
          ) : findings.data?.items.length ? (
            <div className="table-scroll">
              <DataTable caption="Cloud account findings">
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Finding</th>
                    <th scope="col">Region</th>
                    <th scope="col">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.data.items.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <span
                          className={`severity severity-${item.severity.toLowerCase()}`}
                        >
                          {item.severity}
                        </span>
                      </td>
                      <td>
                        <Link
                          className="row-primary"
                          to={`/findings/${item.id}`}
                        >
                          {item.title}
                        </Link>
                        <small>{item.rule_id}</small>
                      </td>
                      <td>{item.region_code}</td>
                      <td>{item.status.replaceAll("_", " ")}</td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
          ) : (
            <div className="empty-inline">No findings for this account.</div>
          )}
        </section>
      )}
      {editOpen && <EditAccountDialog account={row} onClose={() => setEditOpen(false)} onSaved={() => { setEditOpen(false); void client.invalidateQueries({ queryKey: ["account", accountId] }); void client.invalidateQueries({ queryKey: ["accounts"] }); }} />}
      {disableOpen && <ConfirmDialog title="Disable AWS account?" message={`${row.name} will be blocked from new scans. Existing scan and asset records will remain available.`} busy={disable.isPending} confirmLabel="Disable account" onCancel={() => setDisableOpen(false)} onConfirm={() => disable.mutate()} />}
      {removeOpen && <ConfirmDialog title="Remove AWS account?" message="This deletes the account connection metadata and configured regions. Existing scan or asset history may prevent removal." busy={remove.isPending} confirmLabel="Remove account" exactConfirmation={row.name} onCancel={() => setRemoveOpen(false)} onConfirm={() => remove.mutate()} />}
    </>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function SecurityState({
  label,
  state,
  detail,
}: {
  label: string;
  state: string;
  detail: string;
}) {
  const icon =
    state === "passed" || state === "configured"
      ? "✓"
      : state === "failed"
        ? "!"
        : "—";
  return (
    <div className={`security-state security-state-${state}`}>
      <span>{icon}</span>
      <div>
        <strong>{label}</strong>
        <small>{detail}</small>
      </div>
      <b>{state.replaceAll("-", " ")}</b>
    </div>
  );
}
