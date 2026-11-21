import { FilterField } from "../shared/FilterField";
import { ViewAction } from "../shared/ViewAction";
import { DataTable } from "../shared/DataTable";
import { FilterFooter } from "../shared/FilterFooter";
import { useLayoutEffect, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { createPortal } from "react-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, NavLink, useParams } from "react-router-dom";
import { api, type OrganizationRetentionSettings, type OrganizationSecuritySettings, type Page, type SamlIdentitySettings } from "../shared/api";
import { useAuth } from "../shared/useAuth";
import { KpiIcon } from "../shared/kpi";
import { kpiTone } from "../shared/kpi-utils";
import { DrawerFact, RightDrawer } from "../shared/RightDrawer";
import {
  formatOrganizationDateTime,
  organizationDateToUtcIso,
} from "../shared/date-time";
import { Pagination } from "../shared/Pagination";

type Organization = {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
  description: string | null;
  default_environment: string | null;
  default_region: string | null;
  timezone: string;
  date_time_format: string;
  created_at: string;
  updated_at: string;
};
type OrganizationSummary = {
  total_users: number;
  active_users: number;
  locked_users: number;
  pending_invitations: number;
  teams: number;
  cloud_accounts: number;
};
type UserRow = {
  user_id: string;
  email: string;
  display_name: string;
  role_code: string;
  is_active: boolean;
  is_locked: boolean;
  force_password_change: boolean;
  created_at: string;
  last_login_at: string | null;
  team_names: string[];
};
type UserDetail = UserRow & {
  organization_id: string;
  organization_name: string;
  permissions: string[];
  active_sessions: number;
  updated_at: string;
};
type UserSummary = {
  total: number;
  active: number;
  disabled: number;
  locked: number;
  pending: number;
};
type Role = { code: string; description: string; permissions: string[] };
type Team = {
  id: string;
  name: string;
  description: string | null;
  member_count: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
};
type TeamMember = {
  user_id: string;
  display_name: string;
  email: string;
  role_code: string;
  is_active: boolean;
  is_locked: boolean;
};
type TeamSummary = {
  total: number;
  active: number;
  archived: number;
  members: number;
};
type SessionRow = {
  id: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string;
  revoked_at: string | null;
  ip_address: string | null;
  user_agent: string | null;
  current: boolean;
};
type Activity = {
  id: string;
  actor_user_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  details: Record<string, unknown>;
  created_at: string;
};

const rolesFallback: Role[] = [];

function useApiQuery<T>(key: string[], path: string, enabled = true) {
  return useQuery({ queryKey: key, queryFn: () => api.get<T>(path), enabled });
}

function AdminNav() {
  const { user } = useAuth();
  const links = [
    {
      to: "/administration/organization",
      label: "Organization",
      permission: "organizations:read",
    },
    { to: "/administration/users", label: "Users", permission: "users:read" },
    { to: "/administration/teams", label: "Teams", permission: "teams:read" },
    { to: "/administration/settings", label: "Settings", permission: "organizations:read" },
  ].filter((link) => user?.permissions.includes(link.permission));
  return (
    <nav className="account-detail-tabs" aria-label="Administration sections">
      {links.map((link) => (
        <NavLink key={link.to} to={link.to}>
          {link.label}
        </NavLink>
      ))}
    </nav>
  );
}

function Heading({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading admin-page-heading">
      <div>
        <span className="eyebrow">ADMINISTRATION</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}

function SummaryCards({ items }: { items: Array<[string, number | string]> }) {
  return (
    <div className="account-summary-grid">
      {items.map(([label, value]) => (
        <div className={`account-summary-card summary-${kpiTone(label)}`} key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
          <KpiIcon label={label} />
        </div>
      ))}
    </div>
  );
}

function OrganizationValue({ label, value, mono = false, title }: { label: string; value: string; mono?: boolean; title?: string }) {
  return (
    <div className={`organization-value ${value === "Not configured" ? "organization-value-empty" : ""}`}>
      <span>{label}</span>
      <strong className={mono ? "organization-value-mono" : undefined} title={title}>{value}</strong>
    </div>
  );
}

function PermissionGroups({ permissions }: { permissions: string[] }) {
  const groups = permissions.reduce<Record<string, string[]>>((result, permission) => {
    const category = permission.split(":", 1)[0] || "other";
    (result[category] ??= []).push(permission);
    return result;
  }, {});
  const labels: Record<string, string> = {
    alerts: "Alerts", assets: "Assets", audit: "Audit", cloud_accounts: "Cloud accounts",
    findings: "Findings", organizations: "Organization", policies: "Policies",
    remediation: "Remediation", reports: "Reports", scans: "Scans",
    security_settings: "Security settings", teams: "Teams", users: "Users",
  };
  if (!permissions.length) return <p className="muted-note">No permissions are assigned.</p>;
  return (
    <div className="permission-groups">
      <div className="permission-groups-summary"><strong>{permissions.length}</strong><span>effective permissions</span><small>{Object.keys(groups).length} categories</small></div>
      {Object.entries(groups).sort(([a], [b]) => a.localeCompare(b)).map(([category, items]) => (
        <details className="permission-group" key={category}>
          <summary><span>{labels[category] ?? category.replaceAll("_", " ")}</span><small>{items.length}</small></summary>
          <div className="permission-group-items">{items.sort().map((permission) => <code key={permission}>{permission}</code>)}</div>
        </details>
      ))}
    </div>
  );
}

function QueryState({
  loading,
  error,
  empty,
  children,
}: {
  loading: boolean;
  error: Error | null;
  empty?: boolean;
  children: ReactNode;
}) {
  if (loading) return <div className="panel empty-state">Loading…</div>;
  if (error)
    return (
      <div className="panel error-state" role="alert">
        {error.message}
      </div>
    );
  if (empty) return <div className="panel empty-state">No records found.</div>;
  return <>{children}</>;
}

function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  return formatOrganizationDateTime(value);
}

function statusLabel(user: UserRow): string {
  if (!user.is_active) return "Disabled";
  if (user.is_locked) return "Locked";
  return "Active";
}

function AdminActionsMenu({ label, heading, description, children }: { label: string; heading: string; description: string; children: ReactNode }) {
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
      const top = window.innerHeight - rect.bottom >= menuHeight + 12
        ? rect.bottom + 6
        : Math.max(8, rect.top - menuHeight - 6);
      setPosition({ top, left: Math.max(8, Math.min(rect.right - 286, window.innerWidth - 294)) });
    };
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
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
  return <>
    <button ref={trigger} type="button" className="account-actions-trigger" aria-label={label} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((value) => !value)}>⋮</button>
    {open && createPortal(<>
      <button type="button" className="account-actions-backdrop" aria-label="Close user actions" onClick={() => setOpen(false)} />
      <div ref={menu} className="account-actions-popover" role="menu" style={{ top: position.top, left: position.left }} onClick={() => setOpen(false)}>
        <div className="account-actions-heading">{heading}<small>{description}</small></div>
        {children}
      </div>
    </>, document.body)}
  </>;
}

export function OrganizationPage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const [editOpen, setEditOpen] = useState(false);
  const [organizationIdCopied, setOrganizationIdCopied] = useState(false);
  const organization = useApiQuery<Organization>(
    ["organization-profile"],
    "/organizations/current",
  );
  const summary = useApiQuery<OrganizationSummary>(
    ["organization-summary"],
    "/organizations/current/summary",
  );
  const update = useMutation({
    mutationFn: (body: Partial<Organization>) =>
      api.patch<Organization>("/organizations/current", body),
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ["organization-profile"] }),
        client.invalidateQueries({ queryKey: ["organization"] }),
      ]);
      setEditOpen(false);
    },
  });
  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    update.mutate({
      name: String(form.get("name")).trim(),
      description: String(form.get("description")).trim() || null,
      default_environment:
        String(form.get("default_environment")).trim() || null,
      default_region: String(form.get("default_region")).trim() || null,
      timezone: String(form.get("timezone")).trim(),
    });
  }
  return (
    <>
      <AdminNav />
      <Heading
        title="Organization"
        description="Manage your organization profile and tenant context."
        action={
          user?.permissions.includes("organizations:update") ? (
            <button
              className="primary-button"
              onClick={() => setEditOpen(true)}
            >
              Edit organization
            </button>
          ) : undefined
        }
      />
      <QueryState loading={organization.isLoading} error={organization.error}>
        {organization.data && (
          <>
            <section className="organization-admin-hero">
              <div className="organization-admin-mark" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path d="M4 20V7.5L12 4l8 3.5V20M2.5 20h19M8 9h1m6 0h1M8 12h1m6 0h1M10 20v-4h4v4" /></svg>
              </div>
              <div className="organization-admin-identity">
                <span className="eyebrow">ACTIVE WORKSPACE</span>
                <h2>{organization.data.name}</h2>
                <p>{organization.data.description || "Organization-wide security workspace and tenant context."}</p>
                <div className="organization-admin-meta">
                  <span><small>Workspace</small><strong>{organization.data.slug}</strong></span>
                  <span><small>Organization ID</small><strong>{organization.data.id}</strong></span>
                </div>
              </div>
              <span className={`organization-status ${organization.data.is_active ? "is-active" : "is-inactive"}`}>
                <i />{organization.data.is_active ? "Active" : "Inactive"}
              </span>
            </section>
            <SummaryCards
              items={[
                ["Total users", summary.data?.total_users ?? "—"],
                ["Active users", summary.data?.active_users ?? "—"],
                ["Teams", summary.data?.teams ?? "—"],
                ["Cloud accounts", summary.data?.cloud_accounts ?? "—"],
              ]}
            />
            <div className="organization-details-grid">
              <section className="panel organization-admin-panel">
                <div className="panel-heading">
                  <div><span className="eyebrow">PROFILE</span><h2>Organization information</h2></div>
                </div>
                <div className="organization-values-grid">
                  <OrganizationValue label="Organization name" value={organization.data.name} />
                  <OrganizationValue label="Workspace slug" value={organization.data.slug} mono />
                  <OrganizationValue label="Created" value={formatDate(organization.data.created_at)} />
                  <OrganizationValue label="Last updated" value={formatDate(organization.data.updated_at)} />
                  <div className="organization-value organization-value-wide"><span>Description</span><strong>{organization.data.description || "No description has been added."}</strong></div>
                </div>
                <div className="organization-id-copy"><OrganizationValue label="Organization ID" value={organization.data.id} mono title={organization.data.id} /><button className="small-button" onClick={async () => { try { await navigator.clipboard.writeText(organization.data!.id); setOrganizationIdCopied(true); window.setTimeout(() => setOrganizationIdCopied(false), 1800); } catch { setOrganizationIdCopied(false); } }}>{organizationIdCopied ? "Copied" : "Copy ID"}</button></div>
              </section>
              <section className="panel organization-admin-panel">
                <div className="panel-heading"><div><span className="eyebrow">WORKSPACE DEFAULTS</span><h2>Tenant configuration</h2></div></div>
                <div className="organization-values-grid organization-config-grid">
                  <OrganizationValue label="Default environment" value={organization.data.default_environment || "Not configured"} />
                  <OrganizationValue label="Default region" value={organization.data.default_region || "Not configured"} mono />
                  <OrganizationValue label="Timezone" value={organization.data.timezone} />
                  <OrganizationValue label="Security mode" value="Enterprise platform baseline" />
                </div>
              </section>
            </div>
            <section className="panel organization-access-panel">
              <div className="panel-heading"><div><span className="eyebrow">IDENTITY &amp; MEMBERSHIP</span><h2>Organization access</h2><p>Membership and invitations are managed by the organization identity service.</p></div></div>
              {summary.data && (
                <div className="organization-access-stats">
                  <div><span>Pending invitations</span><strong>{summary.data.pending_invitations}</strong></div>
                  <div><span>Locked memberships</span><strong>{summary.data.locked_users}</strong></div>
                </div>
              )}
            </section>
          </>
        )}
      </QueryState>
      {editOpen && organization.data && (
        <RightDrawer
          title="Edit organization"
          description="Update the active tenant profile. The workspace slug and organization ID are immutable."
          onClose={() => setEditOpen(false)}
        >
          <form className="drawer-form" onSubmit={save}>
            <label>
              Organization name
              <input
                name="name"
                required
                minLength={2}
                maxLength={200}
                defaultValue={organization.data.name}
              />
            </label>
            <label>
              Description
              <textarea
                name="description"
                maxLength={1000}
                defaultValue={organization.data.description ?? ""}
              />
            </label>
            <label>
              Default environment
              <input
                name="default_environment"
                maxLength={80}
                defaultValue={organization.data.default_environment ?? ""}
                placeholder="e.g. Production"
              />
            </label>
            <label>
              Default region
              <input
                name="default_region"
                maxLength={40}
                defaultValue={organization.data.default_region ?? ""}
                placeholder="e.g. us-east-1"
              />
            </label>
            <label>
              Timezone
              <input
                name="timezone"
                required
                maxLength={64}
                defaultValue={organization.data.timezone}
              />
            </label>
            <div className="drawer-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => setEditOpen(false)}
              >
                Cancel
              </button>
              <button className="primary-button" disabled={update.isPending}>
                {update.isPending ? "Saving…" : "Save changes"}
              </button>
            </div>
            {update.error && (
              <div className="error-state">{update.error.message}</div>
            )}
          </form>
        </RightDrawer>
      )}
    </>
  );
}

export function UsersPage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [role, setRole] = useState("");
  const [userId, setUserId] = useState("");
  const [state, setState] = useState("all");
  const [teamId, setTeamId] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<UserRow | null>(null);
  const [selectedAction, setSelectedAction] = useState<"view" | "access" | "status">("view");
  const [roleDraft, setRoleDraft] = useState("");
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteRole, setInviteRole] = useState("VIEWER");
  const [invitationLink, setInvitationLink] = useState("");
  const [feedback, setFeedback] = useState("");
  const [feedbackType, setFeedbackType] = useState<"success" | "warning" | "error">("success");
  const [linkCopied, setLinkCopied] = useState(false);
  const roles = useApiQuery<Role[]>(["organization-roles"], "/users/roles");
  const summary = useApiQuery<UserSummary>(["users-summary"], "/users/summary");
  const teams = useApiQuery<Page<Team>>(
    ["teams-list", "active"],
    "/teams?status=active&limit=100",
  );
  const userOptionsParams = new URLSearchParams({ status: "all", limit: "100" });
  if (role) userOptionsParams.set("role", role);
  const userOptions = useApiQuery<Page<UserRow>>(
    ["user-filter-options", role],
    `/users?${userOptionsParams}`,
  );
  const selectedRole = (roles.data ?? rolesFallback).find((item) => item.code === roleDraft);
  const selectedInviteRole = (roles.data ?? rolesFallback).find((item) => item.code === inviteRole);
  const query = useMemo(() => {
    const params = new URLSearchParams({
      offset: String(offset),
      limit: "25",
      status: state,
    });
    if (search.trim()) params.set("search", search.trim());
    if (role) params.set("role", role);
    if (userId) params.set("user_id", userId);
    if (teamId) params.set("team_id", teamId);
    const dateFromUtc = dateFrom ? organizationDateToUtcIso(dateFrom, "start") : null;
    const dateToUtc = dateTo ? organizationDateToUtcIso(dateTo, "end") : null;
    if (dateFromUtc) params.set("date_from", dateFromUtc);
    if (dateToUtc) params.set("date_to", dateToUtc);
    return params.toString();
  }, [dateFrom, dateTo, offset, role, search, state, teamId, userId]);
  const users = useApiQuery<Page<UserRow>>(
    ["organization-users", query],
    `/users?${query}`,
  );
  const selectedDetail = useApiQuery<UserDetail>(
    ["user-detail", selected?.user_id ?? ""],
    selected ? `/users/${selected.user_id}` : "/users/summary",
    Boolean(selected),
  );
  const [inviteBusy, setInviteBusy] = useState(false);
  async function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (inviteBusy) return;
    setInviteBusy(true);
    setInvitationLink("");
    setFeedback("");
    setLinkCopied(false);
    const form = new FormData(event.currentTarget);
    try {
      const result = await api.post<{
        email: string;
        invitation_url: string;
        email_delivery: "sent" | "failed";
      }>("/users/invitations", {
        email: String(form.get("email")).trim(),
        display_name: String(form.get("display_name")).trim(),
        role_code: String(form.get("role_code")),
      });
      setInvitationLink(result.invitation_url);
      setFeedback(
        result.email_delivery === "sent"
          ? `Invitation email sent to ${result.email}.`
          : `Invitation created but email delivery failed for ${result.email}. Copy and share the link securely.`,
      );
      setFeedbackType(result.email_delivery === "sent" ? "success" : "warning");
      setInviteOpen(false);
      await Promise.all([
        client.invalidateQueries({ queryKey: ["organization-users"] }),
        client.invalidateQueries({ queryKey: ["users-summary"] }),
      ]);
    } catch (error) {
      setInvitationLink("");
      setFeedbackType("error");
      setFeedback(
        error instanceof Error ? error.message : "Invitation failed.",
      );
    } finally {
      setInviteBusy(false);
    }
  }
  const changeRole = useMutation({
    mutationFn: () =>
      api.patch(`/users/${selected!.user_id}/role`, { role_code: roleDraft }),
    onSuccess: async () => {
      setSelected(null);
      await Promise.all([
        client.invalidateQueries({ queryKey: ["organization-users"] }),
        client.invalidateQueries({ queryKey: ["user-detail"] }),
      ]);
    },
  });
  const changeState = useMutation({
    mutationFn: (enabled: boolean) =>
      enabled
        ? api.post(`/users/${selected!.user_id}/enable`)
        : api.post(`/users/${selected!.user_id}/disable`),
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ["organization-users"] }),
        client.invalidateQueries({ queryKey: ["users-summary"] }),
      ]);
      setSelected(null);
    },
  });
  return (
    <>
      <AdminNav />
      <Heading
        title="Users"
        description="Manage organization invitations, memberships and roles."
        action={
          user?.permissions.includes("users:invite") ? (
            <button
              className="primary-button"
              onClick={() => {
                setInvitationLink("");
                setFeedback("");
                setLinkCopied(false);
                setInviteRole("VIEWER");
                setInviteOpen(true);
              }}
            >
              Invite user
            </button>
          ) : undefined
        }
      />
      <SummaryCards
        items={[
          ["Total users", summary.data?.total ?? "—"],
          ["Active", summary.data?.active ?? "—"],
          ["Disabled", summary.data?.disabled ?? "—"],
          ["Locked", summary.data?.locked ?? "—"],
        ]}
      />
      {feedback && (
        <section className={`user-invitation-result is-${feedbackType}`} role={feedbackType === "error" ? "alert" : "status"}>
          <span className="user-invitation-result-icon" aria-hidden="true">{feedbackType === "success" ? "✓" : feedbackType === "warning" ? "!" : "×"}</span>
          <div className="user-invitation-result-content">
            <strong>{feedbackType === "success" ? "Invitation sent" : feedbackType === "warning" ? "Invitation created" : "Invitation not sent"}</strong>
            <p>{feedback}</p>
          {invitationLink && (
            <div className="user-invitation-link-card">
              <div><span>Secure invitation link</span><code title={invitationLink}>{invitationLink}</code></div>
              <button className="secondary-button" onClick={() => void navigator.clipboard.writeText(invitationLink).then(() => setLinkCopied(true))}>
                {linkCopied ? "Copied" : "Copy link"}
              </button>
            </div>
          )}
          </div>
        </section>
      )}
      <section className="panel table-panel">
        <div className="scan-filter-toolbar admin-users-filter-toolbar">
        <div className="filter-row admin-users-filter-row">
          <FilterField label="Search" className="filter-field-search"><input
            aria-label="Search users"
            placeholder="Search name or email…"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setOffset(0);
            }}
          /></FilterField>
          <FilterField label="Team"><select
            aria-label="Filter by team"
            value={teamId}
            onChange={(event) => {
              setTeamId(event.target.value);
              setOffset(0);
            }}
          >
            <option value="">All teams</option>
            {(teams.data?.items ?? []).map((team) => (
              <option key={team.id} value={team.id}>
                {team.name}
              </option>
            ))}
          </select></FilterField>
          <FilterField label="Role"><select
            aria-label="Filter by role"
            value={role}
            onChange={(event) => {
              setRole(event.target.value);
              setUserId("");
              setOffset(0);
            }}
          >
            <option value="">All roles</option>
            {(roles.data ?? rolesFallback).map((item) => (
              <option key={item.code} value={item.code}>
                {item.code}
              </option>
            ))}
          </select></FilterField>
          <FilterField label="User"><select
            aria-label="Filter by user"
            value={userId}
            onChange={(event) => {
              setUserId(event.target.value);
              setOffset(0);
            }}
          >
            <option value="">All users</option>
            {(userOptions.data?.items ?? []).map((item) => (
              <option key={item.user_id} value={item.user_id}>
                {item.display_name} · {item.email}
              </option>
            ))}
          </select></FilterField>
          <FilterField label="Status"><select
            aria-label="Filter by status"
            value={state}
            onChange={(event) => {
              setState(event.target.value);
              setOffset(0);
            }}
          >
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
            <option value="locked">Locked</option>
          </select></FilterField>
          <label className="admin-user-date-filter">
            From
            <input type="date" value={dateFrom} max={dateTo || undefined} onChange={(event) => { setDateFrom(event.target.value); setOffset(0); }} />
          </label>
          <label className="admin-user-date-filter">
            To
            <input type="date" value={dateTo} min={dateFrom || undefined} onChange={(event) => { setDateTo(event.target.value); setOffset(0); }} />
          </label>
        </div>
        <FilterFooter className="scan-filter-footer" active={Boolean(search.trim() || teamId || role || userId || state !== "all" || dateFrom || dateTo)} onReset={() => {
            setSearch(""); setTeamId(""); setRole(""); setUserId("");
            setState("all"); setDateFrom(""); setDateTo(""); setOffset(0);
          }} />
        </div>
        <QueryState
          loading={users.isLoading}
          error={users.error}
          empty={!users.data?.items.length}
        >
          <div className="table-scroll">
            <DataTable caption="Organization users" actions>
              <thead>
                <tr>
                  <th scope="col">User</th>
                  <th scope="col">Role</th>
                  <th scope="col">Team</th>
                  <th scope="col">Status</th>
                  <th scope="col">Last login</th>
                  <th scope="col">Created</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.data?.items.map((row) => (
                  <tr key={row.user_id}>
                    <td>
                      <button
                        className="text-button row-primary"
                        onClick={() => {
                          setSelected(row);
                          setSelectedAction("view");
                          setRoleDraft(row.role_code);
                        }}
                      >
                        {row.display_name}
                      </button>
                      <small>{row.email}</small>
                    </td>
                    <td>{row.role_code.replaceAll("_", " ")}</td>
                    <td>{row.team_names.join(", ") || "—"}</td>
                    <td>
                      <span
                        className={`status-pill ${row.is_active ? "status-active" : ""}`}
                      >
                        {statusLabel(row)}
                      </span>
                    </td>
                    <td>{formatDate(row.last_login_at)}</td>
                    <td>{formatDate(row.created_at)}</td>
                    <td>
                      <div className="table-row-actions">
                      <ViewAction label={`View user ${row.display_name}`} onClick={() => { setSelected(row); setSelectedAction("view"); setRoleDraft(row.role_code); }} />
                      <AdminActionsMenu
                        label={`Actions for ${row.display_name}`}
                        heading="User actions"
                        description={`Manage ${row.display_name}'s organization access`}
                      >
                        <button role="menuitem" onClick={() => { setSelected(row); setSelectedAction("view"); setRoleDraft(row.role_code); }}>
                          <span className="account-action-icon" aria-hidden="true">↗</span>
                          <span className="account-action-copy"><strong>View user</strong><small>Review profile, membership and activity</small></span>
                        </button>
                        {user?.permissions.includes("users:update") && (
                          <button role="menuitem" onClick={() => { setSelected(row); setSelectedAction("access"); setRoleDraft(row.role_code); }}>
                            <span className="account-action-icon" aria-hidden="true">♙</span>
                            <span className="account-action-copy"><strong>Manage role &amp; access</strong><small>Review permissions and security settings</small></span>
                          </button>
                        )}
                        {user?.permissions.includes("users:disable") && row.user_id !== user.id && (
                          <button role="menuitem" onClick={() => { setSelected(row); setSelectedAction("status"); setRoleDraft(row.role_code); }}>
                            <span className="account-action-icon" aria-hidden="true">⚙</span>
                            <span className="account-action-copy"><strong>Manage account status</strong><small>Enable or disable this membership</small></span>
                          </button>
                        )}
                      </AdminActionsMenu>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </DataTable>
          </div>
          {users.data && <Pagination total={users.data.total} offset={offset} limit={25} onOffsetChange={setOffset} disabled={users.isFetching} label="User pages" />}
        </QueryState>
      </section>
      {selected && (
        <RightDrawer
          title={selectedAction === "view" ? "User profile" : selectedAction === "access" ? "Role & access" : "Account status"}
          description={`${selected.display_name} · ${selected.email}`}
          onClose={() => setSelected(null)}
        >
          {selectedAction === "view" && (
            <>
              {selectedDetail.isLoading ? <div className="empty-state">Loading user details…</div> : selectedDetail.error ? <div className="error-state" role="alert">{selectedDetail.error.message}</div> : <>
                <div className="drawer-section user-action-summary">
                  <span className={`status-pill ${selected.is_active ? "status-active" : ""}`}>{statusLabel(selected)}</span>
                  <h3>{selected.display_name}</h3><p>{selected.email}</p>
                </div>
                <div className="drawer-section">
                  <h3>Membership details</h3>
                  <div className="drawer-facts">
                    <DrawerFact label="Role" value={selected.role_code.replaceAll("_", " ")} />
                    <DrawerFact label="Teams" value={selected.team_names.join(", ") || "—"} />
                    <DrawerFact label="Last login" value={formatDate(selected.last_login_at)} />
                    <DrawerFact label="Joined" value={formatDate(selected.created_at)} />
                    <DrawerFact label="Active sessions" value={String(selectedDetail.data?.active_sessions ?? 0)} />
                    <DrawerFact label="Password change required" value={selected.force_password_change ? "Yes" : "No"} />
                  </div>
                </div>
                <div className="drawer-section">
                  <h3>Effective permissions</h3>
                  <PermissionGroups permissions={selectedDetail.data?.permissions ?? []} />
                </div>
              </>}
            </>
          )}
          {selectedAction === "access" && (
            <>
              <div className="user-action-callout"><span aria-hidden="true">♙</span><div><strong>Role and access controls</strong><p>Select a role to immediately preview its effective permissions before saving.</p></div></div>
              <label className="drawer-field">Organization role
                <select value={roleDraft} onChange={(event) => setRoleDraft(event.target.value)}>
                  {(roles.data ?? rolesFallback).map((item) => <option key={item.code} value={item.code}>{item.code.replaceAll("_", " ")}</option>)}
                </select>
              </label>
              <div className="drawer-section">
                <h3>Permissions for {roleDraft.replaceAll("_", " ") || "selected role"}</h3>
                {roles.isLoading ? <div className="empty-state">Loading role permissions…</div> : selectedRole ? <>
                  <p className="user-role-description">{selectedRole.description}</p>
                  <PermissionGroups permissions={selectedRole.permissions} />
                </> : <div className="empty-state">Role permissions are unavailable.</div>}
              </div>
              {roleDraft !== selected.role_code && <div className="user-role-change-note">Role change: <strong>{selected.role_code.replaceAll("_", " ")}</strong><span aria-hidden="true">→</span><strong>{roleDraft.replaceAll("_", " ")}</strong></div>}
              <div className="drawer-actions"><button className="secondary-button" onClick={() => { setRoleDraft(selected.role_code); setSelected(null); }}>Cancel</button><button className="primary-button" disabled={roleDraft === selected.role_code || changeRole.isPending} onClick={() => changeRole.mutate()}>{changeRole.isPending ? "Saving…" : "Save role changes"}</button></div>
              {changeRole.error && <div className="error-state" role="alert">{changeRole.error.message}</div>}
            </>
          )}
          {selectedAction === "status" && (
            <>
              <div className={`user-status-card ${selected.is_active ? "is-enabled" : "is-disabled"}`}>
                <span className="user-status-card-icon" aria-hidden="true">{selected.is_active ? "✓" : "Ⅱ"}</span>
                <div><small>Current membership status</small><strong>{statusLabel(selected)}</strong><p>{selected.is_locked ? "This account is locked. Membership enablement is managed separately below." : selected.is_active ? "This user can access the organization workspace." : "This user currently cannot access the organization workspace."}</p></div>
              </div>
              <div className="drawer-section user-status-impact"><h3>{selected.is_active ? "What happens when disabled" : "Restore organization access"}</h3><p>{selected.is_active ? "The user will lose access to this organization and their active sessions will be revoked. Their account and audit history remain intact." : "The user will be able to sign in to this organization again using their existing account."}</p></div>
              <div className="drawer-actions"><button className="secondary-button" onClick={() => setSelected(null)}>Cancel</button><button className={selected.is_active ? "danger-button" : "primary-button"} disabled={changeState.isPending} onClick={() => changeState.mutate(!selected.is_active)}>{changeState.isPending ? "Updating…" : selected.is_active ? "Disable membership" : "Enable membership"}</button></div>
              {changeState.error && <div className="error-state" role="alert">{changeState.error.message}</div>}
            </>
          )}
        </RightDrawer>
      )}
      {inviteOpen && (
        <RightDrawer
          className="invite-user-drawer"
          title="Invite user"
          description="Add a teammate to your organization workspace."
          onClose={() => setInviteOpen(false)}
        >
          <form className="drawer-form invite-user-form" onSubmit={invite}>
            <div className="invite-user-section-heading">
              <span>INVITATION DETAILS</span>
              <p>Enter the teammate’s identity and choose their organization access.</p>
            </div>
            <label>
              Full name
              <input name="display_name" autoComplete="name" placeholder="e.g. Alex Morgan" required minLength={2} maxLength={200} />
            </label>
            <label>
              Work email
              <input name="email" type="email" autoComplete="email" placeholder="alex@company.com" required maxLength={320} />
              <small className="invite-field-hint">The invitation will be sent to this address.</small>
            </label>
            <label>
              Organization role
              <select name="role_code" required value={inviteRole} onChange={(event) => setInviteRole(event.target.value)}>
                {(roles.data ?? []).map((item) => (
                  <option key={item.code} value={item.code}>{item.code.replaceAll("_", " ")}</option>
                ))}
              </select>
            </label>
            {selectedInviteRole && (
              <div className="invite-role-preview">
                <span className="invite-role-icon" aria-hidden="true">♙</span>
                <div>
                  <strong>{selectedInviteRole.code.replaceAll("_", " ")}</strong>
                  <p>{selectedInviteRole.description}</p>
                  <small>{selectedInviteRole.permissions.length} permissions included</small>
                </div>
              </div>
            )}
            <div className="invite-expiry-note">
              <span aria-hidden="true">◷</span>
              <p><strong>Invitation link expires in 72 hours.</strong><br />Reissuing an invitation invalidates its previous link.</p>
            </div>
            {feedbackType === "error" && feedback && <p className="error-state invite-form-error" role="alert">{feedback}</p>}
            <div className="drawer-actions invite-user-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => setInviteOpen(false)}
              >
                Cancel
              </button>
              <button className="primary-button" disabled={inviteBusy}>
                {inviteBusy ? "Sending…" : "Send invitation"}
              </button>
            </div>
          </form>
        </RightDrawer>
      )}
    </>
  );
}

type UserTab = "overview" | "access" | "sessions" | "activity" | "cloud-access";
export function UserDetailsPage() {
  const { user_id: userId = "" } = useParams();
  const { user: actor } = useAuth();
  const client = useQueryClient();
  const [tab, setTab] = useState<UserTab>("overview");
  const [action, setAction] = useState<
    | "edit"
    | "role"
    | "disable"
    | "enable"
    | "lock"
    | "unlock"
    | "reset"
    | "force-password"
    | "revoke-sessions"
    | null
  >(null);
  const [sessionToRevoke, setSessionToRevoke] = useState<SessionRow | null>(
    null,
  );
  const detail = useApiQuery<UserDetail>(
    ["user-detail", userId],
    `/users/${userId}`,
    Boolean(userId),
  );
  const roles = useApiQuery<Role[]>(["organization-roles"], "/users/roles");
  const sessions = useApiQuery<Page<SessionRow>>(
    ["user-sessions", userId],
    `/users/${userId}/sessions?limit=100`,
    tab === "sessions",
  );
  const activity = useApiQuery<Page<Activity>>(
    ["user-activity", userId],
    `/users/${userId}/activity?limit=50`,
    tab === "activity" && Boolean(actor?.permissions.includes("audit:read")),
  );
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState("");
  async function mutate(
    path: string,
    method: "POST" | "PATCH" | "DELETE",
    body?: object,
  ) {
    setBusy(true);
    setFeedback("");
    try {
      if (method === "POST") await api.post(path, body);
      else if (method === "PATCH") await api.patch(path, body);
      else await api.delete(path);
      await Promise.all([
        client.invalidateQueries({ queryKey: ["user-detail", userId] }),
        client.invalidateQueries({ queryKey: ["organization-users"] }),
        client.invalidateQueries({ queryKey: ["users-summary"] }),
        client.invalidateQueries({ queryKey: ["user-sessions", userId] }),
      ]);
      setFeedback("User record updated.");
      setAction(null);
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Action failed.");
    } finally {
      setBusy(false);
    }
  }
  async function saveUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await mutate(`/users/${userId}`, "PATCH", {
      display_name: String(form.get("display_name")).trim(),
    });
  }
  async function saveRole(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await mutate(`/users/${userId}/role`, "PATCH", {
      role_code: String(form.get("role_code")),
    });
  }
  async function requestReset() {
    try {
      await api.post(`/users/${userId}/password-reset`);
      setFeedback("Password reset email requested.");
    } catch (error) {
      setFeedback(
        error instanceof Error
          ? error.message
          : "Reset email could not be requested.",
      );
    }
  }
  if (detail.isLoading)
    return <div className="panel empty-state">Loading user…</div>;
  if (detail.error || !detail.data)
    return (
      <div className="panel error-state">
        {detail.error?.message ?? "User not found."}
      </div>
    );
  const member = detail.data;
  const canUpdate = Boolean(actor?.permissions.includes("users:update"));
  return (
    <>
      <AdminNav />
      <div className="breadcrumbs">
        <Link to="/administration/users">Users</Link>
        <span>/</span>
        <span>{member.display_name}</span>
      </div>
      <div className="finding-summary panel">
        <div>
          <span className="eyebrow">ORGANIZATION USER</span>
          <h1>{member.display_name}</h1>
          <p>
            {member.email} · {member.role_code.replaceAll("_", " ")}
          </p>
        </div>
        <span
          className={`status-pill ${member.is_active ? "status-active" : ""}`}
        >
          {statusLabel(member)}
        </span>
        <div className="drawer-actions">
          {canUpdate && (
            <>
              <button
                className="secondary-button"
                onClick={() => setAction("edit")}
              >
                Edit
              </button>
              <button
                className="secondary-button"
                onClick={() => setAction("role")}
              >
                Change role
              </button>
              {userId !== actor?.id &&
                (member.is_active ? (
                  <button
                    className="secondary-button"
                    onClick={() => setAction("disable")}
                  >
                    Disable
                  </button>
                ) : (
                  <button
                    className="secondary-button"
                    onClick={() => setAction("enable")}
                  >
                    Enable
                  </button>
                ))}
            </>
          )}
        </div>
      </div>
      {feedback && (
        <div className="inline-feedback" role="status">
          {feedback}
        </div>
      )}
      <SummaryCards
        items={[
          ["Account", statusLabel(member)],
          ["Active sessions", member.active_sessions],
          ["Last login", formatDate(member.last_login_at)],
          ["Created", formatDate(member.created_at)],
        ]}
      />
      <nav className="account-detail-tabs" aria-label="User details">
        <button
          className={tab === "overview" ? "active" : ""}
          onClick={() => setTab("overview")}
        >
          Overview
        </button>
        <button
          className={tab === "access" ? "active" : ""}
          onClick={() => setTab("access")}
        >
          Access
        </button>
        <button
          className={tab === "sessions" ? "active" : ""}
          onClick={() => setTab("sessions")}
        >
          Sessions
        </button>
        {actor?.permissions.includes("audit:read") && (
          <button
            className={tab === "activity" ? "active" : ""}
            onClick={() => setTab("activity")}
          >
            Activity
          </button>
        )}
        <button
          className={tab === "cloud-access" ? "active" : ""}
          onClick={() => setTab("cloud-access")}
        >
          Cloud Access
        </button>
      </nav>
      {tab === "overview" && (
        <section className="panel">
          <h2>Account information</h2>
          <div className="drawer-facts">
            <DrawerFact label="Full name" value={member.display_name} />
            <DrawerFact label="Email" value={member.email} />
            <DrawerFact label="Status" value={statusLabel(member)} />
            <DrawerFact label="Role" value={member.role_code} />
            <DrawerFact
              label="Teams"
              value={member.team_names.join(", ") || "—"}
            />
            <DrawerFact label="Organization" value={member.organization_name} />
            <DrawerFact label="Created" value={formatDate(member.created_at)} />
            <DrawerFact label="Updated" value={formatDate(member.updated_at)} />
            <DrawerFact
              label="Last login"
              value={formatDate(member.last_login_at)}
            />
          </div>
        </section>
      )}
      {tab === "access" && (
        <section className="panel">
          <h2>Effective access</h2>
          <div className="drawer-facts">
            <DrawerFact label="Role" value={member.role_code} />
            <DrawerFact label="Organization" value={member.organization_name} />
            <DrawerFact
              label="Password change required"
              value={member.force_password_change ? "Yes" : "No"}
            />
          </div>
          <PermissionGroups permissions={member.permissions} />
          <div className="drawer-actions">
            {canUpdate && (
              <>
                <button
                  className="secondary-button"
                  disabled={busy || member.force_password_change}
                  onClick={() => setAction("force-password")}
                >
                  Require password change
                </button>
                <button
                  className="secondary-button"
                  disabled={busy}
                  onClick={() => setAction("reset")}
                >
                  Send password reset link
                </button>
                {member.is_locked ? (
                  <button
                    className="secondary-button"
                    disabled={busy}
                    onClick={() => setAction("unlock")}
                  >
                    Unlock account
                  </button>
                ) : (
                  <button
                    className="secondary-button"
                    disabled={busy || userId === actor?.id}
                    onClick={() => setAction("lock")}
                  >
                    Lock account
                  </button>
                )}
              </>
            )}
          </div>
        </section>
      )}
      {tab === "sessions" && (
        <section className="panel table-panel">
          <div className="panel-heading">
            <h2>Authentication sessions</h2>
            {canUpdate && (
              <button
                className="secondary-button"
                disabled={busy || member.active_sessions === 0}
                onClick={() => setAction("revoke-sessions")}
              >
                Revoke other sessions
              </button>
            )}
          </div>
          <QueryState
            loading={sessions.isLoading}
            error={sessions.error}
            empty={!sessions.data?.items.length}
          >
            <div className="table-scroll">
              <DataTable caption="User sessions" actions>
                <thead>
                  <tr>
                    <th scope="col">Session</th>
                    <th scope="col">IP</th>
                    <th scope="col">User agent</th>
                    <th scope="col">Created</th>
                    <th scope="col">Last active</th>
                    <th scope="col">Expires</th>
                    <th scope="col">State</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.data?.items.map((row) => (
                    <tr key={row.id}>
                      <td>
                        {row.id.slice(0, 12)}
                        {row.current && <small>Current session</small>}
                      </td>
                      <td>{row.ip_address ?? "Not recorded"}</td>
                      <td>{row.user_agent ?? "Not recorded"}</td>
                      <td>{formatDate(row.created_at)}</td>
                      <td>{formatDate(row.last_used_at)}</td>
                      <td>{formatDate(row.expires_at)}</td>
                      <td>
                        {row.revoked_at
                          ? "Revoked"
                          : new Date(row.expires_at) < new Date()
                            ? "Expired"
                            : "Active"}
                      </td>
                      <td>
                        {canUpdate && !row.revoked_at && !row.current && (
                          <button
                            className="small-button danger-button"
                            disabled={busy}
                            onClick={() => setSessionToRevoke(row)}
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
          </QueryState>
        </section>
      )}
      {tab === "activity" && (
        <section className="panel table-panel">
          <h2>User activity</h2>
          <QueryState
            loading={activity.isLoading}
            error={activity.error}
            empty={!activity.data?.items.length}
          >
            <div className="table-scroll">
              <DataTable caption="User activity">
                <thead>
                  <tr>
                    <th scope="col">Timestamp</th>
                    <th scope="col">Actor</th>
                    <th scope="col">Action</th>
                    <th scope="col">Resource</th>
                    <th scope="col">Result</th>
                  </tr>
                </thead>
                <tbody>
                  {activity.data?.items.map((row) => (
                    <tr key={row.id}>
                      <td>{formatDate(row.created_at)}</td>
                      <td>
                        {row.actor_user_id === userId
                          ? "User"
                          : (row.actor_user_id ?? "System")}
                      </td>
                      <td>{row.action}</td>
                      <td>
                        {row.resource_type} {row.resource_id ?? ""}
                      </td>
                      <td>Recorded</td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
          </QueryState>
        </section>
      )}
      {tab === "cloud-access" && (
        <section className="panel empty-state">
          <h2>Cloud access</h2>
          <p>
            Cloud account assignments are managed in the Cloud Accounts workflow
            and are not assigned to users in this order.
          </p>
        </section>
      )}
      {action === "edit" && (
        <RightDrawer
          title="Edit user"
          description="Update organization-visible user details."
          onClose={() => setAction(null)}
        >
          <form className="drawer-form" onSubmit={saveUser}>
            <label>
              Full name
              <input
                name="display_name"
                required
                minLength={2}
                maxLength={200}
                defaultValue={member.display_name}
              />
            </label>
            <label>
              Email
              <input value={member.email} disabled readOnly />
            </label>
            <div className="drawer-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => setAction(null)}
              >
                Cancel
              </button>
              <button className="primary-button" disabled={busy}>
                Save changes
              </button>
            </div>
          </form>
        </RightDrawer>
      )}
      {action === "role" && (
        <RightDrawer
          title="Change role"
          description="Role changes affect effective permissions."
          onClose={() => setAction(null)}
        >
          <form className="drawer-form" onSubmit={saveRole}>
            <DrawerFact label="Current role" value={member.role_code} />
            <label>
              New role
              <select name="role_code" defaultValue={member.role_code}>
                {(roles.data ?? []).map((item) => (
                  <option key={item.code} value={item.code}>
                    {item.code}
                  </option>
                ))}
              </select>
            </label>
            <div className="drawer-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => setAction(null)}
              >
                Cancel
              </button>
              <button className="primary-button" disabled={busy}>
                Change role
              </button>
            </div>
          </form>
        </RightDrawer>
      )}
      {action === "disable" && (
        <RightDrawer
          title="Disable user"
          description="This removes the user's access to this organization and revokes its active sessions."
          onClose={() => setAction(null)}
        >
          <p>Disable access for {member.display_name}?</p>
          <div className="drawer-actions">
            <button
              className="secondary-button"
              onClick={() => setAction(null)}
            >
              Cancel
            </button>
            <button
              className="danger-button"
              disabled={busy}
              onClick={() => void mutate(`/users/${userId}/disable`, "POST")}
            >
              Disable user
            </button>
          </div>
        </RightDrawer>
      )}
      {action === "enable" && (
        <RightDrawer
          title="Enable user"
          description="Restore this user's membership access to the current organization."
          onClose={() => setAction(null)}
        >
          <p>Enable access for {member.display_name}?</p>
          <div className="drawer-actions">
            <button
              className="secondary-button"
              onClick={() => setAction(null)}
            >
              Cancel
            </button>
            <button
              className="primary-button"
              disabled={busy}
              onClick={() => void mutate(`/users/${userId}/enable`, "POST")}
            >
              Enable user
            </button>
          </div>
        </RightDrawer>
      )}
      {action === "lock" && (
        <RightDrawer
          title="Lock user"
          description="Lock this user's membership in the current organization and end its active sessions."
          onClose={() => setAction(null)}
        >
          <form
            className="drawer-form"
            onSubmit={(event) => {
              event.preventDefault();
              const reason = String(
                new FormData(event.currentTarget).get("reason") ?? "",
              );
              void mutate(`/users/${userId}/lock`, "POST", {
                reason: reason || null,
              });
            }}
          >
            <label>
              Reason
              <textarea name="reason" maxLength={500} />
            </label>
            <div className="drawer-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => setAction(null)}
              >
                Cancel
              </button>
              <button className="danger-button" disabled={busy}>
                Lock user
              </button>
            </div>
          </form>
        </RightDrawer>
      )}
      {action === "unlock" && (
        <RightDrawer
          title="Unlock user"
          description="Restore sign-in eligibility for this organization's membership."
          onClose={() => setAction(null)}
        >
          <p>Unlock {member.display_name}?</p>
          <div className="drawer-actions">
            <button
              className="secondary-button"
              onClick={() => setAction(null)}
            >
              Cancel
            </button>
            <button
              className="primary-button"
              disabled={busy}
              onClick={() => void mutate(`/users/${userId}/unlock`, "POST")}
            >
              Unlock user
            </button>
          </div>
        </RightDrawer>
      )}
      {action === "reset" && (
        <RightDrawer
          title="Send password reset link"
          description="A one-time reset link will be emailed to the user's registered address."
          onClose={() => setAction(null)}
        >
          <p>Send a password reset link to {member.email}?</p>
          <div className="drawer-actions">
            <button
              className="secondary-button"
              onClick={() => setAction(null)}
            >
              Cancel
            </button>
            <button
              className="primary-button"
              disabled={busy}
              onClick={() => {
                void requestReset();
                setAction(null);
              }}
            >
              Send reset link
            </button>
          </div>
        </RightDrawer>
      )}
      {action === "force-password" && (
        <RightDrawer
          title="Require password change"
          description="The user must update their password before accessing CloudSentinel again."
          onClose={() => setAction(null)}
        >
          <p>Require {member.display_name} to change their password?</p>
          <div className="drawer-actions">
            <button
              className="secondary-button"
              onClick={() => setAction(null)}
            >
              Cancel
            </button>
            <button
              className="primary-button"
              disabled={busy}
              onClick={() =>
                void mutate(`/users/${userId}/force-password-change`, "POST")
              }
            >
              Require change
            </button>
          </div>
        </RightDrawer>
      )}
      {action === "revoke-sessions" && (
        <RightDrawer
          title="Revoke other sessions"
          description="All active sessions belonging to this user will be ended, except the current administrator session if it belongs to this user."
          onClose={() => setAction(null)}
        >
          <p>Revoke the other sessions for {member.display_name}?</p>
          <div className="drawer-actions">
            <button
              className="secondary-button"
              onClick={() => setAction(null)}
            >
              Cancel
            </button>
            <button
              className="danger-button"
              disabled={busy}
              onClick={() =>
                void mutate(`/users/${userId}/sessions/revoke-all`, "POST")
              }
            >
              Revoke sessions
            </button>
          </div>
        </RightDrawer>
      )}
      {sessionToRevoke && (
        <RightDrawer
          title="Revoke session"
          description="This session will no longer be able to access CloudSentinel."
          onClose={() => setSessionToRevoke(null)}
        >
          <div className="drawer-facts">
            <DrawerFact
              label="IP address"
              value={sessionToRevoke.ip_address ?? "Not recorded"}
            />
            <DrawerFact
              label="User agent"
              value={sessionToRevoke.user_agent ?? "Not recorded"}
            />
            <DrawerFact
              label="Last active"
              value={formatDate(sessionToRevoke.last_used_at)}
            />
          </div>
          <div className="drawer-actions">
            <button
              className="secondary-button"
              onClick={() => setSessionToRevoke(null)}
            >
              Cancel
            </button>
            <button
              className="danger-button"
              disabled={busy}
              onClick={() => {
                void mutate(
                  `/users/${userId}/sessions/${sessionToRevoke.id}`,
                  "DELETE",
                );
                setSessionToRevoke(null);
              }}
            >
              Revoke session
            </button>
          </div>
        </RightDrawer>
      )}
    </>
  );
}

type TeamTab = "overview" | "members" | "access" | "activity";
export function TeamsPage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [teamFilter, setTeamFilter] = useState("");
  const [state, setState] = useState("all");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Team | null>(null);
  const [editTeam, setEditTeam] = useState<Team | null>(null);
  const [confirmArchive, setConfirmArchive] = useState<Team | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [memberOpen, setMemberOpen] = useState(false);
  const [teamSaving, setTeamSaving] = useState(false);
  const summary = useApiQuery<TeamSummary>(["teams-summary"], "/teams/summary");
  const teamOptions = useApiQuery<Page<Team>>(
    ["teams-filter-options"],
    "/teams?status=all&limit=100",
  );
  const params = new URLSearchParams({
    status: state,
    offset: String(offset),
    limit: "25",
  });
  if (search.trim()) params.set("search", search.trim());
  if (teamFilter) params.set("team_id", teamFilter);
  if (dateFrom) params.set("date_from", dateFrom);
  if (dateTo) params.set("date_to", dateTo);
  const teams = useApiQuery<Page<Team>>(
    ["teams-list", params.toString()],
    `/teams?${params}`,
  );
  async function invalidate() {
    await Promise.all([
      client.invalidateQueries({ queryKey: ["teams-list"] }),
      client.invalidateQueries({ queryKey: ["teams-summary"] }),
      client.invalidateQueries({ queryKey: ["organization-summary"] }),
    ]);
  }
  async function saveTeam(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (teamSaving) return;
    const form = new FormData(event.currentTarget);
    const body = {
      name: String(form.get("name")).trim(),
      description: String(form.get("description")).trim() || null,
    };
    setFeedback("");
    setTeamSaving(true);
    try {
      if (editTeam) await api.patch(`/teams/${editTeam.id}`, body);
      else await api.post("/teams", body);
      await invalidate();
      setCreateOpen(false);
      setEditTeam(null);
      setSelected(null);
    } catch (error) {
      setFeedback(
        error instanceof Error ? error.message : "Team could not be saved.",
      );
    } finally {
      setTeamSaving(false);
    }
  }
  const [feedback, setFeedback] = useState("");
  const members = useApiQuery<Page<TeamMember>>(
    selected ? ["team-members", selected.id] : ["team-members"],
    selected ? `/teams/${selected.id}/members?limit=100` : "/teams/summary",
    Boolean(selected),
  );
  const available = useApiQuery<TeamMember[]>(
    selected
      ? ["team-available-members", selected.id]
      : ["team-available-members"],
    selected ? `/teams/${selected.id}/available-members` : "/teams/summary",
    Boolean(memberOpen && selected),
  );
  const [memberBusy, setMemberBusy] = useState(false);
  async function toggleMember(userId: string, add: boolean) {
    if (!selected) return;
    setMemberBusy(true);
    try {
      if (add) await api.put(`/teams/${selected.id}/members/${userId}`);
      else await api.delete(`/teams/${selected.id}/members/${userId}`);
      await Promise.all([
        invalidate(),
        client.invalidateQueries({ queryKey: ["team-members", selected.id] }),
        client.invalidateQueries({
          queryKey: ["team-available-members", selected.id],
        }),
      ]);
    } catch (error) {
      setFeedback(
        error instanceof Error
          ? error.message
          : "Membership could not be updated.",
      );
    } finally {
      setMemberBusy(false);
    }
  }
  const archive = useMutation({
    mutationFn: (team: Team) =>
      team.is_active
        ? api.delete(`/teams/${team.id}`)
        : api.post(`/teams/${team.id}/restore`),
    onSuccess: async () => {
      await invalidate();
      setConfirmArchive(null);
      setSelected(null);
    },
    onError: (error) => setFeedback(error.message),
  });
  return (
    <>
      <AdminNav />
      <Heading
        title="Teams"
        description="Organize users into tenant-scoped security and operations groups."
        action={
          user?.permissions.includes("teams:create") ? (
            <button
              className="primary-button"
              onClick={() => { setFeedback(""); setCreateOpen(true); }}
            >
              Create team
            </button>
          ) : undefined
        }
      />
      <SummaryCards
        items={[
          ["Total teams", summary.data?.total ?? "—"],
          ["Active", summary.data?.active ?? "—"],
          ["Archived", summary.data?.archived ?? "—"],
          ["Members", summary.data?.members ?? "—"],
        ]}
      />
      {feedback && (
        <div className="inline-feedback" role="status">
          {feedback}
        </div>
      )}
      <section className="panel table-panel">
        <div className="scan-filter-toolbar team-filter-toolbar">
        <div className="filter-row teams-page-filter-row">
          <FilterField label="Search" className="filter-field-search"><input
            aria-label="Search teams"
            placeholder="Search teams…"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setOffset(0);
            }}
          /></FilterField>
          <FilterField label="Team"><select
            aria-label="Filter by team"
            value={teamFilter}
            onChange={(event) => { setTeamFilter(event.target.value); setOffset(0); }}
          >
            <option value="">All teams</option>
            {(teamOptions.data?.items ?? []).map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
          </select></FilterField>
          <FilterField label="Status"><select
            aria-label="Filter teams by status"
            value={state}
            onChange={(event) => {
              setState(event.target.value);
              setOffset(0);
            }}
          >
            <option value="active">Active</option>
            <option value="archived">Archived</option>
            <option value="all">All statuses</option>
          </select></FilterField>
          <label className="admin-user-date-filter">From
            <input type="date" aria-label="Teams created from" max={dateTo || undefined} value={dateFrom} onClick={(event) => { try { event.currentTarget.showPicker?.(); } catch { /* Native picker may already be open. */ } }} onChange={(event) => { setDateFrom(event.target.value); setOffset(0); }} />
          </label>
          <label className="admin-user-date-filter">To
            <input type="date" aria-label="Teams created to" min={dateFrom || undefined} value={dateTo} onClick={(event) => { try { event.currentTarget.showPicker?.(); } catch { /* Native picker may already be open. */ } }} onChange={(event) => { setDateTo(event.target.value); setOffset(0); }} />
          </label>
        </div>
        <FilterFooter className="scan-filter-footer" active={Boolean(search.trim() || teamFilter || state !== "all" || dateFrom || dateTo)} onReset={() => { setSearch(""); setTeamFilter(""); setState("all"); setDateFrom(""); setDateTo(""); setOffset(0); }} />
        </div>
        <QueryState
          loading={teams.isLoading}
          error={teams.error}
          empty={!teams.data?.items.length}
        >
          <div className="table-scroll">
            <DataTable caption="Organization teams" actions>
              <thead>
                <tr>
                  <th scope="col">Team</th>
                  <th scope="col">Description</th>
                  <th scope="col">Members</th>
                  <th scope="col">Status</th>
                  <th scope="col">Updated</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {teams.data?.items.map((team) => (
                  <tr key={team.id}>
                    <td>
                      <button
                        className="text-button row-primary"
                        onClick={() => setSelected(team)}
                      >
                        {team.name}
                      </button>
                    </td>
                    <td>{team.description ?? "—"}</td>
                    <td>{team.member_count}</td>
                    <td>{team.is_active ? "Active" : "Archived"}</td>
                    <td>{formatDate(team.updated_at)}</td>
                    <td>
                      <div className="table-row-actions">
                      <ViewAction label={`View team ${team.name}`} onClick={() => setSelected(team)} />
                      <AdminActionsMenu label={`Actions for ${team.name}`} heading="Team actions" description={`Manage ${team.name} and its members`}>
                        <button role="menuitem" onClick={() => setSelected(team)}>
                          <span className="account-action-icon" aria-hidden="true">↗</span>
                          <span className="account-action-copy"><strong>View team</strong><small>Review team details and membership</small></span>
                        </button>
                        {team.is_active && user?.permissions.includes("teams:update") && <>
                          <button role="menuitem" onClick={() => { setSelected(team); setMemberOpen(true); }}>
                            <span className="account-action-icon" aria-hidden="true">♙</span>
                            <span className="account-action-copy"><strong>Manage members</strong><small>Add or remove organization users</small></span>
                          </button>
                          <button role="menuitem" onClick={() => { setFeedback(""); setEditTeam(team); }}>
                            <span className="account-action-icon" aria-hidden="true">✎</span>
                            <span className="account-action-copy"><strong>Edit team</strong><small>Update the team name or description</small></span>
                          </button>
                        </>}
                        {user?.permissions.includes("teams:delete") && <button role="menuitem" className={team.is_active ? "destructive-text" : undefined} onClick={() => setConfirmArchive(team)}>
                          <span className={`account-action-icon ${team.is_active ? "account-action-icon-danger" : ""}`} aria-hidden="true">{team.is_active ? "⊘" : "↻"}</span>
                          <span className="account-action-copy"><strong>{team.is_active ? "Archive team" : "Restore team"}</strong><small>{team.is_active ? "Retain history and prevent new assignments" : "Make this team available again"}</small></span>
                        </button>}
                      </AdminActionsMenu>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </DataTable>
          </div>
          {teams.data && <Pagination total={teams.data.total} offset={offset} limit={25} onOffsetChange={setOffset} disabled={teams.isFetching} label="Team pages" />}
        </QueryState>
      </section>
      {(createOpen || editTeam) && (
        <RightDrawer
          className="team-edit-drawer"
          title={editTeam ? "Edit team" : "Create team"}
          description={editTeam ? "Update this organization team’s profile." : "Create a group for users in your organization."}
          onClose={() => {
            setCreateOpen(false);
            setEditTeam(null);
          }}
        >
          <form className="drawer-form team-edit-form" onSubmit={saveTeam} aria-busy={teamSaving}>
            <div className="team-form-intro">
              <span className="team-form-intro-icon" aria-hidden="true">♧</span>
              <div><span>TEAM PROFILE</span><strong>{editTeam ? "Update team details" : "Set up a new team"}</strong><p>Teams help organize people and collaboration across your workspace.</p></div>
            </div>
            <label>
              <span>Team name <span className="field-required">Required</span></span>
              <input
                name="name"
                required
                minLength={1}
                maxLength={120}
                defaultValue={editTeam?.name ?? ""}
                placeholder="e.g. Security Operations"
                autoComplete="off"
                disabled={teamSaving}
              />
            </label>
            <label>
              Description <small>Optional</small>
              <textarea
                name="description"
                maxLength={500}
                rows={5}
                defaultValue={editTeam?.description ?? ""}
                placeholder="Describe the team’s focus, responsibilities, or working scope."
                disabled={teamSaving}
              />
            </label>
            <div className="team-scope-note"><span aria-hidden="true">ⓘ</span><p><strong>Organization membership only</strong><br />Team membership groups users; it does not grant cloud permissions.</p></div>
            {feedback && <div className="error-state team-form-error" role="alert">{feedback}</div>}
            <div className="drawer-actions team-edit-actions">
              <button
                type="button"
                className="secondary-button"
                disabled={teamSaving}
                onClick={() => {
                  setCreateOpen(false);
                  setEditTeam(null);
                }}
              >
                Cancel
              </button>
              <button type="submit" className="primary-button" disabled={teamSaving}>
                {teamSaving ? "Saving…" : editTeam ? "Save changes" : "Create team"}
              </button>
            </div>
          </form>
        </RightDrawer>
      )}
      {selected && !memberOpen && (
        <RightDrawer
          className="team-preview-drawer"
          title={selected.name}
          description={selected.description ?? "Organization team"}
          onClose={() => setSelected(null)}
        >
          <div className="team-preview-hero">
            <span className="team-preview-mark">{selected.name.slice(0, 2).toUpperCase()}</span>
            <div><span className={`team-preview-status ${selected.is_active ? "is-active" : "is-archived"}`}><i />{selected.is_active ? "Active team" : "Archived team"}</span><h3>{selected.name}</h3><p>{selected.description || "No team description has been added."}</p></div>
          </div>
          <div className="team-preview-metrics">
            <div><span>Members</span><strong>{members.data?.total ?? selected.member_count}</strong></div>
            <div><span>Created</span><strong>{formatDate(selected.created_at)}</strong></div>
            <div><span>Last updated</span><strong>{formatDate(selected.updated_at)}</strong></div>
          </div>
          <div className="drawer-section">
            <div className="drawer-section-heading">
              <div><h3>Team members</h3><small>Users assigned to this organization team</small></div>
              <span className="team-member-count">{members.data?.total ?? selected.member_count}</span>
            </div>
            {members.isLoading ? (
              <p className="muted-note">Loading members…</p>
            ) : members.error ? (
              <p className="error-state">{members.error.message}</p>
            ) : (
              <div className="drawer-member-list">
                {members.data?.items.slice(0, 8).map((member) => (
                  <div key={member.user_id}>
                    <span className="member-avatar">
                      {member.display_name.slice(0, 1).toUpperCase()}
                    </span>
                    <span>
                      <strong>{member.display_name}</strong>
                      <small>{member.email} · {member.role_code.replaceAll("_", " ")}</small>
                    </span>
                    <span
                      className={`status-pill ${member.is_active && !member.is_locked ? "status-active" : ""}`}
                    >
                      {member.is_locked
                        ? "Locked"
                        : member.is_active
                          ? "Active"
                          : "Disabled"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
              <div className="drawer-actions">
            {selected.is_active &&
              user?.permissions.includes("teams:update") && (
                <button
                  className="primary-button"
                  onClick={() => setMemberOpen(true)}
                >
                  Manage members
                </button>
              )}
          </div>
        </RightDrawer>
      )}
      {memberOpen && selected && (
        <RightDrawer
          className="team-member-management-drawer"
          title="Manage members"
          description={`Current members of ${selected.name}. Add or remove active users in this organization.`}
          onClose={() => setMemberOpen(false)}
        >
          <div className="team-member-manager-intro"><span className="team-preview-mark">{selected.name.slice(0, 2).toUpperCase()}</span><div><small>TEAM MEMBERSHIP</small><strong>{selected.name}</strong><p>Assign organization users to this team.</p></div></div>
          <div className="team-member-manager-section"><div className="drawer-section-heading"><div><h3>Current members</h3><small>Remove access from this team while keeping the organization account.</small></div><span className="team-member-count">{members.data?.total ?? selected.member_count}</span></div>
          <QueryState
            loading={members.isLoading}
            error={members.error}
            empty={!members.data?.items.length}
          >
            <div className="member-picker team-member-picker">
              {members.data?.items.map((member) => (
                <div key={member.user_id}>
                  <span className="member-avatar">{member.display_name.slice(0, 1).toUpperCase()}</span>
                  <span className="team-picker-copy"><strong>{member.display_name}</strong><small>{member.email}</small><small>{member.role_code.replaceAll("_", " ")}</small></span>
                  <button
                    className="small-button danger-button"
                    disabled={memberBusy}
                    onClick={() => void toggleMember(member.user_id, false)}
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
          </QueryState>
          </div>
          <div className="team-member-manager-section"><div className="drawer-section-heading"><div><h3>Available users</h3><small>Add an active organization user to this team.</small></div></div>
          <QueryState
            loading={available.isLoading}
            error={available.error}
            empty={!available.data?.length}
          >
            <div className="member-picker team-member-picker">
              {available.data?.map((member) => (
                <div key={member.user_id}>
                  <span className="member-avatar">{member.display_name.slice(0, 1).toUpperCase()}</span>
                  <span className="team-picker-copy"><strong>{member.display_name}</strong><small>{member.email}</small><small>{member.role_code.replaceAll("_", " ")}</small></span>
                  <button
                    className="small-button"
                    disabled={memberBusy}
                    onClick={() => void toggleMember(member.user_id, true)}
                  >
                    Add
                  </button>
                </div>
              ))}
            </div>
          </QueryState>
          </div>
        </RightDrawer>
      )}
      {confirmArchive && (
        <RightDrawer
          className="team-archive-drawer"
          title={confirmArchive.is_active ? "Archive team" : "Restore team"}
          description="This change applies only to the selected team's status; its membership history is retained."
          onClose={() => setConfirmArchive(null)}
        >
          <div className={`team-archive-callout ${confirmArchive.is_active ? "is-archive" : "is-restore"}`}><span aria-hidden="true">{confirmArchive.is_active ? "⊘" : "↻"}</span><div><small>{confirmArchive.is_active ? "ARCHIVE TEAM" : "RESTORE TEAM"}</small><h3>{confirmArchive.name}</h3><p>{confirmArchive.is_active ? "New members cannot be added while archived. Existing membership and activity history will be retained." : "This team will become active and available for membership management again."}</p></div></div>
          <div className="drawer-actions">
            <button
              className="secondary-button"
              onClick={() => setConfirmArchive(null)}
            >
              Cancel
            </button>
            <button
              className={
                confirmArchive.is_active ? "danger-button" : "primary-button"
              }
              disabled={archive.isPending}
              onClick={() => archive.mutate(confirmArchive)}
            >
              {archive.isPending
                ? "Saving…"
                : confirmArchive.is_active
                  ? "Archive team"
                  : "Restore team"}
            </button>
          </div>
        </RightDrawer>
      )}
    </>
  );
}

export function TeamDetailsPage() {
  const { team_id: teamId = "" } = useParams();
  const { user } = useAuth();
  const [tab, setTab] = useState<TeamTab>("overview");
  const team = useApiQuery<Team>(
    ["team-detail", teamId],
    `/teams/${teamId}`,
    Boolean(teamId),
  );
  const members = useApiQuery<Page<TeamMember>>(
    ["team-members", teamId],
    `/teams/${teamId}/members?limit=100`,
    tab === "members",
  );
  const available = useApiQuery<TeamMember[]>(
    ["team-available-members", teamId],
    `/teams/${teamId}/available-members`,
    tab === "members" && Boolean(user?.permissions.includes("teams:update")),
  );
  const activity = useApiQuery<Page<Activity>>(
    ["team-activity", teamId],
    `/teams/${teamId}/activity?limit=50`,
    tab === "activity" && Boolean(user?.permissions.includes("audit:read")),
  );
  const client = useQueryClient();
  const [editOpen, setEditOpen] = useState(false);
  const [addMembersOpen, setAddMembersOpen] = useState(false);
  const [removeMember, setRemoveMember] = useState<TeamMember | null>(null);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState("");
  async function changeMember(memberId: string, add: boolean) {
    setBusy(true);
    try {
      if (add) await api.put(`/teams/${teamId}/members/${memberId}`);
      else await api.delete(`/teams/${teamId}/members/${memberId}`);
      await Promise.all([
        client.invalidateQueries({ queryKey: ["team-detail", teamId] }),
        client.invalidateQueries({ queryKey: ["team-members", teamId] }),
        client.invalidateQueries({
          queryKey: ["team-available-members", teamId],
        }),
        client.invalidateQueries({ queryKey: ["teams-list"] }),
        client.invalidateQueries({ queryKey: ["teams-summary"] }),
      ]);
    } catch (error) {
      setFeedback(
        error instanceof Error ? error.message : "Membership update failed.",
      );
    } finally {
      setBusy(false);
    }
  }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    try {
      await api.patch(`/teams/${teamId}`, {
        name: String(form.get("name")).trim(),
        description: String(form.get("description")).trim() || null,
      });
      await client.invalidateQueries({ queryKey: ["team-detail", teamId] });
      setEditOpen(false);
    } catch (error) {
      setFeedback(
        error instanceof Error ? error.message : "Team update failed.",
      );
    } finally {
      setBusy(false);
    }
  }
  if (team.isLoading)
    return <div className="panel empty-state">Loading team…</div>;
  if (team.error || !team.data)
    return (
      <div className="panel error-state">
        {team.error?.message ?? "Team not found."}
      </div>
    );
  return (
    <>
      <AdminNav />
      <div className="breadcrumbs">
        <Link to="/administration/teams">Teams</Link>
        <span>/</span>
        <span>{team.data.name}</span>
      </div>
      <div className="finding-summary panel">
        <div>
          <span className="eyebrow">ORGANIZATION TEAM</span>
          <h1>{team.data.name}</h1>
          <p>{team.data.description ?? "No description"}</p>
        </div>
        <span className="status-pill">
          {team.data.is_active ? "Active" : "Archived"}
        </span>
        <div className="drawer-actions">
          {team.data.is_active &&
            user?.permissions.includes("teams:update") && (
              <button
                className="secondary-button"
                onClick={() => setEditOpen(true)}
              >
                Edit team
              </button>
            )}
        </div>
      </div>
      {feedback && <div className="inline-feedback">{feedback}</div>}
      <SummaryCards
        items={[
          ["Members", team.data.member_count],
          ["Created", formatDate(team.data.created_at)],
          ["Updated", formatDate(team.data.updated_at)],
        ]}
      />
      <nav className="account-detail-tabs" aria-label="Team details">
        <button
          className={tab === "overview" ? "active" : ""}
          onClick={() => setTab("overview")}
        >
          Overview
        </button>
        <button
          className={tab === "members" ? "active" : ""}
          onClick={() => setTab("members")}
        >
          Members
        </button>
        <button
          className={tab === "access" ? "active" : ""}
          onClick={() => setTab("access")}
        >
          Access
        </button>
        {user?.permissions.includes("audit:read") && (
          <button
            className={tab === "activity" ? "active" : ""}
            onClick={() => setTab("activity")}
          >
            Activity
          </button>
        )}
      </nav>
      {tab === "overview" && (
        <section className="panel">
          <h2>Team information</h2>
          <div className="drawer-facts">
            <DrawerFact label="Team name" value={team.data.name} />
            <DrawerFact
              label="Status"
              value={team.data.is_active ? "Active" : "Archived"}
            />
            <DrawerFact label="Organization" value="Current organization" />
            <DrawerFact
              label="Description"
              value={team.data.description ?? "—"}
            />
            <DrawerFact
              label="Created"
              value={formatDate(team.data.created_at)}
            />
            <DrawerFact
              label="Updated"
              value={formatDate(team.data.updated_at)}
            />
          </div>
        </section>
      )}
      {tab === "members" && (
        <section className="panel table-panel">
          <div className="panel-heading">
            <h2>Team members</h2>
            {user?.permissions.includes("teams:update") &&
              team.data.is_active && (
                <button
                  className="secondary-button"
                  onClick={() => setAddMembersOpen(true)}
                >
                  Add members
                </button>
              )}
          </div>
          <QueryState
            loading={members.isLoading}
            error={members.error}
            empty={!members.data?.items.length}
          >
            <div className="table-scroll">
              <DataTable caption="Team members" actions>
                <thead>
                  <tr>
                    <th scope="col">User</th>
                    <th scope="col">Role</th>
                    <th scope="col">Status</th>
                    <th scope="col">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {members.data?.items.map((member) => (
                    <tr key={member.user_id}>
                      <td>
                        {member.display_name}
                        <small>{member.email}</small>
                      </td>
                      <td>{member.role_code}</td>
                      <td>
                        {member.is_locked
                          ? "Locked"
                          : member.is_active
                            ? "Active"
                            : "Disabled"}
                      </td>
                      <td>
                        {user?.permissions.includes("teams:update") && (
                          <button
                            className="small-button danger-button"
                            disabled={busy}
                            onClick={() => setRemoveMember(member)}
                          >
                            Remove from team
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
          </QueryState>
        </section>
      )}
      {tab === "access" && (
        <section className="panel empty-state">
          <h2>Team access</h2>
          <p>
            Cloud account and resource access assignments are not part of the
            current Teams workflow.
          </p>
        </section>
      )}
      {tab === "activity" && (
        <section className="panel table-panel">
          <h2>Team activity</h2>
          <QueryState
            loading={activity.isLoading}
            error={activity.error}
            empty={!activity.data?.items.length}
          >
            <div className="table-scroll">
              <DataTable caption="Team activity">
                <thead>
                  <tr>
                    <th scope="col">Timestamp</th>
                    <th scope="col">Actor</th>
                    <th scope="col">Action</th>
                    <th scope="col">Resource</th>
                  </tr>
                </thead>
                <tbody>
                  {activity.data?.items.map((row) => (
                    <tr key={row.id}>
                      <td>{formatDate(row.created_at)}</td>
                      <td>{row.actor_user_id ?? "System"}</td>
                      <td>{row.action}</td>
                      <td>{row.resource_type}</td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
          </QueryState>
        </section>
      )}
      {editOpen && (
        <RightDrawer
          title="Edit team"
          description="Update the name or description for this organization team."
          onClose={() => setEditOpen(false)}
        >
          <form className="drawer-form" onSubmit={save}>
            <label>
              Team name
              <input
                name="name"
                required
                minLength={1}
                maxLength={120}
                defaultValue={team.data.name}
              />
            </label>
            <label>
              Description
              <textarea
                name="description"
                maxLength={500}
                defaultValue={team.data.description ?? ""}
              />
            </label>
            <div className="drawer-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => setEditOpen(false)}
              >
                Cancel
              </button>
              <button className="primary-button" disabled={busy}>
                Save changes
              </button>
            </div>
          </form>
        </RightDrawer>
      )}
      {addMembersOpen && (
        <RightDrawer
          title="Add members"
          description={`Add existing users from this organization to ${team.data.name}.`}
          onClose={() => setAddMembersOpen(false)}
        >
          <QueryState
            loading={available.isLoading}
            error={available.error}
            empty={!available.data?.length}
          >
            <div className="member-picker">
              {available.data?.map((member) => (
                <div key={member.user_id}>
                  <span>
                    <strong>{member.display_name}</strong>
                    <small>
                      {member.email} · {member.role_code}
                    </small>
                  </span>
                  <button
                    className="small-button"
                    disabled={busy}
                    onClick={() => void changeMember(member.user_id, true)}
                  >
                    Add
                  </button>
                </div>
              ))}
            </div>
          </QueryState>
          {feedback && (
            <p className="inline-feedback" role="status">
              {feedback}
            </p>
          )}
        </RightDrawer>
      )}
      {removeMember && (
        <RightDrawer
          title="Remove team member"
          description="The user's organization account remains active; only this team membership is removed."
          onClose={() => setRemoveMember(null)}
        >
          <p>
            Remove {removeMember.display_name} from {team.data.name}?
          </p>
          <div className="drawer-actions">
            <button
              className="secondary-button"
              onClick={() => setRemoveMember(null)}
            >
              Cancel
            </button>
            <button
              className="danger-button"
              disabled={busy}
              onClick={() => {
                void changeMember(removeMember.user_id, false);
                setRemoveMember(null);
              }}
            >
              Remove member
            </button>
          </div>
        </RightDrawer>
      )}
    </>
  );
}

type SettingsSection = "general" | "security" | "sessions" | "retention" | "notifications" | "integrations";

const settingSections: Array<{ id: SettingsSection; label: string; description: string }> = [
  { id: "general", label: "General", description: "Organization profile and regional defaults." },
  { id: "security", label: "Security", description: "Canonical password requirements." },
  { id: "sessions", label: "Sessions", description: "Session lifetime and concurrency limits." },
  { id: "retention", label: "Retention & offboarding", description: "Audit retention and tenant data deletion." },
  { id: "notifications", label: "Notifications", description: "Organization notification delivery." },
  { id: "integrations", label: "Integrations", description: "Connected external services." },
];

function EnterpriseIdentitySettings({ canManage }: { canManage: boolean }) {
  const client = useQueryClient();
  const saml = useApiQuery<SamlIdentitySettings>(["enterprise-saml"], "/organizations/current/sso/saml", canManage);
  const tokens = useApiQuery<{ items: Array<{ id: string; description: string; created_at: string; expires_at: string | null; last_used_at: string | null; revoked_at: string | null }> }>(["scim-tokens"], "/organizations/current/scim-token", canManage);
  const mappings = useApiQuery<{ items: Array<{ external_id: string; display_name: string; role_code: string; is_active: boolean }> }>(["scim-groups"], "/organizations/current/scim/groups", canManage);
  const [message, setMessage] = useState("");
  const [newToken, setNewToken] = useState<{ token: string; scim_base_url: string; expires_at: string } | null>(null);
  const saveSaml = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.put<SamlIdentitySettings>("/organizations/current/sso/saml", body),
    onSuccess: async () => { setMessage("SAML single sign-on settings saved."); await client.invalidateQueries({ queryKey: ["enterprise-saml"] }); },
  });
  const disableSaml = useMutation({
    mutationFn: () => api.delete<void>("/organizations/current/sso/saml"),
    onSuccess: async () => { setMessage("SAML sign-in disabled. Existing local access remains available."); await client.invalidateQueries({ queryKey: ["enterprise-saml"] }); },
  });
  const createToken = useMutation({
    mutationFn: () => api.post<{ token: string; scim_base_url: string; expires_at: string }>("/organizations/current/scim-token", { description: "Enterprise identity provisioning" }),
    onSuccess: async (result) => { setNewToken(result); setMessage("SCIM credential created. Copy it now; it will not be shown again."); await client.invalidateQueries({ queryKey: ["scim-tokens"] }); },
  });
  const saveMapping = useMutation({
    mutationFn: (value: { externalId: string; displayName: string; roleCode: string }) => api.put(`/organizations/current/scim/groups/${encodeURIComponent(value.externalId)}`, { display_name: value.displayName, role_code: value.roleCode }),
    onSuccess: async () => { setMessage("SCIM group role mapping saved."); await client.invalidateQueries({ queryKey: ["scim-groups"] }); },
  });

  function submitSaml(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const metadata = String(data.get("metadata_xml") ?? "").trim();
    if (!metadata) { setMessage("Paste the IdP metadata XML to save or rotate the SAML trust configuration."); return; }
    saveSaml.mutate({
      metadata_xml: metadata,
      is_active: data.get("is_active") === "on",
      enforce_sso: data.get("enforce_sso") === "on",
      jit_provisioning: data.get("jit_provisioning") === "on",
      default_role_code: String(data.get("default_role_code") ?? "VIEWER"),
      email_attribute: String(data.get("email_attribute") ?? "email").trim(),
      name_attribute: String(data.get("name_attribute") ?? "name").trim(),
      require_mfa: data.get("require_mfa") === "on",
      mfa_contexts: String(data.get("mfa_contexts") ?? "").split("\n").map((item) => item.trim()).filter(Boolean),
    });
  }

  function submitMapping(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    saveMapping.mutate({ externalId: String(data.get("external_id") ?? "").trim(), displayName: String(data.get("display_name") ?? "").trim(), roleCode: String(data.get("role_code") ?? "VIEWER") });
    event.currentTarget.reset();
  }

  if (!canManage) return <div className="panel empty-state">Identity administration permission is required to view or change SAML and SCIM settings.</div>;
  return <div className="enterprise-identity-settings">
    <QueryState loading={saml.isLoading} error={saml.error}>
      {saml.data && <section className="panel settings-panel">
        <div className="settings-panel-heading"><div><h3>SAML single sign-on</h3><p>Trust signed IdP responses and optionally provision first sign-ins. Keep an administrator account available until your IdP is verified.</p></div><span className={`status-badge ${saml.data.active ? "status-connected" : ""}`}>{saml.data.active ? "Configured" : "Not configured"}</span></div>
        <div className="settings-policy-note"><strong>Service provider metadata</strong><p>Share this URL with your IdP administrator. The ACS accepts signed responses and assertions, validates the request state, and rejects replayed assertions.</p><a href={saml.data.metadata_url} target="_blank" rel="noreferrer">View SP metadata</a>{saml.data.active && <span> · <a href={saml.data.login_url}>Start SAML sign-in</a></span>}</div>
        <form className="settings-form" onSubmit={submitSaml}>
          <label>Identity provider metadata XML<textarea name="metadata_xml" rows={7} maxLength={100000} placeholder={saml.data.configured ? "Paste refreshed IdP metadata to update the trusted certificate and endpoints." : "Paste the XML metadata exported by your identity provider."} required disabled={saveSaml.isPending} /></label>
          <div className="settings-checkboxes"><label><input name="is_active" type="checkbox" defaultChecked={saml.data.active || !saml.data.configured} /> Enable SAML sign-in</label><label><input name="enforce_sso" type="checkbox" defaultChecked={saml.data.enforce_sso} /> Require SSO for password sign-in</label><label><input name="jit_provisioning" type="checkbox" defaultChecked={saml.data.jit_provisioning} /> Create users on first SSO sign-in</label><label><input name="require_mfa" type="checkbox" defaultChecked={saml.data.require_mfa} /> Require IdP MFA for every SAML sign-in</label></div>
          <label>New user default role<select name="default_role_code" defaultValue={saml.data.default_role_code}><option>VIEWER</option><option>AUDITOR</option><option>SECURITY_ANALYST</option><option>CLOUD_ENGINEER</option><option>SECURITY_ADMIN</option><option>ORG_ADMIN</option></select><small>Only used when just-in-time provisioning is enabled.</small></label>
          <div className="settings-form-row"><label>Email attribute<input name="email_attribute" defaultValue={saml.data.email_attribute} maxLength={200} required /></label><label>Name attribute<input name="name_attribute" defaultValue={saml.data.name_attribute} maxLength={200} required /></label></div>
          <label>MFA authentication context URNs<textarea name="mfa_contexts" rows={2} defaultValue={saml.data.mfa_contexts.join("\n")} placeholder="urn:example:idp:mfa" /><small>Required when organization MFA is enforced, or when a user has local MFA enabled.</small></label>
          <div className="settings-form-footer"><button className="primary-button" disabled={saveSaml.isPending}>{saveSaml.isPending ? "Saving…" : "Save SAML settings"}</button>{saml.data.configured && <button type="button" className="danger-button" disabled={disableSaml.isPending} onClick={() => disableSaml.mutate()}>{disableSaml.isPending ? "Disabling…" : "Disable SAML"}</button>}</div>
        </form>
      </section>}
    </QueryState>
    <QueryState loading={tokens.isLoading || mappings.isLoading} error={tokens.error ?? mappings.error}>
      <section className="panel settings-panel">
        <div className="settings-panel-heading"><div><h3>SCIM 2.0 provisioning</h3><p>Provision and deactivate organization memberships using a tenant-scoped, rotating bearer credential.</p></div><span className="status-badge">SCIM 2.0</span></div>
        {newToken && <div className="settings-policy-note"><strong>Copy this credential now</strong><p>It is shown once. Store it in your IdP secret vault and rotate it if it is lost.</p><label>SCIM endpoint<input readOnly value={newToken.scim_base_url} /></label><label>Bearer token<input readOnly value={newToken.token} onFocus={(event) => event.currentTarget.select()} /></label><small>Expires {formatOrganizationDateTime(newToken.expires_at)}</small></div>}
        <button type="button" className="primary-button" disabled={createToken.isPending} onClick={() => createToken.mutate()}>{createToken.isPending ? "Creating…" : tokens.data?.items.some((item) => !item.revoked_at) ? "Rotate SCIM credential" : "Create SCIM credential"}</button>
        <DataTable caption="SCIM provisioning credentials">
          <thead><tr><th scope="col">Credential</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">Last used</th><th scope="col">Status</th></tr></thead>
          <tbody>{tokens.data?.items.length ? tokens.data.items.map((item) => <tr key={item.id}><td>{item.description}</td><td>{formatOrganizationDateTime(item.created_at)}</td><td>{item.expires_at ? formatOrganizationDateTime(item.expires_at) : "—"}</td><td>{item.last_used_at ? formatOrganizationDateTime(item.last_used_at) : "Never"}</td><td>{item.revoked_at ? "Revoked" : item.expires_at && new Date(item.expires_at) < new Date() ? "Expired" : "Active"}</td></tr>) : <tr><td colSpan={5}><span className="empty-inline">No SCIM credentials have been issued.</span></td></tr>}</tbody>
        </DataTable>
        <form className="settings-form" onSubmit={submitMapping}><h4>Pre-authorize an IdP group</h4><p>Unknown or unmapped groups cannot grant access. Super Admin is never assignable through SCIM.</p><label>External group ID<input name="external_id" maxLength={200} required /></label><label>Display name<input name="display_name" maxLength={200} required /></label><label>Role<select name="role_code"><option>VIEWER</option><option>AUDITOR</option><option>SECURITY_ANALYST</option><option>CLOUD_ENGINEER</option><option>SECURITY_ADMIN</option><option>ORG_ADMIN</option></select></label><button className="secondary-button" disabled={saveMapping.isPending}>Save group mapping</button></form>
        <DataTable caption="SAML identity provider group mappings">
          <thead><tr><th scope="col">IdP group</th><th scope="col">External ID</th><th scope="col">Role</th><th scope="col">Status</th></tr></thead>
          <tbody>{mappings.data?.items.length ? mappings.data.items.map((item) => <tr key={item.external_id}><td>{item.display_name}</td><td>{item.external_id}</td><td>{item.role_code}</td><td>{item.is_active ? "Mapped" : "Disabled"}</td></tr>) : <tr><td colSpan={4}><span className="empty-inline">No IdP groups are mapped yet.</span></td></tr>}</tbody>
        </DataTable>
      </section>
    </QueryState>
    {(message || saveSaml.error || disableSaml.error || createToken.error || saveMapping.error) && <p className={`inline-feedback ${saveSaml.error || disableSaml.error || createToken.error || saveMapping.error ? "error-state" : ""}`} role="status">{message || (saveSaml.error ?? disableSaml.error ?? createToken.error ?? saveMapping.error)?.message}</p>}
  </div>;
}

function RetentionSettings({ organization, canUpdate, canOffboard }: { organization: Organization | undefined; canUpdate: boolean; canOffboard: boolean }) {
  const { clearLocalSession } = useAuth();
  const client = useQueryClient();
  const retention = useQuery({
    queryKey: ["organization-retention-settings"],
    queryFn: () => api.get<OrganizationRetentionSettings>("/organizations/current/settings/retention"),
    enabled: Boolean(organization),
  });
  const [message, setMessage] = useState("");
  const [confirmSlug, setConfirmSlug] = useState("");
  const update = useMutation({
    mutationFn: (days: number) => api.patch<OrganizationRetentionSettings>("/organizations/current/settings/retention", { audit_retention_days: days }),
    onSuccess: async () => { setMessage("Retention policy saved. Existing audit records keep their original expiry dates."); await client.invalidateQueries({ queryKey: ["organization-retention-settings"] }); },
  });
  const offboard = useMutation({
    mutationFn: () => api.post<{ status: string; purge_after: string }>("/organizations/current/offboard", { confirm_slug: confirmSlug }),
    onSuccess: (result) => {
      setMessage(`Offboarding accepted. Data erasure is scheduled after ${formatOrganizationDateTime(result.purge_after)}.`);
      clearLocalSession();
      window.setTimeout(() => window.location.assign("/login"), 600);
    },
  });
  function submitRetention(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    update.mutate(Number(data.get("audit_retention_days")));
  }
  return <div className="enterprise-identity-settings">
    <QueryState loading={retention.isLoading} error={retention.error}>
      {retention.data && <section className="panel settings-panel">
        <div className="settings-panel-heading"><div><h3>Audit retention</h3><p>Retention applies to newly created audit events. Existing event expiry dates stay unchanged, and reports retain their own configured lifetime.</p></div><span className="status-badge">{retention.data.audit_retention_days} days</span></div>
        <form className="settings-form" onSubmit={submitRetention}>
          <label>Audit event retention<input type="number" name="audit_retention_days" min={30} max={3650} defaultValue={retention.data.audit_retention_days} required disabled={!canUpdate || update.isPending} /><small>30–3650 days. Expired events are removed by the scheduled retention worker.</small></label>
          <div className="settings-form-footer">{!canUpdate ? <span>Read only: retention policy update permission is required.</span> : <button className="primary-button" disabled={update.isPending}>{update.isPending ? "Saving…" : "Save retention policy"}</button>}</div>
        </form>
      </section>}
    </QueryState>
    {organization && <section className="panel settings-panel settings-danger-panel">
      <div className="settings-panel-heading"><div><h3>Offboard organization</h3><p>Access is disabled immediately. Sessions and IdP credentials are revoked, active scans and report generation are cancelled, and tenant data is erased only after the longest audit/report deadline, a 30-day grace period, and the configured backup retention window.</p></div><span className="status-badge">Irreversible</span></div>
      <form className="settings-form" onSubmit={(event) => { event.preventDefault(); offboard.mutate(); }}>
        <label>Type <strong>{organization.slug}</strong> to confirm<input value={confirmSlug} onChange={(event) => setConfirmSlug(event.target.value)} autoComplete="off" required disabled={!canOffboard || !organization.is_active || offboard.isPending} /></label>
        <div className="settings-form-footer"><span>{canOffboard ? "Offboarding immediately signs you out and cannot be undone." : "Read only: organization offboarding permission is required."}</span><button className="danger-button" disabled={!canOffboard || !organization.is_active || confirmSlug !== organization.slug || offboard.isPending}>{offboard.isPending ? "Scheduling…" : "Schedule offboarding"}</button></div>
      </form>
    </section>}
    {(message || update.error || offboard.error) && <p className={`inline-feedback ${update.error || offboard.error ? "error-state" : ""}`} role="status">{message || (update.error ?? offboard.error)?.message}</p>}
  </div>;
}

export function SettingsPage() {
  const { section: sectionParam } = useParams();
  const section = (settingSections.some((item) => item.id === sectionParam) ? sectionParam : "general") as SettingsSection;
  const { user } = useAuth();
  const client = useQueryClient();
  const canUpdateGeneral = Boolean(user?.permissions.includes("organizations:update"));
  const canReadSecurity = Boolean(user?.permissions.includes("security_settings:read"));
  const canUpdateSecurity = Boolean(user?.permissions.includes("security_settings:update"));
  const canManageIdentity = Boolean(user?.permissions.includes("identity:manage"));
  const canUpdateRetention = Boolean(user?.permissions.includes("organization:retention:update"));
  const canOffboard = Boolean(user?.permissions.includes("organization:offboard"));
  const org = useApiQuery<Organization>(["organization-settings"], "/organizations/current");
  const security = useApiQuery<OrganizationSecuritySettings>(
    ["organization-security-settings"],
    "/organizations/current/settings/security",
    canReadSecurity,
  );
  const [message, setMessage] = useState("");
  const [pendingSecurityUpdate, setPendingSecurityUpdate] = useState<Partial<OrganizationSecuritySettings> | null>(null);
  const updateGeneral = useMutation({
    mutationFn: (body: Partial<Organization>) => api.patch<Organization>("/organizations/current", body),
    onSuccess: async () => {
      setMessage("Organization settings saved.");
      await client.invalidateQueries({ queryKey: ["organization-settings"] });
      await client.invalidateQueries({ queryKey: ["organization"] });
    },
  });
  const updateSecurity = useMutation({
    mutationFn: (body: Partial<OrganizationSecuritySettings>) =>
      api.patch<OrganizationSecuritySettings>("/organizations/current/settings/security", body),
    onSuccess: async () => {
      setMessage("Security policy saved. New sessions and password changes will use the updated policy.");
      await client.invalidateQueries({ queryKey: ["organization-security-settings"] });
    },
  });

  function saveGeneral(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    const data = new FormData(event.currentTarget);
    updateGeneral.mutate({
      name: String(data.get("name") ?? "").trim(),
      description: String(data.get("description") ?? "").trim() || null,
      timezone: String(data.get("timezone") ?? "UTC"),
      date_time_format: String(data.get("date_time_format") ?? "YYYY-MM-DD HH:mm"),
      default_environment: String(data.get("default_environment") ?? "").trim() || null,
      default_region: String(data.get("default_region") ?? "").trim() || null,
    });
  }

  function saveSecurity(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    const data = new FormData(event.currentTarget);
    if (section === "security") {
      setPendingSecurityUpdate({ password_min_length: Number(data.get("password_min_length")) });
    } else {
      setPendingSecurityUpdate({
        session_ttl_days: Number(data.get("session_ttl_days")),
        remembered_session_ttl_days: Number(data.get("remembered_session_ttl_days")),
        max_concurrent_sessions: Number(data.get("max_concurrent_sessions")),
      });
    }
  }

  const isSecuritySection = section === "security" || section === "sessions";
  const sectionTitle = settingSections.find((item) => item.id === section)?.label ?? "General";
  const mutationError = updateGeneral.error ?? updateSecurity.error;

  return (
    <div className="admin-page">
      <AdminNav />
      <Heading title="Settings" description="Manage organization-wide operational and security configuration." />
      <div className="settings-layout">
        <nav className="settings-navigation" aria-label="Settings sections">
          <span className="settings-navigation-title">SETTINGS</span>
          {settingSections.map((item) => (
            <NavLink key={item.id} to={`/administration/settings/${item.id}`} className={({ isActive }) => isActive || (item.id === "general" && !sectionParam) ? "active" : ""}>
              <strong>{item.label}</strong><small>{item.description}</small>
            </NavLink>
          ))}
        </nav>
        <section className="settings-content">
          <div className="settings-content-heading"><div><h2>{sectionTitle}</h2><p>{settingSections.find((item) => item.id === section)?.description}</p></div></div>
          {section === "general" && (
            <QueryState loading={org.isLoading} error={org.error}>
              {org.data && <form className="settings-form" onSubmit={saveGeneral}>
                <label>Organization name<input name="name" defaultValue={org.data.name} minLength={2} maxLength={200} required disabled={!canUpdateGeneral || updateGeneral.isPending} /></label>
                <label>Description<input name="description" defaultValue={org.data.description ?? ""} maxLength={1000} disabled={!canUpdateGeneral || updateGeneral.isPending} /></label>
                <label>Time zone<input name="timezone" defaultValue={org.data.timezone} maxLength={64} required placeholder="UTC or America/New_York" disabled={!canUpdateGeneral || updateGeneral.isPending} /><small>Use an IANA time zone identifier.</small></label>
                <label>Default environment<input name="default_environment" defaultValue={org.data.default_environment ?? ""} maxLength={80} placeholder="Not set" disabled={!canUpdateGeneral || updateGeneral.isPending} /></label>
                <label>Default region<input name="default_region" defaultValue={org.data.default_region ?? ""} maxLength={40} placeholder="Not set" disabled={!canUpdateGeneral || updateGeneral.isPending} /></label>
                <label>Date &amp; time format<select name="date_time_format" defaultValue={org.data.date_time_format} disabled={!canUpdateGeneral || updateGeneral.isPending}><option value="YYYY-MM-DD HH:mm">YYYY-MM-DD HH:mm (24-hour)</option><option value="MM/DD/YYYY hh:mm A">MM/DD/YYYY hh:mm A (12-hour)</option><option value="DD/MM/YYYY HH:mm">DD/MM/YYYY HH:mm (24-hour)</option></select><small>Organization display preference.</small></label>
                <div className="settings-form-footer">{!canUpdateGeneral ? <span>Read only: organization update permission is required.</span> : <button className="primary-button" disabled={updateGeneral.isPending}>{updateGeneral.isPending ? "Saving…" : "Save changes"}</button>}</div>
              </form>}
            </QueryState>
          )}
          {isSecuritySection && (!canReadSecurity ? <div className="panel empty-state">You do not have permission to view organization security settings.</div> : <QueryState loading={security.isLoading} error={security.error}>
            {security.data && (section === "security" ? <form className="settings-form" onSubmit={saveSecurity}>
              <div className="settings-policy-note"><strong>Password policy</strong><p>This minimum is enforced by password reset, invitation acceptance, and forced password change.</p></div>
              <div className="settings-policy-note"><strong>Multi-factor authentication</strong><p>Users can enroll an authenticator and recovery codes from their personal Profile page. IdP MFA can be enforced for every SAML sign-in in Integrations.</p><span className="status-badge">User managed / SAML policy</span></div>
              <label>Minimum password length<input type="number" name="password_min_length" min={12} max={128} defaultValue={security.data.password_min_length} required disabled={!canUpdateSecurity || updateSecurity.isPending} /><small>Allowed range: 12–128 characters.</small></label>
              <div className="settings-form-footer">{!canUpdateSecurity ? <span>Read only: security settings update permission is required.</span> : <button className="primary-button" disabled={updateSecurity.isPending}>{updateSecurity.isPending ? "Saving…" : "Save policy"}</button>}</div>
            </form> : <form className="settings-form" onSubmit={saveSecurity}>
              <div className="settings-policy-note"><strong>Session policy</strong><p>Limits apply to sessions created after the policy is saved. At the concurrent session limit, the oldest active session is revoked on next successful sign in.</p></div>
              <label>Standard session lifetime<input type="number" name="session_ttl_days" min={1} max={30} defaultValue={security.data.session_ttl_days} required disabled={!canUpdateSecurity || updateSecurity.isPending} /><small>1–30 days</small></label>
              <label>Remembered session lifetime<input type="number" name="remembered_session_ttl_days" min={1} max={90} defaultValue={security.data.remembered_session_ttl_days} required disabled={!canUpdateSecurity || updateSecurity.isPending} /><small>1–90 days and cannot be shorter than the standard lifetime.</small></label>
              <label>Maximum concurrent sessions<input type="number" name="max_concurrent_sessions" min={1} max={50} defaultValue={security.data.max_concurrent_sessions} required disabled={!canUpdateSecurity || updateSecurity.isPending} /><small>1–50 sessions per user in this organization.</small></label>
              <div className="settings-form-footer">{!canUpdateSecurity ? <span>Read only: security settings update permission is required.</span> : <button className="primary-button" disabled={updateSecurity.isPending}>{updateSecurity.isPending ? "Saving…" : "Save policy"}</button>}</div>
            </form>)}
          </QueryState>)}
          {section === "integrations" && <EnterpriseIdentitySettings canManage={canManageIdentity} />}
          {section === "retention" && <RetentionSettings organization={org.data} canUpdate={canUpdateRetention} canOffboard={canOffboard} />}
          {section === "notifications" && <div className="panel settings-unavailable"><span aria-hidden="true">◇</span><h3>Notification settings are not configured</h3><p>Organization-wide notification preferences will appear here when the notification policy service is available.</p><span className="status-badge">Not configured</span></div>}
          {message && <p className="inline-feedback" role="status">{message}</p>}
          {mutationError && <p className="inline-feedback error-state" role="alert">{mutationError.message}</p>}
        </section>
      </div>
      {pendingSecurityUpdate && security.data && <RightDrawer title="Review security policy change" description="Confirm the organization-wide policy values before saving. The change will be recorded in the audit log." onClose={() => setPendingSecurityUpdate(null)}>
        <div className="settings-review-list">
          {Object.entries(pendingSecurityUpdate).map(([key, value]) => <div key={key}><span>{key === "password_min_length" ? "Minimum password length" : key === "session_ttl_days" ? "Standard session lifetime" : key === "remembered_session_ttl_days" ? "Remembered session lifetime" : "Maximum concurrent sessions"}</span><strong>{security.data?.[key as keyof OrganizationSecuritySettings]} → {value}{key.includes("ttl_days") ? " days" : key === "password_min_length" ? " characters" : " sessions"}</strong></div>)}
        </div>
        <div className="drawer-actions"><button className="secondary-button" onClick={() => setPendingSecurityUpdate(null)}>Cancel</button><button className="primary-button" disabled={updateSecurity.isPending} onClick={() => { updateSecurity.mutate(pendingSecurityUpdate); setPendingSecurityUpdate(null); }}>{updateSecurity.isPending ? "Saving…" : "Confirm and save"}</button></div>
      </RightDrawer>}
    </div>
  );
}
