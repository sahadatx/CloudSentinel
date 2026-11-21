import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../shared/useAuth";
import { api, type Notification } from "../shared/api";
import { DrawerFact, RightDrawer } from "../shared/RightDrawer";
import { Icon } from "../shared/Icon";
import type { IconName } from "../shared/kpi-utils";
import { FilterField } from "../shared/FilterField";
import { formatOrganizationDateTime } from "../shared/date-time";

function notificationDestination(item: Notification): string {
  const resourceType = item.resource_type?.toLowerCase();
  const resourceId = item.resource_id ? encodeURIComponent(item.resource_id) : "";
  if (resourceType === "finding" && resourceId) return `/findings/${resourceId}`;
  if (["scan", "scan_job"].includes(resourceType ?? "") && resourceId) return `/scans/${resourceId}`;
  if (resourceType === "remediation_request" && resourceId) return `/remediation/${resourceId}`;
  if (resourceType === "report" && resourceId) return `/reports/${resourceId}`;
  if (["cloud_account", "account"].includes(resourceType ?? "") && resourceId) return `/cloud-accounts/${resourceId}`;
  if (resourceType === "asset" && resourceId) return `/assets/${resourceId}`;
  if (["alert", "security_alert"].includes(resourceType ?? "")) return "/alerts";
  const category = item.category.toLowerCase();
  if (category === "finding") return "/findings";
  if (category === "scan") return "/scans";
  if (category === "report") return "/reports";
  if (category === "remediation") return "/remediation";
  if (category.includes("alert")) return "/alerts";
  return "/notifications";
}

const nav: Array<{
  title: string;
  links: Array<{ label: string; to: string; permission: string; icon: IconName }>;
}> = [
  {
    title: "Overview",
    links: [
      {
        label: "Dashboard",
        to: "/dashboard",
        permission: "organizations:read",
        icon: "dashboard",
      },
    ],
  },
  {
    title: "Cloud",
    links: [
      {
        label: "Cloud Accounts",
        to: "/cloud-accounts",
        permission: "cloud_accounts:read",
        icon: "cloud",
      },
      {
        label: "Scan Management",
        to: "/scans",
        permission: "scans:read",
        icon: "scan",
      },
      {
        label: "IaC & Container Scans",
        to: "/customer-scans",
        permission: "scans:read",
        icon: "shield",
      },
      { label: "Assets", to: "/assets", permission: "assets:read", icon: "assets" },
    ],
  },
  {
    title: "Security",
    links: [
      {
        label: "Findings",
        to: "/findings",
        permission: "findings:read",
        icon: "shield",
      },
      {
        label: "Policies",
        to: "/policies",
        permission: "policies:read",
        icon: "policy",
      },
      { label: "Risk", to: "/risk", permission: "findings:read", icon: "risk" },
      {
        label: "Compliance",
        to: "/compliance",
        permission: "findings:read",
        icon: "check",
      },
    ],
  },
  {
    title: "Operations",
    links: [
      {
        label: "Remediation",
        to: "/remediation",
        permission: "remediation:read",
        icon: "remediation",
      },
      {
        label: "Reports",
        to: "/reports",
        permission: "reports:read",
        icon: "report",
      },
      {
        label: "Alerts",
        to: "/alerts",
        permission: "alerts:read",
        icon: "warning",
      },
      {
        label: "Notifications",
        to: "/notifications",
        permission: "organizations:read",
        icon: "bell",
      },
    ],
  },
  {
    title: "Governance",
    links: [
      {
        label: "Audit Logs",
        to: "/audit",
        permission: "audit:read",
        icon: "activity",
      },
    ],
  },
  {
    title: "Administration",
    links: [
      {
        label: "Organization",
        to: "/administration/organization",
        permission: "organizations:read",
        icon: "organization",
      },
      {
        label: "Users",
        to: "/administration/users",
        permission: "users:read",
        icon: "user",
      },
      {
        label: "Teams",
        to: "/administration/teams",
        permission: "teams:read",
        icon: "team",
      },
      {
        label: "Settings",
        to: "/administration/settings",
        permission: "organizations:read",
        icon: "settings",
      },
    ],
  },
];

type SearchResult = {
  type: string;
  id: string;
  title: string;
  subtitle: string;
  href: string;
  rank: number;
};

const searchScopes = [
  ["all", "All"],
  ["finding", "Findings"],
  ["asset", "Assets"],
  ["cloud_account", "Accounts"],
  ["policy", "Policies"],
  ["compliance_control", "Compliance"],
  ["scan", "Scans"],
  ["user", "Users"],
  ["team", "Teams"],
  ["report", "Reports"],
] as const;

export function Shell() {
  const { user, logout, updateDisplayName } = useAuth();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [searchScope, setSearchScope] = useState("all");
  const [searchSeverity, setSearchSeverity] = useState("");
  const [searchStatus, setSearchStatus] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const searchInput = useRef<HTMLInputElement>(null);
  const noticeWrap = useRef<HTMLDivElement>(null);
  const profileWrap = useRef<HTMLDivElement>(null);
  const [feedback, setFeedback] = useState("");
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const [profilePanel, setProfilePanel] = useState<"details" | "edit" | "sessions" | null>(null);
  const [profileNameDraft, setProfileNameDraft] = useState<string | null>(null);
  const [collapsedGroups, setCollapsedGroups] = useState<
    Record<string, boolean>
  >({});
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);
  useEffect(() => {
    const timer = window.setTimeout(
      () => setDebouncedSearch(search.trim()),
      350,
    );
    return () => window.clearTimeout(timer);
  }, [search]);
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen(true);
        window.setTimeout(() => searchInput.current?.focus(), 0);
      } else if (event.key === "Escape") {
        setSearchOpen(false);
        setNoticeOpen(false);
        setProfileMenuOpen(false);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
  useEffect(() => {
    if (!noticeOpen) return;
    function onPointerDown(event: PointerEvent) {
      if (!noticeWrap.current?.contains(event.target as Node)) {
        setNoticeOpen(false);
      }
    }
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [noticeOpen]);
  useEffect(() => {
    if (!profileMenuOpen) return;
    function onPointerDown(event: PointerEvent) {
      if (!profileWrap.current?.contains(event.target as Node)) setProfileMenuOpen(false);
    }
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [profileMenuOpen]);
  const org = useQuery({
    queryKey: ["organization"],
    queryFn: () =>
      api.get<{
        name: string;
        slug: string;
        timezone: string;
        date_time_format: string;
        default_environment: string | null;
        default_region: string | null;
      }>("/organizations/current"),
  });
  const profileDetails = useQuery({
    queryKey: ["my-profile"],
    queryFn: () => api.get<{
      email: string;
      display_name: string;
      role_code: string;
      organization_name: string;
      is_active: boolean;
      team_names: string[];
    }>("/users/me"),
    enabled: profilePanel === "details" || profilePanel === "edit",
  });
  const profileName = profileNameDraft ?? profileDetails.data?.display_name ?? "";
  const profileSessions = useQuery({
    queryKey: ["my-profile-sessions"],
    queryFn: () => api.get<{ id: string; created_at: string; last_used_at: string | null; expires_at: string; current: boolean }[]>("/auth/sessions"),
    enabled: profilePanel === "sessions",
  });
  const saveProfile = useMutation({
    mutationFn: () => updateDisplayName(profileName.trim()),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["my-profile"] });
      setProfileNameDraft(null);
      setProfilePanel("details");
    },
  });
  useEffect(() => {
    if (!org.data) return;
    document.documentElement.dataset.timezone = org.data.timezone;
    document.documentElement.dataset.dateTimeFormat = org.data.date_time_format;
  }, [org.data]);
  const notices = useQuery({
    queryKey: ["notifications"],
    queryFn: () =>
      api.get<{ unread: number; items: Notification[] }>(
        "/notifications?limit=5",
      ),
    enabled: Boolean(user?.permissions.includes("organizations:read")),
    refetchInterval: 30_000,
  });
  const searchResults = useQuery({
    queryKey: [
      "global-search",
      debouncedSearch,
      searchScope,
      searchSeverity,
      searchStatus,
    ],
    enabled: searchOpen && debouncedSearch.length >= 2,
    queryFn: () => {
      const params = new URLSearchParams({
        q: debouncedSearch,
        page_size: "50",
      });
      if (searchScope !== "all") params.set("type", searchScope);
      if (searchSeverity) params.set("severity", searchSeverity);
      if (searchStatus) params.set("status", searchStatus);
      return api.get<{ results: SearchResult[]; total: number }>(
        `/search?${params}`,
      );
    },
  });
  const markRead = useMutation({
    mutationFn: (id: string) => api.post(`/notifications/${id}/read`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["notifications"] }),
  });

  async function signOut() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <aside className={`sidebar${mobileNavOpen ? " mobile-nav-open" : ""}`}>
        <NavLink to="/dashboard" className="brand">
          <span className="brand-mark"><Icon name="shield" /></span>
          <span>
            CloudSentinel<small>SECURITY OPERATIONS</small>
          </span>
        </NavLink>
        <button
          className="mobile-menu-toggle"
          aria-expanded={mobileNavOpen}
          aria-controls="primary-navigation"
          onClick={() => setMobileNavOpen((open) => !open)}
        >
          {mobileNavOpen ? "Close menu" : "Menu"}
        </button>
        <nav id="primary-navigation" aria-label="Primary navigation">
          {nav.map((group) => {
            const links = group.links.filter((link) =>
              user?.permissions.includes(link.permission),
            );
            return links.length ? (
              <section className="nav-group" key={group.title}>
                <button
                  type="button"
                  className="nav-title nav-group-toggle"
                  aria-expanded={!collapsedGroups[group.title]}
                  aria-controls={`nav-group-${group.title.toLowerCase()}`}
                  onClick={() =>
                    setCollapsedGroups((current) => ({
                      ...current,
                      [group.title]: !current[group.title],
                    }))
                  }
                >
                  {group.title}
                  <span
                    className={`nav-group-chevron${collapsedGroups[group.title] ? " collapsed" : ""}`}
                    aria-hidden="true"
                  >
                    <Icon name="chevron-down" />
                  </span>
                </button>
                <div
                  id={`nav-group-${group.title.toLowerCase()}`}
                  hidden={collapsedGroups[group.title]}
                >
                  {links.map((link) => (
                    <NavLink
                      end={link.to === "/"}
                      to={link.to}
                      key={link.to}
                      className={({ isActive }) =>
                        `nav-link${isActive ? " active" : ""}`
                      }
                      onClick={() => setMobileNavOpen(false)}
                    >
                      <span className="nav-icon"><Icon name={link.icon} /></span>
                      {link.label}
                      {link.to === "/notifications" &&
                        (notices.data?.unread ?? 0) > 0 && (
                          <span className="nav-count">
                            {notices.data?.unread}
                          </span>
                        )}
                    </NavLink>
                  ))}
                </div>
              </section>
            ) : null;
          })}
        </nav>
        <div className="sidebar-foot">
          <span className="status-dot" /> AWS security workspace
        </div>
      </aside>
      <main className="main-shell">
        <header className="topbar">
          <div className="context" aria-label="Workspace context">
            <div className="context-item">
              <span>Organization</span>
              <strong>{org.data?.name ?? "Loading organization"}</strong>
            </div>
            <div className="context-item">
              <span>Environment</span>
              <strong>{org.data?.default_environment ?? "Organization-wide"}</strong>
            </div>
            <div className="context-item">
              <span>Region</span>
              <strong>{org.data?.default_region ?? "Global"}</strong>
            </div>
          </div>
          <div className="header-tools">
            {user ? (
              <>
                <button
                  className="global-search-trigger"
                  type="button"
                  aria-haspopup="dialog"
                  aria-expanded={searchOpen}
                  onClick={() => {
                    setSearchOpen(true);
                    setNoticeOpen(false);
                    window.setTimeout(() => searchInput.current?.focus(), 0);
                  }}
                >
                  <span className="global-search-trigger-copy"><Icon name="search" />Search CloudSentinel</span>
                  <kbd><span>⌘</span><span>Ctrl K</span></kbd>
                </button>
                {searchOpen && (
                  <div
                    className="global-search-backdrop"
                    onMouseDown={(event) => {
                      if (event.target === event.currentTarget)
                        setSearchOpen(false);
                    }}
                  >
                    <section
                      className="global-search-dialog"
                      role="dialog"
                      aria-modal="true"
                      aria-label="Global search"
                    >
                      <div className="global-search-query">
                        <Icon name="search" />
                        <input
                          ref={searchInput}
                          autoFocus
                          aria-label="Global search"
                          placeholder="Search findings, assets, accounts, policies…"
                          value={search}
                          onChange={(event) => setSearch(event.target.value)}
                          onKeyDown={(event) => {
                            if (event.key === "Enter" && searchResults.data?.results[0] && !searchResults.isFetching) {
                              navigate(searchResults.data.results[0].href);
                              setSearchOpen(false);
                              setSearch("");
                            }
                          }}
                        />
                        {search && <button type="button" className="global-search-clear" aria-label="Clear search" onClick={() => { setSearch(""); searchInput.current?.focus(); }}><Icon name="close" /></button>}
                        <kbd>ESC · Close</kbd>
                      </div>
                      <div
                        className="global-search-scopes"
                        aria-label="Search entity type"
                      >
                        {searchScopes.map(([value, label]) => (
                          <button
                            key={value}
                            type="button"
                            className={searchScope === value ? "selected" : ""}
                            onClick={() => {
                              setSearchScope(value);
                              if (value !== "finding") {
                                setSearchSeverity("");
                                setSearchStatus("");
                              }
                            }}
                          >
                            {label}
                          </button>
                        ))}
                      </div>
                      {searchScope === "finding" && (
                        <div className="global-search-filters">
                          <FilterField label="Severity">
                          <select
                            aria-label="Filter by finding severity"
                            value={searchSeverity}
                            onChange={(event) =>
                              setSearchSeverity(event.target.value)
                            }
                          >
                            <option value="">Any severity</option>
                            {[
                              "CRITICAL",
                              "HIGH",
                              "MEDIUM",
                              "LOW",
                              "INFORMATIONAL",
                            ].map((value) => (
                              <option key={value}>{value}</option>
                            ))}
                          </select>
                          </FilterField>
                          <FilterField label="Status">
                          <select
                            aria-label="Filter by finding status"
                            value={searchStatus}
                            onChange={(event) =>
                              setSearchStatus(event.target.value)
                            }
                          >
                            <option value="">Any status</option>
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
                              <option key={value} value={value}>
                                {value.replaceAll("_", " ")}
                              </option>
                            ))}
                          </select>
                          </FilterField>
                        </div>
                      )}
                      <div className="global-search-results">
                        {debouncedSearch.length < 2 ? (
                          <p>Enter at least two characters to search.</p>
                        ) : searchResults.isFetching ? (
                          <p>Searching…</p>
                        ) : searchResults.error ? (
                          <p className="search-error" role="alert">
                            {searchResults.error instanceof Error ? searchResults.error.message : "Search could not be completed."}
                          </p>
                        ) : !searchResults.data?.results.length ? (
                          <p>No matching records.</p>
                        ) : (
                          (() => {
                            const groups = new Map<string, SearchResult[]>();
                            for (const item of searchResults.data.results)
                              groups.set(item.type, [
                                ...(groups.get(item.type) ?? []),
                                item,
                              ]);
                            return [...groups.entries()].map(
                              ([type, results]) => (
                                <div className="global-search-group" key={type}>
                                  <h3>{type.replaceAll("_", " ")}</h3>
                                  {results.map((result) => (
                                    <button
                                      key={`${result.type}-${result.id}`}
                                      type="button"
                                      onClick={() => {
                                        navigate(result.href);
                                        setSearchOpen(false);
                                        setSearch("");
                                      }}
                                    >
                                      {result.title}
                                      <small>{result.subtitle}</small>
                                    </button>
                                  ))}
                                </div>
                              ),
                            );
                          })()
                        )}
                        {searchResults.data?.total &&
                        searchResults.data.total >
                          searchResults.data.results.length ? (
                          <small className="global-search-more">
                            Showing {searchResults.data.results.length} of{" "}
                            {searchResults.data.total} matches
                          </small>
                        ) : null}
                      </div>
                    </section>
                  </div>
                )}
              </>
            ) : null}
            {user?.permissions.includes("scans:create") && (
              <button
                className="secondary-button header-run-scan"
                type="button"
                onClick={() => {
                  setFeedback("");
                  navigate("/scans?create=1");
                }}
              >
                <Icon name="scan" /> Run scan
              </button>
            )}
            {user?.permissions.includes("organizations:read") && (
              <div className="notice-wrap" ref={noticeWrap}>
                <button
                  className="notice-button"
                  aria-label="Notifications"
                  aria-expanded={noticeOpen}
                  aria-controls="notification-popover"
                  type="button"
                  onClick={() => setNoticeOpen(!noticeOpen)}
                >
                  <Icon name="bell" />
                  {(notices.data?.unread ?? 0) > 0 && (
                    <span>{notices.data?.unread}</span>
                  )}
                </button>
                {noticeOpen && (
                  <div className="notice-popover" id="notification-popover">
                    <strong>Notifications</strong>
                    {notices.isLoading ? <span>Loading notifications…</span> : notices.error ? <span role="alert">Notifications could not be loaded.</span> : notices.data?.items.length ? (
                      notices.data.items.map((item) => (
                        <button
                          key={item.id}
                          className={item.read_at ? "notice-read" : ""}
                          onClick={() => {
                            if (!item.read_at) markRead.mutate(item.id);
                            navigate(notificationDestination(item));
                            setNoticeOpen(false);
                          }}
                        >
                          <b>{item.title}</b>
                          <small>{item.message}</small>
                        </button>
                      ))
                    ) : (
                      <span>No notifications yet.</span>
                    )}
                    <NavLink
                      to="/notifications"
                      onClick={() => setNoticeOpen(false)}
                    >
                      View all notifications →
                    </NavLink>
                  </div>
                )}
              </div>
            )}
          </div>
          <div className="profile" ref={profileWrap}>
            <button className="profile-trigger" type="button" aria-label="Open profile options" aria-haspopup="menu" aria-expanded={profileMenuOpen} onClick={() => setProfileMenuOpen((open) => !open)}>
              <span className="avatar">{user?.display_name?.slice(0, 1).toUpperCase() ?? "U"}</span>
              <span className="profile-trigger-copy"><strong>{user?.display_name}</strong><small>{user?.role?.replaceAll("_", " ")}</small></span>
              <span className="profile-trigger-chevron" aria-hidden="true"><Icon name="chevron-down" /></span>
            </button>
            {profileMenuOpen && <div className="profile-menu" role="menu" aria-label="Account options">
              <div className="profile-menu-heading">Account options<small>Manage your profile and security</small></div>
              <button type="button" role="menuitem" onClick={() => { setProfileMenuOpen(false); setProfilePanel("details"); }}><span className="profile-menu-icon" aria-hidden="true"><Icon name="user" /></span><span className="profile-menu-copy"><strong>Profile details</strong><small>View your account information</small></span></button>
              <button type="button" role="menuitem" onClick={() => { setProfileMenuOpen(false); setProfilePanel("edit"); }}><span className="profile-menu-icon" aria-hidden="true"><Icon name="remediation" /></span><span className="profile-menu-copy"><strong>Edit profile</strong><small>Update your display name</small></span></button>
              <button type="button" role="menuitem" onClick={() => { setProfileMenuOpen(false); setProfilePanel("sessions"); }}><span className="profile-menu-icon" aria-hidden="true"><Icon name="lock" /></span><span className="profile-menu-copy"><strong>Active sessions</strong><small>Review signed-in devices</small></span></button>
              <div className="profile-menu-separator" />
              <button className="profile-menu-signout" type="button" role="menuitem" onClick={() => { setProfileMenuOpen(false); void signOut(); }}><span className="profile-menu-icon" aria-hidden="true"><Icon name="logout" /></span><span className="profile-menu-copy"><strong>Sign out</strong><small>End your current session</small></span></button>
            </div>}
          </div>
        </header>
        {profilePanel && (
          <RightDrawer title={profilePanel === "details" ? "Profile details" : profilePanel === "edit" ? "Edit profile" : "Active sessions"} description={profilePanel === "sessions" ? "Sessions for your account" : "Your account information"} onClose={() => setProfilePanel(null)} className="profile-drawer">
            {(profilePanel === "details" || profilePanel === "edit") && (profileDetails.isLoading ? <div className="state-panel"><span className="spinner" />Loading profile…</div> : profileDetails.error ? <div className="state-panel error-state">{profileDetails.error.message}</div> : profileDetails.data ? (
              <>
                {profilePanel === "details" ? <>
                <div className="drawer-facts">
                  <DrawerFact label="Name" value={profileDetails.data.display_name} />
                  <DrawerFact label="Email" value={profileDetails.data.email} />
                  <DrawerFact label="Role" value={profileDetails.data.role_code.replaceAll("_", " ")} />
                  <DrawerFact label="Organization" value={profileDetails.data.organization_name} />
                  <DrawerFact label="Status" value={profileDetails.data.is_active ? "Active" : "Inactive"} />
                  <DrawerFact label="Teams" value={profileDetails.data.team_names.join(", ") || "No teams assigned"} />
                </div>
                <div className="profile-drawer-actions">
                  <button className="primary-button profile-edit-trigger" type="button" onClick={() => setProfilePanel("edit")}>
                    <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M12.9 3.1a1.8 1.8 0 0 1 2.5 2.5l-8.7 8.7-3.5 1 1-3.5 8.7-8.7Z" /><path d="m11.7 4.3 3 3" /></svg>
                    Edit profile
                  </button>
                </div>
                </> : <form className="profile-edit-form" onSubmit={(event) => { event.preventDefault(); saveProfile.mutate(); }}>
                  {saveProfile.error && <div className="banner-error">{saveProfile.error.message}</div>}
                  <label className="profile-field">Full name<input required minLength={2} maxLength={200} value={profileName} onChange={(event) => setProfileNameDraft(event.target.value)} /></label>
                  <div className="profile-field"><span>Email address</span><div className="profile-readonly-value">{profileDetails.data.email}</div></div>
                  <p>Your email address and organization role are managed by your organization.</p>
                  <button className="primary-button" type="submit" disabled={saveProfile.isPending || profileName.trim().length < 2}>{saveProfile.isPending ? "Saving…" : "Save changes"}</button>
                </form>}
              </>
            ) : null)}
            {profilePanel === "sessions" && (profileSessions.isLoading ? <div className="state-panel"><span className="spinner" />Loading sessions…</div> : profileSessions.error ? <div className="state-panel error-state">{profileSessions.error.message}</div> : profileSessions.data?.length ? <div className="profile-session-list">{profileSessions.data.map((session) => <div className="profile-session-item" key={session.id}><strong>{session.current ? "Current session" : "Signed-in session"}</strong><span>Started {formatOrganizationDateTime(session.created_at)}</span><span>Expires {formatOrganizationDateTime(session.expires_at)}</span></div>)}</div> : <div className="state-panel">No active sessions.</div>)}
          </RightDrawer>
        )}
        <div
          id="main-content"
          tabIndex={-1}
          className="content"
          onMouseOver={(event) => {
            const target = event.target;
            if (!(target instanceof HTMLElement)) return;
            const cell = target.closest<HTMLElement>("td small, td button, td a, td, th");
            if (!cell || cell.title || cell.scrollWidth <= cell.clientWidth + 1) return;
            const fullText = cell.innerText.trim();
            if (fullText) cell.title = fullText;
          }}
        >
          <Outlet />
        </div>
      </main>
      {feedback && (
        <button className="toast-message" onClick={() => setFeedback("")}>
          {feedback} · dismiss
        </button>
      )}
    </div>
  );
}
